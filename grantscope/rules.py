"""The GrantScope rule registry.

Each rule is a small, pure function that receives a :class:`Context` and
returns zero or more :class:`~grantscope.models.Finding` objects. Rules never
perform I/O and never mutate the context, which makes them trivial to unit
test and safe to run in parallel in a future version.

Rule IDs are grouped by artefact:

======  ==========================================
Range   Artefact
======  ==========================================
GS1xx   OIDC discovery / authorization server metadata
GS2xx   Authorization request
GS3xx   PKCE (RFC 7636)
GS4xx   Token endpoint response
GS5xx   ID token / JWT claims
GS6xx   HTTP response headers / transport
======  ==========================================

Rules tagged ``(mcp)`` only run under ``--profile mcp`` and implement the
additional requirements that MCP remote servers have on top of OAuth 2.1
(RFC 8707 ``resource``, protected-resource metadata in ``WWW-Authenticate``).
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from .jwt import ParsedToken
from .models import Finding, InputItem, Rule, Severity
from .pkce import (
    b64url_no_pad,
    validate_challenge,
    validate_verifier,
    verify_challenge,
)

__all__ = [
    "Options",
    "Context",
    "RULES",
    "RULE_BY_ID",
    "run_rules",
    "all_rules",
]

# ---------------------------------------------------------------------------
# Registry plumbing
# ---------------------------------------------------------------------------

RULES: List[Rule] = []
RULE_BY_ID: Dict[str, Rule] = {}
_CHECKS: Dict[str, Callable[["Context"], List[Finding]]] = {}


def rule(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    rationale: str,
    remediation: str,
    reference: str = "",
) -> Callable[[Callable[["Context"], List[Finding]]], Callable[["Context"], List[Finding]]]:
    """Register a check function together with its static metadata."""
    if rule_id in RULE_BY_ID:
        raise ValueError("duplicate rule id: %s" % rule_id)
    meta = Rule(rule_id, title, severity, category, rationale, remediation, reference)

    def decorator(fn: Callable[["Context"], List[Finding]]):
        RULES.append(meta)
        RULE_BY_ID[rule_id] = meta
        _CHECKS[rule_id] = fn
        return fn

    return decorator


def emit(
    ctx: "Context",
    rule_id: str,
    message: str,
    location: Optional[str] = None,
    evidence: str = "",
) -> Finding:
    """Build a :class:`Finding` using registered rule metadata."""
    r = RULE_BY_ID[rule_id]
    return Finding(
        rule_id=r.id,
        title=r.title,
        severity=r.severity,
        category=r.category,
        message=message,
        location=location or ctx.location,
        evidence=evidence,
        remediation=r.remediation,
        reference=r.reference,
    )


def all_rules() -> List[Rule]:
    """Return the registry in declaration order."""
    return list(RULES)


def run_rules(ctx: "Context") -> List[Finding]:
    """Execute every rule and return findings in registry order."""
    out: List[Finding] = []
    for r in RULES:
        out.extend(_CHECKS[r.id](ctx))
    return out


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Options:
    """User-supplied audit options."""

    expected_issuer: str = ""
    expected_audience: str = ""
    expected_nonce: str = ""
    code_verifier: str = ""
    profile: str = "default"
    now: float = dataclasses.field(default_factory=time.time)

    @property
    def is_mcp(self) -> bool:
        return self.profile == "mcp"


@dataclasses.dataclass
class Context:
    """Normalised view over the loaded artefacts."""

    items: List[InputItem]
    options: Options
    discovery: Optional[Dict[str, Any]] = None
    client: Optional[Dict[str, Any]] = None
    auth: Optional[Dict[str, Any]] = None
    token_response: Optional[Dict[str, Any]] = None
    id_token: Optional[ParsedToken] = None
    headers: Optional[Dict[str, Any]] = None
    loc_discovery: str = ""
    loc_client: str = ""
    loc_auth: str = ""
    loc_token: str = ""
    loc_id_token: str = ""
    loc_headers: str = ""

    @classmethod
    def build(cls, items: List[InputItem], options: Options) -> "Context":
        ctx = cls(items=items, options=options)
        from .models import Kind

        for item in items:
            if item.kind is Kind.DISCOVERY:
                ctx.discovery, ctx.loc_discovery = item.data, item.label
            elif item.kind is Kind.CLIENT:
                ctx.client, ctx.loc_client = item.data, item.label
            elif item.kind is Kind.AUTH_REQUEST:
                ctx.auth, ctx.loc_auth = item.data, item.label
            elif item.kind is Kind.TOKEN_RESPONSE:
                ctx.token_response, ctx.loc_token = item.data, item.label
            elif item.kind is Kind.ID_TOKEN:
                ctx.id_token, ctx.loc_id_token = item.data, item.label
            elif item.kind is Kind.HEADERS:
                ctx.headers, ctx.loc_headers = item.data, item.label
        return ctx

    @property
    def location(self) -> str:
        for loc in (
            self.loc_discovery,
            self.loc_auth,
            self.loc_client,
            self.loc_token,
            self.loc_id_token,
            self.loc_headers,
        ):
            if loc:
                return loc
        return self.items[0].label if self.items else "<none>"

    @property
    def params(self) -> Dict[str, str]:
        return (self.auth or {}).get("params", {}) or {}

    @property
    def claims(self) -> Dict[str, Any]:
        return (self.id_token.claims if self.id_token else {}) or {}

    @property
    def header_map(self) -> Dict[str, List[str]]:
        return (self.headers or {}).get("headers", {}) or {}

    def header_joined(self, name: str) -> str:
        return ", ".join(self.header_map.get(name.lower(), []))

    def has_header_value(self, name: str, needle: str) -> bool:
        return needle.lower() in self.header_joined(name).lower()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_REQUIRED_CLAIMS = ("iss", "sub", "aud", "exp", "iat")
_SENSITIVE_CLAIM_KEYS = {
    "password",
    "passwd",
    "client_secret",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "credit_card",
    "ssn",
    "private_key",
}
_SENSITIVE_QUERY_KEYS = {"client_secret", "access_token", "refresh_token", "id_token"}
# A token response *legitimately* carries access_token / refresh_token / id_token.
# Only credential-like keys are suspicious there.
_SENSITIVE_RESPONSE_KEYS = {
    "client_secret", "secret", "password", "passwd", "api_key", "apikey",
    "private_key", "credit_card", "ssn",
}
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _is_https(url: str) -> bool:
    return urlsplit(url or "").scheme.lower() == "https"


def _is_loopback_http(url: str) -> bool:
    split = urlsplit(url or "")
    return split.scheme.lower() == "http" and (split.hostname or "").lower() in _LOOPBACK


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def _one(ctx: Context, rule_id: str, condition: bool, message: str,
         location: Optional[str] = None, evidence: str = "") -> List[Finding]:
    return [emit(ctx, rule_id, message, location, evidence)] if condition else []


# ---------------------------------------------------------------------------
# GS1xx — OIDC discovery / authorization server metadata
# ---------------------------------------------------------------------------

_REF_OIDC = "OpenID Connect Discovery 1.0 §3"
_REF_BCP = "OAuth 2.0 Security Best Current Practice (RFC 9700)"


@rule("GS101", "Missing issuer in discovery document", Severity.HIGH, "Discovery",
      "The issuer is the trust anchor for every ID token and must be present.",
      "Publish a canonical https issuer in /.well-known/openid-configuration.", _REF_OIDC)
def _gs101(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    return _one(ctx, "GS101", not ctx.discovery.get("issuer"),
                "Discovery document has no 'issuer' field; token iss cannot be validated.",
                ctx.loc_discovery)


@rule("GS102", "Issuer is not https", Severity.CRITICAL, "Discovery",
      "OIDC issuers must use https; plaintext issuers enable token substitution.",
      "Serve the issuer and all endpoints over TLS.", _REF_OIDC)
def _gs102(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    issuer = str(ctx.discovery.get("issuer") or "")
    return _one(ctx, "GS102", bool(issuer) and not _is_https(issuer),
                "issuer uses a non-https scheme: %r" % issuer,
                ctx.loc_discovery, issuer)


@rule("GS103", "Required endpoint missing from discovery", Severity.HIGH, "Discovery",
      "authorization_endpoint, token_endpoint and jwks_uri are mandatory for a usable provider.",
      "Add every required endpoint to the discovery document.", _REF_OIDC)
def _gs103(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri")
               if not ctx.discovery.get(k)]
    return _one(ctx, "GS103", bool(missing),
                "Missing required discovery keys: %s" % ", ".join(missing),
                ctx.loc_discovery, ", ".join(missing))


@rule("GS104", "Discovery endpoint is not https", Severity.HIGH, "Discovery",
      "Authorization, token and JWKS endpoints must be TLS-protected.",
      "Replace plaintext endpoint URLs with https equivalents.", _REF_OIDC)
def _gs104(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    bad = [str(ctx.discovery.get(k)) for k in
           ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint")
           if ctx.discovery.get(k) and not _is_https(str(ctx.discovery.get(k)))]
    return _one(ctx, "GS104", bool(bad),
                "Non-https endpoint(s): %s" % "; ".join(bad),
                ctx.loc_discovery, "; ".join(bad))


@rule("GS105", "Provider does not advertise PKCE S256", Severity.HIGH, "Discovery",
      "OAuth 2.1 requires PKCE with S256; a provider that does not advertise it cannot be used safely by public clients.",
      "Add 'S256' to code_challenge_methods_supported and enforce it at the token endpoint.", _REF_BCP)
def _gs105(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    methods = [m.upper() for m in _as_list(ctx.discovery.get("code_challenge_methods_supported"))]
    return _one(ctx, "GS105", "S256" not in methods,
                "code_challenge_methods_supported does not include S256 (found: %s)"
                % (", ".join(methods) or "none"),
                ctx.loc_discovery, ", ".join(methods))


@rule("GS106", "Issuer does not match expected issuer", Severity.CRITICAL, "Discovery",
      "An issuer mismatch is a classic mix-up / token-substitution signal.",
      "Verify the provider URL out-of-band and pin it with --expected-issuer.", _REF_BCP)
def _gs106(ctx: Context) -> List[Finding]:
    expected = ctx.options.expected_issuer.strip().rstrip("/")
    if ctx.discovery is None or not expected:
        return []
    actual = str(ctx.discovery.get("issuer") or "").rstrip("/")
    return _one(ctx, "GS106", bool(actual) and actual != expected,
                "issuer %r does not match expected %r" % (actual, expected),
                ctx.loc_discovery, actual)


@rule("GS107", "Provider still advertises implicit-flow response types", Severity.MEDIUM, "Discovery",
      "The implicit flow is deprecated: tokens travel in the URL fragment and leak through history/referrers.",
      "Remove 'token' / 'id_token' response types; use authorization code + PKCE.", _REF_BCP)
def _gs107(ctx: Context) -> List[Finding]:
    if ctx.discovery is None:
        return []
    bad = [v for v in _as_list(ctx.discovery.get("response_types_supported"))
           if "token" in v.lower().split() or v.strip().lower() in ("token", "id_token")]
    return _one(ctx, "GS107", bool(bad),
                "Implicit-flow response types advertised: %s" % ", ".join(bad),
                ctx.loc_discovery, ", ".join(bad))


# ---------------------------------------------------------------------------
# GS2xx — Authorization request
# ---------------------------------------------------------------------------


@rule("GS201", "Authorization request has no response_type", Severity.HIGH, "Authorization request",
      "Without response_type the flow is undefined.",
      "Set response_type=code.", "RFC 6749 §3.1.1")
def _gs201(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS201", ctx.auth is not None and not ctx.params.get("response_type"),
                "response_type is missing from the authorization request.", ctx.loc_auth)


@rule("GS202", "Implicit flow used in authorization request", Severity.CRITICAL, "Authorization request",
      "Implicit/hybrid response types expose tokens in the URL fragment.",
      "Switch to response_type=code with PKCE.", _REF_BCP)
def _gs202(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    rt = ctx.params.get("response_type", "").lower()
    implicit = bool(rt) and rt != "code" and ("token" in rt.split() or rt in ("token", "id_token"))
    return _one(ctx, "GS202", implicit,
                "response_type=%r uses the deprecated implicit/hybrid flow." % rt,
                ctx.loc_auth, rt)


@rule("GS203", "response_type is not 'code'", Severity.HIGH, "Authorization request",
      "OAuth 2.1 only permits the authorization code flow (with PKCE) for user authorization.",
      "Use response_type=code.", _REF_BCP)
def _gs203(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    rt = ctx.params.get("response_type", "")
    return _one(ctx, "GS203", bool(rt) and rt.lower() != "code" and "token" not in rt.lower().split()
                and rt.lower() not in ("token", "id_token"),
                "response_type=%r is neither 'code' nor a known implicit value." % rt,
                ctx.loc_auth, rt)


@rule("GS204", "Authorization request has no client_id", Severity.HIGH, "Authorization request",
      "client_id identifies the client to the authorization server.",
      "Include client_id in the authorization request.", "RFC 6749 §4.1.1")
def _gs204(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS204", ctx.auth is not None and not ctx.params.get("client_id"),
                "client_id is missing.", ctx.loc_auth)


@rule("GS205", "Authorization request has no redirect_uri", Severity.MEDIUM, "Authorization request",
      "Omitting redirect_uri relies on a single registered default and hides misconfiguration.",
      "Pass redirect_uri explicitly and register it exactly.", "RFC 6749 §4.1.1")
def _gs205(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS205", ctx.auth is not None and not ctx.params.get("redirect_uri"),
                "redirect_uri is missing.", ctx.loc_auth)


@rule("GS206", "redirect_uri uses plaintext http", Severity.HIGH, "Authorization request",
      "Authorization responses carry the code; plaintext transport enables interception.",
      "Use https, or http only for loopback native clients.", _REF_BCP)
def _gs206(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    uri = ctx.params.get("redirect_uri", "")
    bad = bool(uri) and not _is_https(uri) and not _is_loopback_http(uri)
    return _one(ctx, "GS206", bad,
                "redirect_uri %r is neither https nor a loopback http URI." % uri,
                ctx.loc_auth, uri)


@rule("GS207", "redirect_uri contains a fragment", Severity.HIGH, "Authorization request",
      "RFC 6749 forbids fragments in redirect_uri; fragments interact badly with implicit tokens.",
      "Remove the fragment component from redirect_uri.", "RFC 6749 §3.1.2")
def _gs207(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    uri = ctx.params.get("redirect_uri", "")
    return _one(ctx, "GS207", "#" in uri,
                "redirect_uri contains a fragment: %r" % uri, ctx.loc_auth, uri)


@rule("GS208", "redirect_uri contains a wildcard", Severity.CRITICAL, "Authorization request",
      "Wildcard redirect URIs allow authorization-code injection into attacker-controlled origins.",
      "Register exact redirect URIs; never use '*' or path wildcards.", _REF_BCP)
def _gs208(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    uri = ctx.params.get("redirect_uri", "")
    return _one(ctx, "GS208", "*" in uri,
                "redirect_uri contains a wildcard: %r" % uri, ctx.loc_auth, uri)


@rule("GS209", "redirect_uri does not match client registration", Severity.CRITICAL, "Authorization request",
      "Exact string matching of redirect_uri against the registered list is mandatory.",
      "Use one of the registered redirect URIs verbatim.", "RFC 6749 §4.1.2 / RFC 9700")
def _gs209(ctx: Context) -> List[Finding]:
    if ctx.auth is None or ctx.client is None:
        return []
    uri = ctx.params.get("redirect_uri", "")
    registered = _as_list(ctx.client.get("redirect_uris"))
    bad = bool(uri) and bool(registered) and uri not in registered
    return _one(ctx, "GS209", bad,
                "redirect_uri %r is not in registered redirect_uris (%s)."
                % (uri, ", ".join(registered)), ctx.loc_auth, uri)


@rule("GS210", "Authorization request has no state", Severity.HIGH, "Authorization request",
      "state binds the response to the request and is the primary CSRF defence.",
      "Generate a fresh, unpredictable state per request and verify it on callback.", "RFC 6749 §4.1.1")
def _gs210(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS210", ctx.auth is not None and not ctx.params.get("state"),
                "state parameter is missing; the callback cannot be bound to this request.",
                ctx.loc_auth)


@rule("GS211", "state has insufficient entropy", Severity.MEDIUM, "Authorization request",
      "Short or predictable state values are guessable and weaken CSRF protection.",
      "Use at least 16 characters from a cryptographically random source.", "RFC 9700 §2.1")
def _gs211(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    state = ctx.params.get("state", "")
    return _one(ctx, "GS211", bool(state) and len(state) < 16,
                "state is only %d characters (recommended >= 16)." % len(state),
                ctx.loc_auth, state)


@rule("GS212", "OIDC request without nonce", Severity.HIGH, "Authorization request",
      "nonce binds an ID token to the authorization request and prevents replay in code/hybrid flows.",
      "Add a fresh nonce whenever scope contains openid, and verify the nonce claim.", _REF_OIDC)
def _gs212(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    scope = ctx.params.get("scope", "")
    needs_nonce = "openid" in scope.split()
    return _one(ctx, "GS212", needs_nonce and not ctx.params.get("nonce"),
                "scope includes openid but nonce is missing.", ctx.loc_auth, scope)


@rule("GS213", "Sensitive value leaked in authorization URL", Severity.CRITICAL, "Authorization request",
      "Secrets and tokens in a URL end up in browser history, proxies and Referer headers.",
      "Never place secrets or tokens in a URL; use the token endpoint over TLS with a body.", "RFC 9700")
def _gs213(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    leaked = sorted(k for k in _SENSITIVE_QUERY_KEYS if k in ctx.params)
    return _one(ctx, "GS213", bool(leaked),
                "Sensitive parameter(s) present in URL query: %s" % ", ".join(leaked),
                ctx.loc_auth, ", ".join(leaked))


@rule("GS214", "MCP request missing RFC 8707 resource parameter", Severity.HIGH, "Authorization request",
      "MCP remote servers require the resource indicator so tokens are audience-bound to one server.",
      "Add resource=<canonical MCP server URI> to authorization and token requests.",
      "RFC 8707 / MCP Authorization spec (2025-06-18)")
def _gs214(ctx: Context) -> List[Finding]:
    if ctx.auth is None or not ctx.options.is_mcp:
        return []
    return _one(ctx, "GS214", not ctx.params.get("resource"),
                "MCP profile requires a 'resource' parameter; none was found.", ctx.loc_auth)


# ---------------------------------------------------------------------------
# GS3xx — PKCE
# ---------------------------------------------------------------------------


def _verifier(ctx: Context) -> str:
    return ctx.options.code_verifier or ctx.params.get("code_verifier", "")


@rule("GS301", "PKCE code_challenge missing", Severity.CRITICAL, "PKCE",
      "OAuth 2.1 mandates PKCE for authorization code grants; without it, a stolen code is directly redeemable.",
      "Generate a code_verifier, derive the S256 challenge and add code_challenge + code_challenge_method=S256.", _REF_BCP)
def _gs301(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS301", ctx.auth is not None and not ctx.params.get("code_challenge"),
                "code_challenge is missing from the authorization request.", ctx.loc_auth)


@rule("GS302", "PKCE uses plain method", Severity.HIGH, "PKCE",
      "'plain' sends the verifier itself as the challenge and provides no protection.",
      "Use code_challenge_method=S256.", "RFC 7636 §4.2")
def _gs302(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    method = ctx.params.get("code_challenge_method", "")
    return _one(ctx, "GS302", method.lower() == "plain",
                "code_challenge_method=plain is forbidden by OAuth 2.1.", ctx.loc_auth, method)


@rule("GS303", "PKCE method not declared", Severity.MEDIUM, "PKCE",
      "Per RFC 7636 an omitted method defaults to 'plain'.",
      "Always send code_challenge_method=S256 explicitly.", "RFC 7636 §4.3")
def _gs303(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    has_challenge = bool(ctx.params.get("code_challenge"))
    return _one(ctx, "GS303", has_challenge and not ctx.params.get("code_challenge_method"),
                "code_challenge present but code_challenge_method is omitted (defaults to plain).",
                ctx.loc_auth)


@rule("GS304", "code_challenge has invalid syntax", Severity.MEDIUM, "PKCE",
      "A S256 challenge is always 43 unpadded base64url characters.",
      "Recompute BASE64URL(SHA256(ASCII(code_verifier))) without padding.", "RFC 7636 §4.2")
def _gs304(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    challenge = ctx.params.get("code_challenge", "")
    problems = validate_challenge(challenge) if challenge else []
    return _one(ctx, "GS304", bool(problems), "; ".join(problems),
                ctx.loc_auth, challenge)


@rule("GS305", "code_verifier has invalid syntax", Severity.HIGH, "PKCE",
      "RFC 7636 restricts the verifier to 43-128 unreserved ASCII characters.",
      "Generate the verifier with a CSPRNG from [A-Za-z0-9-._~] with length 43-128.", "RFC 7636 §4.1")
def _gs305(ctx: Context) -> List[Finding]:
    verifier = _verifier(ctx)
    problems = validate_verifier(verifier) if verifier else []
    return _one(ctx, "GS305", bool(problems), "; ".join(problems),
                ctx.loc_auth, verifier[:24] + ("..." if len(verifier) > 24 else ""))


@rule("GS306", "code_challenge does not match code_verifier", Severity.CRITICAL, "PKCE",
      "A mismatch means the token endpoint will reject the exchange, or the client and server disagree on the algorithm.",
      "Recompute the challenge with S256 and compare; do not copy a stale challenge across requests.",
      "RFC 7636 §4.6")
def _gs306(ctx: Context) -> List[Finding]:
    verifier = _verifier(ctx)
    challenge = ctx.params.get("code_challenge", "")
    if not verifier or not challenge:
        return []
    method = ctx.params.get("code_challenge_method", "S256")
    matched = verify_challenge(verifier, challenge, method)
    expected = ""
    if not matched and method.lower() in ("s256", ""):
        try:
            expected = b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
        except UnicodeEncodeError:
            expected = ""
    return _one(ctx, "GS306", not matched,
                "S256 recomputation does not match code_challenge%s."
                % (" (expected %s)" % expected if expected else ""),
                ctx.loc_auth, challenge)


@rule("GS307", "code_challenge contains base64 padding", Severity.LOW, "PKCE",
      "Padding characters are not part of base64url and cause interoperability failures.",
      "Strip '=' padding from the challenge.", "RFC 7636 Appendix A")
def _gs307(ctx: Context) -> List[Finding]:
    if ctx.auth is None:
        return []
    challenge = ctx.params.get("code_challenge", "")
    return _one(ctx, "GS307", "=" in challenge,
                "code_challenge contains '=' padding.", ctx.loc_auth, challenge)


# ---------------------------------------------------------------------------
# GS4xx — Token endpoint response
# ---------------------------------------------------------------------------


@rule("GS401", "Token response has no access_token", Severity.HIGH, "Token response",
      "A successful token response must contain an access token.",
      "Check the error response path separately; only audit successful responses as success fixtures.", "RFC 6749 §5.1")
def _gs401(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS401", ctx.token_response is not None and not ctx.token_response.get("access_token"),
                "access_token is missing from the token response.", ctx.loc_token)


@rule("GS402", "token_type is not Bearer", Severity.MEDIUM, "Token response",
      "Clients must know how to present the token; Bearer is the interoperable default.",
      "Return token_type='Bearer' (case-insensitive) as required by RFC 6750.", "RFC 6750")
def _gs402(ctx: Context) -> List[Finding]:
    if ctx.token_response is None:
        return []
    tt = str(ctx.token_response.get("token_type") or "")
    return _one(ctx, "GS402", bool(tt) and tt.lower() != "bearer",
                "token_type=%r is not Bearer." % tt, ctx.loc_token, tt)


@rule("GS403", "Token response has no expires_in", Severity.MEDIUM, "Token response",
      "Without expires_in a client cannot schedule refresh and may reuse an expired token.",
      "Include expires_in (seconds) in every successful token response.", "RFC 6749 §5.1")
def _gs403(ctx: Context) -> List[Finding]:
    return _one(ctx, "GS403", ctx.token_response is not None and "expires_in" not in ctx.token_response,
                "expires_in is missing.", ctx.loc_token)


@rule("GS404", "Credential echoed in token response", Severity.CRITICAL, "Token response",
      "A secret in a response body will be logged, cached and forwarded by intermediaries.",
      "Never echo credentials in responses; rotate the secret immediately if this occurred.", "RFC 9700")
def _gs404(ctx: Context) -> List[Finding]:
    if ctx.token_response is None:
        return []
    leaked = [k for k in ctx.token_response if k.lower() in _SENSITIVE_RESPONSE_KEYS]
    return _one(ctx, "GS404", bool(leaked),
                "Credential-like key(s) in token response: %s" % ", ".join(sorted(leaked)),
                ctx.loc_token, ", ".join(sorted(leaked)))


@rule("GS405", "Granted scope differs from requested scope", Severity.LOW, "Token response",
      "A silent scope downgrade usually indicates a broken client assumption.",
      "Compare the returned scope to the request and surface the difference to the user.", "RFC 6749 §5.1")
def _gs405(ctx: Context) -> List[Finding]:
    if ctx.token_response is None or ctx.auth is None:
        return []
    requested = set(ctx.params.get("scope", "").split())
    granted = set(str(ctx.token_response.get("scope") or "").split())
    bad = bool(requested) and bool(granted) and granted != requested
    return _one(ctx, "GS405", bad,
                "Granted scope %s differs from requested %s."
                % (sorted(granted), sorted(requested)), ctx.loc_token)


# ---------------------------------------------------------------------------
# GS5xx — ID token / JWT claims
# ---------------------------------------------------------------------------


def _number(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


@rule("GS501", "ID token has invalid compact JWS structure", Severity.HIGH, "ID token",
      "A malformed token cannot be validated at all; downstream checks would be meaningless.",
      "Ensure the token is a three-segment compact JWS with base64url JSON header/payload.",
      "RFC 7519")
def _gs501(ctx: Context) -> List[Finding]:
    if ctx.id_token is None:
        return []
    problems = list(ctx.id_token.errors)
    return _one(ctx, "GS501", bool(problems), "; ".join(problems),
                ctx.loc_id_token, ctx.id_token.token[:48])


@rule("GS502", "ID token uses alg=none", Severity.CRITICAL, "ID token",
      "An unsecured JWT lets anyone forge identity claims.",
      "Reject alg=none; require a signature algorithm allowed by the provider.", "RFC 8725")
def _gs502(ctx: Context) -> List[Finding]:
    if ctx.id_token is None:
        return []
    return _one(ctx, "GS502", ctx.id_token.alg.lower() == "none",
                "JWT header declares alg=none (no signature).", ctx.loc_id_token, ctx.id_token.alg)


@rule("GS503", "ID token signed with symmetric HS256", Severity.MEDIUM, "ID token",
      "Symmetric signing means every client holding the secret can mint ID tokens.",
      "Prefer asymmetric algorithms (RS256/ES256) with a published JWKS.", "OIDC Core §2")
def _gs503(ctx: Context) -> List[Finding]:
    if ctx.id_token is None:
        return []
    return _one(ctx, "GS503", ctx.id_token.alg.upper().startswith("HS"),
                "ID token uses symmetric algorithm %s." % ctx.id_token.alg,
                ctx.loc_id_token, ctx.id_token.alg)


@rule("GS504", "Asymmetric ID token has no kid", Severity.LOW, "ID token",
      "Without kid, key rotation requires trial verification against every key.",
      "Include kid in the JOSE header and publish the matching key in jwks_uri.", "RFC 7515 §4.1.4")
def _gs504(ctx: Context) -> List[Finding]:
    if ctx.id_token is None:
        return []
    alg = ctx.id_token.alg.upper()
    asymmetric = alg.startswith(("RS", "ES", "PS", "Ed"))
    return _one(ctx, "GS504", asymmetric and not ctx.id_token.header.get("kid"),
                "Asymmetrically signed ID token has no 'kid' in its header.", ctx.loc_id_token)


@rule("GS505", "ID token missing required claims", Severity.HIGH, "ID token",
      "iss, sub, aud, exp and iat are mandatory for ID token validation.",
      "Add all required claims; verify them against the expected issuer/audience.", "OIDC Core §2")
def _gs505(ctx: Context) -> List[Finding]:
    if ctx.id_token is None or ctx.id_token.errors:
        return []
    missing = [k for k in _REQUIRED_CLAIMS if k not in ctx.claims]
    return _one(ctx, "GS505", bool(missing),
                "Missing required claim(s): %s" % ", ".join(missing),
                ctx.loc_id_token, ", ".join(missing))


@rule("GS506", "ID token is expired", Severity.HIGH, "ID token",
      "An expired token must never be accepted.",
      "Refresh the token; check clock skew explicitly.", "OIDC Core §2")
def _gs506(ctx: Context) -> List[Finding]:
    exp = _number(ctx.claims.get("exp"))
    return _one(ctx, "GS506", exp is not None and exp < ctx.options.now,
                "exp=%s is earlier than now=%s." % (exp, ctx.options.now),
                ctx.loc_id_token, str(exp)) if exp is not None else []


@rule("GS507", "ID token issued in the future", Severity.HIGH, "ID token",
      "A future iat indicates clock skew or a forged token.",
      "Synchronise clocks (NTP) and reject tokens with implausible iat.", "OIDC Core §2")
def _gs507(ctx: Context) -> List[Finding]:
    iat = _number(ctx.claims.get("iat"))
    return _one(ctx, "GS507", iat is not None and iat > ctx.options.now + 60,
                "iat=%s is more than 60s in the future." % iat,
                ctx.loc_id_token, str(iat)) if iat is not None else []


@rule("GS508", "ID token is not yet valid (nbf)", Severity.MEDIUM, "ID token",
      "nbf in the future means the token must not be used yet.",
      "Wait until nbf or investigate clock skew.", "RFC 7519 §4.1.5")
def _gs508(ctx: Context) -> List[Finding]:
    nbf = _number(ctx.claims.get("nbf"))
    return _one(ctx, "GS508", nbf is not None and nbf > ctx.options.now,
                "nbf=%s is in the future." % nbf, ctx.loc_id_token, str(nbf)) if nbf is not None else []


@rule("GS509", "ID token audience does not match expected client", Severity.CRITICAL, "ID token",
      "Accepting a token issued for another client enables token replay across services.",
      "Verify aud contains your own client_id; pass it via --expected-audience.", "OIDC Core §2")
def _gs509(ctx: Context) -> List[Finding]:
    expected = ctx.options.expected_audience.strip()
    if not expected or not ctx.claims:
        return []
    aud = ctx.claims.get("aud")
    audiences = _as_list(aud)
    return _one(ctx, "GS509", expected not in audiences,
                "aud=%s does not contain expected audience %r." % (audiences, expected),
                ctx.loc_id_token, str(aud))


@rule("GS510", "Multiple audiences without azp", Severity.MEDIUM, "ID token",
      "When aud is an array, azp identifies the actual authorized party.",
      "Include azp=client_id whenever aud has more than one entry.", "OIDC Core §2")
def _gs510(ctx: Context) -> List[Finding]:
    aud = ctx.claims.get("aud")
    return _one(ctx, "GS510", isinstance(aud, list) and len(aud) > 1 and not ctx.claims.get("azp"),
                "aud is a multi-value array but azp is missing.", ctx.loc_id_token, str(aud))


@rule("GS511", "ID token nonce does not match", Severity.HIGH, "ID token",
      "nonce binds the ID token to the original authorization request.",
      "Verify the nonce claim equals the value sent in the authorization request.",
      "OIDC Core §2")
def _gs511(ctx: Context) -> List[Finding]:
    expected = ctx.options.expected_nonce.strip()
    if not expected or not ctx.claims:
        return []
    actual = str(ctx.claims.get("nonce") or "")
    return _one(ctx, "GS511", actual != expected,
                "nonce=%r does not match expected %r." % (actual, expected),
                ctx.loc_id_token, actual)


@rule("GS512", "Sensitive field present in ID token claims", Severity.HIGH, "ID token",
      "ID tokens are bearer artefacts frequently logged by proxies and clients; secrets must never be embedded.",
      "Remove the field, rotate the leaked value, and keep secrets out of JWT payloads.", "RFC 8725")
def _gs512(ctx: Context) -> List[Finding]:
    if not ctx.claims:
        return []
    leaked = sorted(k for k in ctx.claims if k.lower() in _SENSITIVE_CLAIM_KEYS)
    return _one(ctx, "GS512", bool(leaked),
                "Sensitive claim(s) present: %s" % ", ".join(leaked),
                ctx.loc_id_token, ", ".join(leaked))


@rule("GS513", "MCP ID token audience does not match resource", Severity.HIGH, "ID token",
      "MCP requires the token audience to be bound to the exact resource server, preventing cross-server replay.",
      "Ensure aud equals the RFC 8707 resource value sent in the authorization request.",
      "RFC 8707 / MCP Authorization spec (2025-06-18)")
def _gs513(ctx: Context) -> List[Finding]:
    if not ctx.options.is_mcp or not ctx.claims:
        return []
    resource = ctx.params.get("resource", "").rstrip("/")
    audiences = [a.rstrip("/") for a in _as_list(ctx.claims.get("aud"))]
    return _one(ctx, "GS513", bool(resource) and resource not in audiences,
                "aud=%s does not contain the requested resource %r." % (audiences, resource),
                ctx.loc_id_token, resource)


# ---------------------------------------------------------------------------
# GS6xx — HTTP response headers / transport
# ---------------------------------------------------------------------------


@rule("GS601", "Token response missing Cache-Control: no-store", Severity.HIGH, "HTTP headers",
      "RFC 6749 requires no-store so tokens are never written to shared or browser caches.",
      "Add 'Cache-Control: no-store' to every token endpoint response.", "RFC 6749 §5.1")
def _gs601(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    return _one(ctx, "GS601", not ctx.has_header_value("cache-control", "no-store"),
                "Cache-Control header does not include 'no-store'.",
                ctx.loc_headers, ctx.header_joined("cache-control"))


@rule("GS602", "Token response missing Pragma: no-cache", Severity.LOW, "HTTP headers",
      "Legacy HTTP/1.0 intermediaries still honour Pragma.",
      "Add 'Pragma: no-cache' alongside Cache-Control: no-store.", "RFC 6749 §5.1")
def _gs602(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    return _one(ctx, "GS602", not ctx.has_header_value("pragma", "no-cache"),
                "Pragma: no-cache is missing.", ctx.loc_headers, ctx.header_joined("pragma"))


@rule("GS603", "Token response Content-Type is not JSON", Severity.LOW, "HTTP headers",
      "A non-JSON content type causes strict clients to reject the response.",
      "Return 'Content-Type: application/json;charset=UTF-8'.", "RFC 6749 §5.1")
def _gs603(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    ct = ctx.header_joined("content-type")
    return _one(ctx, "GS603", bool(ct) and "json" not in ct.lower(),
                "Content-Type is %r, expected application/json." % ct, ctx.loc_headers, ct)


@rule("GS604", "Set-Cookie missing security attributes", Severity.MEDIUM, "HTTP headers",
      "Session cookies without Secure/HttpOnly/SameSite are exposed to network and script access.",
      "Set Secure, HttpOnly and an explicit SameSite attribute on all session cookies.", "RFC 6265bis")
def _gs604(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    missing: List[str] = []
    for value in ctx.header_map.get("set-cookie", []):
        low = value.lower()
        absent = [a for a in ("secure", "httponly", "samesite") if a not in low]
        if absent:
            missing.append("missing %s in %r" % ("/".join(absent), value.split(";")[0]))
    return _one(ctx, "GS604", bool(missing), "; ".join(missing),
                ctx.loc_headers, "; ".join(missing))


@rule("GS605", "Wildcard CORS combined with credentials", Severity.MEDIUM, "HTTP headers",
      "Browsers reject, and misconfigured proxies may allow, wildcard ACAO with ACAC:true.",
      "Echo a specific origin instead of '*' when credentials are allowed.", "Fetch Standard")
def _gs605(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    wildcard = "*" in ctx.header_joined("access-control-allow-origin")
    creds = "true" in ctx.header_joined("access-control-allow-credentials").lower()
    return _one(ctx, "GS605", wildcard and creds,
                "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                ctx.loc_headers)


@rule("GS606", "Missing HTTP Strict Transport Security", Severity.LOW, "HTTP headers",
      "Without HSTS, a downgrade to plaintext can expose authorization codes and tokens.",
      "Send Strict-Transport-Security with a meaningful max-age on all endpoints.", "RFC 6797")
def _gs606(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    return _one(ctx, "GS606", not ctx.header_map.get("strict-transport-security"),
                "Strict-Transport-Security header is absent.", ctx.loc_headers)


@rule("GS607", "MCP 401 response missing resource_metadata", Severity.HIGH, "HTTP headers",
      "MCP clients discover the authorization server from WWW-Authenticate's resource_metadata parameter.",
      "Include WWW-Authenticate: Bearer resource_metadata=\"<protected-resource-metadata URL>\" on 401 responses.",
      "MCP Authorization spec (2025-06-18) / RFC 9728")
def _gs607(ctx: Context) -> List[Finding]:
    if ctx.headers is None or not ctx.options.is_mcp:
        return []
    www = ctx.header_joined("www-authenticate")
    status = (ctx.headers.get("status") or "").strip()
    applies = "401" in status or "bearer" in www.lower()
    return _one(ctx, "GS607", applies and "resource_metadata" not in www.lower(),
                "WWW-Authenticate does not advertise resource_metadata: %r" % www,
                ctx.loc_headers, www)
