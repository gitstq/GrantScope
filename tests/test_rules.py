"""Rule-level tests.

The centrepiece is ``test_every_registered_rule_can_fire``: for each of the 53
registered rules there is an explicit minimal bundle that triggers it. This
guarantees that no rule is silently dead code, and that a future edit cannot
accidentally disable a check without a test failing.
"""

from __future__ import annotations

import base64
import json
import os
import unittest

from grantscope import Options, all_rules, audit, audit_paths, load_text
from grantscope.jwt import parse_token

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOD = os.path.join(ROOT, "examples", "good")
BAD = os.path.join(ROOT, "examples", "bad")

VERIFIER = "GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv"
NONCE = "N0nce-Value-For-Replay-01"
PIN_OPTS = dict(
    expected_issuer="https://id.example.com",
    expected_audience="mcp-client-01",
    expected_nonce=NONCE,
    code_verifier=VERIFIER,
)


def _b64(obj: object) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwt(header: dict, claims: dict) -> str:
    return "%s.%s.%s" % (_b64(header), _b64(claims), "c2ln")


def url(**params: str) -> str:
    from urllib.parse import urlencode

    return "https://as.example.com/authorize?" + urlencode(params)


def items(files: dict):
    return [load_text(text, name) for name, text in files.items()]


def run(files: dict, **opts):
    return audit(items(files), Options(**opts))


# rule id -> (files, options). Every registered rule MUST appear here.
TRIGGERS = {
    # GS1xx ---------------------------------------------------------------
    "GS101": ({"discovery.json": "{}"}, {}),
    "GS102": ({"discovery.json": '{"issuer":"http://as.example.com"}'}, {}),
    "GS103": ({"discovery.json": '{"issuer":"https://as.example.com"}'}, {}),
    "GS104": ({"discovery.json": '{"issuer":"https://as.example.com","authorization_endpoint":"http://as.example.com/a"}'}, {}),
    "GS105": ({"discovery.json": '{"issuer":"https://as.example.com","code_challenge_methods_supported":["plain"]}'}, {}),
    "GS106": ({"discovery.json": '{"issuer":"https://attacker.example.com"}'}, {"expected_issuer": "https://as.example.com"}),
    "GS107": ({"discovery.json": '{"issuer":"https://as.example.com","response_types_supported":["token"]}'}, {}),
    # GS2xx ---------------------------------------------------------------
    "GS201": ({"auth_request.url": url(client_id="c")}, {}),
    "GS202": ({"auth_request.url": url(response_type="token", client_id="c")}, {}),
    "GS203": ({"auth_request.url": url(response_type="weird", client_id="c")}, {}),
    "GS204": ({"auth_request.url": url(response_type="code")}, {}),
    "GS205": ({"auth_request.url": url(response_type="code", client_id="c")}, {}),
    "GS206": ({"auth_request.url": url(response_type="code", client_id="c", redirect_uri="http://evil.example.com/cb")}, {}),
    "GS207": ({"auth_request.url": url(response_type="code", client_id="c", redirect_uri="https://x.example.com/cb#f")}, {}),
    "GS208": ({"auth_request.url": url(response_type="code", client_id="c", redirect_uri="https://x.example.com/*")}, {}),
    "GS209": ({
        "auth_request.url": url(response_type="code", client_id="c", redirect_uri="https://evil.example.com/cb"),
        "client.json": '{"client_id":"c","redirect_uris":["https://good.example.com/cb"]}',
    }, {}),
    "GS210": ({"auth_request.url": url(response_type="code", client_id="c")}, {}),
    "GS211": ({"auth_request.url": url(response_type="code", client_id="c", state="abc")}, {}),
    "GS212": ({"auth_request.url": url(response_type="code", client_id="c", scope="openid")}, {}),
    "GS213": ({"auth_request.url": url(response_type="code", client_id="c", client_secret="s3cr3t")}, {}),
    "GS214": ({"auth_request.url": url(response_type="code", client_id="c")}, {"profile": "mcp"}),
    # GS3xx ---------------------------------------------------------------
    "GS301": ({"auth_request.url": url(response_type="code", client_id="c")}, {}),
    "GS302": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="A" * 43, code_challenge_method="plain")}, {}),
    "GS303": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="A" * 43)}, {}),
    "GS304": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="short")}, {}),
    "GS305": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="A" * 43)}, {"code_verifier": "too-short"}),
    "GS306": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="A" * 43, code_challenge_method="S256")}, {"code_verifier": VERIFIER}),
    "GS307": ({"auth_request.url": url(response_type="code", client_id="c", code_challenge="A" * 42 + "=")}, {}),
    # GS4xx ---------------------------------------------------------------
    "GS401": ({"token_response.json": '{"token_type":"Bearer","expires_in":3600}'}, {}),
    "GS402": ({"token_response.json": '{"access_token":"a","token_type":"MAC","expires_in":3600}'}, {}),
    "GS403": ({"token_response.json": '{"access_token":"a","token_type":"Bearer"}'}, {}),
    "GS404": ({"token_response.json": '{"access_token":"a","client_secret":"leak"}'}, {}),
    "GS405": ({
        "auth_request.url": url(response_type="code", client_id="c", scope="openid profile"),
        "token_response.json": '{"access_token":"a","token_type":"Bearer","expires_in":3600,"scope":"profile"}',
    }, {}),
    # GS5xx ---------------------------------------------------------------
    "GS501": ({"id_token.jwt": "this-is-not-a-jws"}, {}),
    "GS502": ({"id_token.jwt": jwt({"alg": "none", "typ": "JWT"}, {"iss": "i", "sub": "s"})}, {}),
    "GS503": ({"id_token.jwt": jwt({"alg": "HS256", "typ": "JWT"}, {"iss": "i", "sub": "s"})}, {}),
    "GS504": ({"id_token.jwt": jwt({"alg": "RS256", "typ": "JWT"}, {"iss": "i", "sub": "s"})}, {}),
    "GS505": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {})}, {"now": 1800000000}),
    "GS506": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 1000000000, "iat": 1700000000})}, {"now": 1800000000}),
    "GS507": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 4102444800, "iat": 4102444800})}, {"now": 1800000000}),
    "GS508": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 4102444800, "iat": 1700000000, "nbf": 4102444800})}, {"now": 1800000000}),
    "GS509": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "someone-else", "exp": 4102444800, "iat": 1700000000})}, {"expected_audience": "my-client", "now": 1800000000}),
    "GS510": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": ["a", "b"], "exp": 4102444800, "iat": 1700000000})}, {"now": 1800000000}),
    "GS511": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 4102444800, "iat": 1700000000, "nonce": "actual"})}, {"expected_nonce": "wanted", "now": 1800000000}),
    "GS512": ({"id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 4102444800, "iat": 1700000000, "password": "hunter2"})}, {"now": 1800000000}),
    "GS513": ({
        "auth_request.url": url(response_type="code", client_id="c", resource="https://mcp.example.com/mcp"),
        "id_token.jwt": jwt({"alg": "RS256", "kid": "k"}, {"iss": "i", "sub": "s", "aud": "c", "exp": 4102444800, "iat": 1700000000}),
    }, {"profile": "mcp", "now": 1800000000}),
    # GS6xx ---------------------------------------------------------------
    "GS601": ({"headers.http": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"}, {}),
    "GS602": ({"headers.http": "HTTP/1.1 200 OK\nCache-Control: no-store\nContent-Type: application/json\nStrict-Transport-Security: max-age=1\n\n{}"}, {}),
    "GS603": ({"headers.http": "HTTP/1.1 200 OK\nCache-Control: no-store\nPragma: no-cache\nContent-Type: text/plain\nStrict-Transport-Security: max-age=1\n\n{}"}, {}),
    "GS604": ({"headers.http": "HTTP/1.1 200 OK\nCache-Control: no-store\nPragma: no-cache\nContent-Type: application/json\nStrict-Transport-Security: max-age=1\nSet-Cookie: sid=1; Path=/\n\n{}"}, {}),
    "GS605": ({"headers.http": "HTTP/1.1 200 OK\nCache-Control: no-store\nPragma: no-cache\nContent-Type: application/json\nStrict-Transport-Security: max-age=1\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n\n{}"}, {}),
    "GS606": ({"headers.http": "HTTP/1.1 200 OK\nCache-Control: no-store\nPragma: no-cache\nContent-Type: application/json\n\n{}"}, {}),
    "GS607": ({"headers.http": 'HTTP/1.1 401 Unauthorized\nCache-Control: no-store\nPragma: no-cache\nContent-Type: application/json\nStrict-Transport-Security: max-age=1\nWWW-Authenticate: Bearer realm="mcp"\n\n{}'}, {"profile": "mcp"}),
}


class RuleCatalogueTests(unittest.TestCase):
    def test_catalogue_is_complete(self):
        registered = {r.id for r in all_rules()}
        self.assertEqual(registered, set(TRIGGERS),
                         "every rule needs an explicit trigger fixture")
        self.assertEqual(len(registered), len(all_rules()), "rule ids must be unique")

    def test_rule_metadata_is_well_formed(self):
        for r in all_rules():
            with self.subTest(rule=r.id):
                self.assertRegex(r.id, r"^GS\d{3}$")
                self.assertTrue(r.title.strip())
                self.assertTrue(r.rationale.strip())
                self.assertTrue(r.remediation.strip())
                self.assertTrue(r.category.strip())
                self.assertTrue(r.reference.strip())

    def test_every_registered_rule_can_fire(self):
        for r in all_rules():
            with self.subTest(rule=r.id):
                files, opts = TRIGGERS[r.id]
                report = run(files, **opts)
                fired = {f.rule_id for f in report.findings}
                self.assertIn(r.id, fired,
                              "%s did not fire with its dedicated fixture (got %s)"
                              % (r.id, sorted(fired)))


class BundleTests(unittest.TestCase):
    def test_good_bundle_is_clean_default(self):
        report = audit_paths([GOOD])
        self.assertEqual([], report.findings, [f.rule_id for f in report.findings])

    def test_good_bundle_is_clean_mcp_with_pins(self):
        opts = Options(profile="mcp", **PIN_OPTS)
        report = audit_paths([GOOD], opts)
        self.assertEqual([], report.findings, [f.rule_id for f in report.findings])

    def test_bad_bundle_triggers_many_rules(self):
        opts = Options(
            expected_audience="mcp-client-01",
            expected_nonce=NONCE,
            now=1800000000,
        )
        report = audit_paths([BAD], opts)
        fired = {f.rule_id for f in report.findings}
        expected = {
            "GS102", "GS103", "GS104", "GS105", "GS107", "GS206", "GS207",
            "GS208", "GS209", "GS211", "GS212", "GS213", "GS302", "GS304",
            "GS307", "GS401", "GS402", "GS403", "GS404", "GS405", "GS502",
            "GS505", "GS506", "GS507", "GS508", "GS509", "GS510", "GS511",
            "GS512", "GS601", "GS602", "GS603", "GS604", "GS605", "GS606",
        }
        self.assertTrue(expected.issubset(fired), sorted(expected - fired))
        self.assertEqual(0, report.counts["info"])

    def test_normal_token_response_does_not_false_positive_on_access_token(self):
        report = run({"token_response.json":
                      '{"access_token":"a","token_type":"Bearer","expires_in":3600,"refresh_token":"r"}'})
        self.assertNotIn("GS404", {f.rule_id for f in report.findings})

    def test_pkce_roundtrip_via_audit(self):
        from grantscope import compute_challenge

        ch = compute_challenge(VERIFIER, "S256")
        files = {"auth_request.url": url(response_type="code", client_id="c",
                                         code_challenge=ch, code_challenge_method="S256")}
        clean = run(files, code_verifier=VERIFIER)
        self.assertNotIn("GS306", {f.rule_id for f in clean.findings})
        broken = run(files, code_verifier=VERIFIER + "X")
        self.assertIn("GS306", {f.rule_id for f in broken.findings})

    def test_mcp_rules_only_run_in_mcp_profile(self):
        files, opts = TRIGGERS["GS214"]
        self.assertNotIn("GS214", {f.rule_id for f in run(files).findings})
        self.assertIn("GS214", {f.rule_id for f in run(files, **opts).findings})

    def test_unknown_input_is_reported_as_source_only(self):
        report = run({"mystery.json": '{"hello":"world"}'})
        self.assertEqual("unknown:mystery.json", report.sources[0])


class JwtParsingTests(unittest.TestCase):
    def test_parse_returns_header_and_claims(self):
        t = parse_token(jwt({"alg": "RS256", "kid": "k"}, {"sub": "u"}))
        self.assertTrue(t.valid_structure)
        self.assertEqual("RS256", t.alg)
        self.assertEqual("u", t.claims["sub"])
        self.assertFalse(t.to_dict()["signature_verified"])

    def test_malformed_segment_count(self):
        t = parse_token("abc.def")
        self.assertFalse(t.valid_structure)
        self.assertTrue(t.errors)

    def test_non_object_payload_is_rejected(self):
        t = parse_token("%s.%s.x" % (_b64({"alg": "none"}), _b64(["not", "object"])))
        self.assertFalse(t.valid_structure)


if __name__ == "__main__":
    unittest.main()
