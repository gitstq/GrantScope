"""PKCE (RFC 7636) primitives, implemented with the standard library only.

GrantScope does not just check whether ``code_challenge`` exists: when a
``code_verifier`` is supplied it *recomputes* the S256 challenge and compares
it byte-for-byte. That makes the auditor useful as a real interoperability
probe rather than a keyword linter.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from typing import List

__all__ = [
    "VERIFIER_MIN",
    "VERIFIER_MAX",
    "CHALLENGE_LENGTH",
    "VERIFIER_PATTERN",
    "b64url_no_pad",
    "generate_verifier",
    "compute_challenge",
    "validate_verifier",
    "validate_challenge",
    "verify_challenge",
]

VERIFIER_MIN = 43
VERIFIER_MAX = 128
CHALLENGE_LENGTH = 43

# RFC 7636 section 4.1: unreserved characters only.
VERIFIER_PATTERN = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")
_B64URL_BODY = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_no_pad(data: bytes) -> str:
    """Base64url-encode without ``=`` padding (RFC 7636 appendix A)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_verifier(length: int = 64) -> str:
    """Generate a cryptographically random, RFC-compliant code verifier."""
    if not VERIFIER_MIN <= length <= VERIFIER_MAX:
        raise ValueError(
            "code_verifier length must be between %d and %d"
            % (VERIFIER_MIN, VERIFIER_MAX)
        )
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def compute_challenge(verifier: str, method: str = "S256") -> str:
    """Derive the code challenge for a verifier.

    ``plain`` returns the verifier unchanged; ``S256`` returns
    ``BASE64URL(SHA256(ASCII(verifier)))``. Unknown methods raise
    ``ValueError`` rather than silently degrading to ``plain``.
    """
    m = (method or "plain").strip().lower()
    if m == "plain":
        return verifier
    if m == "s256":
        return b64url_no_pad(hashlib.sha256(verifier.encode("ascii")).digest())
    raise ValueError("unsupported code_challenge_method %r" % method)


def validate_verifier(verifier: str) -> List[str]:
    """Return a list of human-readable syntax problems (empty == valid)."""
    problems: List[str] = []
    if not verifier:
        return ["code_verifier is empty"]
    if not VERIFIER_MIN <= len(verifier) <= VERIFIER_MAX:
        problems.append(
            "code_verifier length is %d; RFC 7636 requires %d-%d characters"
            % (len(verifier), VERIFIER_MIN, VERIFIER_MAX)
        )
    if not VERIFIER_PATTERN.match(verifier):
        problems.append(
            "code_verifier contains characters outside the unreserved set "
            "[A-Za-z0-9-._~]"
        )
    try:
        verifier.encode("ascii")
    except UnicodeEncodeError:
        problems.append("code_verifier must be ASCII")
    return problems


def validate_challenge(challenge: str) -> List[str]:
    """Return syntax problems for a code challenge value."""
    problems: List[str] = []
    if not challenge:
        return ["code_challenge is empty"]
    if len(challenge) != CHALLENGE_LENGTH:
        problems.append(
            "code_challenge is %d characters; a S256 challenge is always %d"
            % (len(challenge), CHALLENGE_LENGTH)
        )
    if not _B64URL_BODY.match(challenge):
        problems.append(
            "code_challenge is not unpadded base64url ([A-Za-z0-9_-] only)"
        )
    return problems


def verify_challenge(verifier: str, challenge: str, method: str = "S256") -> bool:
    """Recompute and compare, using :func:`hmac.compare_digest` semantics."""
    import hmac

    try:
        expected = compute_challenge(verifier, method)
    except (ValueError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(expected, challenge or "")
