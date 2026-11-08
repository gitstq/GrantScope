"""Minimal, *signature-agnostic* JWT structure decoder.

GrantScope is an offline static auditor. It deliberately **does not verify
signatures** (that requires network access to a JWKS endpoint and a trust
decision that belongs to the caller). Every caller is told this explicitly in
the CLI help and in the README so nobody mistakes a structural check for
token validation.

What it *does* do is decode header/claims safely, surface structural problems,
and make the claims available to the ID Token rules.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Tuple

__all__ = ["ParsedToken", "parse_token", "b64url_decode"]


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + pad).encode("ascii"))


class ParsedToken:
    """Result of decoding a compact JWS/JWT string."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.header: Dict[str, Any] = {}
        self.claims: Dict[str, Any] = {}
        self.signature: str = ""
        self.errors: List[str] = []
        self.valid_structure = False
        self._parse()

    def _parse(self) -> None:
        token = (self.token or "").strip()
        if not token:
            self.errors.append("token is empty")
            return
        parts = token.split(".")
        if len(parts) != 3:
            self.errors.append(
                "compact JWS must have exactly 3 dot-separated segments, got %d"
                % len(parts)
            )
            return
        head, body, sig = parts
        self.signature = sig
        for label, segment, target in (
            ("header", head, "header"),
            ("payload", body, "claims"),
        ):
            try:
                decoded = b64url_decode(segment)
                obj = json.loads(decoded.decode("utf-8"))
                if not isinstance(obj, dict):
                    self.errors.append("%s segment is not a JSON object" % label)
                    continue
                if target == "header":
                    self.header = obj
                else:
                    self.claims = obj
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.errors.append("%s segment is not valid base64url JSON: %s" % (label, exc))
        if not self.errors:
            self.valid_structure = True

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "claims": self.claims,
            "errors": self.errors,
            "valid_structure": self.valid_structure,
            "signature_verified": False,
        }


def parse_token(token: str) -> ParsedToken:
    """Decode a compact token. Never performs signature verification."""
    return ParsedToken(token)
