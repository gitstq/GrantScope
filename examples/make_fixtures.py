#!/usr/bin/env python3
"""Regenerate the ``good/`` and ``bad/`` example bundles deterministically.

Run from the repository root::

    python examples/make_fixtures.py

The fixtures are deliberately static files (committed to git) so that users
can run an audit without executing any code first. This script only exists to
make the JWTs and the S256 challenge reproducible.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from urllib.parse import urlencode

HERE = os.path.dirname(os.path.abspath(__file__))

VERIFIER = "GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv"
STATE = "St4te-Value-With-Enough-Entropy-0001"
NONCE = "N0nce-Value-For-Replay-01"
ISSUER = "https://id.example.com"
RESOURCE = "https://mcp.example.com/mcp"
CLIENT_ID = "mcp-client-01"
REDIRECT = "http://127.0.0.1:33418/callback"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt(header: dict, claims: dict, signature: str = "c2lnbmF0dXJlLXBsYWNlaG9sZGVy") -> str:
    return ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode()),
            b64url(json.dumps(claims, separators=(",", ":")).encode()),
            signature,
        ]
    )


def challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def write(folder: str, name: str, content: str) -> None:
    path = os.path.join(HERE, folder, name)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content.rstrip("\n") + "\n")
    print("wrote", os.path.relpath(path, HERE))


def dump(folder: str, name: str, obj: dict) -> None:
    write(folder, name, json.dumps(obj, indent=2, ensure_ascii=False))


def build_good() -> None:
    dump("good", "discovery.json", {
        "issuer": ISSUER,
        "authorization_endpoint": ISSUER + "/authorize",
        "token_endpoint": ISSUER + "/token",
        "jwks_uri": ISSUER + "/.well-known/jwks.json",
        "revocation_endpoint": ISSUER + "/revoke",
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
        "scopes_supported": ["openid", "profile", "email"],
    })
    dump("good", "client.json", {
        "client_id": CLIENT_ID,
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    })
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid profile",
        "state": STATE,
        "nonce": NONCE,
        "code_challenge": challenge(VERIFIER),
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    write("good", "auth_request.url", ISSUER + "/authorize?" + urlencode(params))
    dump("good", "token_response.json", {
        "access_token": "eyJhbGciOiJSUzI1NiJ9.e30.c2ln",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid profile",
        "refresh_token": "rt_demo_value",
    })
    write("good", "id_token.jwt", jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "key-2026-01"},
        {
            "iss": ISSUER,
            "sub": "user-123",
            "aud": [CLIENT_ID, RESOURCE],
            "azp": CLIENT_ID,
            "exp": 4102444800,
            "iat": 1700000000,
            "nonce": NONCE,
        },
    ))
    write("good", "headers.http", "\n".join([
        "HTTP/1.1 200 OK",
        "Cache-Control: no-store",
        "Pragma: no-cache",
        "Content-Type: application/json;charset=UTF-8",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "",
        "{}",
    ]))
    print("GOOD verifier:", VERIFIER)
    print("GOOD challenge:", challenge(VERIFIER))


def build_bad() -> None:
    dump("bad", "discovery.json", {
        "issuer": "http://id.example.com",
        "authorization_endpoint": "http://id.example.com/authorize",
        "jwks_uri": "http://id.example.com/keys",
        "response_types_supported": ["code", "token", "id_token"],
        "code_challenge_methods_supported": ["plain"],
    })
    dump("bad", "client.json", {
        "client_id": CLIENT_ID,
        "redirect_uris": ["https://legit.example.com/callback"],
    })
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://evil.example.com/cb*#frag",
        "scope": "openid profile email",
        "state": "abc",
        "client_secret": "super-secret-should-not-be-here",
        "code_challenge": "not-a-valid-s256-challenge=",
        "code_challenge_method": "plain",
    }
    write("bad", "auth_request.url", "http://id.example.com/authorize?" + urlencode(params))
    dump("bad", "token_response.json", {
        "token_type": "MAC",
        "scope": "profile",
        "client_secret": "leaked-into-response",
    })
    write("bad", "id_token.jwt", jwt(
        {"alg": "none", "typ": "JWT"},
        {
            "iss": "https://evil.example.com",
            "aud": ["other-client", "https://mcp.example.com/mcp"],
            "exp": 1000000000,
            "iat": 4102444800,
            "nbf": 4102444800,
            "nonce": "wrong-nonce",
            "password": "hunter2",
        },
    ))
    write("bad", "headers.http", "\n".join([
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        "Set-Cookie: session=abc123; Path=/",
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Credentials: true",
        "",
        "{}",
    ]))


if __name__ == "__main__":
    for folder in ("good", "bad"):
        os.makedirs(os.path.join(HERE, folder), exist_ok=True)
    build_good()
    build_bad()
