"""Input loading and artefact detection.

GrantScope accepts a heterogeneous bundle of offline artefacts: an OIDC
discovery document, a client registration document, an authorization request
URL, a token endpoint response, an ID token, and raw HTTP response headers.
Everything is read from disk or stdin; no network request is ever made.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from .jwt import ParsedToken, parse_token
from .models import InputItem, Kind

__all__ = [
    "detect_kind",
    "parse_headers",
    "parse_auth_url",
    "load_text",
    "load_file",
    "load_path",
    "load_stdin",
    "KIND_NAMES",
]

KIND_NAMES = [k.value for k in Kind if k is not Kind.UNKNOWN]

_HTTP_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}", re.IGNORECASE)
_JWT_PREFIX = re.compile(r"^eyJ[A-Za-z0-9_-]*\.", re.IGNORECASE)
_URL_PREFIX = re.compile(r"^https?://", re.IGNORECASE)
_SUFFIXES = (".json", ".txt", ".url", ".http", ".headers", ".jwt", ".token", ".md")


def parse_headers(raw: str) -> Dict[str, Any]:
    """Parse a ``curl -i`` style response into a normalised structure.

    Returns a dict with ``status``, ``headers`` (lower-case name -> list of
    values, so repeated ``Set-Cookie`` survives) and ``raw``.
    """
    lines = (raw or "").replace("\r\n", "\n").split("\n")
    status = ""
    headers: Dict[str, List[str]] = {}
    for line in lines:
        if not line.strip():
            break
        if line.upper().startswith("HTTP/"):
            status = line.strip()
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        key = name.strip().lower()
        if not key:
            continue
        headers.setdefault(key, []).append(value.strip())
    return {"status": status, "headers": headers, "raw": raw}


def parse_auth_url(url: str) -> Dict[str, Any]:
    """Split an authorization request URL into a normalised parameter dict."""
    clean = (url or "").strip().strip('"').strip("'")
    split = urlsplit(clean)
    params: Dict[str, str] = {}
    for key, values in parse_qs(split.query, keep_blank_values=True).items():
        params[key] = values[0] if values else ""
    return {
        "url": clean,
        "scheme": split.scheme.lower(),
        "host": (split.hostname or "").lower(),
        "path": split.path,
        "params": params,
    }


def detect_kind(name: str, text: str, forced: Optional[str] = None) -> Kind:
    """Best-effort detection of an artefact type from filename and content."""
    if forced:
        try:
            return Kind(forced)
        except ValueError:
            raise ValueError(
                "unknown --kind %r (expected one of: %s)" % (forced, ", ".join(KIND_NAMES))
            )
    low = (name or "").lower()
    body = (text or "").strip()

    if "header" in low or "http" in low or _HTTP_STATUS.match(body):
        return Kind.HEADERS
    if "discovery" in low or "well-known" in low or "well_known" in low:
        return Kind.DISCOVERY
    if "client" in low or "registration" in low:
        return Kind.CLIENT
    if "id_token" in low or "idtoken" in low or "jwt" in low:
        return Kind.ID_TOKEN
    if _JWT_PREFIX.match(body):
        return Kind.ID_TOKEN
    if "auth" in low or "request" in low or _URL_PREFIX.match(body):
        return Kind.AUTH_REQUEST
    if "token" in low or "response" in low:
        return Kind.TOKEN_RESPONSE

    # Content-based fallback for generically named JSON files.
    if body.startswith("{"):
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            obj = None
        if isinstance(obj, dict):
            keys = set(obj.keys())
            if "issuer" in keys and ("authorization_endpoint" in keys or "jwks_uri" in keys):
                return Kind.DISCOVERY
            if "access_token" in keys or "token_type" in keys:
                return Kind.TOKEN_RESPONSE
            if "client_id" in keys and "redirect_uris" in keys:
                return Kind.CLIENT
            if "client_id" in keys:
                return Kind.AUTH_REQUEST
            return Kind.CLIENT if "client" in low else Kind.UNKNOWN
    return Kind.UNKNOWN


def _coerce(kind: Kind, raw: str) -> Any:
    body = (raw or "").strip()
    if kind is Kind.HEADERS:
        return parse_headers(raw)
    if kind is Kind.ID_TOKEN:
        return parse_token(body)
    if kind is Kind.AUTH_REQUEST:
        return parse_auth_url(body)
    try:
        obj = json.loads(body)
    except (ValueError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def load_text(text: str, source: str = "<stdin>", kind: Optional[str] = None) -> InputItem:
    """Parse one in-memory artefact."""
    detected = detect_kind(source, text, kind)
    return InputItem(
        kind=detected,
        source=source,
        raw=text,
        data=_coerce(detected, text),
    )


def load_file(path: str, kind: Optional[str] = None) -> InputItem:
    """Parse one file. UTF-8 BOM and CRLF are handled transparently."""
    with open(path, "r", encoding="utf-8-sig") as handle:
        text = handle.read()
    return load_text(text, source=path, kind=kind)


def load_path(paths: List[str], kind: Optional[str] = None) -> List[InputItem]:
    """Load files and/or whole directories into a flat list of artefacts.

    Directories are scanned non-recursively for known suffixes. Unknown files
    are still loaded (as ``Kind.UNKNOWN``) so the report can tell the user
    that an artefact was ignored, instead of silently dropping it.
    """
    items: List[InputItem] = []
    for path in paths:
        if path == "-":
            items.append(load_stdin(kind))
            continue
        if os.path.isdir(path):
            for entry in sorted(os.listdir(path)):
                full = os.path.join(path, entry)
                if not os.path.isfile(full):
                    continue
                if entry.startswith(".") or entry.upper() == "README.MD":
                    continue
                if not entry.lower().endswith(_SUFFIXES):
                    continue
                items.append(load_file(full, kind))
        elif os.path.isfile(path):
            items.append(load_file(path, kind))
        else:
            raise FileNotFoundError("input path does not exist: %s" % path)
    return items


def load_stdin(kind: Optional[str] = None) -> InputItem:
    """Read one artefact from standard input."""
    import sys

    return load_text(sys.stdin.read(), source="<stdin>", kind=kind)
