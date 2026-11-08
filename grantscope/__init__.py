"""GrantScope — offline OAuth 2.1 / OIDC authorization-flow auditor.

Public API (all dependency-free)::

    from grantscope import audit_paths, Options, render

    report = audit_paths(["./examples/bad"], Options(profile="mcp"))
    print(render(report, "markdown"))
    print(report.counts)

GrantScope is a **static** auditor. It reads local artefacts, never opens a
network connection, and never verifies JWT signatures. Signature verification
and live endpoint probing remain the responsibility of the caller.
"""

from __future__ import annotations

from .engine import __version__, audit, audit_paths, audit_text, gate
from .inputs import load_file, load_path, load_text
from .models import (
    Finding,
    InputItem,
    Kind,
    Report,
    Rule,
    SEVERITY_RANK,
    Severity,
    parse_severity,
)
from .pkce import compute_challenge, generate_verifier, validate_verifier, verify_challenge
from .report import FORMATS, render
from .rules import Context, Options, all_rules

__all__ = [
    "__version__",
    "audit",
    "audit_paths",
    "audit_text",
    "gate",
    "load_file",
    "load_path",
    "load_text",
    "Finding",
    "InputItem",
    "Kind",
    "Report",
    "Rule",
    "Severity",
    "SEVERITY_RANK",
    "parse_severity",
    "Context",
    "Options",
    "all_rules",
    "render",
    "FORMATS",
    "compute_challenge",
    "generate_verifier",
    "validate_verifier",
    "verify_challenge",
]
