"""Command line interface for GrantScope.

The CLI is intentionally boring: argparse, standard streams, no colour
libraries, no progress spinners. That keeps it usable in minimal containers,
cron jobs and MCP sandboxes.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .engine import __version__, audit_paths, gate
from .inputs import KIND_NAMES
from .pkce import compute_challenge, generate_verifier, validate_verifier, verify_challenge
from .report import FORMATS, render
from .rules import Options, all_rules

__all__ = ["main", "build_parser"]

_PROFILE_CHOICES = ("default", "mcp")
_FAIL_CHOICES = ("critical", "high", "medium", "low", "info", "never")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grantscope",
        description=(
            "Offline OAuth 2.1 / OIDC authorization-flow conformance auditor. "
            "Reads local artefacts only; never makes network requests and never "
            "verifies JWT signatures."
        ),
        epilog="Docs: https://github.com/gitstq/GrantScope",
    )
    parser.add_argument("--version", action="version", version="GrantScope " + __version__)
    sub = parser.add_subparsers(dest="command")

    # ---- audit -----------------------------------------------------------
    a = sub.add_parser("audit", help="audit a bundle of OAuth/OIDC artefacts")
    a.add_argument("paths", nargs="*", default=["."],
                   help="files, directories or '-' for stdin (default: current directory)")
    a.add_argument("-f", "--format", choices=FORMATS, default="text",
                   help="output format (default: text)")
    a.add_argument("-o", "--output", default="", help="write report to this file instead of stdout")
    a.add_argument("--profile", choices=_PROFILE_CHOICES, default="default",
                   help="mcp adds MCP/RFC 8707 specific rules (default: default)")
    a.add_argument("--kind", choices=KIND_NAMES, default="",
                   help="force all inputs to one artefact kind (default: auto-detect)")
    a.add_argument("--expected-issuer", default="", help="pin the expected issuer (GS106)")
    a.add_argument("--expected-audience", default="", help="pin the expected aud (GS509)")
    a.add_argument("--expected-nonce", default="", help="pin the expected nonce (GS511)")
    a.add_argument("--code-verifier", default="",
                   help="supply the verifier so S256 can be recomputed (GS305/GS306)")
    a.add_argument("--now", type=float, default=0.0,
                   help="override the current epoch second (deterministic testing)")
    a.add_argument("--fail-on", choices=_FAIL_CHOICES, default="high",
                   help="exit 1 when a finding is at or above this level (default: high)")
    a.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    a.add_argument("--quiet", action="store_true", help="omit fix/reference details")

    # ---- pkce ------------------------------------------------------------
    p = sub.add_parser("pkce", help="generate / verify PKCE values (RFC 7636)")
    p.add_argument("--generate", nargs="?", const=64, type=int, metavar="LENGTH",
                   help="generate a verifier of LENGTH characters (default 64)")
    p.add_argument("--verifier", default="", help="code_verifier to use")
    p.add_argument("--challenge", default="", help="code_challenge to compare against")
    p.add_argument("--method", default="S256", choices=("S256", "plain", "s256"),
                   help="challenge method (default: S256)")
    p.add_argument("--json", action="store_true", help="emit JSON")

    # ---- rules -----------------------------------------------------------
    r = sub.add_parser("rules", help="list the built-in rule catalogue")
    r.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    r.add_argument("--category", default="", help="filter by category substring")

    # ---- version ---------------------------------------------------------
    sub.add_parser("version", help="print the version and exit")

    return parser


def _cmd_audit(args: argparse.Namespace) -> int:
    paths: List[str] = args.paths or ["."]
    opts = Options(
        expected_issuer=args.expected_issuer,
        expected_audience=args.expected_audience,
        expected_nonce=args.expected_nonce,
        code_verifier=args.code_verifier,
        profile=args.profile,
    )
    if args.now:
        opts.now = args.now
    try:
        report = audit_paths(paths, opts, kind=args.kind or None)
    except (OSError, ValueError) as exc:
        print("grantscope: %s" % exc, file=sys.stderr)
        return 2

    text = render(report, args.format, color=not args.no_color, verbose=not args.quiet)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        print("wrote %s report to %s" % (args.format, args.output), file=sys.stderr)
    else:
        sys.stdout.write(text)
    return gate(report, args.fail_on)


def _cmd_pkce(args: argparse.Namespace) -> int:
    verifier = args.verifier
    if args.generate:
        verifier = generate_verifier(args.generate)
    if not verifier:
        print("grantscope pkce: supply --generate or --verifier", file=sys.stderr)
        return 2
    problems = validate_verifier(verifier)
    method = "S256" if args.method.lower() == "s256" else args.method
    try:
        challenge = compute_challenge(verifier, method)
    except ValueError as exc:
        print("grantscope pkce: %s" % exc, file=sys.stderr)
        return 2
    matched = verify_challenge(verifier, args.challenge, method) if args.challenge else None
    payload = {
        "code_verifier": verifier,
        "code_challenge_method": method,
        "code_challenge": challenge,
        "verifier_valid": not problems,
        "verifier_problems": problems,
        "challenge_matches": matched,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print("code_verifier          : %s" % verifier)
        print("code_challenge_method  : %s" % method)
        print("code_challenge         : %s" % challenge)
        print("verifier valid         : %s" % (not problems))
        for p in problems:
            print("  - %s" % p)
        if args.challenge:
            print("provided challenge     : %s" % args.challenge)
            print("challenge matches      : %s" % matched)
    return 0 if not problems and matched is not False else 1


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = [r for r in all_rules()
             if not args.category or args.category.lower() in r.category.lower()]
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in rules], indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print("| Rule | Severity | Category | Title |")
        print("| --- | --- | --- | --- |")
        for r in rules:
            print("| `%s` | %s | %s | %s |" % (r.id, r.severity.value, r.category, r.title))
    else:
        for r in rules:
            print("%s  %-8s  %-22s  %s" % (r.id, r.severity.value, r.category, r.title))
        print("\n%d rules" % len(rules))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    known = {"audit", "pkce", "rules", "version"}
    # Make `audit` the implicit subcommand so `grantscope ./bundle` works too.
    if not raw:
        raw = ["audit", "."]
    elif raw[0] not in known and not raw[0].startswith("-"):
        raw = ["audit"] + raw

    parser = build_parser()
    args = parser.parse_args(raw)
    command = args.command or "audit"
    if command == "audit":
        return _cmd_audit(args)
    if command == "pkce":
        return _cmd_pkce(args)
    if command == "rules":
        return _cmd_rules(args)
    if command == "version":
        print("GrantScope " + __version__)
        return 0
    parser.print_help()
    return 0
