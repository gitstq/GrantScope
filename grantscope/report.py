"""Output renderers: human text, Markdown, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Dict, List

from .models import Report, Rule, Severity
from .rules import all_rules

__all__ = ["render", "render_text", "render_markdown", "render_sarif", "render_json", "FORMATS"]

FORMATS = ("text", "markdown", "json", "sarif")

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_BADGE = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH    ",
    Severity.MEDIUM: "MEDIUM  ",
    Severity.LOW: "LOW     ",
    Severity.INFO: "INFO    ",
}

_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def render_json(report: Report) -> str:
    """JSON renderer (the canonical machine-readable form)."""
    return report.to_json()


def render_text(report: Report, color: bool = True, verbose: bool = True,
                rule_lookup: bool = True) -> str:
    """Terminal-friendly report with a summary and grouped findings."""
    lines: List[str] = []
    counts = report.counts
    lines.append("GrantScope %s  |  profile=%s  |  sources=%d"
                 % (report.tool_version, report.profile, len(report.sources)))
    lines.append("=" * 72)
    lines.append(
        "FINDINGS: %d   critical=%d high=%d medium=%d low=%d info=%d   max=%s"
        % (
            len(report.findings),
            counts["critical"], counts["high"], counts["medium"],
            counts["low"], counts["info"],
            report.max_severity.value if report.max_severity else "none",
        )
    )
    if report.sources:
        lines.append("INPUTS  : " + ", ".join(report.sources))
    lines.append("=" * 72)

    if not report.findings:
        lines.append("")
        lines.append("No findings. All applicable rules passed.")
        return "\n".join(lines) + "\n"

    by_severity: Dict[Severity, list] = {}
    for f in report.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for severity in Severity:
        group = by_severity.get(severity, [])
        if not group:
            continue
        label = _BADGE[severity]
        prefix = _COLOR[severity] if color else ""
        suffix = _RESET if color else ""
        lines.append("")
        lines.append("%s%s (%d)%s" % (prefix, label.strip(), len(group), suffix))
        lines.append("-" * 72)
        for f in group:
            head = "[%s] %s" % (f.rule_id, f.title)
            lines.append("  %s%s%s" % (prefix, head, suffix))
            lines.append("    %s" % f.message)
            lines.append("    location : %s" % f.location)
            if f.evidence:
                lines.append("    evidence : %s" % f.evidence)
            if verbose:
                lines.append("    fix      : %s" % f.remediation)
                if f.reference:
                    lines.append("    ref      : %s" % f.reference)
    lines.append("")
    lines.append("Note: GrantScope is an offline static auditor; it never verifies")
    lines.append("JWT signatures and never contacts the authorization server.")
    return "\n".join(lines) + "\n"


def render_markdown(report: Report) -> str:
    """Markdown report suitable for PR comments and job summaries."""
    lines = ["# GrantScope audit report", ""]
    lines.append("- **Tool**: GrantScope `%s`" % report.tool_version)
    lines.append("- **Profile**: `%s`" % report.profile)
    lines.append("- **Generated**: `%s`" % report.generated_at)
    lines.append("- **Sources**: %s" % (", ".join("`%s`" % s for s in report.sources) or "none"))
    c = report.counts
    lines.append("- **Findings**: %d (critical %d / high %d / medium %d / low %d / info %d)"
                 % (len(report.findings), c["critical"], c["high"], c["medium"], c["low"], c["info"]))
    lines.append("")
    if not report.findings:
        lines.append("> All applicable rules passed. No findings.")
        return "\n".join(lines) + "\n"
    lines.append("| Rule | Severity | Category | Location | Message |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in report.findings:
        msg = f.message.replace("|", "\\|").replace("\n", " ")
        loc = f.location.replace("|", "\\|")
        lines.append("| `%s` | %s | %s | `%s` | %s |"
                     % (f.rule_id, f.severity.value, f.category, loc, msg))
    lines.append("")
    lines.append("> GrantScope performs offline static analysis only. JWT signatures are "
                 "**not** verified and no network request is made.")
    lines.append("")
    return "\n".join(lines)


def render_sarif(report: Report) -> str:
    """SARIF 2.1.0 output, uploadable to GitHub code scanning."""
    rules: List[Rule] = all_rules()
    rule_index = {r.id: i for i, r in enumerate(rules)}
    driver_rules = []
    for r in rules:
        driver_rules.append({
            "id": r.id,
            "name": r.title,
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.rationale},
            "help": {"text": r.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
            "properties": {
                "category": r.category,
                "severity": r.severity.value,
                "reference": r.reference,
            },
        })
    results = []
    for f in report.findings:
        uri = f.location.split(":", 1)[1] if ":" in f.location else f.location
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index.get(f.rule_id, 0),
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message + ((" | evidence: " + f.evidence) if f.evidence else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri or f.location},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.location}],
            }],
            "properties": {"category": f.category, "remediation": f.remediation},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GrantScope",
                "version": report.tool_version,
                "informationUri": "https://github.com/gitstq/GrantScope",
                "rules": driver_rules,
            }},
            "results": results,
            "properties": {
                "profile": report.profile,
                "summary": {"total": len(report.findings), "counts": report.counts},
                "sources": report.sources,
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def render(report: Report, fmt: str = "text", color: bool = True,
           verbose: bool = True) -> str:
    """Dispatch to a renderer. Unknown formats raise ``ValueError``."""
    key = (fmt or "text").strip().lower()
    if key == "text":
        return render_text(report, color=color, verbose=verbose)
    if key == "markdown":
        return render_markdown(report)
    if key == "json":
        return render_json(report)
    if key == "sarif":
        return render_sarif(report)
    raise ValueError("unknown format %r (expected one of: %s)" % (fmt, ", ".join(FORMATS)))
