"""Audit orchestration: build context, run rules, normalise and gate."""

from __future__ import annotations

from typing import List, Optional

from .inputs import load_path, load_text
from .models import (
    InputItem,
    Report,
    SEVERITY_RANK,
    Severity,
    parse_severity,
)
from .rules import Context, Options, run_rules

__all__ = ["audit", "audit_paths", "audit_text", "gate", "__version__"]

__version__ = "1.0.0"


def audit(items: List[InputItem], options: Optional[Options] = None) -> Report:
    """Run every rule against a bundle of parsed artefacts.

    Findings are de-duplicated on ``(rule_id, location, message)`` and sorted
    by severity (most severe first) then rule id, so the output is stable and
    deterministic — an explicit design goal for CI diffing.
    """
    opts = options or Options()
    ctx = Context.build(items, opts)
    raw = run_rules(ctx)

    seen = set()
    unique = []
    for finding in raw:
        key = (finding.rule_id, finding.location, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)

    unique.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id, f.location))

    sources = []
    for item in items:
        label = item.label
        if label not in sources:
            sources.append(label)

    from datetime import datetime, timezone

    return Report(
        findings=unique,
        sources=sources,
        profile=opts.profile,
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        tool_version=__version__,
    )


def audit_paths(
    paths: List[str],
    options: Optional[Options] = None,
    kind: Optional[str] = None,
) -> Report:
    """Convenience wrapper: load files/directories, then audit."""
    return audit(load_path(paths, kind), options)


def audit_text(text: str, source: str = "<stdin>", options: Optional[Options] = None,
               kind: Optional[str] = None) -> Report:
    """Convenience wrapper: audit a single in-memory artefact."""
    return audit([load_text(text, source, kind)], options)


def gate(report: Report, fail_on: str = "high") -> int:
    """Return a process exit code for the CI gate.

    ``fail_on='never'`` always returns 0. Otherwise any finding at or above
    the threshold returns 1.
    """
    key = (fail_on or "high").strip().lower()
    if key == "never":
        return 0
    threshold = parse_severity(key)
    limit = SEVERITY_RANK[threshold]
    for finding in report.findings:
        if SEVERITY_RANK[finding.severity] >= limit:
            return 1
    return 0
