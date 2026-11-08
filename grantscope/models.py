"""Core data structures for GrantScope.

Everything in this module is deliberately dependency-free: the library only
uses the Python standard library so that it can run in an air-gapped CI job,
inside an MCP server sandbox, or from a single-file zipapp.
"""

from __future__ import annotations

import dataclasses
import enum
import json
from typing import Any, Dict, Iterable, List, Optional

__all__ = [
    "Severity",
    "SEVERITY_RANK",
    "Rule",
    "Finding",
    "Report",
    "InputItem",
    "Kind",
]


class Severity(str, enum.Enum):
    """Ordered severity levels used both for display and for CI gates."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Larger number == more severe. Used for sorting and for --fail-on.
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_SEVERITY_BY_NAME = {s.value: s for s in Severity}


def parse_severity(value: str) -> Severity:
    """Convert a user supplied string into a :class:`Severity`.

    Raises ``ValueError`` with a helpful message for unknown values.
    """
    key = (value or "").strip().lower()
    if key in _SEVERITY_BY_NAME:
        return _SEVERITY_BY_NAME[key]
    raise ValueError(
        "unknown severity %r (expected one of: %s)"
        % (value, ", ".join(s.value for s in Severity))
    )


class Kind(str, enum.Enum):
    """Supported input artefacts."""

    DISCOVERY = "discovery"
    CLIENT = "client"
    AUTH_REQUEST = "auth_request"
    TOKEN_RESPONSE = "token_response"
    ID_TOKEN = "id_token"
    HEADERS = "headers"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class Rule:
    """Static metadata for one audit rule."""

    id: str
    title: str
    severity: Severity
    category: str
    rationale: str
    remediation: str
    reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "rationale": self.rationale,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclasses.dataclass(frozen=True)
class Finding:
    """One concrete problem detected in an input bundle."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    location: str
    evidence: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclasses.dataclass(frozen=True)
class InputItem:
    """A parsed input artefact."""

    kind: Kind
    source: str
    raw: str
    data: Any

    @property
    def label(self) -> str:
        return "%s:%s" % (self.kind.value, self.source)


@dataclasses.dataclass
class Report:
    """The complete result of one audit run."""

    findings: List[Finding]
    sources: List[str]
    profile: str = "default"
    generated_at: str = ""
    tool_version: str = ""

    @property
    def counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "GrantScope",
            "version": self.tool_version,
            "profile": self.profile,
            "generated_at": self.generated_at,
            "summary": {
                "total": len(self.findings),
                "counts": self.counts,
                "max_severity": self.max_severity.value if self.max_severity else None,
            },
            "sources": self.sources,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def iter_by_category(self) -> Iterable[Any]:
        """Yield ``(category, findings)`` grouped in first-seen order."""
        seen: Dict[str, List[Finding]] = {}
        for f in self.findings:
            seen.setdefault(f.category, []).append(f)
        for category, group in seen.items():
            yield category, group
