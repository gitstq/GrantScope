"""Engine behaviour: ordering, de-duplication, gating and convenience APIs."""

from __future__ import annotations

import unittest

from grantscope import (
    Options,
    SEVERITY_RANK,
    Severity,
    audit,
    audit_text,
    gate,
    load_text,
)


class EngineTests(unittest.TestCase):
    def test_findings_are_sorted_by_severity_then_id(self):
        report = audit([load_text('{"issuer":"http://x"}', "discovery.json"),
                        load_text("https://as.example.com/a?response_type=code", "auth_request.url")])
        pairs = [(SEVERITY_RANK[f.severity], f.rule_id) for f in report.findings]
        self.assertEqual(sorted(pairs, key=lambda p: (-p[0], p[1])), pairs)
        self.assertTrue(len(report.findings) > 3)

    def test_findings_are_deduplicated(self):
        files = [load_text('{"issuer":"http://x"}', "discovery.json")] * 2
        ids = [f.rule_id for f in audit(files).findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_gate_thresholds(self):
        report = audit([load_text('{"issuer":"http://x"}', "discovery.json")])
        self.assertEqual(Severity.CRITICAL, report.max_severity)
        self.assertEqual(1, gate(report, "critical"))
        self.assertEqual(1, gate(report, "high"))
        self.assertEqual(1, gate(report, "info"))
        self.assertEqual(0, gate(report, "never"))

    def test_gate_on_clean_report(self):
        report = audit([])
        self.assertIsNone(report.max_severity)
        self.assertEqual(0, gate(report, "info"))

    def test_gate_rejects_unknown_level(self):
        with self.assertRaises(ValueError):
            gate(audit([]), "catastrophic")

    def test_audit_text_single_artefact(self):
        report = audit_text('{"issuer":"http://x"}', "discovery.json")
        self.assertIn("GS102", {f.rule_id for f in report.findings})
        self.assertEqual(1, len(report.sources))

    def test_now_override_makes_time_rules_deterministic(self):
        import base64
        import json

        def tok(claims):
            b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
            return "%s.%s.x" % (b({"alg": "RS256", "kid": "k"}), b(claims))

        claims = {"iss": "i", "sub": "s", "aud": "c", "exp": 1000, "iat": 900}
        text = tok(claims)
        past = audit([load_text(text, "id_token.jwt")], Options(now=500))
        future = audit([load_text(text, "id_token.jwt")], Options(now=2000))
        self.assertNotIn("GS506", {f.rule_id for f in past.findings})
        self.assertIn("GS506", {f.rule_id for f in future.findings})

    def test_profile_is_recorded(self):
        self.assertEqual("mcp", audit([], Options(profile="mcp")).profile)


if __name__ == "__main__":
    unittest.main()
