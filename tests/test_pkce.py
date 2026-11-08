"""PKCE primitives, including the RFC 7636 Appendix B test vector."""

from __future__ import annotations

import unittest

from grantscope.pkce import (
    CHALLENGE_LENGTH,
    VERIFIER_MAX,
    VERIFIER_MIN,
    b64url_no_pad,
    compute_challenge,
    generate_verifier,
    validate_challenge,
    validate_verifier,
    verify_challenge,
)

# RFC 7636 Appendix B — the canonical S256 vector.
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class PkceTests(unittest.TestCase):
    def test_rfc7636_appendix_b_vector(self):
        self.assertEqual(RFC_CHALLENGE, compute_challenge(RFC_VERIFIER, "S256"))
        self.assertTrue(verify_challenge(RFC_VERIFIER, RFC_CHALLENGE, "S256"))

    def test_plain_method_returns_verifier(self):
        self.assertEqual(RFC_VERIFIER, compute_challenge(RFC_VERIFIER, "plain"))
        self.assertTrue(verify_challenge(RFC_VERIFIER, RFC_VERIFIER, "plain"))

    def test_unknown_method_is_rejected(self):
        with self.assertRaises(ValueError):
            compute_challenge(RFC_VERIFIER, "md5")

    def test_generated_verifier_is_valid(self):
        for length in (VERIFIER_MIN, 64, VERIFIER_MAX):
            with self.subTest(length=length):
                v = generate_verifier(length)
                self.assertEqual(length, len(v))
                self.assertEqual([], validate_verifier(v))
                self.assertEqual(CHALLENGE_LENGTH, len(compute_challenge(v)))

    def test_generate_rejects_bad_length(self):
        for length in (1, 42, 129, 500):
            with self.subTest(length=length), self.assertRaises(ValueError):
                generate_verifier(length)

    def test_validate_verifier_reports_all_problem_classes(self):
        problems = validate_verifier("short with spaces!")
        joined = " ".join(problems)
        self.assertIn("length", joined)
        self.assertIn("unreserved", joined)
        self.assertEqual(["code_verifier is empty"], validate_verifier(""))

    def test_non_ascii_verifier_is_rejected(self):
        v = "ä" * 43
        self.assertTrue(any("ASCII" in p for p in validate_verifier(v)))

    def test_validate_challenge(self):
        self.assertEqual([], validate_challenge(RFC_CHALLENGE))
        self.assertTrue(validate_challenge(""))
        self.assertTrue(any("43" in p for p in validate_challenge("abc")))
        self.assertTrue(any("base64url" in p for p in validate_challenge("A" * 42 + "=")))

    def test_verify_rejects_mismatch_and_non_ascii(self):
        self.assertFalse(verify_challenge(RFC_VERIFIER, "A" * 43, "S256"))
        self.assertFalse(verify_challenge("ä" * 43, RFC_CHALLENGE, "S256"))

    def test_b64url_has_no_padding(self):
        encoded = b64url_no_pad(b"\xfb\xff\xfe")
        self.assertNotIn("=", encoded)
        self.assertTrue(encoded)


if __name__ == "__main__":
    unittest.main()
