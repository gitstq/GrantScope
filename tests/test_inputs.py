"""Input detection and parsing."""

from __future__ import annotations

import os
import unittest

from grantscope.inputs import (
    detect_kind,
    load_file,
    load_path,
    load_text,
    parse_auth_url,
    parse_headers,
)
from grantscope.models import Kind

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOD = os.path.join(ROOT, "examples", "good")


class DetectionTests(unittest.TestCase):
    def test_filename_based_detection(self):
        cases = [
            ("discovery.json", "{}", Kind.DISCOVERY),
            ("client.json", "{}", Kind.CLIENT),
            ("auth_request.url", "https://x.example/a", Kind.AUTH_REQUEST),
            ("token_response.json", "{}", Kind.TOKEN_RESPONSE),
            ("id_token.jwt", "eyJhbGciOiJub25lIn0.e30.", Kind.ID_TOKEN),
            ("headers.http", "HTTP/1.1 200 OK\n\n", Kind.HEADERS),
        ]
        for name, text, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(expected, detect_kind(name, text))

    def test_content_based_detection(self):
        self.assertEqual(Kind.DISCOVERY,
                         detect_kind("x.json", '{"issuer":"https://i","jwks_uri":"https://j"}'))
        self.assertEqual(Kind.TOKEN_RESPONSE,
                         detect_kind("x.json", '{"access_token":"a","token_type":"Bearer"}'))
        self.assertEqual(Kind.ID_TOKEN,
                         detect_kind("blob.txt", "eyJhbGciOiJub25lIn0.e30.x"))
        self.assertEqual(Kind.AUTH_REQUEST,
                         detect_kind("blob.txt", "https://as.example.com/authorize?a=1"))
        self.assertEqual(Kind.HEADERS,
                         detect_kind("blob.txt", "HTTP/1.1 401 Unauthorized\n\n"))

    def test_forced_kind_and_invalid_kind(self):
        self.assertEqual(Kind.CLIENT, detect_kind("x.json", "{}", "client"))
        with self.assertRaises(ValueError):
            detect_kind("x.json", "{}", "not-a-kind")


class UrlParsingTests(unittest.TestCase):
    def test_params_are_url_decoded(self):
        parsed = parse_auth_url(
            "https://as.example.com/authorize?response_type=code&"
            "redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid+profile"
        )
        self.assertEqual("code", parsed["params"]["response_type"])
        self.assertEqual("https://app.example.com/cb", parsed["params"]["redirect_uri"])
        self.assertEqual("openid profile", parsed["params"]["scope"])
        self.assertEqual("as.example.com", parsed["host"])

    def test_surrounding_quotes_are_stripped(self):
        parsed = parse_auth_url('"https://as.example.com/a?a=1"')
        self.assertEqual("1", parsed["params"]["a"])


class HeaderParsingTests(unittest.TestCase):
    def test_repeated_headers_survive(self):
        raw = ("HTTP/1.1 200 OK\r\n"
               "Set-Cookie: a=1\r\n"
               "Set-Cookie: b=2\r\n"
               "Cache-Control: no-store\r\n"
               "\r\n{}")
        parsed = parse_headers(raw)
        self.assertIn("HTTP/1.1 200 OK", parsed["status"])
        self.assertEqual(["a=1", "b=2"], parsed["headers"]["set-cookie"])
        self.assertEqual(["no-store"], parsed["headers"]["cache-control"])

    def test_crlf_and_blank_line_handling(self):
        self.assertEqual({}, parse_headers("HTTP/1.1 200 OK\n\nnonsense: x")["headers"])


class LoadingTests(unittest.TestCase):
    def test_directory_loads_all_six_artefacts(self):
        loaded = load_path([GOOD])
        self.assertEqual(6, len(loaded))
        kinds = {item.kind for item in loaded}
        self.assertEqual(6, len(kinds), kinds)

    def test_forced_kind_applies_to_directory(self):
        loaded = load_path([GOOD], kind="client")
        self.assertTrue(all(i.kind is Kind.CLIENT for i in loaded))

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_path(["/definitely/not/here"])

    def test_load_text_and_load_file_agree(self):
        path = os.path.join(GOOD, "discovery.json")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(load_file(path).data, load_text(text, path).data)


if __name__ == "__main__":
    unittest.main()
