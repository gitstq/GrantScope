# 📜 Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-09

### 🎉 Added

- **53 built-in audit rules** across six artefact categories:
  - `GS1xx` OIDC discovery / authorization-server metadata (7 rules)
  - `GS2xx` authorization request (14 rules)
  - `GS3xx` PKCE / RFC 7636 (7 rules)
  - `GS4xx` token endpoint response (5 rules)
  - `GS5xx` ID token / JWT claims (13 rules)
  - `GS6xx` HTTP response headers / transport (7 rules)
- **Live S256 recomputation** (`GS306`): when a `code_verifier` is supplied,
  the challenge is recomputed and compared, not merely checked for presence.
  Verified against the RFC 7636 Appendix B test vector.
- **MCP profile** (`--profile mcp`) adding RFC 8707 `resource`,
  protected-resource metadata (`WWW-Authenticate: resource_metadata=...`) and
  resource/audience binding checks (`GS214`, `GS513`, `GS607`).
- **Four output formats**: coloured terminal text, Markdown, JSON and
  **SARIF 2.1.0** (uploadable to GitHub code scanning).
- **CI gate** with `--fail-on critical|high|medium|low|info|never`.
- **Python library API** (`audit`, `audit_paths`, `audit_text`, `Options`,
  `render`) alongside the CLI; fully typed (`py.typed`).
- **Single-file zipapp build** (`python build.py` → `dist/grantscope.pyz`)
  using only the standard library.
- **Deterministic example bundles** `examples/good` (0 findings) and
  `examples/bad` (35 findings) plus `examples/make_fixtures.py`.
- **64 unit tests**, including a trigger fixture for every single rule.
- Trilingual README (简体中文 / 繁體中文 / English), CONTRIBUTING guide and
  GitHub Actions CI covering Python 3.8–3.12.

### 🔐 Design decisions

- Zero runtime dependencies, zero network calls, zero telemetry.
- JWT signatures are explicitly **not** verified; the tool states this in the
  CLI help, README and text report footer so it cannot be mistaken for a token
  validator.
- `access_token` / `refresh_token` / `id_token` are treated as legitimate
  fields in a token response (`GS404` only flags credential-like keys), which
  avoids a common false positive in naive linters.
