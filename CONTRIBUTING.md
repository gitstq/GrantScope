# 🤝 Contributing to GrantScope

First of all — thank you! GrantScope is deliberately small and dependency-free;
keeping it that way is the main contribution guideline.

## 🚀 Getting started

```bash
git clone https://github.com/gitstq/GrantScope.git
cd GrantScope
python -m unittest discover -s tests -v   # 64 tests, no install needed
python build.py                            # -> dist/grantscope.pyz
```

No `pip install`, no virtualenv, no network access is required for development.
Python **3.8+** is the only prerequisite.

## 📐 Ground rules

| Rule | Why |
| --- | --- |
| **Standard library only** | The tool must run offline in CI, containers and MCP sandboxes. Do not add runtime dependencies, ever. |
| **No network I/O** | GrantScope is a static auditor. Never add `requests`, `urllib.request` calls or live JWKS fetching. |
| **Never verify signatures** | Signature verification needs a trust decision and network access; it is out of scope by design. |
| **Deterministic output** | Findings are sorted and de-duplicated. `--now` exists to make time-based rules reproducible. |
| **One rule = one function** | Add checks in `grantscope/rules.py` via the `@rule(...)` decorator. |

## 🧩 Adding a new rule

1. Pick the next free ID in the matching `GSx` range (see the table in
   `grantscope/rules.py`).
2. Register it with the `@rule(...)` decorator: unique ID, short title,
   severity, category, rationale, remediation and a spec reference.
3. Implement a pure function `def _gsNNN(ctx: Context) -> List[Finding]`.
   Use `emit(ctx, "GSNNN", ...)` or the `_one(...)` helper. Return `[]` when
   the corresponding artefact is absent.
4. **Add a trigger fixture** to `TRIGGERS` in `tests/test_rules.py`.
   `test_every_registered_rule_can_fire` will fail until you do.
5. Update `CHANGELOG.md` and the rule count in the README if needed.

```python
@rule("GS608", "Example rule", Severity.MEDIUM, "HTTP headers",
      "Why this matters.", "How to fix it.", "RFC XXXX")
def _gs608(ctx: Context) -> List[Finding]:
    if ctx.headers is None:
        return []
    return _one(ctx, "GS608", condition, "clear message")
```

## ✅ Definition of done

- `python -m unittest discover -s tests -v` → **OK**
- `python build.py` → zipapp smoke test passes
- `python -m grantscope audit examples/good --fail-on high` → **exit 0**
- `python -m grantscope audit examples/bad --fail-on critical` → **exit 1**
- No credentials, tokens or personal data in any file, example or commit.

## 🧾 Commit messages

We use the [Angular convention](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format):

```
feat: add GS608 example rule
fix: handle repeated Set-Cookie headers
docs: add MCP integration example
test: cover alg=none tokens
refactor: split report renderers
chore: bump version to 1.1.0
```

## 🐛 Reporting issues

Please include:

- GrantScope version (`python -m grantscope version`) and Python version
- the **anonymised** artefact that triggered the problem (never paste real
  tokens, secrets or production URLs)
- the exact command and the expected vs. actual output

## 📄 License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
