# 🧪 Example bundles

Two ready-to-audit bundles, both generated deterministically by
[`make_fixtures.py`](make_fixtures.py). Run from the repository root:

```bash
# ✅ clean bundle — 0 findings, exit code 0
python -m grantscope audit examples/good --no-color --fail-on high

# ❌ broken bundle — 35 findings, exit code 1 with the default gate
python -m grantscope audit examples/bad --no-color --fail-on critical --quiet
```

| Bundle | Files | Findings (default profile) |
| --- | --- | --- |
| `good/` | 6 | **0** |
| `bad/` | 6 | **35** |

## 📁 Artefacts in each bundle

| File | Kind | What it represents |
| --- | --- | --- |
| `discovery.json` | `discovery` | `/.well-known/openid-configuration` response body |
| `client.json` | `client` | Client registration metadata (`redirect_uris` etc.) |
| `auth_request.url` | `auth_request` | The full authorization request URL |
| `token_response.json` | `token_response` | A successful token endpoint response body |
| `id_token.jwt` | `id_token` | A compact ID token (structure only, never verified) |
| `headers.http` | `headers` | Raw `curl -i` style response headers |

## 🔑 The `good/` PKCE pair

The S256 challenge in `good/auth_request.url` was derived from this verifier:

```
code_verifier         = GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv
code_challenge_method = S256
code_challenge        = J9tsEYviA3Mb3lbuYmTQwCcXNPihkZdMISlBe9c_tYs
```

Verify it yourself:

```bash
python -m grantscope pkce \
  --verifier 'GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv' \
  --challenge 'J9tsEYviA3Mb3lbuYmTQwCcXNPihkZdMISlBe9c_tYs'

# Recompute the challenge inside a full audit (GS305 / GS306):
python -m grantscope audit examples/good \
  --code-verifier 'GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv' \
  --profile mcp \
  --expected-issuer https://id.example.com \
  --expected-audience mcp-client-01 \
  --expected-nonce N0nce-Value-For-Replay-01 \
  --no-color --fail-on high
```

That last command also exercises the three MCP-specific rules and all pinned
value checks, and still produces **zero findings**.

## ♻️ Regenerating

```bash
python examples/make_fixtures.py
```

> ⚠️ All tokens and secrets in these fixtures are obvious placeholders. Never
> replace them with real credentials.
