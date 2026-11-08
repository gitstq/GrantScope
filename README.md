<div align="center">

# 🔐 GrantScope

**零依赖 · 离线优先的 OAuth 2.1 / OIDC 授权流合规与风险审计引擎**
**Zero-dependency, offline-first OAuth 2.1 / OIDC authorization-flow conformance & risk auditor**

`53 rules` · `4 report formats` · `SARIF 2.1.0` · `MCP profile` · `Python 3.8+` · `0 runtime dependencies`

[简体中文](#zh-cn) ｜ [繁體中文](#zh-tw) ｜ [English](#en)

</div>

---

> ⚠️ **边界说明**：GrantScope 是**离线静态审计器**。它只读取本地文件，**从不发起任何网络请求**，也**不验证 JWT 签名**（签名验证需要 JWKS 与信任决策，属于调用方职责）。请勿把它当作线上令牌校验器使用。

---

<a id="zh-cn"></a>

## 简体中文

### 🎉 项目介绍

MCP 远程服务器、AI Agent 工具链和各类「用 OAuth 登录」的集成，正在把授权配置散落到六个地方：OIDC 发现文档、客户端注册信息、授权请求 URL、令牌响应、ID Token，以及 HTTP 响应头。**任何一处写错，都可能导致授权码被截获、令牌被缓存、或跨服务重放**；而这类问题往往要等到真机联调、甚至上线之后才暴露。

**GrantScope** 把这六类产物收进一个离线包，用 **53 条规则**逐项体检：从 `issuer` 是否强制 HTTPS、PKCE 是否真的用了 S256，到 `Cache-Control: no-store` 是否缺失、MCP 的 `resource` 参数有没有把令牌绑定到正确的资源服务器。它输出人能读的报告、机器能吃的 JSON、PR 里能贴的 Markdown，以及可直接上传 GitHub 代码扫描的 **SARIF 2.1.0**，并用 `--fail-on` 把结果变成 CI 门禁。

**灵感来源**：今日 GitHub Trending 上 `vercel-labs/agent-browser`（面向 AI Agent 的浏览器自动化）与 `anthropics/skills`（Agent Skills 生态）所代表的工具链授权浪潮；以及 [MCP 授权规范（2025-06-18）](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) 对远程服务器强制要求 OAuth 2.1 + PKCE 与 [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) 资源指示符。代码与规则为**独立自研实现**，仅参考公开规范（RFC 6749 / 7636 / 8707 / 9700 / 9728、OIDC Core、RFC 8725），未复制任何既有项目代码。

**解决的痛点**：① 授权配置没有「一次看全」的入口；② CI 阶段没有凭据、不能联网，无法做授权流检查；③ 常见 linter 只判断 `code_challenge` 存不存在，不重算 S256；④ 安全扫描结果难以接入现有 CI 与代码扫描平台。

### ✨ 核心特性

| | 特性 |
| --- | --- |
| 🔬 | **真·PKCE 重算**：提供 `--code-verifier` 后，会用 `BASE64URL(SHA256(verifier))` 重新计算并与 `code_challenge` 比对（`GS306`），已通过 RFC 7636 附录 B 标准向量验证；`plain` 方法、非法字符集、padding 全部单独告警 |
| 📋 | **53 条规则 / 6 大类别**：发现文档、授权请求、PKCE、令牌响应、ID Token、HTTP 响应头，每条都带规则编号、严重级别、证据、修复建议与规范出处 |
| 🤖 | **MCP 专用 profile**：`--profile mcp` 额外启用 RFC 8707 `resource`、`WWW-Authenticate: resource_metadata`、`aud` 与资源绑定三条规则 |
| 📤 | **四种输出**：彩色终端文本、Markdown 表格、结构化 JSON、**SARIF 2.1.0**（含完整 `rules` 定义，可上传 GitHub code scanning） |
| 🚦 | **CI 门禁**：`--fail-on critical\|high\|medium\|low\|info\|never`，命中阈值即返回退出码 1；输出按严重级别与规则号排序且去重，便于 diff |
| 🧊 | **零依赖 · 纯离线**：仅用 Python 标准库，无网络、无遥测、无第三方包；支持 `--now` 固定时钟，结果完全确定 |
| 🧩 | **三种形态**：源码目录直接 `python -m grantscope`、`pip install` 后的 `grantscope` 命令、以及 `dist/grantscope.pyz` 单文件 zipapp |
| 🌏 | **三语母语文档**：简体中文 / 繁體中文 / English 三个完整版本，非机翻 |
| 🛡️ | **低误报设计**：`access_token`、`refresh_token`、`id_token` 在令牌响应里是合法字段，只有凭据类字段才会触发 `GS404` |

### 🚀 快速开始

**环境要求**：Python **3.8+**（Windows / macOS / Linux 均可）。运行时依赖 **0**，不需要 `pip install`，不需要网络。

```bash
# 1️⃣ 克隆并跑测试（64 项，标准库 unittest）
git clone https://github.com/gitstq/GrantScope.git
cd GrantScope
python -m unittest discover -s tests -v

# 2️⃣ 审计「合规」示例：0 条发现，退出码 0
python -m grantscope audit examples/good --no-color --fail-on high

# 3️⃣ 审计「问题」示例：35 条发现，默认门禁返回退出码 1
python -m grantscope audit examples/bad --no-color --quiet --fail-on critical

# 4️⃣ 生成单文件可执行包
python build.py
python dist/grantscope.pyz --version
```

**三种安装方式**（任选其一）：

```bash
# A. 零安装：直接在源码目录使用
python -m grantscope --help

# B. 安装为命令
pip install .
grantscope rules --format text

# C. 单文件 zipapp（无需安装，拷走即用）
python build.py
python dist/grantscope.pyz audit examples/good --no-color
```

> 💡 Windows 用户可用 `py -3 -m grantscope ...`，或直接运行一键验证脚本：
> `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1`

### 📖 详细使用指南

#### 支持的输入产物

把文件放进同一个目录，GrantScope 会按**文件名 + 内容**自动识别；也可以用 `--kind` 强制指定。

| 文件示例 | 类型 | 对应内容 |
| --- | --- | --- |
| `discovery.json` | `discovery` | `/.well-known/openid-configuration` 响应体 |
| `client.json` | `client` | 客户端注册信息（`redirect_uris` 等） |
| `auth_request.url` | `auth_request` | 完整授权请求 URL（参数会自动 URL 解码） |
| `token_response.json` | `token_response` | 令牌端点成功响应体 |
| `id_token.jwt` | `id_token` | 紧凑格式 ID Token（**仅解析结构，不验签**） |
| `headers.http` | `headers` | `curl -i` 风格的原始响应头，支持重复头 |

#### 常用命令

```bash
# 审计单个目录 / 多个文件 / 标准输入
python -m grantscope audit ./captured
python -m grantscope audit discovery.json auth_request.url
cat discovery.json | python -m grantscope audit - --kind discovery

# MCP 场景 + 固定期望值（issuer / aud / nonce）
python -m grantscope audit ./captured --profile mcp \
  --expected-issuer https://id.example.com \
  --expected-audience mcp-client-01 \
  --expected-nonce 'N0nce-Value-For-Replay-01'

# 重算 PKCE（把令牌请求里的 verifier 传进来）
python -m grantscope audit ./captured \
  --code-verifier 'GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv'

# 输出 SARIF 供 GitHub 代码扫描消费
python -m grantscope audit ./captured --format sarif \
  --output grantscope.sarif --fail-on never

# 独立 PKCE 计算器（遵循 RFC 7636 附录 B 向量）
python -m grantscope pkce --generate 64 --json
python -m grantscope pkce \
  --verifier 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' \
  --challenge 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

# 查看全部 53 条规则
python -m grantscope rules --format markdown
```

#### 参数速查

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `-f, --format` | `text` / `markdown` / `json` / `sarif` | `text` |
| `-o, --output` | 写入文件而非标准输出 | 标准输出 |
| `--profile` | `default` / `mcp` | `default` |
| `--kind` | 强制所有输入为某一类型 | 自动识别 |
| `--expected-issuer` | 锁定 issuer（`GS106`） | 不锁定 |
| `--expected-audience` | 锁定 `aud`（`GS509`） | 不锁定 |
| `--expected-nonce` | 锁定 `nonce`（`GS511`） | 不锁定 |
| `--code-verifier` | 传入 verifier 以重算 S256（`GS305`/`GS306`） | 不传入 |
| `--now` | 覆盖当前 Unix 秒，令时间类规则可复现 | 系统时间 |
| `--fail-on` | 门禁阈值 | `high` |
| `--no-color` / `--quiet` | 关闭 ANSI 颜色 / 省略修复与出处 | 关闭 |

#### 规则分类

| 编号段 | 类别 | 规则数 | 代表检查 |
| --- | --- | --- | --- |
| `GS1xx` | 发现文档 | 7 | issuer 必须 HTTPS、端点完整性、是否声明 S256、是否仍开放隐式流 |
| `GS2xx` | 授权请求 | 14 | 隐式流、redirect_uri 通配符/fragment/明文、state 熵、nonce、URL 泄露凭据、MCP `resource` |
| `GS3xx` | PKCE | 7 | challenge 缺失、`plain`、语法、**S256 重算不一致**、padding |
| `GS4xx` | 令牌响应 | 5 | `access_token` / `Bearer` / `expires_in`、凭据回显、scope 降级 |
| `GS5xx` | ID Token | 13 | `alg=none`、HS256、缺 `kid`、必要 claims、过期/未来时间、`aud`/`azp`/`nonce`、敏感字段 |
| `GS6xx` | 响应头 | 7 | `no-store`、`Pragma`、Content-Type、Cookie 安全属性、CORS、HSTS、MCP `resource_metadata` |

#### 作为 Python 库使用

```python
from grantscope import audit_paths, Options, render

report = audit_paths(
    ["./captured"],
    Options(profile="mcp", expected_audience="mcp-client-01"),
)

print(report.counts)            # {'critical': 0, 'high': 2, ...}
print(report.max_severity)      # Severity.HIGH
print(render(report, "markdown"))
```

#### 接入 CI

```yaml
- name: Audit OAuth flow
  run: |
    python -m grantscope audit ./captured \
      --format sarif --output grantscope.sarif \
      --fail-on high
```

`examples/good` 在默认与 MCP profile 下均为 **0 发现**，`examples/bad` 在默认 profile 下为 **35 发现**，可直接当作 CI 的正向/反向基线。

#### ❓ 常见问题

- **为什么不验证签名？** 离线工具拿不到可信 JWKS，且信任决策应由你的应用做出；把结构检查伪装成验签反而危险。工具在 CLI 帮助、README 和文本报告页脚都会明确声明。
- **报告里出现 `GS401` 但我明明有 access_token？** 检查文件是否被识别成 `token_response`（文件名建议含 `token` 或 `response`），或用 `--kind token_response` 强制指定。
- **时间类规则结果不稳定？** 用 `--now 1800000000` 固定时钟。
- **线上产物怎么采集？** 用 `curl -i` 自行落盘后再审计；本工具绝不会替你联网。

### 💡 设计思路与迭代规划

**设计理念**：把「授权流正确性」拆成**可离线观测的静态事实**，而不是重放一次真实登录。因此每条规则都是无 I/O 的纯函数（`Context → List[Finding]`），上下文集中归一化六类产物，引擎统一负责去重、排序与门禁——这让 53 条规则可以逐条单测，也让报告在两次运行间保持字节级稳定。

**技术选型**：只用 Python 标准库（`hashlib`/`hmac`/`base64`/`urllib.parse`/`argparse`/`json`/`unittest`/`zipapp`/`dataclasses`）。选 Python 是因为 CI、MCP 服务器与运维脚本几乎都有解释器；选 `unittest` 与 `zipapp` 是为了让「测试 + 打包」同样零依赖、跨平台。

**迭代规划**：🔭 支持 OAuth 2.0 授权服务器元数据（RFC 8414）与 RFC 9728 受保护资源元数据文档；🧪 规则级别白名单 / 基线快照（suppress 已接受的风险）；🔑 可选离线 JWKS 验签（显式开启、明确标注）；📊 两次审计结果的 diff 模式；🌐 新增日语、韩语、西班牙语 README；🧩 输出 JUnit XML 以适配更多 CI。

**社区贡献方向**：补齐更多厂商特有的 discovery 字段、补充真实（脱敏）样本夹具、把规则翻译成更多语言。

### 📦 打包与部署指南

GrantScope 属于**工具库 / CLI / 脚本类项目**，按发布策略**不创建 Release、不上传平台安装包**；安装、引入、集成与兼容环境全部在本文档说明。

| 形态 | 命令 | 适用场景 |
| --- | --- | --- |
| 源码目录 | `python -m grantscope ...` | 开发、CI 里直接 checkout 使用 |
| Python 包 | `pip install .` → `grantscope ...` | 长期安装在构建机 / 容器 |
| 单文件 zipapp | `python build.py` → `dist/grantscope.pyz` | 拷到任意机器，`python grantscope.pyz ...` 即用 |

```bash
# 完整验证（Linux / macOS / WSL）
make verify

# 完整验证（Windows PowerShell）
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1

# 清理构建产物
make clean
```

**兼容范围**：Python 3.8 / 3.9 / 3.10 / 3.11 / 3.12；Windows、macOS、Linux 全平台（纯标准库，无 C 扩展、无编译步骤）。`dist/*.pyz` 为可复现构建产物，已加入 `.gitignore`，不随仓库分发；任何平台都能用 `python build.py` 重新生成。CI 覆盖 3 个操作系统 × 3 个 Python 版本。

> 📌 无环境变量、无配置文件、无凭据需求；参见 `.env.example`。

### 🤝 贡献指南

欢迎提交 PR 与 Issue！完整规范见 [CONTRIBUTING.md](CONTRIBUTING.md)：

- **铁律**：标准库 only、绝不联网、绝不验签、输出必须确定性；
- **新增规则**：`@rule(...)` 注册 → 实现纯函数 → 在 `tests/test_rules.py` 的 `TRIGGERS` 里补一条触发夹具（`test_every_registered_rule_can_fire` 会强制检查）；
- **提交信息**：遵循 Angular 规范 `feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:`；
- **Issue**：请附上版本号、Python 版本、脱敏后的产物片段、命令与预期/实际输出；**切勿粘贴真实令牌或密钥**。

### 📄 开源协议说明

本项目采用 [MIT License](LICENSE)，Copyright (c) 2026 gitstq。可自由使用、复制、修改、合并、发布与商用，只需保留版权与许可声明；软件按「现状」提供，不附带任何担保。示例夹具中的令牌与密钥均为占位符。

---

<a id="zh-tw"></a>

## 繁體中文

### 🎉 專案介紹

MCP 遠端伺服器、AI Agent 工具鏈，以及各式各樣「用 OAuth 登入」的整合，正把授權設定散落在六個地方：OIDC 探索文件、用戶端註冊資訊、授權請求網址、權杖回應、ID Token，以及 HTTP 回應標頭。**任何一處寫錯，都可能讓授權碼遭攔截、權杖被快取，或發生跨服務重放**；而這類問題往往要等到真機聯調、甚至上線之後才會浮現。

**GrantScope** 把這六類產物收進一個離線包，用 **53 條規則**逐項健檢：從 `issuer` 是否強制 HTTPS、PKCE 是否真的用了 S256，到 `Cache-Control: no-store` 是否遺漏、MCP 的 `resource` 參數有沒有把權杖綁定到正確的資源伺服器。它輸出人看得懂的報告、機器吃得下的 JSON、PR 裡能貼的 Markdown，以及可直接上傳 GitHub 程式碼掃描的 **SARIF 2.1.0**，並用 `--fail-on` 把結果轉成 CI 關卡。

**靈感來源**：今日 GitHub Trending 上 `vercel-labs/agent-browser`（面向 AI Agent 的瀏覽器自動化）與 `anthropics/skills`（Agent Skills 生態）所代表的工具鏈授權浪潮；以及 [MCP 授權規格（2025-06-18）](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) 對遠端伺服器強制要求 OAuth 2.1 + PKCE 與 [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) 資源指示符。程式碼與規則皆為**獨立自研**，僅參考公開規格（RFC 6749 / 7636 / 8707 / 9700 / 9728、OIDC Core、RFC 8725），未複製任何既有專案程式碼。

**解決的痛點**：① 授權設定沒有一個「一次看全」的入口；② CI 階段沒有憑據、不能連網，無從檢查授權流；③ 常見 linter 只判斷 `code_challenge` 存不存在，不會重算 S256；④ 掃描結果難以串接既有 CI 與程式碼掃描平台。

### ✨ 核心特性

| | 特性 |
| --- | --- |
| 🔬 | **真正重算 PKCE**：提供 `--code-verifier` 後，會以 `BASE64URL(SHA256(verifier))` 重新計算並比對 `code_challenge`（`GS306`），已通過 RFC 7636 附錄 B 標準向量驗證；`plain` 方法、非法字元集、padding 皆獨立告警 |
| 📋 | **53 條規則 / 6 大類別**：探索文件、授權請求、PKCE、權杖回應、ID Token、HTTP 回應標頭，每條皆附規則編號、嚴重等級、證據、修復建議與規格出處 |
| 🤖 | **MCP 專用 profile**：`--profile mcp` 額外啟用 RFC 8707 `resource`、`WWW-Authenticate: resource_metadata`、`aud` 與資源綁定三條規則 |
| 📤 | **四種輸出**：彩色終端文字、Markdown 表格、結構化 JSON、**SARIF 2.1.0**（含完整 `rules` 定義，可上傳 GitHub code scanning） |
| 🚦 | **CI 關卡**：`--fail-on critical\|high\|medium\|low\|info\|never`，命中門檻即回傳結束碼 1；輸出依嚴重等級與規則編號排序並去重，方便 diff |
| 🧊 | **零依賴 · 純離線**：只用 Python 標準函式庫，無網路、無遙測、無第三方套件；支援 `--now` 固定時鐘，結果完全確定 |
| 🧩 | **三種形態**：原始碼目錄直接 `python -m grantscope`、`pip install` 後的 `grantscope` 指令、以及 `dist/grantscope.pyz` 單檔 zipapp |
| 🌏 | **三語母語文件**：簡體中文 / 繁體中文 / English 三個完整版本，非機器翻譯 |
| 🛡️ | **低誤報設計**：`access_token`、`refresh_token`、`id_token` 在權杖回應中是合法欄位，只有憑證類欄位才會觸發 `GS404` |

### 🚀 快速開始

**環境需求**：Python **3.8+**（Windows / macOS / Linux 皆可）。執行期依賴 **0**，不需要 `pip install`，不需要網路。

```bash
# 1️⃣ 複製並跑測試（64 項，標準函式庫 unittest）
git clone https://github.com/gitstq/GrantScope.git
cd GrantScope
python -m unittest discover -s tests -v

# 2️⃣ 稽核「合規」範例：0 項發現，結束碼 0
python -m grantscope audit examples/good --no-color --fail-on high

# 3️⃣ 稽核「有問題」範例：35 項發現，預設關卡回傳結束碼 1
python -m grantscope audit examples/bad --no-color --quiet --fail-on critical

# 4️⃣ 產生單檔可執行包
python build.py
python dist/grantscope.pyz --version
```

**三種安裝方式**（任選其一）：

```bash
# A. 免安裝：直接在原始碼目錄使用
python -m grantscope --help

# B. 安裝成指令
pip install .
grantscope rules --format text

# C. 單檔 zipapp（免安裝，拷走即用）
python build.py
python dist/grantscope.pyz audit examples/good --no-color
```

> 💡 Windows 使用者可用 `py -3 -m grantscope ...`，或直接執行一鍵驗證腳本：
> `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1`

### 📖 詳細使用指南

#### 支援的輸入產物

把檔案放進同一個目錄，GrantScope 會依**檔名 + 內容**自動辨識；也可用 `--kind` 強制指定。

| 檔案範例 | 類型 | 對應內容 |
| --- | --- | --- |
| `discovery.json` | `discovery` | `/.well-known/openid-configuration` 回應主體 |
| `client.json` | `client` | 用戶端註冊資訊（`redirect_uris` 等） |
| `auth_request.url` | `auth_request` | 完整授權請求網址（參數會自動 URL 解碼） |
| `token_response.json` | `token_response` | 權杖端點成功回應主體 |
| `id_token.jwt` | `id_token` | 緊湊格式 ID Token（**僅解析結構，不驗簽**） |
| `headers.http` | `headers` | `curl -i` 風格的原始回應標頭，支援重複標頭 |

#### 常用指令

```bash
# 稽核單一目錄 / 多個檔案 / 標準輸入
python -m grantscope audit ./captured
python -m grantscope audit discovery.json auth_request.url
cat discovery.json | python -m grantscope audit - --kind discovery

# MCP 情境 + 固定期望值（issuer / aud / nonce）
python -m grantscope audit ./captured --profile mcp \
  --expected-issuer https://id.example.com \
  --expected-audience mcp-client-01 \
  --expected-nonce 'N0nce-Value-For-Replay-01'

# 重算 PKCE（把權杖請求裡的 verifier 傳進來）
python -m grantscope audit ./captured \
  --code-verifier 'GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv'

# 輸出 SARIF 供 GitHub 程式碼掃描使用
python -m grantscope audit ./captured --format sarif \
  --output grantscope.sarif --fail-on never

# 獨立 PKCE 計算機（遵循 RFC 7636 附錄 B 向量）
python -m grantscope pkce --generate 64 --json
python -m grantscope pkce \
  --verifier 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' \
  --challenge 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

# 查看全部 53 條規則
python -m grantscope rules --format markdown
```

#### 參數速查

| 參數 | 說明 | 預設值 |
| --- | --- | --- |
| `-f, --format` | `text` / `markdown` / `json` / `sarif` | `text` |
| `-o, --output` | 寫入檔案而非標準輸出 | 標準輸出 |
| `--profile` | `default` / `mcp` | `default` |
| `--kind` | 強制所有輸入為某一類型 | 自動辨識 |
| `--expected-issuer` | 鎖定 issuer（`GS106`） | 不鎖定 |
| `--expected-audience` | 鎖定 `aud`（`GS509`） | 不鎖定 |
| `--expected-nonce` | 鎖定 `nonce`（`GS511`） | 不鎖定 |
| `--code-verifier` | 傳入 verifier 以重算 S256（`GS305`/`GS306`） | 不傳入 |
| `--now` | 覆寫目前 Unix 秒，讓時間類規則可重現 | 系統時間 |
| `--fail-on` | 關卡門檻 | `high` |
| `--no-color` / `--quiet` | 關閉 ANSI 色彩 / 省略修復與出處 | 關閉 |

#### 規則分類

| 編號段 | 類別 | 規則數 | 代表檢查 |
| --- | --- | --- | --- |
| `GS1xx` | 探索文件 | 7 | issuer 必須 HTTPS、端點完整性、是否宣告 S256、是否仍開放隱式流 |
| `GS2xx` | 授權請求 | 14 | 隱式流、redirect_uri 萬用字元/fragment/明文、state 熵、nonce、網址洩漏憑證、MCP `resource` |
| `GS3xx` | PKCE | 7 | challenge 遺漏、`plain`、語法、**S256 重算不一致**、padding |
| `GS4xx` | 權杖回應 | 5 | `access_token` / `Bearer` / `expires_in`、憑證回顯、scope 降級 |
| `GS5xx` | ID Token | 13 | `alg=none`、HS256、缺 `kid`、必要 claims、過期/未來時間、`aud`/`azp`/`nonce`、敏感欄位 |
| `GS6xx` | 回應標頭 | 7 | `no-store`、`Pragma`、Content-Type、Cookie 安全屬性、CORS、HSTS、MCP `resource_metadata` |

#### 作為 Python 函式庫使用

```python
from grantscope import audit_paths, Options, render

report = audit_paths(
    ["./captured"],
    Options(profile="mcp", expected_audience="mcp-client-01"),
)

print(report.counts)            # {'critical': 0, 'high': 2, ...}
print(report.max_severity)      # Severity.HIGH
print(render(report, "markdown"))
```

#### 串接 CI

```yaml
- name: Audit OAuth flow
  run: |
    python -m grantscope audit ./captured \
      --format sarif --output grantscope.sarif \
      --fail-on high
```

`examples/good` 在預設與 MCP profile 下皆為 **0 項發現**，`examples/bad` 在預設 profile 下為 **35 項發現**，可直接作為 CI 的正向 / 反向基線。

#### ❓ 常見問題

- **為什麼不驗簽？** 離線工具拿不到可信 JWKS，且信任決策應由你的應用程式負責；把結構檢查偽裝成驗簽反而危險。工具在 CLI 說明、README 與文字報告頁尾都會明確聲明。
- **報告出現 `GS401`，但我明明有 access_token？** 檢查檔案是否被辨識成 `token_response`（檔名建議含 `token` 或 `response`），或用 `--kind token_response` 強制指定。
- **時間類規則結果不穩定？** 用 `--now 1800000000` 固定時鐘。
- **線上產物怎麼採集？** 用 `curl -i` 自行落盤後再稽核；本工具絕不會替你連網。

### 💡 設計思路與迭代規劃

**設計理念**：把「授權流正確性」拆成**可離線觀測的靜態事實**，而不是重放一次真實登入。因此每條規則都是無 I/O 的純函式（`Context → List[Finding]`），上下文集中正規化六類產物，引擎統一負責去重、排序與關卡——這讓 53 條規則可以逐條單測，也讓報告在兩次執行間保持位元組級穩定。

**技術選型**：只用 Python 標準函式庫（`hashlib`/`hmac`/`base64`/`urllib.parse`/`argparse`/`json`/`unittest`/`zipapp`/`dataclasses`）。選 Python 是因為 CI、MCP 伺服器與維運腳本幾乎都有直譯器；選 `unittest` 與 `zipapp` 是為了讓「測試 + 打包」同樣零依賴、跨平台。

**迭代規劃**：🔭 支援 OAuth 2.0 授權伺服器中繼資料（RFC 8414）與 RFC 9728 受保護資源中繼文件；🧪 規則層級白名單 / 基線快照（抑制已接受風險）；🔑 可選離線 JWKS 驗簽（顯式開啟、明確標註）；📊 兩次稽核結果的 diff 模式；🌐 新增日語、韓語、西班牙語 README；🧩 輸出 JUnit XML 以支援更多 CI。

**社群貢獻方向**：補齊更多廠商特有的 discovery 欄位、補充真實（去識別化）樣本夾具、把規則翻譯成更多語言。

### 📦 打包與部署指南

GrantScope 屬於**工具庫 / CLI / 腳本類專案**，依發布策略**不建立 Release、不上傳平台安裝包**；安裝、引入、整合與相容環境全部在本文說明。

| 形態 | 指令 | 適用情境 |
| --- | --- | --- |
| 原始碼目錄 | `python -m grantscope ...` | 開發、CI 裡直接 checkout 使用 |
| Python 套件 | `pip install .` → `grantscope ...` | 長期安裝在構建機 / 容器 |
| 單檔 zipapp | `python build.py` → `dist/grantscope.pyz` | 拷到任意機器，`python grantscope.pyz ...` 即用 |

```bash
# 完整驗證（Linux / macOS / WSL）
make verify

# 完整驗證（Windows PowerShell）
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1

# 清理構建產物
make clean
```

**相容範圍**：Python 3.8 / 3.9 / 3.10 / 3.11 / 3.12；Windows、macOS、Linux 全平台（純標準函式庫，無 C 擴充、無編譯步驟）。`dist/*.pyz` 為可重現構建產物，已加入 `.gitignore`，不隨倉庫散佈；任何平台都能用 `python build.py` 重新產生。CI 涵蓋 3 個作業系統 × 3 個 Python 版本。

> 📌 無環境變數、無設定檔、無憑證需求；參見 `.env.example`。

### 🤝 貢獻指南

歡迎提交 PR 與 Issue！完整規範見 [CONTRIBUTING.md](CONTRIBUTING.md)：

- **鐵律**：標準函式庫 only、絕不連網、絕不驗簽、輸出必須確定性；
- **新增規則**：`@rule(...)` 註冊 → 實作純函式 → 在 `tests/test_rules.py` 的 `TRIGGERS` 補一條觸發夾具（`test_every_registered_rule_can_fire` 會強制檢查）；
- **提交訊息**：遵循 Angular 規範 `feat:` / `fix:` / `docs:` / `test:` / `refactor:` / `chore:`；
- **Issue**：請附上版本號、Python 版本、去識別化後的產物片段、指令與預期/實際輸出；**切勿貼上真實權杖或金鑰**。

### 📄 開源協議說明

本專案採用 [MIT License](LICENSE)，Copyright (c) 2026 gitstq。可自由使用、複製、修改、合併、發佈與商用，只需保留版權與授權聲明；軟體按「現狀」提供，不附帶任何擔保。範例夾具中的權杖與金鑰皆為占位符。

---

<a id="en"></a>

## English

### 🎉 About the project

MCP remote servers, AI-agent toolchains and the general "sign in with OAuth"
sprawl have scattered authorization configuration across **six places**: the
OIDC discovery document, client registration metadata, the authorization
request URL, the token response, the ID token, and the HTTP response headers.
**A mistake in any one of them can expose an authorization code, cause tokens
to be cached, or enable cross-service replay** — and these defects usually
surface only during live integration, or worse, in production.

**GrantScope** bundles those six artefacts into one offline package and checks
them with **53 rules**: from enforcing an HTTPS `issuer` and genuinely using
S256 PKCE, to verifying `Cache-Control: no-store` and confirming that an MCP
`resource` parameter binds the token to the right resource server. It emits a
human-readable report, machine-friendly JSON, Markdown for pull requests, and
**SARIF 2.1.0** that can be uploaded straight to GitHub code scanning.
`--fail-on` turns the result into a CI gate.

**Inspiration**: today's GitHub Trending entries `vercel-labs/agent-browser`
(browser automation for AI agents) and `anthropics/skills` (the Agent Skills
ecosystem) represent a wave of toolchains that all need authorization; the
[MCP authorization spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
requires OAuth 2.1 + PKCE for remote servers, with [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
resource indicators. Both the code and the rules are **independently written**,
referencing only public specifications (RFC 6749 / 7636 / 8707 / 9700 / 9728,
OIDC Core, RFC 8725); no code was copied from any existing project.

**The pain it solves**: (1) there is no single place to review authorization
configuration; (2) CI has neither credentials nor network access, so flows go
unchecked; (3) typical linters only test whether `code_challenge` *exists*
instead of recomputing S256; (4) findings rarely integrate with existing CI or
code-scanning platforms.

### ✨ Key features

| | Feature |
| --- | --- |
| 🔬 | **Real PKCE recomputation**: with `--code-verifier`, GrantScope recomputes `BASE64URL(SHA256(verifier))` and compares it to `code_challenge` (`GS306`), validated against the RFC 7636 Appendix B vector; `plain`, illegal character sets and padding each get their own finding |
| 📋 | **53 rules in 6 categories**: discovery, authorization request, PKCE, token response, ID token, HTTP headers — every finding carries an ID, severity, evidence, remediation and a spec reference |
| 🤖 | **Dedicated MCP profile**: `--profile mcp` enables the RFC 8707 `resource`, `WWW-Authenticate: resource_metadata` and audience-to-resource binding checks |
| 📤 | **Four output formats**: coloured terminal text, Markdown tables, structured JSON, and **SARIF 2.1.0** with a complete `rules` array for GitHub code scanning |
| 🚦 | **CI gate**: `--fail-on critical\|high\|medium\|low\|info\|never` returns exit code 1 at or above the threshold; output is de-duplicated and sorted for stable diffs |
| 🧊 | **Zero dependencies, fully offline**: Python standard library only; no network, no telemetry, no third-party packages. `--now` pins the clock for fully deterministic results |
| 🧩 | **Three distributions**: `python -m grantscope` from a checkout, the `grantscope` console script after `pip install`, and a single-file `dist/grantscope.pyz` zipapp |
| 🌏 | **Three native-language docs**: 简体中文 / 繁體中文 / English, hand-written rather than machine-translated |
| 🛡️ | **Low false positives**: `access_token`, `refresh_token` and `id_token` are legitimate token-response fields; only credential-like keys trigger `GS404` |

### 🚀 Quick start

**Requirements**: Python **3.8+** on Windows, macOS or Linux. **Zero runtime
dependencies** — no `pip install`, no network access.

```bash
# 1️⃣ Clone and run the 64 unit tests (stdlib unittest)
git clone https://github.com/gitstq/GrantScope.git
cd GrantScope
python -m unittest discover -s tests -v

# 2️⃣ Audit the compliant bundle: 0 findings, exit code 0
python -m grantscope audit examples/good --no-color --fail-on high

# 3️⃣ Audit the broken bundle: 35 findings, exit code 1 with the default gate
python -m grantscope audit examples/bad --no-color --quiet --fail-on critical

# 4️⃣ Build the single-file executable archive
python build.py
python dist/grantscope.pyz --version
```

**Three ways to install** (pick one):

```bash
# A. No installation at all
python -m grantscope --help

# B. Install the console script
pip install .
grantscope rules --format text

# C. Single-file zipapp — copy it anywhere and run it
python build.py
python dist/grantscope.pyz audit examples/good --no-color
```

> 💡 On Windows use `py -3 -m grantscope ...`, or run the one-shot verifier:
> `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1`

### 📖 Detailed usage

#### Supported input artefacts

Drop the files into one directory; GrantScope detects the type from the
**filename and content**. Use `--kind` to force a type.

| Example file | Kind | Represents |
| --- | --- | --- |
| `discovery.json` | `discovery` | `/.well-known/openid-configuration` response body |
| `client.json` | `client` | Client registration metadata (`redirect_uris`, …) |
| `auth_request.url` | `auth_request` | Full authorization request URL (params are URL-decoded) |
| `token_response.json` | `token_response` | Successful token endpoint response body |
| `id_token.jwt` | `id_token` | Compact ID token (**structure only, signature never verified**) |
| `headers.http` | `headers` | Raw `curl -i` style response headers; repeated headers are preserved |

#### Everyday commands

```bash
# A directory, explicit files, or stdin
python -m grantscope audit ./captured
python -m grantscope audit discovery.json auth_request.url
cat discovery.json | python -m grantscope audit - --kind discovery

# MCP profile with pinned expected values
python -m grantscope audit ./captured --profile mcp \
  --expected-issuer https://id.example.com \
  --expected-audience mcp-client-01 \
  --expected-nonce 'N0nce-Value-For-Replay-01'

# Recompute PKCE using the verifier from the token request
python -m grantscope audit ./captured \
  --code-verifier 'GrantScope-Demo-Verifier-0123456789-abcdefghijklmnopqrstuv'

# SARIF for GitHub code scanning
python -m grantscope audit ./captured --format sarif \
  --output grantscope.sarif --fail-on never

# Standalone PKCE calculator (RFC 7636 Appendix B vector)
python -m grantscope pkce --generate 64 --json
python -m grantscope pkce \
  --verifier 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' \
  --challenge 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

# List all 53 rules
python -m grantscope rules --format markdown
```

#### Option reference

| Option | Meaning | Default |
| --- | --- | --- |
| `-f, --format` | `text` / `markdown` / `json` / `sarif` | `text` |
| `-o, --output` | Write to file instead of stdout | stdout |
| `--profile` | `default` / `mcp` | `default` |
| `--kind` | Force all inputs to one artefact kind | auto-detect |
| `--expected-issuer` | Pin issuer (`GS106`) | unset |
| `--expected-audience` | Pin `aud` (`GS509`) | unset |
| `--expected-nonce` | Pin `nonce` (`GS511`) | unset |
| `--code-verifier` | Supply verifier to recompute S256 (`GS305`/`GS306`) | unset |
| `--now` | Override the current epoch second for reproducible time rules | system clock |
| `--fail-on` | CI gate threshold | `high` |
| `--no-color` / `--quiet` | Disable ANSI colour / omit fix & reference lines | off |

#### Rule catalogue

| Range | Category | Rules | Representative checks |
| --- | --- | --- | --- |
| `GS1xx` | Discovery | 7 | HTTPS issuer, endpoint completeness, S256 advertised, implicit flow still offered |
| `GS2xx` | Authorization request | 14 | Implicit flow, wildcard/fragment/plaintext `redirect_uri`, state entropy, nonce, secrets in URL, MCP `resource` |
| `GS3xx` | PKCE | 7 | Missing challenge, `plain`, syntax, **S256 mismatch on recomputation**, padding |
| `GS4xx` | Token response | 5 | `access_token` / `Bearer` / `expires_in`, credential echo, scope downgrade |
| `GS5xx` | ID token | 13 | `alg=none`, HS256, missing `kid`, required claims, expired/future times, `aud`/`azp`/`nonce`, sensitive fields |
| `GS6xx` | HTTP headers | 7 | `no-store`, `Pragma`, Content-Type, cookie attributes, CORS, HSTS, MCP `resource_metadata` |

#### As a Python library

```python
from grantscope import audit_paths, Options, render

report = audit_paths(
    ["./captured"],
    Options(profile="mcp", expected_audience="mcp-client-01"),
)

print(report.counts)            # {'critical': 0, 'high': 2, ...}
print(report.max_severity)      # Severity.HIGH
print(render(report, "markdown"))
```

#### CI integration

```yaml
- name: Audit OAuth flow
  run: |
    python -m grantscope audit ./captured \
      --format sarif --output grantscope.sarif \
      --fail-on high
```

`examples/good` yields **0 findings** under both the default and MCP profiles;
`examples/bad` yields **35 findings** under the default profile. Use them as
positive and negative CI baselines.

#### ❓ FAQ

- **Why no signature verification?** An offline tool cannot obtain a trusted
  JWKS, and the trust decision belongs to your application. Pretending a
  structural check is signature validation would be dangerous, so the CLI
  help, README and the text report footer all say so explicitly.
- **`GS401` although I do have an access_token?** Check that the file was
  detected as `token_response` (put `token` or `response` in the name), or
  force it with `--kind token_response`.
- **Time-based findings are flaky?** Pin the clock with `--now 1800000000`.
- **How do I capture live artefacts?** Use `curl -i` and save the files
  yourself. GrantScope will never make a network request on your behalf.

### 💡 Design & roadmap

**Design**: we reduce "is this flow correct?" to **static facts observable
offline**, rather than replaying a real login. Every rule is a pure, I/O-free
function (`Context → List[Finding]`); a single context normalises all six
artefacts, and the engine owns de-duplication, ordering and gating. That makes
all 53 rules individually unit-testable and keeps reports byte-stable across
runs.

**Technology choices**: Python standard library only (`hashlib`/`hmac`/
`base64`/`urllib.parse`/`argparse`/`json`/`unittest`/`zipapp`/`dataclasses`).
Python is ubiquitous in CI, MCP servers and ops scripts; `unittest` and
`zipapp` keep testing and packaging equally dependency-free and cross-platform.

**Roadmap**: 🔭 RFC 8414 authorization-server metadata and RFC 9728
protected-resource metadata; 🧪 per-rule allowlists / baseline snapshots; 🔑
optional offline JWKS verification (explicit opt-in, clearly labelled); 📊
diff mode between two audits; 🌐 Japanese, Korean and Spanish READMEs; 🧩
JUnit XML output for broader CI support.

**Where the community can help**: vendor-specific discovery fields, more
realistic (redacted) sample bundles, and translations of the rule catalogue.

### 📦 Packaging & deployment

GrantScope is a **library / CLI / script project**, so the release policy means
**no Release and no platform binaries**. Installation, integration and
compatibility are documented here instead.

| Form | Command | Best for |
| --- | --- | --- |
| Source checkout | `python -m grantscope ...` | Development, CI after checkout |
| Python package | `pip install .` → `grantscope ...` | Long-lived build agents / containers |
| Single-file zipapp | `python build.py` → `dist/grantscope.pyz` | Copy anywhere, run with `python grantscope.pyz ...` |

```bash
# Full verification (Linux / macOS / WSL)
make verify

# Full verification (Windows PowerShell)
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1

# Clean build artefacts
make clean
```

**Compatibility**: Python 3.8 / 3.9 / 3.10 / 3.11 / 3.12 on Windows, macOS and
Linux (pure standard library, no C extensions, no compile step).
`dist/*.pyz` is a reproducible build artefact listed in `.gitignore` and is not
distributed with the repository — regenerate it with `python build.py` on any
platform. CI covers 3 operating systems × 3 Python versions.

> 📌 No environment variables, no config file, no credentials required; see
> `.env.example`.

### 🤝 Contributing

PRs and issues are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md):

- **Non-negotiables**: standard library only, never network, never verify
  signatures, deterministic output;
- **Adding a rule**: register with `@rule(...)`, implement a pure function, and
  add a trigger fixture to `TRIGGERS` in `tests/test_rules.py`
  (`test_every_registered_rule_can_fire` enforces this);
- **Commits**: Angular convention `feat:` / `fix:` / `docs:` / `test:` /
  `refactor:` / `chore:`;
- **Issues**: include the version, Python version, a redacted artefact, the
  command, and expected vs. actual output. **Never paste real tokens or keys.**

### 📄 License

[MIT License](LICENSE), Copyright (c) 2026 gitstq. Use, copy, modify, merge,
publish, distribute, sublicense and sell freely, provided the copyright and
license notices are retained. The software is provided "as is", without
warranty of any kind. All tokens and secrets in the example bundles are
placeholders.
