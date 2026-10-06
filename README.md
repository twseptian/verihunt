# VeriHunt

AI-Powered Security Analysis for Burp Suite — part of the **Agentic Web Pentest** project.

Analyze HTTP requests and responses directly inside Burp Suite using any major LLM provider. Findings are structured, severity-classified, and registered as native Burp scan issues.

---

## Features

- **AI Analysis (Results tab)** — right-click any request → *Analyze with AI*. Single or **batch/queue** (select many in Proxy history → "Analyze N requests with AI", concurrent workers, live progress, Stop). Optional **Self-verify** second pass cuts false positives **without discarding attack-surface hypotheses** (Potential SQLi / auth-bypass / LFI / SSRF that a passive response can never prove are kept, not dropped). Re-analysing an endpoint no longer produces duplicate findings (de-dup by severity + URL + parameter). Findings become native Burp scan issues with Advisory + Analyzed Request/Response, Toggle False Positive, and an **AI Assistant chat**.
- **AI Hunt (passive heuristics + enhanced AI triage)** — HUNT-style flagging of suspicious parameters across 12 vuln classes (SQLi, XSS, LFI/Path Traversal, SSRF, IDOR/BOLA, Command Injection, SSTI, XXE, Open Redirect, Deserialization, Mass-Assignment, Debug), plus a generic **"Other Parameter (review)"** catch-all so no user-controllable input is missed. Tick *Passive (Proxy)* to flag params as you browse, or press **Scan History** to run the heuristics over Burp's existing Proxy history retroactively — instant, free, no payloads, static assets skipped, off the proxy thread. Candidates are **POTENTIAL until validated**. Per-candidate Request/Response viewer + right-click **Deep Analyze (AI)** / Send to Repeater / Send to Intruder / Copy URL. **Triage (AI)** is evidence-grounded (reflection, SQL-error, stack-trace, status, content-type signals) → verdict + confidence % + evidence + tailored payloads + next step.
- **Cross-Scan Memory** — remembers, per host, your false positives + AI-confirmed findings (persisted across restarts); later scans skip known FPs and stay aware of prior confirmations. Toggle with *Memory*; reset with *Clear Memory*.
- **Reports & Export** — Export **JSON**, or **HTML / Markdown** reports (grouped by severity, PoC + remediation); right-click a finding → *Copy as Markdown*.
- **Token Usage Tracker** — last-call + running session tokens in the Results header (TPM / quota awareness).
- **12 providers**, per-provider tuning + *Test & Detect Models*, and Auto / Light / Dark theme.

See the in-app **About** tab for full documentation.

---

## Providers Supported

| Provider    | Models (defaults; editable, use *Test & Detect Models* for the live list) |
|-------------|---------------------------------------------------------------------|
| Anthropic   | claude-sonnet-5, claude-opus-5, claude-haiku-4-5, claude-fable-5-1  |
| OpenAI      | gpt-5.1, gpt-5, gpt-5-mini, gpt-4.1, gpt-4o, o3, o4-mini            |
| OpenRouter  | Any 400+ models via unified API (free & paid)                       |
| Gemini      | gemini-2.5-flash/pro, gemini-2.5-flash-lite, gemini-3.x (preview)   |
| Ollama      | Local server OR Ollama Cloud (ollama.com) — model + optional API key |
| DeepSeek    | deepseek-chat (V-series), deepseek-reasoner                         |
| Kimi        | Moonshot kimi-latest, kimi-k2, moonshot-v1-8k/32k/128k             |
| Mistral     | mistral-large / medium / small, codestral                          |
| Groq        | llama-3.3/4, openai/gpt-oss, moonshotai/kimi-k2 (very fast)         |
| xAI (Grok)  | grok-4.6, grok-4.5, grok-4.3                                        |
| OpenCode Zen| Gateway (claude-sonnet-5, gpt-5.1, kimi-k3, ...)                    |
| Z.AI (GLM)  | glm-4.6 (flagship), glm-4.5 / -air / -flash (free tier)             |
| Z.AI Coding Plan | Same GLM models - USE THIS entry for GLM Coding Plan keys (coding endpoint) |
| Custom      | Any OpenAI-compatible gateway (LiteLLM, Azure-compatible, proxy) - set Base URL + Model |

---

## Installation

### 1. Install Jython

1. Download **Jython Standalone** JAR from https://www.jython.org/download
2. In Burp Suite: **Extensions → Extensions Settings → Python Environment** → click **Select file** → choose the Jython JAR

### 2. Install VeriHunt

1. In Burp Suite: **Extensions → Add**
2. Set **Extension type**: Python
3. Set **Extension file**: `verihunt.py`
4. Set **Folder for loading modules**: the folder containing all `.py` files (this directory)
5. Click **Next** — the extension loads without errors

---

## Configuration

1. Open the **VeriHunt** tab in Burp Suite
2. Go to **Settings**
3. Select your **Active Provider** (Anthropic / OpenAI / OpenRouter / Gemini / Ollama / DeepSeek / Kimi / Mistral / Groq / xAI / OpenCode Zen / Z.AI)
   - **Theme**: leave on *Auto* to follow Burp's Look & Feel, or force *Light* / *Dark* if the panels render with the wrong theme (applies immediately).
4. Enter your API key in the provider's panel
5. Select or type your model name
6. Click **Save Settings**

---

## Usage

1. Browse target application (Proxy → HTTP history accumulates traffic)
2. Right-click any request → **VeriHunt → Analyze with AI**
3. The analysis runs in the background (UI stays responsive)
4. Switch to the **Results** tab to view findings

The Results tab shows a severity tally (`3 High · 2 Med · 3 Low · 21 Info`), the
**active AI model** driving the analysis, and a per-finding advisory. The analysed
exchange appears in read-only **Analyzed Request** / **Analyzed Response** viewers
(native Burp editors — right-click, Send to Repeater, etc. still work). A
**resizable AI Chat** box (drag the divider) answers follow-up questions grounded
on the selected request (e.g. "test the `file` parameter for LFI"). The UI adapts
to Burp's light or dark theme. The **Analyzed Request** / **Analyzed Response**
viewers are native Burp editors, so right-click → *Send to Repeater* / *Send to
Intruder* works to verify a Potential finding without copy-paste.

### Confirmed vs Potential findings

Analysis is **passive** — the extension never sends the payload itself. A finding
whose evidence is present in the actual response (reflected value, error, missing
header, disclosed data) is reported with its plain name and Certain/Firm
confidence. A finding the AI can only infer from parameter names (e.g. LFI/SQLi
from a `content` parameter) is marked **Tentative** and prefixed **"Potential"**,
so an unverified High never reads like a proven one. Use the AI Chat to verify a
Potential finding interactively.

**Self-verification** (Settings → *Self-verify*, on by default) adds a second AI
pass that re-judges every finding against the actual response: proven findings are
kept, unproven ones are automatically downgraded to **Potential**, and refuted ones
are dropped — cutting false positives at the cost of one extra API call per
analysis. The Results tab also has a **severity filter** and sorts findings
High → Information.

Mark a finding as a false positive with **Toggle False Positive** (it is greyed and
kept out of the severity tally); tick **Hide FP** to collapse false positives out of
the list entirely. **Export JSON** flags each record with `false_positive` and reports
`total_active` / `total_false_positive` so marked FPs stay distinguishable in the file.

---

## Prompt Customization

The **Settings** tab shows the editable **User Prompt Template**.

Available placeholders:

| Placeholder             | Description                        |
|-------------------------|------------------------------------|
| `{URL}`                 | Full target URL                    |
| `{METHOD}`              | HTTP method (GET, POST, etc.)      |
| `{REQUEST}`             | Full raw HTTP request              |
| `{REQUEST_HEADERS}`     | Request headers only               |
| `{REQUEST_BODY}`        | Request body only                  |
| `{RESPONSE}`            | Full raw HTTP response             |
| `{RESPONSE_STATUS_LINE}`| Status line (HTTP/1.1 200 OK)      |
| `{RESPONSE_HEADERS}`    | Response headers only              |
| `{RESPONSE_BODY}`       | Response body (truncated if large) |
| `{IS_TRUNCATED_PROMPT}` | True if content was truncated      |
| `{COLLABORATOR_URL}`    | Burp Collaborator OOB payload URL  |

The **System Prompt** is built-in and not editable — it provides the security expert persona and analysis framework.

---

## Advanced Prompting

The system prompt and analysis template are built for the Agentic Web Pentest pipeline. Each request is evaluated across:

- **Injection**: SQLi, NoSQLi, OS Command, SSTI, XXE, LDAP/XPath
- **Auth/AuthZ**: Bypass, JWT (alg:none, key confusion, kid injection), OAuth/OIDC, IDOR, BOLA, 2FA bypass
- **Client-side**: Reflected/Stored/DOM XSS, CSRF, CORS misconfiguration, Clickjacking
- **Server-side**: SSRF, Path Traversal, File Upload bypass, HTTP Smuggling, Cache Poisoning
- **Deserialization**: Java (ysoserial), PHP, Python pickle, .NET ViewState, JSON, prototype pollution
- **JavaScript Analysis**: Hardcoded secrets, dangerous sinks, exposed endpoints, source maps
- **Sensitive File Exposure**: `.env`, `.git`, backup files, config leaks, directory listing
- **Business Logic**: Race conditions, price tampering, mass assignment, flow bypass
- **API Security**: REST, GraphQL, WebSocket, gRPC attack surfaces
- **CVE Identification**: Maps detected technology versions to known CVEs (Spring4Shell, Log4Shell, Ghostcat, Struts, etc.)
- **OOB Detection**: Burp Collaborator payloads injected into SSRF, blind SQLi, XXE, and blind XSS PoCs

---

## Files

```
burpversion/
├── verihunt.py      # Main BurpExtender entry point (load this in Burp)
├── api_client.py       # Multi-provider LLM client (Anthropic, OpenAI, OpenRouter, Ollama)
├── prompt_handler.py   # Advanced prompt engineering
├── scanner.py          # Background analysis orchestration
├── ui.py               # Full Swing UI with tabbed settings + results
├── report_generator.py # AI response parser → structured Burp issues
└── README.md
```

---

## OpenRouter Free Models (No API Key Cost)

OpenRouter offers several free models suitable for security analysis:

- `meta-llama/llama-3.3-70b-instruct:free`
- `google/gemini-2.0-flash-exp:free`
- `mistralai/mistral-7b-instruct:free`

Get a free key at https://openrouter.ai/keys
