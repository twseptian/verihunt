# AgenticBurp

AI-Powered Security Analysis for Burp Suite — part of the **Agentic Web Pentest** project.

Analyze HTTP requests and responses directly inside Burp Suite using any major LLM provider. Findings are structured, severity-classified, and registered as native Burp scan issues.

---

## Providers Supported

| Provider    | Models                                                              |
|-------------|---------------------------------------------------------------------|
| Anthropic   | claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5, claude-3.5-* |
| OpenAI      | gpt-4o, gpt-4-turbo, gpt-4, o1, o1-mini, o3-mini                   |
| OpenRouter  | Any 400+ models via unified API (free & paid)                       |
| Gemini      | gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash                  |
| Ollama      | Local server OR Ollama Cloud (ollama.com) — model + optional API key |
| DeepSeek    | deepseek-chat (V3), deepseek-reasoner (R1)                          |
| Kimi        | Moonshot moonshot-v1-8k/32k/128k, kimi-k2                           |
| Mistral     | mistral-large, mistral-small, codestral                            |
| Groq        | llama-3.3-70b, llama-3.1-8b (very fast inference)                   |
| xAI (Grok)  | grok-2-latest, grok-2-vision, grok-beta                            |
| OpenCode Zen| Gateway to 60+ models (claude-sonnet-4-5, gpt-5-codex, kimi-k2, ...) |

---

## Installation

### 1. Install Jython

1. Download **Jython Standalone** JAR from https://www.jython.org/download
2. In Burp Suite: **Extensions → Extensions Settings → Python Environment** → click **Select file** → choose the Jython JAR

### 2. Install AgenticBurp

1. In Burp Suite: **Extensions → Add**
2. Set **Extension type**: Python
3. Set **Extension file**: `agenticburp.py`
4. Set **Folder for loading modules**: the folder containing all `.py` files (this directory)
5. Click **Next** — the extension loads without errors

---

## Configuration

1. Open the **AgenticBurp** tab in Burp Suite
2. Go to **Settings**
3. Select your **Active Provider** (Anthropic / OpenAI / OpenRouter / Gemini / Ollama / DeepSeek / Kimi / Mistral / Groq / xAI / OpenCode Zen)
   - **Theme**: leave on *Auto* to follow Burp's Look & Feel, or force *Light* / *Dark* if the panels render with the wrong theme (applies immediately).
4. Enter your API key in the provider's panel
5. Select or type your model name
6. Click **Save Settings**

---

## Usage

1. Browse target application (Proxy → HTTP history accumulates traffic)
2. Right-click any request → **AgenticBurp → Analyze with AI**
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
├── agenticburp.py      # Main BurpExtender entry point (load this in Burp)
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
