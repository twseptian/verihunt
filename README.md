# AgenticBurp v1.0.0

**AI-Powered Security Analysis for Burp Suite**

Analyze HTTP requests and responses directly inside Burp Suite using any major LLM provider (Anthropic, OpenAI, OpenRouter, Gemini, Ollama). Findings are structured, severity-classified, and registered as native Burp scan issues.

---

## Supported Providers

| Provider   | Models                                                              |
|------------|---------------------------------------------------------------------|
| Anthropic  | claude-sonnet-4-6, claude-opus-4-6, claude-haiku-4-5, claude-3.5-* |
| OpenAI     | gpt-4o, gpt-4-turbo, gpt-4, o1, o1-mini, o3-mini                   |
| OpenRouter | Any 400+ models via unified API (free & paid)                       |
| Gemini     | gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash                  |
| Ollama     | Any local model: qwen2.5-coder, llama3.2, deepseek-coder, etc.      |

---

## Requirements

- **Burp Suite** Pro or Community (any recent version)
- **Jython Standalone JAR** 2.7.x — download from https://www.jython.org/download

---

## Installation

### Step 1 — Configure Jython in Burp Suite

1. Open Burp Suite
2. Go to **Extensions → Extensions Settings**
3. Under **Python Environment**, click **Select file**
4. Choose the downloaded `jython-standalone-2.7.x.jar`

### Step 2 — Load AgenticBurp

1. Go to **Extensions → Add**
2. Set **Extension type**: `Python`
3. Set **Extension file**: browse to `agenticburp.py` in this folder
4. Set **Folder for loading modules**: the same folder containing all `.py` files
5. Click **Next**

The extension tab **AgenticBurp** appears in Burp Suite without errors.

> **Note:** All 6 `.py` files must be in the same directory. Do not move `agenticburp.py` without moving the other files.

---

## Configuration

1. Open the **AgenticBurp** tab
2. Go to **Settings**
3. Select your **Active Provider**
4. Enter your **API Key** in the provider's panel (use the **Clear** button to remove a saved key)
5. Select or type your **Model name**
6. Click **Save Settings**

---

## Usage

1. Browse the target application — traffic accumulates in **Proxy → HTTP history**
2. Right-click any request → **Extensions → AgenticBurp → Analyze with AI**
3. Analysis runs in the background (UI stays responsive)
4. Open the **Results** tab to view structured findings
5. Each finding is also registered as a native **Burp scan issue** (Dashboard → Issue activity)

---

## Coverage

Each request is analyzed across:

- **Injection**: SQLi, NoSQLi, OS Command, SSTI, XXE, LDAP/XPath injection
- **Authentication & Authorization**: Bypass, JWT (alg:none, key confusion, kid injection), OAuth/OIDC, IDOR, BOLA, 2FA bypass
- **Client-side**: Reflected/Stored/DOM XSS, CSRF, CORS misconfiguration, Clickjacking
- **Server-side**: SSRF, Path Traversal, File Upload bypass, HTTP Smuggling, Cache Poisoning
- **JavaScript Analysis**: Hardcoded secrets, dangerous sinks, exposed endpoints, source maps, prototype pollution, postMessage, CSTI, client-side storage, JSONP
- **Deserialization**: Java (ysoserial), PHP, Python pickle, .NET ViewState, prototype pollution
- **Sensitive Exposure**: `.env`, `.git`, backup files, config leaks, directory listing
- **Business Logic**: Race conditions, price tampering, mass assignment, flow bypass
- **API Security**: REST, GraphQL, WebSocket, gRPC
- **CVE Detection**: Maps detected technology versions to known CVEs
- **OOB Detection**: Burp Collaborator payloads for SSRF, blind SQLi, XXE, blind XSS

---

## Prompt Customization

The **Settings** tab exposes the editable **User Prompt Template**.

Available placeholders:

| Placeholder              | Description                         |
|--------------------------|-------------------------------------|
| `{URL}`                  | Full target URL                     |
| `{METHOD}`               | HTTP method (GET, POST, etc.)       |
| `{REQUEST}`              | Full raw HTTP request               |
| `{REQUEST_HEADERS}`      | Request headers only                |
| `{REQUEST_BODY}`         | Request body only                   |
| `{RESPONSE}`             | Full raw HTTP response              |
| `{RESPONSE_STATUS_LINE}` | Status line (e.g. `HTTP/1.1 200 OK`)|
| `{RESPONSE_HEADERS}`     | Response headers only               |
| `{RESPONSE_BODY}`        | Response body (truncated if large)  |
| `{IS_TRUNCATED_PROMPT}`  | `True` if content was truncated     |
| `{COLLABORATOR_URL}`     | Burp Collaborator OOB payload URL   |

---

## OpenRouter Free Models

No-cost models suitable for security analysis:

- `meta-llama/llama-3.3-70b-instruct:free`
- `google/gemini-2.0-flash-exp:free`
- `mistralai/mistral-7b-instruct:free`

Get a free key at https://openrouter.ai/keys

---

## Files

```
agenticburp-v1.0/
├── agenticburp.py       # Burp entry point — load this file in Burp Suite
├── api_client.py        # Multi-provider LLM client
├── prompt_handler.py    # Advanced security prompt engineering
├── scanner.py           # Background analysis orchestration & concurrency
├── report_generator.py  # AI response parser → structured Burp issues
└── ui.py                # Swing UI: Settings, Results, About tabs
```

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `NameError: __file__ is not defined` | Make sure **Folder for loading modules** is set in Burp's Add Extension dialog |
| `ImportError: No module named ui` | All 6 `.py` files must be in the same folder as `agenticburp.py` |
| Extension loads but no menu appears | Right-click a request that has a response (not a pending request) |
| API errors (401/403) | Check API key in Settings — use **Clear** then re-enter |
| Ollama connection refused | Verify Ollama is running: `ollama serve` and base URL is correct |
