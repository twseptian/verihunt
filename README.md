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
| Ollama      | Any local model: qwen2.5-coder, llama3.2, deepseek-coder, etc.      |

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
3. Select your **Active Provider** (Anthropic / OpenAI / OpenRouter / Ollama)
4. Enter your API key in the provider's panel
5. Select or type your model name
6. Click **Save Settings**

---

## Usage

1. Browse target application (Proxy → HTTP history accumulates traffic)
2. Right-click any request → **AgenticBurp → Analyze with AI**
3. The analysis runs in the background (UI stays responsive)
4. Switch to the **Results** tab to view findings

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
