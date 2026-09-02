# AgenticBurp Changelog

---

## [v1.2.0] — 2026-08-13

### Added
- **Self-verification pass** (toggle in Settings, on by default) — a second AI pass judges each finding against the actual HTTP response: findings proven by the response are kept and annotated *confirmed*, unproven ones are downgraded to **Potential** (Confidence → Tentative), and refuted ones are dropped. One extra API call per analysis; fails open (never loses findings on an error).
- **Severity filter + sorting** in the Results tab — a severity dropdown (All/High/Medium/Low/Information) narrows the list, which is now always sorted High → Information.
- **"Hide FP" filter** — a checkbox that collapses false-positive findings out of the list (they were only greyed before).
- **False-positive flag in JSON export** — each record now carries `"false_positive": true/false`, and the export includes `total_active` and `total_false_positive` counts, so a marked FP is distinguishable in the exported file.
- **OpenCode Zen provider** — OpenAI-compatible gateway (opencode.ai/zen) exposing 60+ models (claude-sonnet-4-5, gpt-5-codex, kimi-k2, ...). 11 providers total.
- **Active AI model shown in the Results tab** — the header now displays the provider/model driving the analysis (e.g. `Model: Ollama (Cloud) / gpt-oss:20b`).
- **Resizable AI Chat** — drag the divider between the finding detail and the chat box; one-touch expand and sensible minimum heights.

### Changed
- **Smarter finding de-duplication** — near-duplicate findings within one analysis (e.g. "SQL Injection" and "SQL Injection (SQLi)") are collapsed to one; a leading "Potential" keeps a potential finding distinct from a confirmed one.
- **Request/Response tabs renamed to "Analyzed Request" / "Analyzed Response"** — the exchange is read-only evidence (editors are non-editable); the name makes that explicit and stays accurate for both Confirmed and Potential findings.
- **Remediation and advisory lists render as bullets** — numbered lists LLMs emit as `1. 1. 1.` (and that Swing restarts after every code block) now render as one clean bullet list.

### Added
- **Groq-safe Max Tokens default** — selecting Groq as the Active Provider now auto-sets Max Tokens to 1536 to stay under its free-tier tokens-per-minute limit (the usual cause of 429s). Loading saved settings does not override a value you already chose.

### Fixed
- **429 rate-limit handling for OpenAI-compatible providers (esp. Groq)** — the retry now honours the provider's suggested wait ("try again in Xs", capped at 30s) instead of a fixed backoff, and the final message surfaces the provider's real rate/TPM message plus what to do (lower Max Tokens, wait, smaller model, upgrade).
- **Theme handling under Burp light/dark** — detection probed only one Look & Feel colour (`Panel.background`) and fell back to *light*, so some Burp dark themes rendered every panel as a glaring white/washed-out block. Detection now probes several L&F surfaces and infers from the text colour as a fallback. A new **Theme: Auto/Light/Dark** selector in Settings forces the mode, applied live (no reload). Switching now fully re-skins the Advisory and AI Chat panes — previously they kept their old (dark) background when the theme changed — and forcing a mode uses palette-consistent surfaces even when it differs from Burp's actual L&F.
- **OpenCode Zen returned 401 with a valid key** and was mislabelled "Invalid API key" — the real cause (e.g. no credits / no payment method) from the provider's error body is now surfaced.
- **Malformed advisory HTML when a list or table followed prose/heading without a blank line** — the block was wrapped as `<p><ul>…</ul></p>` with stray `<br>` before each `<li>`, giving broken/extra-spaced lists (e.g. under `## Remediation`). Paragraph assembly now walks line by line and emits block-level markup as bare siblings; verified across list-after-prose, list-after-heading, table, fenced-code, and inline-code cases.
- **Redundant double-add of the Results header** — the header panel was added to the container twice, relying on Swing reparenting; removed the no-op add.
- **Stale version in the UI banner** — the header read `v1.0.0` regardless of the real version; it is now driven by `agenticburp.EXTENSION_VERSION` (single source of truth) and shows `v1.2.0`.
- **Generic placeholder Background/Remediation** ("Identified by AgenticBurp AI analysis." / "Review and remediate the identified vulnerability.") no longer render in the Advisory when the model gave no dedicated section — they sat next to real, detailed remediation and read as unfinished. Real content is unaffected.

---

## [v1.1.0] — 2026-08-13

### Added
- **5 new OpenAI-compatible providers**: DeepSeek, Kimi (Moonshot), Mistral, Groq, xAI (Grok) — 10 providers total.
- **Ollama two modes**: Local server (no auth) or Ollama Cloud (ollama.com, API key). Mode selector on the Ollama settings tab.
- **AI Chat** box in the Results tab — interactive follow-up questions grounded on the selected request/response (e.g. "test the file parameter for LFI"), non-blocking, works across all providers.
- **Findings summary strip** — severity tally (High/Med/Low/Info/FP + total) across the session.
- **Burp dark-theme support** — findings list, advisory, and chat adapt to Burp's light/dark Look & Feel instead of hardcoding light colours.

### Changed
- **"Potential" tagging** — passive-analysis findings the AI cannot confirm from the actual response (Confidence: Tentative) are prefixed "Potential", so an unverified High no longer reads as proven.
- Prompt reinforced so the model assigns Confidence honestly (Certain/Firm only with evidence in the data).

### Fixed
- **Multi-finding responses collapsed into one** — Jython 2.7 `re.split` does not split on a zero-width lookahead, so a response with several `# Findings` yielded only one. Now sliced with finditer; N findings → N issues.
- **Clean "No Vulnerabilities" result** rendered as a generic "AI Analysis Result" — now a clearly named informational finding.
- Parser recognises `##`-style headings as a fallback when the model ignores the `#` format.
- Ollama base URL ending in `/v1` no longer produces `/v1/v1/chat/completions`.
- OpenRouter key validation no longer reports bad keys as valid.

---

## [v1.0.0] — 2026-04-17

Initial stable release.

### Features

- **Multi-provider LLM support**: Anthropic, OpenAI, OpenRouter, Gemini, Ollama
- **Native Burp integration**: findings registered as Burp scan issues (severity, detail, background, remediation)
- **Results tab**: filterable findings list with deduplication; click to view full advisory
- **Settings tab**: per-provider API key management with Clear button, model selector, concurrent scan limit, editable prompt template
- **About tab**: model reference tables and provider info
- **Advanced security prompt**: 6-step methodology covering Injection, Auth/AuthZ, Client-side, Server-side, JavaScript, Business Logic, API, CVE detection, OOB (Burp Collaborator)
- **Advanced JavaScript analysis**: secrets in JS bundles, hidden endpoints, DOM sources/sinks, Webpack source maps, prototype pollution, postMessage, CSTI, client-side storage, JSONP, framework-specific sinks
- **Markdown rendering**: bold, italic, headings, tables, code blocks, lists — rendered via Swing HTMLEditorKit
- **Concurrent bulk scanning**: semaphore-controlled parallel analysis (configurable 1–10)
- **Unicode safety**: full Jython 2.7 ASCII/Unicode handling to prevent codec errors on all platforms

---
