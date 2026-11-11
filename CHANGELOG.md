# VeriHunt Changelog

---

## [v1.9.0] — 2026-10-27

### Changed
- **JS scan noise reduction (quiet by default)** — clean library fingerprints, bare DOM-sink presence and per-file endpoint lists no longer flood the AI Hunt table: only CVE-matched libraries (High), secrets (High — with documentation placeholders like `YOUR_API_KEY` filtered), exposed source maps and per-host endpoint disclosures become candidates. JS candidates now deduplicate **per host** instead of per file. All of the underlying detail (libraries + exact versions, sinks, endpoints) still reaches the LLM via the full-file JS digest, where Triage (AI) / AI Discover can turn it into real candidates.

### Added
- **Automatic CVE matching for fingerprinted JS libraries** — JS Library candidates are no longer just "check this version manually". Every fingerprinted library+version is now automatically matched against **OSV.dev** (querying the exact version against the live GHSA/NVD-backed database — so a CVE published yesterday is covered; traffic goes to `api.osv.dev`, never to the target) with an **embedded offline ruleset** (jQuery, Bootstrap, Lodash, AngularJS, Axios, Moment.js, Underscore, Handlebars, jQuery UI, Socket.IO) as fallback when offline. Matching libraries upgrade from "JS Library Fingerprint" (Medium) to **"JS Library Outdated (CVE)" (High)** with the CVE IDs in the candidate, and known CVEs are also attached to the "Analyze with AI" JS digest. Results are cached per library+version for the session; the OSV query covers all npm-mapped libraries automatically — no manual rule maintenance.

---

## [v1.8.0] — 2026-10-27

### Added
- **JavaScript analysis (new `JS scan` toggle + full-file LLM digest)** — two gaps closed in one feature:
  - **Passive JS fingerprinting (AI Hunt)** — a new *JS scan* checkbox (next to *Passive (Proxy)*) makes the passive hunter include `.js` files, which were previously skipped as static assets. A deterministic engine fingerprints frontend libraries **with exact versions** (jQuery, Bootstrap, AngularJS, React, Vue, Lodash, GSAP, DataTables and 25+ more — Retire.js-style), and surfaces candidates: **JS Library Fingerprint** (check the exact version against CVEs), **Secret / Credential in JS** (AWS keys, Google/GitHub/Slack/Stripe tokens, JWTs, private-key blocks, hardcoded `apiKey`/`password` assignments — values masked in the UI), **Source Map Disclosed**, **JS DOM Sink (review)** and **JS Endpoint Disclosure**.
  - **Full-file JS digest for "Analyze with AI"** — JS responses were previously truncated to the first 2,000 characters in the prompt, so everything after that was invisible to the model. When the analyzed response is JavaScript, a deterministic digest (libraries + exact versions, masked secrets with line numbers, source-map reference, DOM sinks, API endpoints, external URLs) computed over the **entire file** is attached to the prompt — the LLM can now reason about the whole bundle and map detected versions to known CVEs.

---

## [v1.7.0] — 2026-10-27

### Changed
- **Model defaults refreshed to current generations (research-verified against vendor docs and the live OpenRouter catalog, 464 models)** — Anthropic: **Claude 5.5 trio** (`claude-sonnet-5-5` recommended, `claude-opus-5-5`, `claude-haiku-5-5`); OpenAI: **GPT-6.1 Sol** (recommended) / **GPT-6.1 Terra** / **GPT-6 Luna** / **GPT-6 Astra**, plus the specialized **`gpt-5.6-cyber`** cybersecurity model for authorized vulnerability research; Google Gemini: **`gemini-flash-latest`** (documented always-current alias) with **Gemini 3.8 Flash** / 3.6 Flash; xAI: **grok-4.7**; Kimi: **kimi-k3** in the model list; Z.AI: **glm-5.3** flagship (with 5.3-flash / 5.2 / 5.1 / 4.7) on both the standard and Coding Plan entries; Groq and Mistral aliases confirmed still current (Groq: llama-3.3-70b / llama-3.1-8b / gpt-oss-120b / gpt-oss-20b; Mistral: Large 4 via `mistral-large-latest`). Previous-generation IDs remain selectable; the OpenAI default is now `gpt-6.1-sol`, Anthropic `claude-sonnet-5-5`, Gemini `gemini-flash-latest`, xAI `grok-4.7`, Z.AI `glm-5.3`.

### Added
- **New AI Hunt class — LLM / AI Feature (Prompt Injection)** (13 classes total, High) — flags parameters that feed server-side LLM features (`prompt`, `messages`, `system_prompt`, `instruction`, `agent`, `model`, …) with prompt-injection methodology (instruction override, system-prompt disclosure, tool abuse, data exfiltration via rendered links, auth/rate-limit checks on AI endpoints) and ready-to-try payloads. Reflects the OWASP LLM Top 10 threat model for 2026-era applications.

### Fixed
- **Chatty models no longer leak narration into findings** — some models (observed with GLM) open with "Let me analyze this HTTP transaction carefully..." instead of the mandated finding format, which packaged the whole narration as a single "AI Analysis Result" fallback finding. Leading/trailing conversational lines are now stripped before parsing (substantive content like the technology-stack notes is kept), and the system prompt adds an explicit "NO conversational narration" output rule (rule 8) targeting this model behaviour.
- **Passive (Proxy) and JS scan toggles are now persisted** across Burp restarts (previously they reset to off on every reload).
- **JS digest now triggers on `.js` URLs too** — minified bundles that lack the text heuristics were analyzed without the full-file digest; the URL alone now activates it.
- **AI Hunt class filter includes the JS/Tech hit classes** (JS Library Fingerprint / Outdated (CVE), Secret / Credential in JS, Source Map Disclosed, JS DOM Sink, JS Endpoint Disclosure, Tech Disclosure) — previously these rows were only visible under "All classes".
- **AI Discover severity mapping for the new LLM class rated Medium instead of High** — the class-to-severity table used by AI Discover lacked an entry for prompt injection, so AI-proposed LLM rows surfaced as Medium while the equivalent heuristic candidates were High. `prompt injection` / `llm` now map to High.

---

## [v1.6.0] — 2026-10-06

### Added
- **Z.AI (GLM) provider** — a twelfth provider behind the OpenAI-compatible registry: base `https://api.z.ai/api/paas/v4`, default model `glm-4.6` (also `glm-4.5` / `-air` / `-flash (free)` on the standard plan), settings keys `zai_key` / `zai_model`.
- **Z.AI Coding Plan (GLM) entry** — GLM Coding Plan keys are ONLY valid on the coding endpoint, which the standard Z.AI base rejects; this dedicated entry ships `https://api.z.ai/api/coding/paas/v4` out of the box with its own `zaicoding_key` / `zaicoding_model` settings so a Coding Plan key and a standard key coexist.
- **Custom (OpenAI-compatible) provider + editable Base URL (enterprise gateways)** — every OpenAI-compatible provider now exposes an editable **Base URL** field (saved per provider, used by Test Connection and analysis), and a built-in **Custom** entry lets enterprises route VeriHunt through an internal LLM gateway — LiteLLM, an Azure OpenAI-compatible surface, or a private proxy — with no code changes. An unset Base URL produces a clear error instead of a malformed request.

### Fixed
- **Malformed endpoint URL for versioned API bases (broke Z.AI)** — the chat-completions URL builder appended `/v1/chat/completions` to any base not literally ending in `/v1`, so versioned bases like Z.AI's `https://api.z.ai/api/paas/v4` became `.../v4/v1/chat/completions` (404). It is now version-segment aware: a base ending in `/v<N>` gets only `/chat/completions` appended.
- **Per-provider Base URL override was never wired** — the analysis client supported a saved `{provider}_base` override, but no UI field existed and the setting was never sent, so the override silently never applied. Every OpenAI-compatible provider tab now has a Base URL field that is saved, restored, used by Test Connection, and passed through to analysis.

---

## [v1.5.0] — 2026-09-24

### Changed
- **Rebranded to VeriHunt** — the tool was renamed (AgenticBurp -> Burp Verdict -> **VeriHunt**) so the product name no longer contains the "Burp" trademark; "for Burp Suite" remains as a descriptive phrase. The load entry point is now **`verihunt.py`** (remove the old extension in Burp and add `verihunt.py`). Internal identifiers and, crucially, the stored-settings keys are unchanged, so your saved API keys and cross-scan memory carry over.

### Added
- **AI Discover now returns literal, copy-paste payloads** — the on-demand *AI Discover* previously showed the same prose instruction under "AI-tailored payloads", "Methodology" and "Try these". It now asks the model for a ready-to-send payload per finding (a full XML/JSON body, a header line, or a concrete parameter value) tailored to the endpoint, parsed into its own field (multi-line payloads carried as `\n` and restored, multiple payloads split on ` ;; `). The raw model reply is logged to the extension output and a clear status is shown when a model returns nothing parseable, so an empty result is diagnosable instead of silent.
- **Enterprise Dashboard redesign** — a security-posture header with a weighted **Risk** pill (severity-first: any High => at least HIGH, 3+ High => CRITICAL), a **KPI tile row** (Findings, High/Medium/Low, Confirmed, Potential, AI Hunt, Tokens), side-by-side **Findings-by-Severity** (with counts + percentages) and **AI Hunt Coverage** (triaged %, status chips, top classes) cards, a **Top Affected Hosts** table, and a memory/session footer. Fully theme-aware and rendered with Swing-safe tables.

### Fixed
- **Dashboard rendered as a black block on the Light theme** — the theme switch never re-skinned the Dashboard editor pane, and a refresh never re-applied the themed stylesheet/background. The Dashboard now re-themes on every refresh and follows a live Light/Dark switch.
- **AI Hunt triage & discovery prompts now state an authorized/educational engagement context** — matching the main analysis prompt, so safety-tuned models stop refusing to produce test payloads (a common cause of empty AI Discover results).
- **Dashboard build fixes** — corrected two HTML double-escape defects (the meta line and the footer card title) and made the risk rating severity-first so a single High finding is no longer downgraded to "MEDIUM".

---

## [v1.4.0] — 2026-09-14

### Added
- **AI Hunt — Scan History** — a new toolbar button that runs the parameter heuristics over Burp's *existing* Proxy history retroactively. Passive scanning only sees traffic that arrives *after* it's enabled, so anything browsed earlier (or with Passive off) was invisible; press *Scan History* to surface candidates for targets you already browsed. Runs off the EDT, honours *Scope only*, skips static assets, and flushes rows in batches so the UI stays responsive on large histories.
- **AI Hunt — generic catch-all** — every user-controllable parameter is now surfaced. Params whose name/value matches no class are listed as **"Other Parameter (review)"** (Information severity) so a parameterised request is never silently empty; known non-injectable noise tokens (anti-CSRF, session, captcha, cache-busters, submit) are excluded. The class is selectable in the filter dropdown.

### Changed
- **SQL Injection coverage — login/credential fields** — the SQLi parameter dictionary now includes common login field names (`username`, `uname`, `login`, `email`, `password`, `passwd`, `pwd`, `j_username`, `j_password`, `txtusername`, …) with auth-bypass payloads (`' OR '1'='1'-- -`, `admin'-- -`, `') OR ('1'='1'-- -`, …). Login forms are now flagged as Potential SQLi / auth-bypass candidates.

### Fixed
- **Results no longer show duplicate findings** — re-analysing the same endpoint previously produced `... (2)` copies of host-level issues (CORS / CSP / missing CSRF), and the model naming the same issue slightly differently across runs (e.g. "Credentialed Wildcard" vs "Credentialed Wildcard Origin") slipped past the old within-batch dedup. Findings are now de-duplicated across analyses by severity + normalized URL + parameter + equal-or-subset name; genuinely distinct findings (different URL, parameter, or class) are still kept. Findings dismissed as False Positive are not resurrected on re-scan.
- **Self-verify no longer drops "Potential" attack-surface findings** — the second-pass verifier used to discard any finding it couldn't prove in the single passive response, which silently deleted *Potential SQL Injection / Authentication Bypass* (and LFI / SSRF / IDOR inferred from parameters) on login and other endpoints — the tool sends no payloads, so those can never be proven passively. Verification now treats **absence of proof as "Potential" (kept), not false positive**, and only drops confidently-asserted findings the response *actively contradicts*. The analysis prompt also now mandates a *Potential SQL Injection / Authentication Bypass* (Tentative) finding on login/auth endpoints (username + password), with auth-bypass payloads for both fields.

---

## [v1.3.0] — 2026-09-11

### Added
- **AI Hunt tab** — passive, HUNT-style parameter heuristics across 12 vulnerability classes (SQLi, XSS, LFI/Path Traversal, SSRF, IDOR/BOLA, Command Injection, SSTI, XXE, Open Redirect, Deserialization, Mass-Assignment, Debug). Runs on Proxy traffic when *Passive (Proxy)* is ticked (default off) — instant, free, no payloads; static assets skipped and work is bounded off the proxy thread. Candidates are **POTENTIAL** until validated.
- **Enhanced AI triage (AI Hunt)** — on-demand *Triage Selected / Triage All*: evidence-grounded (feeds reflection, SQL-error, stack-trace, status and content-type signals) and returns a verdict (LIKELY/POSSIBLE/UNLIKELY) + confidence % + cited evidence + tailored payloads + next step, grouped per endpoint to control token spend.
- **Deep Analyze (AI)** — right-click an AI Hunt candidate to run the full Results analysis pipeline (deep AI + self-verify) on that exact request.
- **Request/Response viewer** for AI Hunt candidates (native Burp editors) with right-click *Send to Repeater / Send to Intruder / Copy URL*.
- **Cross-scan memory** — per-host memory of false positives + AI-confirmed findings, persisted across restarts; fed to the model (skip known FPs, stay aware of prior confirmations) and auto-drops still-unproven known FPs. Settings: *Memory* toggle + *Clear Memory*.
- **Report export: HTML + Markdown** (grouped by severity, PoC + remediation, false positives listed separately), plus right-click *Copy as Markdown* per finding.
- **Token usage tracker** — last-call + running session tokens and call count in the Results header (TPM / quota awareness); resets on Clear All.
- **Batch/queue analysis surfaced** — the context menu shows "Analyze N requests with AI" and the queue shows live "Analyzing X/N" progress.
- **About tab documentation** — a Features section documenting all capabilities.

### Changed
- **Model defaults refreshed** to current generations — Anthropic Claude 5 (sonnet-5 / opus-5 / haiku-4-5 / fable-5-1), OpenAI GPT-5.x + GPT-4.1, Google Gemini 2.5 / 3.x, xAI grok-4.x, Kimi kimi-latest, plus current Mistral / Groq / DeepSeek IDs. All model fields are editable and *Test & Detect Models* pulls the live list.
- **AI Hunt and About made theme-aware** (Light / Dark) with ASCII-only labels to avoid Burp label mojibake; About descriptions now wrap to the panel width.

### Fixed
- **Report parser no longer splits one finding into junk findings** — PoC-step headings a model wrote as `#` (e.g. "Decrypt with:", "Using sslstrip:") are folded into the parent finding instead of becoming bogus Information findings. The prompt was also hardened to reserve `#` for finding titles only.
- **AI Hunt robustness** — bounded passive queue (drops when saturated, never blocks the proxy thread), correct UNLIKELY-vs-LIKELY verdict parsing, and a `_hunt_busy` safety net so triage can never get stuck.

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
- **Generic placeholder Background/Remediation** ("Identified by VeriHunt AI analysis." / "Review and remediate the identified vulnerability.") no longer render in the Advisory when the model gave no dedicated section — they sat next to real, detailed remediation and read as unfinished. Real content is unaffected.

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
