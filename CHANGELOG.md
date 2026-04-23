# AgenticBurp Changelog

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

### Cross-platform Compatibility

- Works on **Windows**, **macOS**, and **Linux** without hardcoded paths
- Robust `__file__` detection via 4-method fallback chain (`inspect.getframe` → `__file__` → `sys.path` scan → `cwd`)
- Compatible with Jython 2.7.2, 2.7.3, and 2.7.4

### Bug Fixes

- Fixed `NameError: __file__ is not defined` on Burp Suite's Jython environment
- Fixed findings list showing report title instead of vulnerability name
- Fixed filter returning 0 results after URL was removed from display key
- Fixed `<h3>` tags rendered as literal text in Burp's native issue viewer — converted to `<b>` tags
- Fixed raw `<` `>` in AI responses (HTTP headers) breaking HTML layout
- Fixed `<p><pre>` invalid nesting in rendered code blocks
- Fixed `## Issue Background` and `## Remediation` sections being swallowed by unclosed code block regex
- Fixed Markdown table rendering (Swing-compatible `border='1'` attributes, no inline CSS)
- Fixed blank space in advisory panel when sections are empty
