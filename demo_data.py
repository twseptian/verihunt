# -*- coding: utf-8 -*-
# VeriHunt - demo_data.py
#
# Canned sample findings + AI Hunt candidates for DEMO MODE: lets you present the
# full workflow (Results advisories + AI Hunt with AI verdicts) with NO internet
# and NO API key -- ideal for a conference / Arsenal booth demo. Pure data; no
# Burp or network imports.

DEMO_TARGET = u"https://demo.testfire.net"

# Results-tab findings (rendered as native Burp scan issues / advisories).
# Each dict maps to AgenticBurpIssue(...) fields built by the UI.
DEMO_FINDINGS = [
    {
        "name": u"SQL Injection", "severity": u"High", "confidence": u"Firm",
        "url": DEMO_TARGET + u"/bank/login.aspx",
        "cvss": u"9.1", "parameter": u"uid", "cve": u"",
        "detail": (u"The `uid` login parameter is injectable. Submitting `uid=' OR '1'='1"
                   u"'--` returned an authenticated session, and `uid='` produced a "
                   u"verbose SQL error:\n\n```\nMicrosoft OLE DB Provider for SQL Server "
                   u"error '80040e14'\nUnclosed quotation mark after the character string\n```"
                   u"\n\n## Proof of Concept\n```\nPOST /bank/login.aspx\nuid=' OR 1=1-- -&passw=x\n```"),
        "background": (u"The application concatenates the `uid` parameter directly into a "
                       u"SQL query without parameterisation."),
        "remediation": (u"Use parameterised queries / prepared statements. Never build SQL "
                        u"by string concatenation. Apply least-privilege DB accounts."),
    },
    {
        "name": u"Reflected Cross-Site Scripting (XSS)", "severity": u"Medium",
        "confidence": u"Firm", "url": DEMO_TARGET + u"/search.aspx",
        "cvss": u"6.1", "parameter": u"query", "cve": u"",
        "detail": (u"The `query` parameter is reflected into the HTML response without "
                   u"encoding. Payload `<script>alert(document.domain)</script>` is echoed "
                   u"verbatim inside the results heading.\n\n## Proof of Concept\n"
                   u"`GET /search.aspx?query=<script>alert(document.domain)</script>`"),
        "background": u"User input is written into HTML without contextual output encoding.",
        "remediation": u"HTML-encode all user input on output; add a strict Content-Security-Policy.",
    },
    {
        "name": u"Insecure Direct Object Reference (IDOR)", "severity": u"High",
        "confidence": u"Tentative", "url": DEMO_TARGET + u"/bank/account.aspx",
        "cvss": u"7.7", "parameter": u"acctId", "cve": u"",
        "detail": (u"`acctId` is a sequential account identifier. Changing `acctId=800001` to "
                   u"`800002` while authenticated as another user appears to return a different "
                   u"account's statement -- unverified (no payload sent), test manually."),
        "background": u"Object references are not scoped to the authenticated user's authorisation.",
        "remediation": u"Enforce per-user authorisation server-side on every object reference.",
    },
    {
        "name": u"Missing Security Headers", "severity": u"Low", "confidence": u"Certain",
        "url": DEMO_TARGET + u"/", "cvss": u"3.1", "parameter": u"", "cve": u"",
        "detail": (u"The response is missing Content-Security-Policy, Strict-Transport-Security, "
                   u"X-Content-Type-Options and X-Frame-Options headers."),
        "background": u"Defence-in-depth headers reduce the impact of XSS, clickjacking and MITM.",
        "remediation": u"Add CSP, HSTS, X-Content-Type-Options: nosniff and X-Frame-Options: DENY.",
    },
]

# AI Hunt candidates (already carry AI verdicts, as if triaged) for the AI Hunt tab.
DEMO_HUNT = [
    {
        "cls": u"SQL Injection", "sev": u"High", "param": u"uid", "where": u"body",
        "value": u"admin", "value_full": u"admin",
        "method": u"POST", "path": u"/bank/login.aspx",
        "url": DEMO_TARGET + u"/bank/login.aspx",
        "endpoint": u"POST demo.testfire.net/bank/login.aspx",
        "why": u"Login parameter feeds a SQL query; classic injectable field.",
        "methodology": u"Send ' and time-based payloads; confirm with sqlmap.",
        "payloads": [u"'", u"1 OR 1=1-- -", u"1 AND SLEEP(5)-- -"],
        "conf": u"heuristic",
        "ai_verdict": u"LIKELY", "ai_confidence": u"88",
        "ai_reason": u"SQL error reflected for uid=' in the response.",
        "ai_payloads": [u"uid=' OR 1=1-- -"], "ai_next": u"Confirm with sqlmap --batch",
        "dedup_key": u"POST demo.testfire.net/bank/login.aspx uid sql injection",
    },
    {
        "cls": u"Cross-Site Scripting (XSS)", "sev": u"Medium", "param": u"query",
        "where": u"url", "value": u"test", "value_full": u"test",
        "method": u"GET", "path": u"/search.aspx",
        "url": DEMO_TARGET + u"/search.aspx",
        "endpoint": u"GET demo.testfire.net/search.aspx",
        "why": u"Value reflected into HTML; likely XSS sink.",
        "methodology": u"Inject a marker, find it unencoded, break out of context.",
        "payloads": [u"<script>alert(1)</script>", u"\"><svg onload=alert(1)>"],
        "conf": u"heuristic",
        "ai_verdict": u"LIKELY", "ai_confidence": u"82",
        "ai_reason": u"query value echoed unencoded in results heading.",
        "ai_payloads": [u"<script>alert(document.domain)</script>"], "ai_next": u"",
        "dedup_key": u"GET demo.testfire.net/search.aspx query cross-site scripting",
    },
    {
        "cls": u"IDOR / Broken Object-Level Auth", "sev": u"High", "param": u"acctId",
        "where": u"url", "value": u"800001", "value_full": u"800001",
        "method": u"GET", "path": u"/bank/account.aspx",
        "url": DEMO_TARGET + u"/bank/account.aspx?acctId=800001",
        "endpoint": u"GET demo.testfire.net/bank/account.aspx",
        "why": u"Sequential object id; check cross-user access.",
        "methodology": u"Swap acctId to another user's id while authenticated as a different user.",
        "payloads": [u"800002", u"800000"],
        "conf": u"heuristic",
        "ai_verdict": u"POSSIBLE", "ai_confidence": u"55",
        "ai_reason": u"Numeric sequential id, but auth scoping not visible in one response.",
        "ai_payloads": [u"acctId=800002"], "ai_next": u"Replay as user B; compare statement",
        "dedup_key": u"GET demo.testfire.net/bank/account.aspx acctid idor / broken object-level auth",
    },
    {
        "cls": u"AI: Broken Access Control", "sev": u"High", "param": u"/admin/",
        "where": u"ai", "value": u"", "value_full": u"",
        "method": u"GET", "path": u"/admin/",
        "url": DEMO_TARGET + u"/admin/",
        "endpoint": u"GET demo.testfire.net/admin/",
        "why": u"Admin path linked in HTML comment; reachable without admin role?",
        "methodology": u"Request /admin/ as a low-privilege / anonymous user; compare responses.",
        "payloads": [u"GET /admin/ (as anon)"],
        "conf": u"ai", "source": u"ai",
        "ai_verdict": u"POSSIBLE", "ai_confidence": u"60",
        "ai_reason": u"Admin link disclosed in an HTML comment in the response.",
        "ai_payloads": [u"GET /admin/ with no session"], "ai_next": u"Diff anon vs admin response",
        "dedup_key": u"ai GET demo.testfire.net/admin/ /admin/ ai: broken access control",
    },
]
