# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# report_generator.py — Parse AI output into structured Burp issues

import re
from burp import IScanIssue


# ── Markdown → HTML converter ──────────────────────────────────────────────────

def _md_to_html(text):
    """
    Convert a subset of Markdown to HTML for Burp's Advisory panel.
    Handles code blocks, inline code, bold/italic, headings, lists, HR, paragraphs.
    """
    if not text:
        return ""

    # 1. Fenced code blocks (```lang\n...\n```)
    def replace_code_block(m):
        code = m.group(2).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return "<pre><code>{0}</code></pre>".format(code)
    text = re.sub(r'```(\w*)\n?(.*?)```', replace_code_block, text, flags=re.DOTALL)

    # 2. Inline code (`...`)
    def replace_inline_code(m):
        code = m.group(1).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return "<code>{0}</code>".format(code)
    text = re.sub(r'`([^`\n]+)`', replace_inline_code, text)

    # 3. Bold+italic (***text***)
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)
    # 4. Bold (**text** or __text__)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    # 5. Italic (*text* or _text_) — avoid matching list bullets
    text = re.sub(r'(?<!\*)\*(?!\*|\s)(.+?)(?<!\s)\*(?!\*)', r'<i>\1</i>', text)

    # 6. ATX headings (## / ### / ####)
    text = re.sub(r'^####\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^###\s+(.+)$',  r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^##\s+(.+)$',   r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^#\s+(.+)$',    r'<h2>\1</h2>', text, flags=re.MULTILINE)

    # 7. Horizontal rules (--- / ***)
    text = re.sub(r'^\s*[-*]{3,}\s*$', r'<hr>', text, flags=re.MULTILINE)

    # 8. Unordered lists (lines starting with - or *)
    lines = text.split("\n")
    out = []
    in_ul = False
    in_ol = False
    for line in lines:
        ul_m = re.match(r'^(\s*)[-*]\s+(.+)', line)
        ol_m = re.match(r'^(\s*)\d+\.\s+(.+)', line)
        if ul_m:
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            if in_ol:
                out.append("</ol>")
                in_ol = False
            out.append("<li>{0}</li>".format(ul_m.group(2)))
        elif ol_m:
            if not in_ol:
                out.append("<ol>")
                in_ol = True
            if in_ul:
                out.append("</ul>")
                in_ul = False
            out.append("<li>{0}</li>".format(ol_m.group(2)))
        else:
            if in_ul:
                out.append("</ul>")
                in_ul = False
            if in_ol:
                out.append("</ol>")
                in_ol = False
            out.append(line)
    if in_ul:
        out.append("</ul>")
    if in_ol:
        out.append("</ol>")
    text = "\n".join(out)

    # 9. Paragraphs: double newlines → <p> breaks; single newlines → <br>
    paragraphs = re.split(r'\n{2,}', text)
    result = []
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        # Don't wrap block-level tags in <p>
        if re.match(r'^<(h[2-4]|ul|ol|li|pre|hr|blockquote)', p):
            result.append(p)
        else:
            p = p.replace("\n", "<br>")
            result.append("<p>{0}</p>".format(p))
    return "\n".join(result)


# ── Field/section extractors ────────────────────────────────────────────────────

def _extract_section(text, *headers):
    """
    Extract text under a Markdown ## section.
    Accepts multiple header aliases (tries each in order).
    Stops at the next heading of ANY level (# or ##) or end of string.
    """
    for header in headers:
        # Stop at \n# (catches both # and ## next headings) or end of string
        pattern = r"##\s*{0}\s*\n(.*?)(?=\n#|\Z)".format(re.escape(header))
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _extract_field(text, field):
    """Extract **Field:** value from Markdown bold field lines."""
    pattern = r"\*\*{0}[\*:]+\s*\**([^\n]+)".format(re.escape(field))
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        return m.group(1).strip().strip("*").strip()
    return ""


def _normalize_severity(raw):
    raw = raw.lower().strip()
    if "critical" in raw:   return "High"   # Burp only supports High/Medium/Low/Information
    if "high" in raw:       return "High"
    if "medium" in raw:     return "Medium"
    if "low" in raw:        return "Low"
    if "info" in raw:       return "Information"
    return "Information"


def _normalize_confidence(raw):
    raw = raw.lower().strip()
    if "certain" in raw:    return "Certain"
    if "firm" in raw:       return "Firm"
    if "tentative" in raw:  return "Tentative"
    return "Tentative"


# ── IScanIssue implementation ──────────────────────────────────────────────────

class AgenticBurpIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages,
                 name, detail, background, remediation, severity, confidence,
                 cvss_score="", parameter="", cve=""):
        self._http_service  = http_service
        self._url           = url
        self._http_messages = http_messages
        self._name          = name
        self._detail        = detail
        self._background    = background
        self._remediation   = remediation
        self._severity      = severity
        self._confidence    = confidence
        self._cvss_score    = cvss_score
        self._parameter     = parameter
        self._cve           = cve

    def getUrl(self):                    return self._url
    def getIssueName(self):              return self._name
    def getIssueType(self):              return 0x08000000
    def getSeverity(self):               return self._severity
    def getConfidence(self):             return self._confidence
    def getIssueBackground(self):        return _md_to_html(self._background) if self._background else ""
    def getRemediationBackground(self):  return None
    def getIssueDetail(self):            return _md_to_html(self._detail) if self._detail else ""
    def getRemediationDetail(self):      return _md_to_html(self._remediation) if self._remediation else ""
    def getHttpMessages(self):           return self._http_messages
    def getHttpService(self):            return self._http_service
    def getCvssScore(self):              return self._cvss_score
    def getParameter(self):              return self._parameter
    def getCve(self):                    return self._cve or ""
    # Raw Markdown accessors — used by ui.py to build combined HTML panel
    def getDetailMarkdown(self):         return self._detail or ""
    def getBackgroundMarkdown(self):     return self._background or ""
    def getRemediationMarkdown(self):    return self._remediation or ""


# ── Parser ─────────────────────────────────────────────────────────────────────

class ReportGenerator(object):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self.stdout     = callbacks.getStdout()

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[ReportGenerator] {0}\n".format(msg))

    def parse_ai_response(self, ai_text, http_service, url, http_messages):
        """
        Parse an AI response that contains multiple # Vulnerability findings.
        Each finding begins with a top-level '# Heading'.
        Returns a list of AgenticBurpIssue objects.
        """
        issues = []
        if not ai_text or not ai_text.strip():
            return issues

        # Normalise line endings
        ai_text = ai_text.replace("\r\n", "\n").replace("\r", "\n")

        # Split on top-level # headings (single #, not ##/###)
        # Use a lookahead so the delimiter is kept with its chunk
        parts = re.split(r'(?m)(?=^# )', ai_text.strip())

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Must start with a single-# heading
            name_match = re.match(r'^#\s+(.+)', part)
            if not name_match:
                continue

            name = name_match.group(1).strip()
            # Remove trailing Markdown formatting from name
            name = re.sub(r'[\*_`]', '', name).strip()

            # Skip template/meta headings that the AI may echo back
            lower_name = name.lower()
            skip_keywords = [
                "analysis instruction", "target information",
                "http request", "http response", "note:",
                "analysis results", "executive summary",
                "vulnerability summary", "overall", "conclusion",
            ]
            if any(kw in lower_name for kw in skip_keywords):
                continue

            # ── Extract structured fields ──────────────────────────────────────
            severity_raw   = _extract_field(part, "Severity")
            confidence_raw = _extract_field(part, "Confidence")
            cvss_raw       = _extract_field(part, "CVSS Score")
            parameter_raw  = _extract_field(part, "Parameter/Location")
            cve_raw        = _extract_field(part, "CVE")

            detail      = _extract_section(part, "Issue Detail", "Detail", "Finding Detail")
            poc         = _extract_section(part, "Proof of Concept", "PoC", "Proof Of Concept")
            background  = _extract_section(part, "Issue Background", "Background", "Technical Background")
            remediation = _extract_section(part, "Remediation", "Fix", "Mitigation")

            # Fallback detail: everything after the first line
            if not detail:
                lines = part.split("\n")
                detail = "\n".join(lines[1:]).strip()

            # Append PoC to detail so it shows in Advisory with formatting
            if poc:
                detail = detail + "\n\n## Proof of Concept\n" + poc

            # Build CVSS/parameter/CVE metadata prefix for Advisory
            meta_parts = []
            if cvss_raw:
                meta_parts.append("**CVSS Score:** {0}".format(cvss_raw))
            if parameter_raw:
                meta_parts.append("**Parameter/Location:** {0}".format(parameter_raw))
            if cve_raw and cve_raw.upper() != "N/A":
                meta_parts.append("**CVE:** {0}".format(cve_raw))
            if meta_parts:
                detail = "\n".join(meta_parts) + "\n\n" + detail

            severity   = _normalize_severity(severity_raw)
            confidence = _normalize_confidence(confidence_raw)

            # Append CVE ID to issue name when present (shows in Burp Issues list)
            display_name = name
            if cve_raw and cve_raw.upper() != "N/A":
                display_name = "{0} [{1}]".format(name, cve_raw)

            # Store as plain Markdown — ui.py converts to HTML for display;
            # Burp's native Issues panel shows readable plain text.
            issue = AgenticBurpIssue(
                http_service  = http_service,
                url           = url,
                http_messages = http_messages,
                name          = display_name,
                detail        = detail,
                background    = background if background else "Identified by AgenticBurp AI analysis.",
                remediation   = remediation if remediation else "Review and remediate the identified vulnerability.",
                severity      = severity,
                confidence    = confidence,
                cvss_score    = cvss_raw,
                parameter     = parameter_raw,
                cve           = cve_raw,
            )
            issues.append(issue)
            self._log("Parsed finding: [{0}] {1}".format(severity, name))

        # If parsing found nothing, wrap entire response as a single info issue
        if not issues:
            self._log("No structured findings parsed — wrapping as single issue.")
            issue = AgenticBurpIssue(
                http_service  = http_service,
                url           = url,
                http_messages = http_messages,
                name          = "AI Analysis Result",
                detail        = ai_text,
                background    = "Identified by AgenticBurp AI analysis.",
                remediation   = "Review the AI analysis and perform manual verification.",
                severity      = "Information",
                confidence    = "Tentative",
            )
            issues.append(issue)

        return issues
