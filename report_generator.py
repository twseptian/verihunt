# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# report_generator.py -- Parse AI output into structured Burp issues

import re
from burp import IScanIssue


def _to_unicode(s):
    """
    Coerce any string type to Python unicode.
    Handles: Python 2 str (bytes), Java String, already-unicode, None.
    """
    if s is None:
        return u""
    if isinstance(s, unicode):
        return s
    if isinstance(s, str):
        try:
            return s.decode("utf-8")
        except Exception:
            return s.decode("latin-1", "replace")
    # Java String or other object -- let Python 2 coerce it
    try:
        return unicode(s)
    except Exception:
        return u""


# Common non-ASCII unicode chars that Claude often produces.
# Replace with ASCII equivalents so Jython 2.7 string ops stay ASCII-safe.
_UNICODE_REPLACE = [
    (u'\u2014', u'--'),   # em dash
    (u'\u2013', u'-'),    # en dash
    (u'\u2018', u"'"),    # left single quotation mark
    (u'\u2019', u"'"),    # right single quotation mark
    (u'\u201c', u'"'),    # left double quotation mark
    (u'\u201d', u'"'),    # right double quotation mark
    (u'\u2022', u'*'),    # bullet
    (u'\u2026', u'...'),  # horizontal ellipsis
    (u'\u00a0', u' '),    # non-breaking space
    (u'\u00b7', u'-'),    # middle dot
    (u'\u2192', u'->'),   # rightwards arrow
    (u'\u2190', u'<-'),   # leftwards arrow
    (u'\u2605', u'*'),    # black star
    (u'\u2713', u'[OK]'), # check mark
    (u'\u2717', u'[X]'),  # ballot x
]


def _ascii_safe(text):
    """
    Normalize unicode to ASCII-safe Python unicode string.
    Replaces known problematic chars; encodes remaining non-ASCII as '?'.
    Use for PARSING operations (not for HTML display).
    """
    if not text:
        return u""
    text = _to_unicode(text)
    for char, repl in _UNICODE_REPLACE:
        text = text.replace(char, repl)
    # Any remaining non-ASCII -- encode as '?' to stay fully ASCII-safe
    return text.encode("ascii", "replace").decode("ascii")


def _html_entity_safe(text):
    """
    Normalize unicode for HTML display: replace non-ASCII with HTML entities.
    Returns an ASCII-safe HTML string where non-ASCII chars render correctly.
    """
    if not text:
        return u""
    text = _to_unicode(text)
    for char, repl in _UNICODE_REPLACE:
        text = text.replace(char, repl)
    # Encode remaining non-ASCII as numeric HTML entities (e.g. &#8212;)
    return text.encode("ascii", "xmlcharrefreplace").decode("ascii")


def _safe_log_str(msg):
    """
    Return a byte string safe to write to a Java OutputStream.
    Non-ASCII characters are replaced with '?' to avoid ascii codec errors.
    """
    try:
        return _ascii_safe(msg).encode("ascii", "replace")
    except Exception:
        try:
            return str(msg)
        except Exception:
            return b"[unencodable log message]"


# ── Markdown → HTML converter ──────────────────────────────────────────────────

def _md_to_html(text):
    """
    Convert a subset of Markdown to HTML for Burp's Advisory panel.
    Handles code blocks, inline code, bold/italic, headings, lists, HR, paragraphs.

    Safety order:
      1. Extract code blocks/inline code into placeholders (escape < > & inside them)
      2. Escape remaining < > in prose text so stray HTTP/HTML content doesn't break layout
      3. Apply Markdown transformations (add safe HTML tags)
      4. Restore placeholders
    """
    if not text:
        return u""
    text = text.strip()
    if not text:
        return u""
    # Normalize unicode -- replace non-ASCII with HTML entities for safe rendering
    text = _html_entity_safe(text)

    # 1a. Extract fenced code blocks into placeholders
    _blocks = {}
    _b_idx  = [0]

    def replace_code_block(m):
        code = m.group(2).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        ph = u"\x00CB{0}\x00".format(_b_idx[0])
        _b_idx[0] += 1
        _blocks[ph] = u"<pre><code>{0}</code></pre>".format(code)
        return ph

    text = re.sub(r'```(\w*)\n?(.*?)```', replace_code_block, text, flags=re.DOTALL)

    # Handle unclosed code blocks: ``` with no closing pair.
    # Stop at the next ## heading (to avoid swallowing subsequent sections).
    def replace_unclosed(m):
        code = m.group(2).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        ph = u"\x00CB{0}\x00".format(_b_idx[0])
        _b_idx[0] += 1
        _blocks[ph] = u"<pre><code>{0}</code></pre>".format(code.strip())
        return ph
    text = re.sub(r'```(\w*)\n?(.*?)(?=\n##\s|\Z)', replace_unclosed, text, flags=re.DOTALL)

    # 1b. Extract inline code into placeholders
    def replace_inline_code(m):
        code = m.group(1).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        ph = u"\x00IC{0}\x00".format(_b_idx[0])
        _b_idx[0] += 1
        _blocks[ph] = u"<code>{0}</code>".format(code)
        return ph

    text = re.sub(r'`([^`\n]+)`', replace_inline_code, text)

    # 2. Escape < and > in prose text (HTTP headers, HTML snippets, etc.)
    #    Do NOT escape & -- _html_entity_safe already converted non-ASCII to &#NNN;
    #    and re-escaping & would break those entities.
    text = text.replace("<", "&lt;").replace(">", "&gt;")

    # 3. Bold+italic (***text***)
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<b><i>\1</i></b>', text)
    # 4. Bold (**text** or __text__)
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    # 5. Italic (*text* or _text_) — avoid matching list bullets
    text = re.sub(r'(?<!\*)\*(?!\*|\s)(.+?)(?<!\s)\*(?!\*)', r'<i>\1</i>', text)

    # 6. ATX headings → bold text (Burp-compatible; <h2>/<h3> not rendered by Burp)
    text = re.sub(r'^####\s+(.+)$', r'<b>\1</b>',        text, flags=re.MULTILINE)
    text = re.sub(r'^###\s+(.+)$',  r'<b>\1</b>',        text, flags=re.MULTILINE)
    text = re.sub(r'^##\s+(.+)$',   r'<b>\1</b>',        text, flags=re.MULTILINE)
    text = re.sub(r'^#\s+(.+)$',    r'<b><u>\1</u></b>', text, flags=re.MULTILINE)

    # 7. Horizontal rules (--- / ***)
    text = re.sub(r'^\s*[-*]{3,}\s*$', r'<hr>', text, flags=re.MULTILINE)

    # 8a. Markdown tables → HTML <table>
    # Uses HTML attributes (not inline CSS) for Swing HTMLEditorKit compatibility.
    def _convert_tables(txt):
        out_lines = []
        i = 0
        raw = txt.split("\n")
        while i < len(raw):
            line = raw[i]
            if re.match(r'^\s*\|', line) and line.count("|") >= 2:
                table_rows = []
                while i < len(raw) and re.match(r'^\s*\|', raw[i]) and raw[i].count("|") >= 2:
                    table_rows.append(raw[i])
                    i += 1
                html_rows = []
                is_header  = True
                for row in table_rows:
                    # Separator row |---|---| — marks end of header, skip
                    if re.match(r'^\s*\|[\s\-\|:]+\|\s*$', row):
                        is_header = False
                        continue
                    cells = [c.strip() for c in row.strip().strip("|").split("|")]
                    if is_header:
                        tds = "".join("<th bgcolor='#EEEEEE'><b>{0}</b></th>".format(c) for c in cells)
                        html_rows.append("<tr>{0}</tr>".format(tds))
                        is_header = False
                    else:
                        tds = "".join("<td>{0}</td>".format(c) for c in cells)
                        html_rows.append("<tr>{0}</tr>".format(tds))
                if html_rows:
                    out_lines.append(
                        "<table border='1' cellpadding='4' cellspacing='0' width='100%'>"
                        "{0}</table>".format("".join(html_rows))
                    )
                continue
            out_lines.append(line)
            i += 1
        return "\n".join(out_lines)

    text = _convert_tables(text)

    # 8. Lists — render BOTH "- item" and "1. item" as bullets.
    #    LLMs frequently number every item "1." (or restart numbering after a code
    #    block), and Swing's HTMLEditorKit reopens a fresh <ol> after any non-list
    #    line — so ordered lists rendered as "1. 1. 1. ...". Bullets sidestep all of
    #    that and read cleanly for advisory/remediation lists.
    lines = text.split("\n")
    out = []
    in_list = False
    for line in lines:
        m = re.match(r'^(\s*)(?:[-*]|\d+\.)\s+(.+)', line)
        if m:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>{0}</li>".format(m.group(2)))
        else:
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(line)
    if in_list:
        out.append("</ul>")
    text = "\n".join(out)

    # 9. Paragraphs: double newlines → <p>; single newlines → <br>
    #    Code-block placeholders (\x00CBN\x00) must NOT be wrapped in <p> because
    #    after restoration they become <pre> blocks — and <p><pre> is invalid HTML
    #    that Swing's HTMLEditorKit renders incorrectly.
    _CB_PH_RE = re.compile(r'\x00CB\d+\x00')  # fenced blocks only (inline code is \x00IC..\x00)
    # Block-level markup that must be a bare sibling, never wrapped in <p>. Matched
    # per LINE (not just at the block start) so a list/table/hr that follows prose
    # or a heading WITHOUT a blank line between them is still split out correctly —
    # otherwise the whole block fell through to the prose branch and produced invalid
    # <p><ul>..</ul></p> with stray <br>s between the <li> tags.
    _BLOCK_LINE_RE = re.compile(
        r'^\s*</?(?:ul|ol|li|pre|hr|blockquote|table|thead|tbody|tr|td|th)\b')
    paragraphs = re.split(r'\n{2,}', text)
    result = []
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        prose = []   # run of consecutive prose lines, joined with <br> into one <p>
        for line in p.split("\n"):
            ls = line.strip()
            if not ls:
                continue
            ph_full = _CB_PH_RE.match(ls)
            if _BLOCK_LINE_RE.match(ls) or (ph_full and ph_full.group(0) == ls):
                # Block-level markup / whole-line code placeholder → bare sibling.
                if prose:
                    result.append("<p>{0}</p>".format("<br>".join(prose)))
                    prose = []
                result.append(ls)
            elif _CB_PH_RE.search(ls):
                # Inline fenced-block placeholder mid-line: split prose around it.
                if prose:
                    result.append("<p>{0}</p>".format("<br>".join(prose)))
                    prose = []
                parts = _CB_PH_RE.split(ls)
                phs   = _CB_PH_RE.findall(ls)
                for idx, chunk in enumerate(parts):
                    chunk = chunk.strip()
                    if chunk:
                        result.append("<p>{0}</p>".format(chunk))
                    if idx < len(phs):
                        result.append(phs[idx])   # bare placeholder → becomes <pre>
            else:
                prose.append(ls)
        if prose:
            result.append("<p>{0}</p>".format("<br>".join(prose)))
    html = "\n".join(result)

    # 10. Restore code block / inline code placeholders
    for ph, block_html in _blocks.items():
        html = html.replace(ph, block_html)

    return html


# ── Field/section extractors ────────────────────────────────────────────────────

def _extract_section(text, *headers):
    """
    Extract text under a Markdown ## section.
    Accepts multiple header aliases (tries each in order).
    Stops at the next heading of ANY level (# or ##) or end of string.
    Always returns unicode.
    """
    for header in headers:
        pattern = u"##\\s*{0}\\s*\\n(.*?)(?=\\n#|\\Z)".format(re.escape(header))
        m = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if m:
            return _to_unicode(m.group(1)).strip()
    return u""


def _extract_field(text, field):
    """
    Extract **Field:** value from Markdown bold field lines.
    Handles both old format (**Field:** value) and new format (**Field** : value).
    Always returns unicode.
    """
    pattern = u"\\*\\*{0}[\\*:\\s]+\\**([^\\n]+)".format(re.escape(field))
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        val = _to_unicode(m.group(1)).strip().strip(u"*").strip()
        return val
    return u""


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

    # Mutators — used by the self-verification pass to adjust a finding in place.
    def set_name(self, name):             self._name = name
    def set_confidence(self, confidence): self._confidence = confidence
    def append_detail(self, md):          self._detail = (self._detail or u"") + md


# ── Parser ─────────────────────────────────────────────────────────────────────

def _split_h1_sections(text):
    """Return each top-level '# ' section as a string.

    Uses finditer + slicing instead of re.split, because Jython/Python 2.7's
    re.split never splits on a zero-width lookahead — so the old
    re.split('(?=^# )', ...) returned the whole document as ONE section and
    collapsed multi-finding responses into a single finding.
    """
    positions = [m.start() for m in re.finditer(u'(?m)^#\\s', text)]
    if not positions:
        return []
    positions.append(len(text))
    return [text[positions[i]:positions[i + 1]] for i in range(len(positions) - 1)]


class ReportGenerator(object):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self.stdout     = callbacks.getStdout()

    def _log(self, msg):
        if self.stdout:
            try:
                self.stdout.write("[ReportGenerator] {0}\n".format(
                    _safe_log_str(msg)))
            except Exception:
                pass

    def parse_ai_response(self, ai_text, http_service, url, http_messages):
        """
        Parse an AI response that contains multiple # Vulnerability findings.
        Each finding begins with a top-level '# Heading'.
        Returns a list of AgenticBurpIssue objects.
        """
        issues = []
        if not ai_text:
            return issues

        # Step 1: normalize to Python unicode, then replace non-ASCII with
        # ASCII equivalents so ALL subsequent string/regex ops stay ASCII-safe.
        # This is the primary defence against 'ascii' codec errors in Jython 2.7.
        ai_text = _ascii_safe(ai_text)

        if not ai_text.strip():
            return issues

        # Normalise line endings
        ai_text = ai_text.replace(u"\r\n", u"\n").replace(u"\r", u"\n")

        # Robustness: some models ignore the "# heading per finding" instruction
        # and use ## as their top level instead. When there is no single-# heading
        # anywhere but ## headings exist, promote ## -> # so the standard parser
        # can read them. The exact-match subsection filter below prevents promoted
        # "## Evidence" / "## Remediation" blocks from becoming bogus findings.
        if not re.search(u'(?m)^#\\s', ai_text) and re.search(u'(?m)^##\\s', ai_text):
            ai_text = re.sub(u'(?m)^##\\s', u'# ', ai_text)

        # Section names that are PART of a finding, never a finding themselves.
        _SUBSECTIONS = set([
            u"evidence", u"attack scenario", u"proof of concept", u"poc",
            u"root cause", u"remediation", u"issue detail", u"issue background",
            u"impact", u"references", u"description", u"details", u"background",
        ])

        skip_keywords = [
            u"analysis instruction", u"target information",
            u"http request", u"http response", u"note:",
            u"analysis results", u"executive summary",
            u"vulnerability summary", u"overall", u"conclusion",
            u"out-of-band", u"phase ", u"reconnaissance",
            u"penetration test", u"pentest", u"test report",
            u"security assessment", u"security report",
            u"web application", u"assessment report",
            u"findings report", u"audit report",
        ]

        # Split on top-level # headings (single #, not ##/###).
        # NOTE: Jython/Python 2.7 re.split does NOT split on a zero-width
        # lookahead match, so `re.split('(?=^# )', ...)` returns the whole string
        # as one piece — which silently collapsed every multi-finding response
        # into a single finding. Slice manually at each heading instead.
        parts = _split_h1_sections(ai_text.strip())

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Must start with a single-# heading
            name_match = re.match(u'^#\\s+(.+)', part)
            if not name_match:
                continue

            raw_heading = _to_unicode(name_match.group(1)).strip().lower()

            # "No vulnerabilities" is the prescribed clean-assessment conclusion.
            # Turn it into a clearly-named Information finding instead of skipping
            # it (which used to collapse to a generic "AI Analysis Result").
            if (u"no vulnerabilit" in raw_heading or u"no issues" in raw_heading
                    or u"no security issue" in raw_heading or u"no findings" in raw_heading):
                issues.append(AgenticBurpIssue(
                    http_service  = http_service,
                    url           = url,
                    http_messages = http_messages,
                    name          = u"No Vulnerabilities Identified",
                    detail        = part,
                    background    = u"AgenticBurp AI analysis found no vulnerabilities on this request.",
                    remediation   = (u"No action required for this request. Consider authenticated "
                                     u"testing and JavaScript analysis for fuller coverage."),
                    severity      = u"Information",
                    confidence    = u"Firm",
                ))
                continue

            name = _to_unicode(name_match.group(1)).strip()
            # Strip " -- [Affected Parameter/Component]" suffix from name
            if u' -- ' in name:
                name = name.split(u' -- ')[0].strip()
            # Remove Markdown formatting and stray brackets from name
            name = re.sub(u'[\\*_`\\[\\]]', u'', name).strip()

            lower_name = name.lower()
            # A promoted subsection heading is not a finding.
            if lower_name in _SUBSECTIONS:
                continue
            # Skip template/meta headings that the AI may echo back
            if any(kw in lower_name for kw in skip_keywords):
                continue

            # -- Extract structured fields -----------------------------------
            # Support both old format (**Field:** value) and
            # new format (**Field**   : value) from updated prompt template.
            severity_raw   = (_extract_field(part, u"Severity")
                              or _extract_field(part, u"Severity   "))
            confidence_raw = (_extract_field(part, u"Confidence")
                              or _extract_field(part, u"Confidence "))
            cvss_raw       = (_extract_field(part, u"CVSS Score")
                              or _extract_field(part, u"CVSS 3.1"))
            parameter_raw  = (_extract_field(part, u"Parameter/Location")
                              or _extract_field(part, u"Location"))
            cve_raw        = _extract_field(part, u"CVE")
            wstg_raw       = _extract_field(part, u"WSTG")

            # Support both old and new section headers from prompt template.
            # Old: Issue Detail / Issue Background
            # New: Evidence + Attack Scenario / Root Cause
            evidence    = _extract_section(part, u"Evidence")
            scenario    = _extract_section(part, u"Attack Scenario")
            detail      = _extract_section(
                part, u"Issue Detail", u"Detail", u"Finding Detail")
            poc         = _extract_section(
                part, u"Proof of Concept", u"PoC", u"Proof Of Concept")
            root_cause  = _extract_section(part, u"Root Cause")
            background  = _extract_section(
                part, u"Issue Background", u"Background", u"Technical Background")
            remediation = _extract_section(
                part, u"Remediation", u"Fix", u"Mitigation")

            # Merge new-format evidence + scenario into detail
            if evidence and not detail:
                detail = evidence
                if scenario:
                    detail = detail + u"\n\n## Attack Scenario\n" + scenario
            elif scenario and not detail:
                detail = scenario

            # Merge root_cause into background
            if root_cause and not background:
                background = root_cause

            # Fallback: use everything after the first line
            if not detail:
                lines = part.split(u"\n")
                detail = u"\n".join(lines[1:]).strip()

            # Append PoC to detail
            if poc:
                detail = detail + u"\n\n## Proof of Concept\n" + poc

            # Build metadata prefix for Advisory display
            meta_parts = []
            if cvss_raw:
                meta_parts.append(u"**CVSS:** {0}".format(cvss_raw))
            if wstg_raw:
                meta_parts.append(u"**WSTG:** {0}".format(wstg_raw))
            if parameter_raw:
                meta_parts.append(u"**Location:** {0}".format(parameter_raw))
            if cve_raw and cve_raw.upper() != u"N/A":
                meta_parts.append(u"**CVE:** {0}".format(cve_raw))
            if meta_parts:
                detail = u"\n".join(meta_parts) + u"\n\n" + detail

            severity   = _normalize_severity(severity_raw)
            confidence = _normalize_confidence(confidence_raw)

            # Anti-hallucination: this extension analyses PASSIVELY -- it never
            # sends the actual payload -- so a finding the AI could not confirm
            # from the provided request/response is a hypothesis, not a proven
            # bug. The AI signals that with Confidence=Tentative. Prefix such
            # findings with "Potential" so an unverified High doesn't read like a
            # proven one. A finding whose response genuinely contains the evidence
            # (reflected value, error, missing header, disclosed data) should be
            # marked Certain/Firm by the AI and keeps its plain name.
            display_name = name
            if confidence == u"Tentative" and not display_name.lower().startswith(u"potential"):
                display_name = u"Potential " + display_name
            if cve_raw and cve_raw.upper() != u"N/A":
                display_name = u"{0} [{1}]".format(display_name, cve_raw)

            issue = AgenticBurpIssue(
                http_service  = http_service,
                url           = url,
                http_messages = http_messages,
                name          = display_name,
                detail        = detail,
                background    = (background if background
                                 else u"Identified by AgenticBurp AI analysis."),
                remediation   = (remediation if remediation
                                 else u"Review and remediate the identified vulnerability."),
                severity      = severity,
                confidence    = confidence,
                cvss_score    = cvss_raw,
                parameter     = parameter_raw,
                cve           = cve_raw,
            )
            issues.append(issue)
            self._log(u"Parsed finding: [{0}] {1}".format(severity, name))

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
