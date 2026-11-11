# -*- coding: utf-8 -*-
# VeriHunt - js_engine.py
#
# Deterministic JavaScript analysis: fingerprints frontend libraries + versions
# (Retire.js-style), detects hardcoded secrets, exposed source maps, DOM sinks
# and API endpoints, and produces a compact digest so the LLM can reason about
# the WHOLE file even when the raw response is far larger than the prompt
# budget. Pure logic - no Burp UI, no network.
#
# Written for Jython 2.7 (Burp Suite Python extension environment).

import re

# ── detection ─────────────────────────────────────────────────────────────────

_JS_EXT_RE = re.compile(r"\.(js|mjs|cjs)(\.map)?($|\?|#)", re.IGNORECASE)
_JS_HINT_RE = re.compile(
    r"(?:function\s*\(|=>|var\s+\w+\s*=|window\.|document\.|node_modules|"
    r"sourceMappingURL|undefined\s*&&?)", re.I)


def is_js_url(url_str):
    """True when the URL path points at a JavaScript file (incl. .map)."""
    if not url_str:
        return False
    return bool(_JS_EXT_RE.search(url_str.split("#", 1)[0]))


def is_js_text(text):
    """Heuristic: does this response body look like JavaScript?"""
    if not text:
        return False
    head = text[:2000]
    if "text/html" in head[:400].lower():
        return False
    hits = len(_JS_HINT_RE.findall(head))
    return hits >= 3


# ── library fingerprints (name, regex with version in group 1) ────────────────

def _lib(name, pattern):
    return (name, re.compile(pattern, re.I))

_LIBS = [
    _lib("jQuery",          r"jquery[^0-9a-z]{0,12}v?(\d+\.\d+(?:\.\d+)?)(?!\d)"),
    _lib("jQuery Migrate",  r"jquery[ -]migrate[^0-9a-z]{0,12}v?(\d+\.\d+(?:\.\d+)?)"),
    _lib("jQuery UI",       r"jquery[ -]ui[^0-9a-z]{0,12}v?(\d+\.\d+(?:\.\d+)?)"),
    _lib("AngularJS",       r"angular[^0-9]{0,40}?(\d+\.\d+(?:\.\d+)?)"),
    _lib("Angular",         r"@angular/core[^0-9]{0,20}(\d{1,2}\.\d+\.\d+)"),
    _lib("React",           r"react[^0-9a-z]{0,12}v?(\d{1,2}\.\d+\.\d+)"),
    _lib("Vue.js",          r"vue(?:\.js)?[^0-9a-z]{0,12}v?(\d{1,2}\.\d+\.\d+)"),
    _lib("Bootstrap",       r"bootstrap[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Lodash",          r"lodash[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Underscore",      r"underscore[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Moment.js",       r"momentjs?[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Axios",           r"axios[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("D3",              r"d3(?:\.js)?[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Three.js",        r"three\.js[^0-9a-z]{0,12}r?(\d{2,3})"),
    _lib("Chart.js",        r"chart\.js[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("DataTables",      r"datatables[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Select2",         r"select2[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Swiper",          r"swiper[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Fancybox",        r"fancybox[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("SweetAlert",      r"sweetalert[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Toastr",          r"toastr[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Backbone",        r"backbone[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Ember",           r"ember[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Handlebars",      r"handlebars[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Mustache",        r"mustache[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("GSAP",            r"(?:gsap|tweenmax)[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Video.js",        r"video\.js[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Leaflet",         r"leaflet[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Socket.IO",       r"socket\.io[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
    _lib("Polymer",         r"polymer[^0-9a-z]{0,12}v?(\d+\.\d+\.\d+)"),
]

# ── secret patterns (kind, regex) ─────────────────────────────────────────────

_SECRETS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key",    re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("GitHub token",      re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Slack token",       re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Stripe live key",   re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    ("JWT",               re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{5,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("Firebase URL",      re.compile(r"[a-z0-9\-]+\.firebaseio\.com")),
    ("Hardcoded credential",
     re.compile(r"(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|"
                r"auth[_-]?token|passwd|password)\s*[:=]\s*[\"']"
                r"[A-Za-z0-9_\-./+=]{8,}[\"']", re.I)),
]

# ── DOM sinks ─────────────────────────────────────────────────────────────────

_SINKS = [
    ("innerHTML assignment",   re.compile(r"\.innerHTML\s*=")),
    ("document.write",         re.compile(r"document\.write\s*\(")),
    ("eval()",                 re.compile(r"(?<![\w.])eval\s*\(")),
    ("new Function()",         re.compile(r"new\s+Function\s*\(")),
    ("setTimeout with string", re.compile(r"setTimeout\s*\(\s*['\"]")),
    ("location.href assign",   re.compile(r"(?:document\.)?location\.href\s*=")),
    ("postMessage",            re.compile(r"\.postMessage\s*\(")),
    ("insertAdjacentHTML",     re.compile(r"insertAdjacentHTML\s*\(")),
    ("document.currentScript", re.compile(r"document\.currentScript")),
]

# ── endpoint extraction ───────────────────────────────────────────────────────

_EP_RE = re.compile(r"[\"'`](/[A-Za-z0-9_\-./]{2,80})[\"'`]")
_EP_FILTER = re.compile(r"/(?:api|v\d|graphql|rest|admin|internal|auth|oauth|"
                        r"service|gateway|json|ajax)(?:/|$)", re.I)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./]{0,80})?")

_SOURCEMAP_RE = re.compile(r"//#\s*sourceMappingURL=(\S+)")

_MASK_LEN = 6

# obvious non-secrets: documentation samples and placeholder values
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]|[_-]your|example|sample[_-]key|placeholder|changeme|"
    r"change[_-]me|dummy|xxxxxx|insert[_-]|[<{]\$\{|\$\{|%s\b|TODO\b)")


def _mask(value):
    v = str(value)
    return v[:_MASK_LEN] + "..." if len(v) > _MASK_LEN else v + "..."


def _line_of(text, pos):
    try:
        return text.count("\n", 0, pos) + 1
    except Exception:
        return 0


def digest_js(body):
    """Run all deterministic checks over one JS body.

    Returns a dict: {size, lines, libraries, secrets, sourcemap, sinks,
    endpoints, external_urls}. `libraries` entries are (name, version);
    `secrets` entries are (kind, masked_value, line); `sinks` entries are
    (kind, line); `endpoints` is a sorted unique list of paths.
    """
    out = {"size": len(body or ""), "lines": (body or "").count("\n") + 1,
           "libraries": [], "secrets": [], "sourcemap": None,
           "sinks": [], "endpoints": [], "external_urls": []}
    if not body:
        return out
    body = body[:2000000]   # bound work on huge bundles

    # libraries (dedup by name, keep first/highest match)
    seen = {}
    for name, rx in _LIBS:
        m = rx.search(body)
        if m:
            ver = m.group(1)
            if name not in seen:
                seen[name] = ver
    out["libraries"] = sorted(seen.items())

    # secrets (dedup by kind+masked value; skip obvious placeholders)
    seen_sec = set()
    for kind, rx in _SECRETS:
        for m in rx.finditer(body):
            raw = m.group(0)
            if _PLACEHOLDER_RE.search(raw):
                continue
            val = _mask(raw)
            key = (kind, val)
            if key in seen_sec:
                continue
            seen_sec.add(key)
            out["secrets"].append((kind, val, _line_of(body, m.start())))
            if len(out["secrets"]) >= 40:
                break
        if len(out["secrets"]) >= 40:
            break

    # source map
    ms = _SOURCEMAP_RE.search(body)
    if ms:
        out["sourcemap"] = ms.group(1)[:200]

    # sinks
    for kind, rx in _SINKS:
        m = rx.search(body)
        if m:
            out["sinks"].append((kind, _line_of(body, m.start())))

    # endpoints + external URLs
    eps = set()
    for m in _EP_RE.finditer(body):
        ep = m.group(1)
        if _EP_FILTER.search(ep):
            eps.add(ep)
    out["endpoints"] = sorted(eps)[:40]
    urls = set()
    for m in _URL_RE.finditer(body):
        u = m.group(0)
        if "w3.org" in u or "schema" in u.lower():
            continue
        urls.add(u[:120])
    out["external_urls"] = sorted(urls)[:20]
    return out


def build_js_context(digest, max_chars=3500, cve_map=None):
    """Render a digest as a compact evidence block for the LLM prompt.
    `cve_map` (optional) adds a Known CVEs section from automatic matching."""
    has_cve = bool(cve_map)
    if not digest or not (digest.get("libraries") or digest.get("secrets") or
                          digest.get("sinks") or digest.get("endpoints") or
                          digest.get("sourcemap") or has_cve):
        return u""
    L = []
    L.append(u"JS file: {0} bytes, {1} lines".format(
        digest.get("size", 0), digest.get("lines", 0)))
    if digest.get("libraries"):
        L.append(u"Libraries detected (name version): " + u"; ".join(
            u"{0} v{1}".format(n, v) for n, v in digest["libraries"]))
    if digest.get("sourcemap"):
        L.append(u"Source map reference: " + digest["sourcemap"])
    if digest.get("secrets"):
        L.append(u"Possible secrets (kind, masked value, line): " + u"; ".join(
            u"{0} [{1}] line {2}".format(k, v, ln)
            for k, v, ln in digest["secrets"][:20]))
    if digest.get("sinks"):
        L.append(u"DOM sinks (kind, first occurrence line): " + u"; ".join(
            u"{0} (line {1})".format(k, ln) for k, ln in digest["sinks"]))
    if digest.get("endpoints"):
        L.append(u"API-ish endpoints referenced: " + u", ".join(
            digest["endpoints"][:30]))
    if digest.get("external_urls"):
        L.append(u"External URLs: " + u", ".join(digest["external_urls"][:10]))
    if has_cve:
        L.append(u"Known CVEs for the detected versions (automatically "
                 u"matched): " + u" | ".join(cve_summary_lines(cve_map)))
    L.append(u"For libraries: compare each version against known CVEs / the "
             u"latest release (retire.js style) and state whether it is "
             u"outdated or has known vulnerabilities; cite the version you "
             u"checked against. For secrets: confirm whether each match looks "
             u"like a real credential or a false positive. Only report what "
             u"the evidence above supports.")
    txt = u"\n".join(L)
    return txt[:max_chars]


# ── CVE knowledge (offline ruleset + OSV.dev online lookup) ───────────────────
# Embedded ruleset (curated 2026-10) covers the most famous frontend-library
# CVEs so passive detection works with no network. The OSV.dev lookup provides
# fresher, exact-version results when the user opts in (traffic goes to
# api.osv.dev, never to the target).

_CVE_RULES = {
    "jquery": [
        {"below": "3.5.0", "cves": "CVE-2020-11022, CVE-2020-11023 (XSS via HTML)",
         "note": "jQuery < 3.5.0"},
        {"below": "3.4.0", "cves": "CVE-2019-11358 (prototype pollution via jQuery.extend)",
         "note": "jQuery < 3.4.0"},
    ],
    "jquery ui": [
        {"below": "1.13.2", "cves": "CVE-2022-31160 (XSS)", "note": "jQuery UI < 1.13.2"},
        {"below": "1.12.1", "cves": "CVE-2016-7103 (XSS)", "note": "jQuery UI < 1.12.1"},
    ],
    "bootstrap": [
        {"below": "4.3.1", "majors": [4], "cves": "CVE-2019-8331 (XSS via tooltip/popover data-template)",
         "note": "Bootstrap 4.x < 4.3.1"},
        {"below": "3.4.1", "majors": [3], "cves": "CVE-2019-8331 (XSS via tooltip/popover data-template)",
         "note": "Bootstrap 3.x < 3.4.1"},
    ],
    "lodash": [
        {"below": "4.17.21", "cves": "CVE-2021-23337 (command injection via template), CVE-2020-8203 (prototype pollution)",
         "note": "Lodash < 4.17.21"},
        {"below": "4.17.11", "cves": "CVE-2019-10744 (prototype pollution)",
         "note": "Lodash < 4.17.11"},
    ],
    "angularjs": [
        {"below": "1.8.3", "cves": "AngularJS 1.x is EOL (Jan 2022); multiple XSS/ReDoS CVEs (incl. CVE-2022-25844, CVE-2023-26116, CVE-2023-26117, CVE-2023-26118)",
         "note": "AngularJS 1.x < 1.8.3"},
    ],
    "axios": [
        {"below": "1.6.0", "cves": "CVE-2023-45857 (XSRF token leak to third-party)",
         "note": "Axios < 1.6.0"},
        {"below": "0.21.4", "cves": "CVE-2021-3749 (ReDoS)", "note": "Axios < 0.21.4"},
        {"below": "0.21.1", "cves": "CVE-2020-28168 (SSRF)", "note": "Axios < 0.21.1"},
    ],
    "moment.js": [
        {"below": "2.29.4", "cves": "CVE-2022-31129 (ReDoS), CVE-2022-24785 (path traversal)",
         "note": "Moment.js < 2.29.4"},
    ],
    "underscore": [
        {"below": "1.13.0", "cves": "CVE-2021-23358 (arbitrary code execution via template)",
         "note": "Underscore < 1.13.0"},
    ],
    "handlebars": [
        {"below": "4.7.7", "cves": "CVE-2021-23369 (RCE via crafted property)",
         "note": "Handlebars < 4.7.7"},
    ],
    "socket.io": [
        {"below": "2.4.0", "cves": "CVE-2020-36049 (insecure default allows XSS)",
         "note": "Socket.IO < 2.4.0"},
    ],
}

# npm package names for OSV.dev queries (lib name lowercase -> npm name)
_NPM_NAMES = {
    "jquery": "jquery", "jquery migrate": "jquery-migrate", "jquery ui": "jquery-ui",
    "angularjs": "angular", "angular": "@angular/core", "react": "react",
    "vue.js": "vue", "bootstrap": "bootstrap", "lodash": "lodash",
    "underscore": "underscore", "moment.js": "moment", "axios": "axios",
    "d3": "d3", "three.js": "three", "chart.js": "chart.js",
    "datatables": "datatables.net", "select2": "select2", "swiper": "swiper",
    "sweetalert": "sweetalert2", "toastr": "toastr", "backbone": "backbone",
    "handlebars": "handlebars", "mustache": "mustache", "gsap": "gsap",
    "video.js": "video.js", "leaflet": "leaflet", "socket.io": "socket.io",
    "polymer": "@polymer/polymer",
}

_OSV_URL = "https://api.osv.dev/v1/query"


def _ver_tuple(version):
    """'1.7.9' -> (1, 7, 9); tolerates 2-part versions and non-numeric tails.
    Returns None when the version cannot be compared."""
    try:
        parts = re.findall(r"\d+", str(version))[:3]
        if not parts:
            return None
        while len(parts) < 3:
            parts.append("0")
        return tuple(int(p) for p in parts)
    except Exception:
        return None


def check_cve(name, version):
    """Offline ruleset check. Returns a list of matching rule dicts (each with
    'cves' and 'note') for `name` at `version`, or [] when none/unknown."""
    rules = _CVE_RULES.get((name or "").lower())
    if not rules:
        return []
    vt = _ver_tuple(version)
    if vt is None:
        return []
    major = vt[0]
    out = []
    for r in rules:
        if "majors" in r and major not in r["majors"]:
            continue
        bt = _ver_tuple(r["below"])
        if bt is not None and vt < bt:
            out.append(r)
    return out


def osv_request(libname, version):
    """Build the OSV.dev query (url, body_json_str) for one library version."""
    npm = _NPM_NAMES.get((libname or "").lower())
    if not npm or _ver_tuple(version) is None:
        return None
    import json as _json
    body = {"version": str(version),
            "package": {"name": npm, "ecosystem": "npm"}}
    return _OSV_URL, _json.dumps(body)


def osv_parse(resp_text):
    """Parse an OSV.dev response into [(id_or_cve, summary)] (may be empty)."""
    out = []
    try:
        import json as _json
        data = _json.loads(resp_text)
        for v in (data.get("vulns") or [])[:10]:
            vid = v.get("id", "")
            for alias in v.get("aliases") or []:
                if str(alias).startswith("CVE-"):
                    vid = alias
                    break
            out.append((vid or "GHSA", (v.get("summary") or "")[:120]))
    except Exception:
        pass
    return out


# ── automatic CVE map (OSV.dev primary + offline fallback) ────────────────────

# Session-wide cache: "lib@version" -> cve_map entry or None (queried once).
_OSV_CACHE = {}


def cve_map_for_libraries(libraries, post_fn=None, online=True,
                          max_queries=12):
    """Automatic CVE matching for fingerprinted libraries.

    For each (name, version): query OSV.dev with the EXACT version (fresh
    GHSA/NVD data, cached per session so each unique library version is
    queried only once). When OSV is unavailable or yields nothing, fall back
    to the embedded offline ruleset.

    `post_fn(url, body_str)` must perform the HTTP POST and return
    (status, text) - pass api_client._http_post. Returns
    {libname: {"source": "OSV.dev"|"local ruleset", ...}} (entries only for
    libraries WITH matches).
    """
    cve_map = {}
    if not libraries:
        return cve_map
    queried = 0
    for name, ver in libraries:
        key = "{0}@{1}".format((name or "").lower(), ver)
        if key in _OSV_CACHE:
            if _OSV_CACHE[key]:
                cve_map[name] = _OSV_CACHE[key]
            continue
        if online and queried < max_queries:
            queried += 1
            try:
                rq = osv_request(name, ver)
                if rq and post_fn is not None:
                    st, bd = post_fn(rq[0], rq[1])
                    vulns = osv_parse(bd) if st == 200 else []
                    if vulns:
                        entry = {"source": "OSV.dev", "vulns": vulns}
                        _OSV_CACHE[key] = entry
                        cve_map[name] = entry
                        continue
                    _OSV_CACHE[key] = None     # known-clean, don't re-query
            except Exception:
                pass
        rules = check_cve(name, ver)
        if rules:
            entry = {"source": "local ruleset", "matches": rules}
            _OSV_CACHE[key] = entry
            cve_map[name] = entry
    return cve_map


def cve_summary_lines(cve_map, limit=10):
    """Render a cve_map as short 'name vX: CVEs (source)' lines."""
    out = []
    for name, cm in (cve_map or {}).items():
        if cm.get("vulns"):
            ids = u", ".join(i for i, _ in cm["vulns"][:5])
            out.append(u"{0}: {1} (source: {2})".format(name, ids,
                                                        cm.get("source", "")))
        elif cm.get("matches"):
            ids = u"; ".join(r["cves"] for r in cm["matches"])
            out.append(u"{0}: {1} (source: {2})".format(name, ids,
                                                        cm.get("source", "")))
        if len(out) >= limit:
            break
    return out


# ── AI Hunt candidates from a digest ─────────────────────────────────────────

def js_hits(digest, method, netloc, path, full_url, cve_map=None):
    """Convert a JS digest into hunt-style candidate dicts (POTENTIAL).
    `cve_map` (optional): {libname: {"source": str, "matches": [rule dicts]}
    or {"source": "OSV.dev", "vulns": [(id, summary), ...]}} - libraries with
    CVE matches become High 'JS Library Outdated (CVE)' candidates."""
    hits = []
    if not digest:
        return hits
    endpoint = u"{0} {1}{2}".format(method, netloc, path)
    cve_map = cve_map or {}
    host = (netloc or u"").split(u"/")[0] or netloc   # per-host dedup base

    def _base(cls, sev, param, value, why, meth, payloads):
        return {
            "cls": cls, "sev": sev, "param": param, "where": "js",
            "value": value[:60] if value else u"",
            "value_full": value[:160] if value else u"",
            "method": method, "path": path, "url": full_url,
            "endpoint": endpoint, "why": why, "methodology": meth,
            "payloads": payloads, "conf": "heuristic",
            "ai_verdict": "", "ai_reason": "", "ai_payloads": [],
            "ai_next": "",
        }

    for name, ver in digest.get("libraries", []):
        cm = cve_map.get(name)
        if not cm:
            # NOISE REDUCTION: a clean library (no CVE match) is not a finding.
            # The version still reaches the LLM via the JS analysis digest.
            continue
        if cm and cm.get("matches"):
            ids = u"; ".join(r["cves"] for r in cm["matches"])
            notes = u"; ".join(r["note"] for r in cm["matches"])
            key = u"js {0} cve {1} {2}".format(host, name.lower(), ver)
            hits.append(_base(
                u"JS Library Outdated (CVE)", u"High",
                name, u"v" + ver,
                u"{0} v{1} matches known-vulnerable version range(s): {2} "
                u"[{3}] (offline ruleset; verify against the vendor advisory)."
                .format(name, ver, notes, ids),
                u"Review the listed CVEs against how the library is used; "
                u"plan an upgrade to the patched release. Triage (AI) can "
                u"explain each CVE's exploitation path.",
                [ids]))
            continue
        if cm and cm.get("vulns"):
            vlist = u"; ".join(u"{0} {1}".format(i, s) for i, s in cm["vulns"][:5])
            key = u"js {0} cve {1} {2}".format(host, name.lower(), ver)
            hits.append(_base(
                u"JS Library Outdated (CVE)", u"High",
                name, u"v" + ver,
                u"{0} v{1} has known vulnerabilities per OSV.dev: {2}"
                .format(name, ver, vlist),
                u"Review the OSV entries against how the library is used; "
                u"upgrade to a patched release.",
                [i for i, _ in cm["vulns"][:5]]))
            continue
        key = u"js {0} {1}{2} {3} {4}".format(method, netloc, path,
                                              name.lower(), ver)
        hits.append(_base(
            u"JS Library Fingerprint", u"Medium",
            name, u"v" + ver,
            u"Frontend library {0} v{1} detected in the JS bundle - check "
            u"whether this version is outdated or has known CVEs "
            u"(retire.js style).".format(name, ver),
            u"Compare {0} v{1} against the latest release and public CVE "
            u"databases; Triage (AI) can map known vulnerabilities from the "
            u"exact version.".format(name, ver),
            [u"{0} v{1}".format(name, ver)]))
    for kind, val, line in digest.get("secrets", []):
        key = u"js {0} secret {1} {2}".format(host, kind.lower(), val)
        h = _base(
            u"Secret / Credential in JS", u"High",
            kind, val,
            u"Possible {0} hardcoded in the JS bundle (line {1}); value is "
            u"masked - inspect the source to confirm.".format(kind, line),
            u"Open the JS file at the reported line; if the value is a real "
            u"credential, rotate it and move secrets server-side. Test "
            u"whether the exposed key is active.",
            [u"verify {0} at line {1}".format(kind, line)])
        h["dedup_key"] = key
        hits.append(h)
    if digest.get("sourcemap"):
        h = _base(
            u"Source Map Disclosed", u"Low",
            u"sourceMappingURL", digest["sourcemap"],
            u"The bundle references a source map; if the .map file is "
            u"fetchable it exposes original source, comments and internal "
            u"paths.",
            u"Request the .map URL; if it resolves, reconstruct the original "
            u"source (e.g. sources-content) and review for secrets/logic.",
            [u"GET " + digest["sourcemap"]])
        h["dedup_key"] = u"js {0} sourcemap {1}".format(host, digest["sourcemap"])
        hits.append(h)
    # NOISE REDUCTION: bare DOM-sink presence and endpoint lists no longer
    # create table candidates (almost every bundle has sinks; endpoint lists
    # are Informational). Both still reach the LLM via the JS analysis
    # digest, where AI Discover / Triage can turn them into real candidates.
    for h in hits:
        if not h.get("dedup_key"):
            h["dedup_key"] = u"js {0} {1}{2} {3}".format(
                method, netloc, path, h["cls"].lower())
    return hits
