# -*- coding: utf-8 -*-
# VeriHunt - memory.py
#
# Cross-scan memory: remembers, per host, the findings you marked FALSE POSITIVE
# and the ones the AI CONFIRMED, so future analyses of the same host skip known
# false positives and stay aware of what was already found. Persisted via Burp's
# extension settings, so it survives restarts.
#
# Written for Jython 2.7.

import json
import re
import threading


def norm_name(name):
    """Normalise a finding name for stable cross-scan matching:
    drop a leading 'Potential ', parenthetical acronyms, a trailing [CVE-...],
    lowercase and collapse punctuation."""
    if not name:
        return u""
    n = name.lower()
    n = re.sub(r'^\s*potential\s+', u'', n)      # unverified prefix
    n = re.sub(r'\s*\[[^\]]*\]', u' ', n)         # [CVE-2024-...]
    n = re.sub(r'\s*\([^)]*\)', u' ', n)          # (SQLi)
    n = re.sub(r'[^a-z0-9]+', u' ', n).strip()
    return n


class Memory(object):
    """Per-host store of false positives + confirmed findings, persisted in Burp."""
    KEY = "ab.memory.v1"

    def __init__(self, callbacks):
        self._cb = callbacks
        self._lock = threading.Lock()
        self._fp = {}         # host -> { name_norm: path }
        self._confirmed = {}  # host -> { name_norm: {"sev":..., "path":...} }
        self._load()

    # -- persistence -----------------------------------------------------------

    def _load(self):
        try:
            raw = self._cb.loadExtensionSetting(self.KEY)
            if raw:
                d = json.loads(raw)
                self._fp = d.get("fp", {}) or {}
                self._confirmed = d.get("confirmed", {}) or {}
        except Exception:
            self._fp = {}
            self._confirmed = {}

    def _save(self):
        try:
            self._cb.saveExtensionSetting(
                self.KEY, json.dumps({"fp": self._fp, "confirmed": self._confirmed}))
        except Exception:
            pass

    # -- false positives -------------------------------------------------------

    def add_fp(self, host, path, name):
        k = norm_name(name)
        if not host or not k:
            return
        with self._lock:
            self._fp.setdefault(host, {})[k] = path or u""
            self._save()

    def remove_fp(self, host, name):
        k = norm_name(name)
        if not host or not k:
            return
        with self._lock:
            if host in self._fp and k in self._fp[host]:
                del self._fp[host][k]
                if not self._fp[host]:
                    del self._fp[host]
                self._save()

    def is_fp(self, host, name):
        k = norm_name(name)
        return bool(host) and host in self._fp and k in self._fp[host]

    # -- confirmed -------------------------------------------------------------

    def add_confirmed(self, host, path, name, sev):
        k = norm_name(name)
        if not host or not k:
            return
        with self._lock:
            self._confirmed.setdefault(host, {})[k] = {
                "sev": sev or u"", "path": path or u""}
            self._save()

    # -- prompt context --------------------------------------------------------

    def context_for(self, host):
        """A compact block for the AI prompt listing this host's known FPs and
        prior confirmed findings. Empty string when nothing is known."""
        if not host:
            return u""
        lines = []
        fps = self._fp.get(host, {})
        if fps:
            lines.append(
                u"KNOWN FALSE POSITIVES on this host (previously dismissed -- do NOT "
                u"re-report unless the CURRENT response now clearly proves it): "
                + u"; ".join(sorted(fps.keys())))
        conf = self._confirmed.get(host, {})
        if conf:
            lines.append(
                u"PREVIOUSLY CONFIRMED on this host (context only; still report if "
                u"present in this request): " + u"; ".join(sorted(conf.keys())))
        return u"\n".join(lines)

    # -- maintenance -----------------------------------------------------------

    def clear(self):
        with self._lock:
            self._fp = {}
            self._confirmed = {}
            self._save()

    def stats(self):
        fp = sum(len(v) for v in self._fp.values())
        cf = sum(len(v) for v in self._confirmed.values())
        return (fp, cf)
