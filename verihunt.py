# -*- coding: utf-8 -*-
# VeriHunt - AI-Powered Security Analysis for Burp Suite
# Main entry point - load this file in Burp Suite Extensions

import sys
import os
import threading
try:
    import Queue as _queue          # Jython 2.7 / Py2
except Exception:                    # pragma: no cover
    import queue as _queue

# Resolve the extension's own directory in a cross-platform, cross-OS way.
# Burp's Jython often does NOT set __file__, so we try multiple methods.
def _resolve_ext_dir():
    # Method 1: inspect frame (works in most Jython versions inside Burp)
    try:
        import inspect
        frame_file = inspect.getfile(inspect.currentframe())
        return os.path.dirname(os.path.abspath(frame_file))
    except Exception:
        pass
    # Method 2: __file__ global (standard Python, sometimes available)
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        pass
    # Method 3: scan sys.path entries for a known sibling module
    for p in sys.path:
        try:
            if os.path.isfile(os.path.join(p, "ui.py")):
                return p
        except Exception:
            pass
    # Method 4: working directory as last resort
    return os.getcwd()

_here = _resolve_ext_dir()
if _here not in sys.path:
    sys.path.insert(0, _here)

from burp import (IBurpExtender, IContextMenuFactory, ITab,
                  IContextMenuInvocation, IHttpListener, IBurpExtenderCallbacks)
from java.util import ArrayList
from javax.swing import JMenuItem

from ui import UI
from scanner import Scanner

EXTENSION_NAME = "VeriHunt"
EXTENSION_VERSION = "1.9.0"


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()
        self.scanner = None
        self.ui = None

        callbacks.setExtensionName(EXTENSION_NAME + " v" + EXTENSION_VERSION)

        try:
            self.ui = UI(callbacks, EXTENSION_VERSION)
            self.scanner = Scanner(callbacks, self.ui)
            # Let the UI drive the scanner (AI Hunt -> Deep Analyze) and reach
            # cross-scan memory (Toggle False Positive updates it).
            self.ui.set_scanner(self.scanner)
            callbacks.registerContextMenuFactory(self)
            # Passive AI-Hunt: heuristic parameter scan of in-scope Proxy traffic.
            # A bounded queue + single worker keeps the proxy thread free and drops
            # work when saturated, so heavy browsing never bogs down Burp or the UI.
            self._hunt_q = _queue.Queue(maxsize=120)
            self._hunt_worker = threading.Thread(target=self._hunt_drain)
            self._hunt_worker.daemon = True
            self._hunt_worker.start()
            callbacks.registerHttpListener(self)
            callbacks.addSuiteTab(self)
            self._log("Loaded OK. Right-click a request > Extensions > VeriHunt > Analyze with AI")
            self._log("AI Hunt tab active: passive parameter heuristics on Proxy traffic.")
        except Exception as e:
            import traceback
            self._err("Init failed: " + str(e))
            self._err(traceback.format_exc())

    # ── Passive AI-Hunt listener ────────────────────────────────────────────────

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        # Only completed Proxy responses; the AI-Hunt tab toggles this on/off.
        # This runs on Burp's proxy thread, so it must stay CHEAP: quick filters
        # then hand off to the background worker (never analyze inline).
        try:
            if message_is_request:
                return
            if tool_flag != IBurpExtenderCallbacks.TOOL_PROXY:
                return
            if self.ui is None or not self.ui.is_hunt_passive():
                return
            # Parse once (proxy thread — keep it cheap). Skip static assets by URL
            # extension; respect the "Scope only" setting when enabled.
            try:
                import hunt_engine as _he
                import js_engine as _js
                url = self._helpers.analyzeRequest(message_info).getUrl()
                if _he.is_static_url(url.toString()):
                    # JS files are skipped like other static assets UNLESS the
                    # AI Hunt "JS scan" toggle is on — then JS URLs are queued
                    # for library/secret/sink fingerprinting.
                    try:
                        js_ok = (self.ui.get_js_scan()
                                 and _js.is_js_url(url.toString()))
                    except Exception:
                        js_ok = False
                    if not js_ok:
                        return
                if self.ui.get_scope_only() and not self._callbacks.isInScope(url):
                    return
            except Exception:
                pass
            # Non-blocking hand-off; drop silently if the worker is saturated.
            try:
                self._hunt_q.put_nowait(message_info)
            except _queue.Full:
                pass
        except Exception as e:
            self._err("Hunt passive error: " + str(e))

    def _hunt_drain(self):
        """Background worker: analyze queued proxy messages one at a time so the
        proxy thread and EDT are never blocked by hunting."""
        while True:
            try:
                msg = self._hunt_q.get()
            except Exception:
                continue
            try:
                if self.ui is not None:
                    self.ui.hunt_passive_scan(msg)
            except Exception as e:
                self._err("Hunt worker error: " + str(e))

    def getTabCaption(self):
        return EXTENSION_NAME

    def getUiComponent(self):
        return self.ui.get_panel()

    def createMenuItems(self, invocation):
        # Guard: if init failed, do not show menu
        if self.scanner is None:
            return None

        context = invocation.getInvocationContext()

        # Collect all known request/response context constants defensively.
        # Different Burp versions may have different subsets available.
        allowed = set()
        for name in (
            "CONTEXT_PROXY_HISTORY",
            "CONTEXT_MESSAGE_EDITOR_REQUEST",
            "CONTEXT_MESSAGE_VIEWER_REQUEST",
            "CONTEXT_MESSAGE_EDITOR_RESPONSE",
            "CONTEXT_MESSAGE_VIEWER_RESPONSE",
            "CONTEXT_TARGET_SITE_MAP_TABLE",
            "CONTEXT_TARGET_SITE_MAP_TREE",
            "CONTEXT_SCANNER_RESULTS",
            "CONTEXT_INTRUDER_ATTACK_RESULTS",
            "CONTEXT_SEARCH_RESULTS",
            "CONTEXT_REPEATER",
        ):
            try:
                allowed.add(getattr(IContextMenuInvocation, name))
            except AttributeError:
                pass

        # If no messages are selected at all, skip (avoids NPE in Scanner)
        try:
            msgs = invocation.getSelectedMessages()
            if not msgs or len(msgs) == 0:
                return None
        except Exception:
            return None

        # Accept any context that has messages (fallback for unknown contexts)
        if context not in allowed:
            # Still show menu if there are selected messages — Burp may add
            # new context constants in future versions
            pass

        scanner = self.scanner
        inv_ref = invocation

        # Count selected messages that actually carry a request, so the menu
        # advertises batch/queue analysis (e.g. "Analyze 12 requests with AI").
        try:
            n = len([m for m in msgs if m.getRequest() is not None])
        except Exception:
            n = len(msgs)

        if n > 1:
            label = "Analyze {0} requests with AI  (queued)".format(n)
        else:
            label = "Analyze with AI"

        item = JMenuItem(label)
        item.addActionListener(lambda e: scanner.analyze_request(inv_ref))

        items = ArrayList()
        items.add(item)
        return items

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[VeriHunt] " + msg + "\n")

    def _err(self, msg):
        if self.stderr:
            self.stderr.write("[VeriHunt] ERROR: " + msg + "\n")
