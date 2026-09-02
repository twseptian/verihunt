# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# Main entry point - load this file in Burp Suite Extensions

import sys
import os

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

from burp import IBurpExtender, IContextMenuFactory, ITab, IContextMenuInvocation
from java.util import ArrayList
from javax.swing import JMenuItem

from ui import UI
from scanner import Scanner

EXTENSION_NAME = "AgenticBurp"
EXTENSION_VERSION = "1.2.0"


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()
        self.scanner = None

        callbacks.setExtensionName(EXTENSION_NAME + " v" + EXTENSION_VERSION)

        try:
            self.ui = UI(callbacks, EXTENSION_VERSION)
            self.scanner = Scanner(callbacks, self.ui)
            callbacks.registerContextMenuFactory(self)
            callbacks.addSuiteTab(self)
            self._log("Loaded OK. Right-click a request > Extensions > AgenticBurp > Analyze with AI")
        except Exception as e:
            import traceback
            self._err("Init failed: " + str(e))
            self._err(traceback.format_exc())

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

        item = JMenuItem("Analyze with AI")
        item.addActionListener(lambda e: scanner.analyze_request(inv_ref))

        items = ArrayList()
        items.add(item)
        return items

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[AgenticBurp] " + msg + "\n")

    def _err(self, msg):
        if self.stderr:
            self.stderr.write("[AgenticBurp] ERROR: " + msg + "\n")
