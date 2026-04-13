# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# scanner.py — Analysis orchestration with background threading
#
# Supports both single-request and bulk multi-request scanning.
# Bulk scanning uses a Semaphore to cap concurrent API calls.
# Includes: scope filtering, request deduplication, Burp Collaborator support.

import hashlib
import threading
from javax.swing import SwingUtilities
from prompt_handler import PromptHandler
from api_client import APIClient
from report_generator import ReportGenerator


class Scanner(object):
    def __init__(self, callbacks, ui):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self.ui         = ui
        self.prompt_handler   = PromptHandler(callbacks)
        self.api_client       = APIClient()
        self.report_generator = ReportGenerator(callbacks)
        self.stdout = callbacks.getStdout()

        # Request deduplication: set of MD5 hashes of analyzed request bytes
        self._seen_hashes = set()
        self._seen_lock   = threading.Lock()

        # Burp Collaborator context (None if not available in this Burp edition)
        self._collaborator = None
        try:
            self._collaborator = callbacks.createBurpCollaboratorClientContext()
        except Exception:
            pass

    def _log(self, msg):
        if self.stdout:
            self.stdout.write("[Scanner] {0}\n".format(msg))

    def _request_hash(self, request_bytes):
        """MD5 fingerprint of request bytes for deduplication."""
        try:
            h = hashlib.md5()
            h.update(bytes(request_bytes))
            return h.hexdigest()
        except Exception:
            return None

    def _is_duplicate(self, request_bytes):
        """Return True if this exact request was already analyzed this session."""
        h = self._request_hash(request_bytes)
        if h is None:
            return False
        with self._seen_lock:
            if h in self._seen_hashes:
                return True
            self._seen_hashes.add(h)
            return False

    def _get_collaborator_payload(self):
        """
        Generate a Burp Collaborator URL for OOB detection.
        Returns empty string if Collaborator is not available.
        """
        if self._collaborator is None:
            return ""
        try:
            return self._collaborator.generatePayload(True)
        except Exception:
            return ""

    # ── Public entry point ─────────────────────────────────────────────────────

    def analyze_request(self, invocation):
        """
        Entry point called from context menu.
        Handles single OR multiple selected messages.
        Multiple messages are processed with a concurrency-limited thread pool.
        """
        messages = invocation.getSelectedMessages()
        if not messages:
            return

        # Filter: only messages with a valid request
        valid = [m for m in messages if m.getRequest() is not None]
        if not valid:
            return

        # Scope filter (if enabled in Settings)
        if self.ui.get_scope_only():
            in_scope = []
            for m in valid:
                try:
                    ri  = self._helpers.analyzeRequest(m)
                    url = ri.getUrl()
                    if self._callbacks.isInScope(url):
                        in_scope.append(m)
                    else:
                        self._log("Out of scope, skipping: {0}".format(url))
                except Exception:
                    in_scope.append(m)
            valid = in_scope
            if not valid:
                self._log("All selected requests are out of Burp scope.")
                return

        if len(valid) == 1:
            self._start_single(valid[0])
        else:
            self._start_bulk(valid)

    # ── Single analysis ────────────────────────────────────────────────────────

    def _start_single(self, message):
        request_info    = self._helpers.analyzeRequest(message)
        url             = str(request_info.getUrl())
        placeholder_key = self.ui.add_placeholder(url, auto_filter=True)
        self._log("Analyzing: {0}".format(url))

        t = threading.Thread(
            target=self._run_analysis,
            args=(message, request_info, url, placeholder_key, None)
        )
        t.daemon = True
        t.start()

    # ── Bulk analysis ──────────────────────────────────────────────────────────

    def _start_bulk(self, messages):
        """
        Called from EDT (ActionListener). Safe to call UI methods directly.
        Deduplicates requests before queuing, adds placeholders, launches threads.
        """
        # Deduplicate before counting / showing placeholders
        unique = []
        for msg in messages:
            req = msg.getRequest()
            if not self._is_duplicate(req):
                unique.append(msg)
            else:
                url = str(self._helpers.analyzeRequest(msg).getUrl())
                self._log("Duplicate skipped: {0}".format(url))

        if not unique:
            self._log("All selected requests are duplicates — nothing to analyze.")
            return

        total = len(unique)
        self._log("Bulk scan: {0} unique requests, concurrency={1}".format(
            total, self.ui.get_max_concurrent()))

        self.ui.start_queue(total)
        max_concurrent = self.ui.get_max_concurrent()
        semaphore = threading.Semaphore(max_concurrent)

        items = []
        for i, msg in enumerate(unique):
            ri  = self._helpers.analyzeRequest(msg)
            url = str(ri.getUrl())
            key = self.ui.add_placeholder(url, auto_filter=(i == 0))
            items.append((msg, ri, url, key))

        for msg, ri, url, key in items:
            t = threading.Thread(
                target=self._run_analysis,
                args=(msg, ri, url, key, semaphore)
            )
            t.daemon = True
            t.start()

    # ── Core analysis worker ───────────────────────────────────────────────────

    def _run_analysis(self, message, request_info, url, placeholder_key, semaphore):
        """
        Background thread: acquire semaphore slot, call AI, update UI.
        semaphore is None for single-request path.
        """
        if semaphore:
            semaphore.acquire()

        # Check cancellation AFTER acquiring slot
        if self.ui.is_cancelled():
            self._log("Skipped (cancelled): {0}".format(url))
            if semaphore:
                semaphore.release()

            def _remove():
                self.ui.update_results(placeholder_key, [])
                self.ui.decrement_queue()

            SwingUtilities.invokeLater(_remove)
            return

        try:
            request_bytes  = message.getRequest()
            response_bytes = message.getResponse()

            # Deduplication for single scans is intentionally skipped — the user
            # explicitly selected the request to analyze.
            # Bulk deduplication is handled upfront in _start_bulk before any
            # threads are launched, so no in-thread check is needed there either.

            settings    = self.ui.get_provider_settings()
            provider    = self.ui.get_provider()
            max_tokens  = self.ui.get_max_tokens()
            prompt_tmpl = self.ui.get_prompt_template()

            # Get Collaborator payload for OOB detection hints
            collab_url = self._get_collaborator_payload()

            system_prompt, user_prompt = self.prompt_handler.build_prompts(
                prompt_template   = prompt_tmpl,
                request_bytes     = request_bytes,
                request_info      = request_info,
                response_bytes    = response_bytes,
                max_request_chars = 3000,
                max_response_chars= 2000,
                collaborator_url  = collab_url,
            )

            self._log("Calling {0} API for {1}...".format(provider, url))

            ai_text = self.api_client.call_api(
                provider      = provider,
                settings      = settings,
                system_prompt = system_prompt,
                user_prompt   = user_prompt,
                max_tokens    = max_tokens,
            )

            self._log("Response ({0} chars) for {1}. Parsing...".format(
                len(ai_text) if ai_text else 0, url))

            marked_message = self._callbacks.applyMarkers(message, None, None)
            issues = self.report_generator.parse_ai_response(
                ai_text      = ai_text,
                http_service = message.getHttpService(),
                url          = request_info.getUrl(),
                http_messages= [marked_message],
            )

            for issue in issues:
                try:
                    self._callbacks.addScanIssue(issue)
                except Exception as ex:
                    self._log("addScanIssue failed: {0}".format(str(ex)))

            self._log("{0} issue(s) for {1}".format(len(issues), url))

            final_issues = issues
            final_key    = placeholder_key
            is_bulk      = semaphore is not None

            def _update():
                self.ui.update_results(final_key, final_issues)
                if is_bulk:
                    self.ui.decrement_queue()

            SwingUtilities.invokeLater(_update)

        except Exception as e:
            self._log("Analysis error for {0}: {1}".format(url, str(e)))
            error_msg = "[Analysis Failed]\n\nError: {0}".format(str(e))

            from report_generator import AgenticBurpIssue
            error_issue = AgenticBurpIssue(
                http_service  = message.getHttpService(),
                url           = request_info.getUrl(),
                http_messages = [self._callbacks.applyMarkers(message, None, None)],
                name          = "Analysis Error",
                detail        = error_msg,
                background    = "The AI analysis encountered an error.",
                remediation   = "Check your API key, model name, and network connectivity.",
                severity      = "Information",
                confidence    = "Tentative",
            )
            final_key = placeholder_key
            is_bulk   = semaphore is not None

            def _update_error():
                self.ui.update_results(final_key, [error_issue])
                if is_bulk:
                    self.ui.decrement_queue()

            SwingUtilities.invokeLater(_update_error)

        finally:
            if semaphore:
                semaphore.release()
