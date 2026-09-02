# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# scanner.py — Analysis orchestration with background threading
#
# Supports both single-request and bulk multi-request scanning.
# Bulk scanning uses a Semaphore to cap concurrent API calls.
# Includes: scope filtering, request deduplication, Burp Collaborator support.

import hashlib
import re
import threading
from javax.swing import SwingUtilities
from prompt_handler import PromptHandler
from api_client import APIClient
from report_generator import ReportGenerator, _safe_log_str


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
            try:
                self.stdout.write("[Scanner] {0}\n".format(_safe_log_str(msg)))
            except Exception:
                pass

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

    # ── Self-verification (second AI pass) ─────────────────────────────────────

    def _verify_findings(self, issues, response_bytes, provider, settings, max_tokens):
        """Judge each actionable finding ONLY on the response evidence.
          CONFIRMED      -> keep, annotate.
          POTENTIAL      -> prefix "Potential", set Confidence=Tentative, annotate.
          FALSE_POSITIVE -> drop.
        Information / error findings pass through untouched. Fails open: any error
        (or unparseable verdicts) returns the input list unchanged so findings are
        never lost to a flaky verification call."""
        actionable = [i for i, iss in enumerate(issues)
                      if iss.getSeverity() in ("High", "Medium", "Low")]
        if not actionable:
            return issues

        try:
            resp_text = self._helpers.bytesToString(response_bytes) if response_bytes else u""
        except Exception:
            resp_text = u""
        resp_text = resp_text[:4000]

        lines = []
        for i in actionable:
            iss = issues[i]
            claim = (iss.getDetailMarkdown() or u"").replace("\n", " ")[:200]
            lines.append(u"{0}. [{1}] {2} | claim: {3}".format(
                i, iss.getSeverity(), iss.getIssueName(), claim))

        sys_p = (
            u"You are a strict, skeptical verifier of web application security findings. "
            u"For each finding decide, using ONLY the HTTP response provided, whether the "
            u"evidence truly supports it. Output one line per finding and NOTHING else, "
            u"in exactly this form:\n"
            u"<index>: CONFIRMED|POTENTIAL|FALSE_POSITIVE - <reason, max 12 words>\n"
            u"CONFIRMED = the response contains concrete proof (reflected payload, error "
            u"message, disclosed data, or the insecure/missing header actually present). "
            u"POTENTIAL = plausible from the request but NOT proven in this response. "
            u"FALSE_POSITIVE = the response contradicts it or gives no basis at all. "
            u"Be conservative: when unsure use POTENTIAL, never CONFIRMED.")
        user_p = (u"FINDINGS:\n" + u"\n".join(lines)
                  + u"\n\nHTTP RESPONSE:\n" + (resp_text or u"(empty response)"))

        try:
            cap = int(max_tokens) if max_tokens else 1000
        except Exception:
            cap = 1000
        verdict_text = self.api_client.call_api(
            provider=provider, settings=settings,
            system_prompt=sys_p, user_prompt=user_p,
            max_tokens=min(cap, 1200))

        verdicts = self._parse_verdicts(verdict_text)
        if not verdicts:
            self._log("Self-verify: no parseable verdicts — keeping findings as-is.")
            return issues

        kept = []
        for i, iss in enumerate(issues):
            v = verdicts.get(i)
            if v is None:
                kept.append(iss)                      # not judged -> keep unchanged
                continue
            verdict, reason = v
            if verdict == "FALSE_POSITIVE":
                self._log(u"Self-verify DROP [{0}] {1} - {2}".format(
                    iss.getSeverity(), iss.getIssueName(), reason))
                continue
            if verdict == "POTENTIAL":
                nm = iss.getIssueName()
                if not nm.lower().startswith("potential"):
                    iss.set_name(u"Potential " + nm)
                iss.set_confidence(u"Tentative")
                iss.append_detail(
                    u"\n\n> **Self-verify:** not proven in the response — " + reason)
            else:  # CONFIRMED
                iss.append_detail(
                    u"\n\n> **Self-verify:** confirmed against the response — " + reason)
            kept.append(iss)
        return kept

    def _parse_verdicts(self, text):
        """Parse '<index>: VERDICT - reason' lines into {index: (VERDICT, reason)}."""
        out = {}
        if not text:
            return out
        pat = re.compile(
            r'^\s*(\d+)\s*[:.\)\-]\s*'
            r'(CONFIRMED|POTENTIAL|FALSE[_ ]?POSITIVE)\b[\s:\-]*(.*)$',
            re.IGNORECASE)
        for line in text.split("\n"):
            m = pat.match(line)
            if not m:
                continue
            idx     = int(m.group(1))
            verdict = m.group(2).upper().replace(" ", "_")
            reason  = (m.group(3) or "").strip()[:160]
            out[idx] = (verdict, reason)
        return out

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

            # Optional second pass: judge each finding against the actual response
            # evidence — unproven findings are downgraded to "Potential" and refuted
            # ones dropped. Strengthens the anti-hallucination posture. Fails open.
            try:
                if issues and self.ui.get_self_verify():
                    before = len(issues)
                    issues = self._verify_findings(
                        issues, response_bytes, provider, settings, max_tokens)
                    self._log("Self-verify: {0} -> {1} finding(s) for {2}".format(
                        before, len(issues), url))
            except Exception as ve:
                self._log("Self-verify skipped (error): {0}".format(str(ve)))

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
