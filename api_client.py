# -*- coding: utf-8 -*-
# VeriHunt - AI-Powered Security Analysis for Burp Suite
# api_client.py — Multi-provider LLM client
# Providers: Anthropic (Claude), OpenAI, OpenRouter, Ollama, Gemini,
#            DeepSeek, Kimi (Moonshot), Mistral, Groq, xAI (Grok)
# Written for Jython 2.7 (Burp Suite Python extension environment)

import json
import re
import time
import threading

# Use Java's networking stack for robust HTTPS/SSL support in Jython
from java.net import URL
from java.io import BufferedReader, InputStreamReader


# ── Session token usage tracker ───────────────────────────────────────────────
# Accumulates token usage across every analysis call so the UI can show a live
# "tokens this session" figure (handy for TPM-limited free tiers like Groq and
# for paid-quota budgeting). Module-level + locked so any APIClient instance and
# the UI thread share one running total safely.
_USAGE_LOCK = threading.Lock()
_USAGE = {"calls": 0, "prompt": 0, "completion": 0, "total": 0,
          "last_prompt": 0, "last_completion": 0, "last_total": 0}


def record_usage(prompt_tokens, completion_tokens, total_tokens=None):
    """Add one call's token usage to the running session total. Silently ignores
    missing/unparseable values so a provider that omits usage never breaks a scan."""
    try:
        p = int(prompt_tokens or 0)
        c = int(completion_tokens or 0)
        t = int(total_tokens) if total_tokens else (p + c)
    except (ValueError, TypeError):
        return
    if p == 0 and c == 0 and t == 0:
        return
    with _USAGE_LOCK:
        _USAGE["calls"] += 1
        _USAGE["prompt"] += p
        _USAGE["completion"] += c
        _USAGE["total"] += t
        _USAGE["last_prompt"] = p
        _USAGE["last_completion"] = c
        _USAGE["last_total"] = t


def get_usage():
    with _USAGE_LOCK:
        return dict(_USAGE)


def reset_usage():
    with _USAGE_LOCK:
        for k in list(_USAGE.keys()):
            _USAGE[k] = 0


def _usage_openai(result):
    u = result.get("usage") or {}
    return (u.get("prompt_tokens"), u.get("completion_tokens"), u.get("total_tokens"))


def _usage_anthropic(result):
    u = result.get("usage") or {}
    return (u.get("input_tokens"), u.get("output_tokens"), None)


def _usage_gemini(result):
    u = result.get("usageMetadata") or {}
    return (u.get("promptTokenCount"), u.get("candidatesTokenCount"), u.get("totalTokenCount"))


def _oai_content_or_diag(provider_label, choices):
    """Return the assistant message content, or an INFORMATIVE diagnostic when it
    is empty. Reasoning models (e.g. deepseek-reasoner, 'thinking' variants) put
    text in `reasoning_content` and can return an empty `content` -- especially
    when finish_reason == 'length' (Max Tokens exhausted during reasoning). Never
    return an empty string, so the caller never silently shows 0 findings."""
    msg = (choices[0].get("message") or {}) if choices else {}
    content = msg.get("content")
    if content and content.strip():
        return content
    # Reasoning models: fall back to the reasoning text so it can still be parsed.
    reasoning = msg.get("reasoning_content") or msg.get("reasoning")
    if reasoning and reasoning.strip():
        return reasoning
    finish = (choices[0].get("finish_reason") if choices else u"") or u"unknown"
    return (u"[{0}] The model returned an EMPTY completion (finish_reason={1}).\n\n"
            u"Likely causes:\n"
            u"- A reasoning model spent all output tokens 'thinking' -> raise **Max "
            u"Tokens** in Settings (try 8192+), or pick a non-reasoning model.\n"
            u"- An invalid model id (e.g. 'deepseek-flash' is not a DeepSeek model -- "
            u"use **deepseek-chat** or **deepseek-reasoner**).\n"
            u"- The endpoint returned only reasoning with no final answer.").format(
                provider_label, finish)


# ── OpenAI-compatible providers ─────────────────────────────────────────────────
#
# DeepSeek, Kimi/Moonshot, Mistral, Groq and xAI all speak the OpenAI
# chat-completions protocol, so they share one code path — only the base URL,
# default model and sign-up link differ. Kept as an ordered list of tuples (NOT
# a dict) because Jython 2.7 dicts don't preserve insertion order and the UI
# renders these tabs in this order.
#
# Each entry: (label, base_url, default_model, key_url, model_hint)
# Model fields are free text: these vendors rotate model IDs often, so a fixed
# dropdown would go stale — the default is a documented, long-lived ID.
OAI_COMPAT_PROVIDERS = [
    ("DeepSeek", "https://api.deepseek.com", "deepseek-chat",
     "platform.deepseek.com",
     "deepseek-chat (V-series, general)  |  deepseek-reasoner (reasoning / chain-of-thought)"),
    ("Kimi (Moonshot)", "https://api.moonshot.ai/v1", "kimi-latest",
     "platform.moonshot.ai",
     "kimi-latest  |  kimi-k2-0905-preview  |  moonshot-v1-8k / -32k / -128k"),
    ("Mistral", "https://api.mistral.ai/v1", "mistral-large-latest",
     "console.mistral.ai",
     "mistral-large-latest  |  mistral-medium-latest  |  mistral-small-latest  |  codestral-latest"),
    ("Groq", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile",
     "console.groq.com/keys",
     "llama-3.3-70b-versatile  |  llama-3.1-8b-instant  |  openai/gpt-oss-120b  |  moonshotai/kimi-k2-instruct"),
    ("xAI (Grok)", "https://api.x.ai/v1", "grok-4.6",
     "console.x.ai",
     "grok-4.6  |  grok-4.5  |  grok-4.3  (see console.x.ai/models)"),
    # OpenCode Zen — a hosted model gateway. OpenAI-compatible at /zen/v1.
    ("OpenCode Zen", "https://opencode.ai/zen/v1", "claude-sonnet-5",
     "opencode.ai/zen",
     "Pick a model from opencode.ai/zen (e.g. claude-sonnet-5, gpt-5.1, kimi-k3)"),
    # Z.AI — Zhipu's international platform; OpenAI-compatible at /api/paas/v4.
    # Standard pay-as-you-go API keys live here. GLM Coding Plan keys are ONLY
    # valid on the coding endpoint -> dedicated "Z.AI Coding Plan (GLM)" entry.
    ("Z.AI (GLM)", "https://api.z.ai/api/paas/v4", "glm-4.6",
     "z.ai",
     "Standard (pay-as-you-go) API key. glm-4.6 (flagship, 200k ctx)  |  glm-4.5  |  glm-4.5-air  |  glm-4.5-flash (free)"),
    # GLM Coding Plan: key is bound to the coding endpoint; standard /api/paas/v4
    # rejects it. Same models; separate settings key so both keys coexist.
    ("Z.AI Coding Plan (GLM)", "https://api.z.ai/api/coding/paas/v4", "glm-4.6",
     "z.ai (Coding Plan)",
     "GLM Coding Plan key ONLY (Personal/Pro plan). glm-4.6  |  glm-4.5  |  glm-4.5-air"),
    # Custom — any internal/OpenAI-compatible gateway (LiteLLM, Azure OpenAI-
    # compatible surface, private proxy). Base URL must be filled in by the user.
    ("Custom (OpenAI-compatible)", "", "", "your LLM gateway",
     "Enterprise gateway (LiteLLM, Azure OpenAI-compatible, private proxy). "
     "Set Base URL + Model, then Test Connection."),
]

# label -> (base_url, default_model) for O(1) dispatch lookup
OAI_COMPAT_MAP = dict((p[0], (p[1], p[2])) for p in OAI_COMPAT_PROVIDERS)

# Stable settings-key prefix per provider. Explicit (not derived from the label)
# so a future label tweak can't silently orphan a user's saved key.
OAI_COMPAT_KEYS = {
    "DeepSeek":        "deepseek",
    "Kimi (Moonshot)": "kimi",
    "Mistral":         "mistral",
    "Groq":            "groq",
    "xAI (Grok)":      "xai",
    "OpenCode Zen":    "opencode",
    "Z.AI (GLM)":      "zai",
    "Z.AI Coding Plan (GLM)": "zaicoding",
    "Custom (OpenAI-compatible)": "custom",
}


def _settings_key(provider_label):
    return OAI_COMPAT_KEYS.get(provider_label, provider_label.lower())


def _oai_error_message(body):
    """Pull a human-readable error out of an OpenAI-compatible error body.

    Handles both the standard {"error": {"message": ...}} shape and nested
    variants like OpenCode Zen's {"error": {"type": "CreditsError", "message": ...}}.
    Returns "" when nothing useful can be extracted.
    """
    try:
        d = json.loads(body)
    except Exception:
        return ""
    err = d.get("error")
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or "")
    if isinstance(err, str):
        return err
    if isinstance(d.get("message"), str):
        return d["message"]
    return ""


def _chat_completions_url(base_url):
    """Build the chat/completions URL from a base, version-segment aware.

    Some vendors publish their base WITH a version segment (Moonshot
    https://api.moonshot.ai/v1, Z.AI https://api.z.ai/api/paas/v4, OpenCode Zen
    https://opencode.ai/zen/v1) and some WITHOUT (DeepSeek
    https://api.deepseek.com). If the root already ends in /v<N>, only
    /chat/completions is appended; otherwise /v1/chat/completions. Never emits
    /v1/v1/... or a bare /chat/completions against a versionless host.
    """
    root = (base_url or "").rstrip("/")
    if re.search(r"/v\d+$", root):
        return root + "/chat/completions"
    return root + "/v1/chat/completions"


# ── HTTP helper ────────────────────────────────────────────────────────────────

def _http_post(url_str, headers, body_str, timeout_ms=120000):
    """
    Perform an HTTPS POST using Java's HttpURLConnection.
    Returns (status_code, response_body_str).
    """
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setDoOutput(True)
        conn.setDoInput(True)
        conn.setConnectTimeout(30000)
        conn.setReadTimeout(timeout_ms)

        for key, val in headers.items():
            conn.setRequestProperty(key, str(val))

        body_bytes = body_str.encode("utf-8")
        out_stream = conn.getOutputStream()
        out_stream.write(body_bytes)
        out_stream.flush()
        out_stream.close()

        status = conn.getResponseCode()

        if status >= 400:
            stream = conn.getErrorStream()
            if stream is None:
                return status, ""
        else:
            stream = conn.getInputStream()

        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        lines = []
        line = reader.readLine()
        while line is not None:
            lines.append(line)
            line = reader.readLine()
        reader.close()
        return status, "\n".join(lines)

    except Exception as e:
        raise RuntimeError("HTTP request failed: {0}".format(str(e)))


def _http_get(url_str, headers, timeout_ms=10000):
    """
    Perform an HTTPS GET using Java's HttpURLConnection.
    Returns (status_code, response_body_str).
    """
    try:
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("GET")
        conn.setDoInput(True)
        conn.setConnectTimeout(10000)
        conn.setReadTimeout(timeout_ms)

        for key, val in headers.items():
            conn.setRequestProperty(key, str(val))

        status = conn.getResponseCode()

        if status >= 400:
            stream = conn.getErrorStream()
            if stream is None:
                return status, ""
        else:
            stream = conn.getInputStream()

        reader = BufferedReader(InputStreamReader(stream, "UTF-8"))
        lines = []
        line = reader.readLine()
        while line is not None:
            lines.append(line)
            line = reader.readLine()
        reader.close()
        return status, "\n".join(lines)

    except Exception as e:
        raise RuntimeError("HTTP GET failed: {0}".format(str(e)))


_RETRY_AFTER_RE = re.compile(r'try again in\s+(?:(\d+)m)?\s*([\d.]+)\s*s', re.IGNORECASE)


def _parse_retry_seconds(body):
    """Extract a provider-suggested wait (seconds) from a 429 body, e.g. Groq's
    'Please try again in 7.66s' or '... in 1m30s'. Capped at 30s so Burp's UI
    thread never hangs on a long daily-limit backoff. Returns None if not found."""
    try:
        m = _RETRY_AFTER_RE.search(body or "")
        if m:
            mins = float(m.group(1)) if m.group(1) else 0.0
            return min(mins * 60.0 + float(m.group(2)) + 0.5, 30.0)
    except Exception:
        pass
    return None


def _http_post_with_retry(url_str, headers, body_str, timeout_ms=120000,
                           max_retries=4):
    """
    Wrapper around _http_post with backoff on 429 (rate limit). Honours the wait
    the provider suggests in the body ('try again in Xs' — Groq/OpenAI style),
    falling back to exponential 2/4/8s. Returns the LAST (status, body) so the
    caller can surface the provider's real rate-limit message.
    """
    last_exc = None
    status, body = 0, ""
    for attempt in range(max_retries):
        try:
            status, body = _http_post(url_str, headers, body_str, timeout_ms)
            if status == 429 and attempt < max_retries - 1:
                suggested = _parse_retry_seconds(body)
                wait = suggested if suggested is not None else min(2 ** (attempt + 1), 16)
                time.sleep(wait)
                continue
            return status, body
        except Exception as e:
            last_exc = e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    if last_exc:
        raise last_exc
    return status, body


# ── API Client ─────────────────────────────────────────────────────────────────

class APIClient(object):
    """
    Unified LLM API client supporting:
      - Anthropic  (Claude models)
      - OpenAI     (GPT models)
      - OpenRouter (any model via OpenAI-compatible API)
      - Gemini     (Google Gemini via generateContent REST)
      - Ollama     (local models via OpenAI-compatible /v1 endpoint)
    """

    # ── Anthropic ──────────────────────────────────────────────────────────────

    def call_anthropic(self, api_key, model, system_prompt, user_prompt, max_tokens):
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            status, body = _http_post_with_retry(url, headers, json.dumps(payload))
            if status != 200:
                return "[Anthropic Error {0}] {1}".format(status, body[:500])
            result = json.loads(body)
            record_usage(*_usage_anthropic(result))
            content = result.get("content") or []
            texts = [c.get("text", "") for c in content if c.get("type") == "text"]
            return "\n".join(texts) or "[Anthropic] Empty response."
        except Exception as e:
            return "[Anthropic Exception] {0}".format(str(e))

    # ── OpenAI ─────────────────────────────────────────────────────────────────

    def call_openai(self, api_key, model, system_prompt, user_prompt, max_tokens,
                    base_url=None):
        url = (base_url or "https://api.openai.com").rstrip("/") + "/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        try:
            status, body = _http_post_with_retry(url, headers, json.dumps(payload))
            if status != 200:
                return "[OpenAI Error {0}] {1}".format(status, body[:500])
            result = json.loads(body)
            choices = result.get("choices") or []
            if not choices:
                return "[OpenAI] No choices in response."
            record_usage(*_usage_openai(result))
            return _oai_content_or_diag("OpenAI", choices)
        except Exception as e:
            return "[OpenAI Exception] {0}".format(str(e))

    # ── Generic OpenAI-compatible (DeepSeek, Kimi, Mistral, Groq, xAI) ──────────

    def call_openai_compatible(self, provider_label, base_url, api_key, model,
                               system_prompt, user_prompt, max_tokens):
        """One chat-completions call for any OpenAI-compatible vendor."""
        if not api_key:
            return "[{0}] No API key set. Add one in Settings.".format(provider_label)
        url = _chat_completions_url(base_url)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        try:
            status, body = _http_post_with_retry(url, headers, json.dumps(payload))
            if status == 401:
                # 401 is not always a bad key -- e.g. OpenCode Zen returns 401 with
                # a "No payment method / CreditsError" body. Surface the provider's
                # actual message instead of blaming the key.
                detail = _oai_error_message(body)
                if detail:
                    return "[{0} Error 401] {1}".format(provider_label, detail)
                return ("[{0} Error 401] Invalid API key. "
                        "Check your key on the provider dashboard.").format(provider_label)
            if status == 402:
                return ("[{0} Error 402] Insufficient credits or quota. "
                        "Top up your account or lower Max Tokens.").format(provider_label)
            if status == 404:
                return ("[{0} Error 404 - Model Not Found]\n"
                        "Model '{1}' is not available. Check the exact model ID on the "
                        "provider's docs and update it in Settings.").format(provider_label, model)
            if status == 429:
                detail = _oai_error_message(body)
                msg = detail[:300] if detail else "rate/token-per-minute limit reached"
                return ("[{0} Error 429 - Rate Limited] {1}\n"
                        "Retried with backoff but still limited. Free tiers (esp. Groq) "
                        "cap tokens-per-minute — lower Max Tokens in Settings, wait a "
                        "minute, pick a smaller/faster model, or upgrade your plan."
                        ).format(provider_label, msg)
            if status != 200:
                return "[{0} Error {1}] {2}".format(provider_label, status, body[:500])
            result = json.loads(body)
            choices = result.get("choices") or []
            if not choices:
                # Some gateways answer 200 with an {"error": ...} body instead of 4xx.
                err = result.get("error")
                if err:
                    detail = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    return "[{0} Error] {1}".format(provider_label, detail[:400])
                return "[{0}] No choices in response.".format(provider_label)
            record_usage(*_usage_openai(result))
            return _oai_content_or_diag(provider_label, choices)
        except Exception as e:
            return "[{0} Exception] {1}".format(provider_label, str(e))

    def test_openai_compatible(self, provider_label, base_url, api_key, model):
        if not (base_url or "").strip():
            return False, "No Base URL set"
        if not api_key:
            return False, "No API key"
        url = _chat_completions_url(base_url)
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
        }
        payload = {"model": model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Hi"}]}
        try:
            status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
            if status == 200:
                return True, "Connected"
            detail = _oai_error_message(body)
            if status == 401:
                # Distinguish a real auth failure from a billing/credits 401.
                if detail and ("payment" in detail.lower() or "credit" in detail.lower()
                               or "billing" in detail.lower()):
                    return False, "Key OK but no credits: " + detail[:80]
                return False, detail[:90] if detail else "Invalid API key (401)"
            if status == 404:
                return False, "Model not found (404) - check model ID"
            return False, "HTTP {0}: {1}".format(status, (detail or body[:80])[:80])
        except Exception as e:
            return False, str(e)[:120]

    # ── OpenRouter ─────────────────────────────────────────────────────────────

    def call_openrouter(self, api_key, model, system_prompt, user_prompt, max_tokens,
                        site_url="https://burp.local", site_name="VeriHunt"):
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
            "HTTP-Referer": site_url,
            "X-Title": site_name,
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3,
        }
        try:
            status, body = _http_post_with_retry(url, headers, json.dumps(payload))

            if status == 402:
                # Insufficient credits or max_tokens exceeds account limit.
                # Parse the affordable token count from the error body if present.
                affordable = None
                try:
                    err = json.loads(body)
                    msg = str(err.get("error", {}).get("message", ""))
                    import re as _re
                    m = _re.search(r"afford\s+(\d+)", msg)
                    if m:
                        affordable = int(m.group(1))
                except Exception:
                    pass
                hint = (
                    "Reduce Max Tokens in Settings to {0} or lower.".format(affordable)
                    if affordable else
                    "Reduce Max Tokens in Settings or top up your OpenRouter credits."
                )
                return (
                    "[OpenRouter Error 402 — Insufficient Credits]\n\n"
                    "Your account cannot afford the requested max_tokens ({0}).\n"
                    "{1}\n\n"
                    "Free models on OpenRouter have per-request token limits. "
                    "Consider: (1) lowering Max Tokens in Settings, "
                    "(2) using a paid model, or (3) topping up credits at "
                    "https://openrouter.ai/settings/credits"
                ).format(max_tokens, hint)

            if status == 401:
                return "[OpenRouter Error 401] Invalid API key. Check your key at https://openrouter.ai/keys"

            if status == 404:
                # Model endpoint not found — likely removed or wrong model ID
                model_hint = payload.get("model", "unknown")
                return (
                    "[OpenRouter Error 404 — Model Not Found]\n\n"
                    "Model '{0}' does not exist or has been removed from OpenRouter.\n\n"
                    "Working free models (check openrouter.ai/models for latest):\n"
                    "  - meta-llama/llama-3.3-70b-instruct:free\n"
                    "  - google/gemma-3-27b-it:free\n"
                    "  - deepseek/deepseek-r1:free\n"
                    "  - mistralai/mistral-7b-instruct:free\n\n"
                    "Update the Model ID in Settings > OpenRouter tab."
                ).format(model_hint)

            if status == 429:
                return "[OpenRouter Error 429] Rate limited. Wait a moment and try again."

            if status != 200:
                return "[OpenRouter Error {0}] {1}".format(status, body[:500])

            result = json.loads(body)
            choices = result.get("choices") or []
            if not choices:
                return "[OpenRouter] No choices in response."
            record_usage(*_usage_openai(result))
            return _oai_content_or_diag("OpenRouter", choices)
        except Exception as e:
            return "[OpenRouter Exception] {0}".format(str(e))

    # ── Ollama ─────────────────────────────────────────────────────────────────

    def call_ollama(self, base_url, model, system_prompt, user_prompt, max_tokens,
                    api_key=None):
        # Tolerate a base that already ends in /v1 (e.g. a custom cloud host) so
        # we never emit /v1/v1/chat/completions.
        url = _chat_completions_url(base_url)
        # Local Ollama ignores the key but the SDK needs a non-empty value; the
        # hosted service (ollama.com) authenticates with a real bearer token.
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key if api_key else "ollama"),
        }
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        payload = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": 0.3,
            "options": {"num_ctx": 8192},
        }
        try:
            status, body = _http_post_with_retry(
                url, headers, json.dumps(payload), timeout_ms=300000, max_retries=1)
            if status != 200:
                return "[Ollama Error {0}] {1}".format(status, body[:500])
            result = json.loads(body)
            choices = result.get("choices") or []
            if not choices:
                return "[Ollama] No choices in response."
            record_usage(*_usage_openai(result))
            return _oai_content_or_diag("Ollama", choices)
        except Exception as e:
            return "[Ollama Exception] {0}".format(str(e))

    # ── Gemini ─────────────────────────────────────────────────────────────────

    def call_gemini(self, api_key, model, system_prompt, user_prompt, max_tokens):
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               "{0}:generateContent?key={1}").format(model, api_key)
        headers = {"Content-Type": "application/json"}

        contents = []
        if system_prompt:
            contents.append({"role": "user",
                              "parts": [{"text": system_prompt}]})
            contents.append({"role": "model",
                              "parts": [{"text": "Understood. I will follow those instructions."}]})
        contents.append({"role": "user", "parts": [{"text": user_prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.3,
            },
        }
        try:
            status, body = _http_post_with_retry(url, headers, json.dumps(payload))
            if status != 200:
                return "[Gemini Error {0}] {1}".format(status, body[:500])
            result = json.loads(body)
            candidates = result.get("candidates") or []
            if not candidates:
                return "[Gemini] No candidates returned."
            record_usage(*_usage_gemini(result))
            parts = (candidates[0].get("content") or {}).get("parts") or []
            texts = [p.get("text", "") for p in parts if "text" in p]
            return "\n".join(texts) or "[Gemini] Empty response."
        except Exception as e:
            return "[Gemini Exception] {0}".format(str(e))

    # ── Connection tests (lightweight — max_tokens=1) ─────────────────────────

    def test_anthropic(self, api_key, model):
        if not api_key:
            return False, "No API key"
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        payload = {"model": model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Hi"}]}
        try:
            status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
            if status == 200:
                return True, "Connected"
            try:
                msg = json.loads(body).get("error", {}).get("message", body[:120])
            except Exception:
                msg = body[:120]
            return False, str(msg)[:120]
        except Exception as e:
            return False, str(e)[:120]

    def test_openai(self, api_key, model):
        if not api_key:
            return False, "No API key"
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Content-Type": "application/json",
                   "Authorization": "Bearer {0}".format(api_key)}
        payload = {"model": model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Hi"}]}
        try:
            status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
            if status == 200:
                return True, "Connected"
            try:
                msg = json.loads(body).get("error", {}).get("message", body[:120])
            except Exception:
                msg = body[:120]
            return False, str(msg)[:120]
        except Exception as e:
            return False, str(e)[:120]

    def test_openrouter(self, api_key, model):
        if not api_key:
            return False, "No API key"
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {0}".format(api_key),
            "HTTP-Referer": "https://burp.local",
            "X-Title": "VeriHunt",
        }
        payload = {"model": model, "max_tokens": 1,
                   "messages": [{"role": "user", "content": "Hi"}]}
        try:
            status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
            if status == 200:
                return True, "Connected"
            if status == 401:
                return False, "Invalid API key (401)"
            try:
                msg = json.loads(body).get("error", {}).get("message", body[:100])
            except Exception:
                msg = body[:100]
            return False, "HTTP {0}: {1}".format(status, str(msg)[:80])
        except Exception as e:
            return False, str(e)[:120]

    def test_gemini(self, api_key, model):
        if not api_key:
            return False, "No API key"
        url = ("https://generativelanguage.googleapis.com/v1beta/models/"
               "{0}:generateContent?key={1}").format(model, api_key)
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
            "generationConfig": {"maxOutputTokens": 1},
        }
        try:
            status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
            if status == 200:
                return True, "Connected"
            try:
                msg = json.loads(body).get("error", {}).get("message", body[:120])
            except Exception:
                msg = body[:120]
            return False, str(msg)[:120]
        except Exception as e:
            return False, str(e)[:120]

    def test_ollama(self, base_url, model, api_key=None):
        if not base_url:
            return False, "No base URL"

        # Cloud mode: /api/tags may not exist on the hosted service, so probe the
        # OpenAI-compatible chat endpoint with the key instead.
        if api_key:
            url = _chat_completions_url(base_url)
            headers = {"Content-Type": "application/json",
                       "Authorization": "Bearer {0}".format(api_key)}
            payload = {"model": model, "max_tokens": 1,
                       "messages": [{"role": "user", "content": "Hi"}]}
            try:
                status, body = _http_post(url, headers, json.dumps(payload), timeout_ms=15000)
                if status == 200:
                    return True, "Connected (cloud)"
                if status == 401:
                    return False, "Invalid API key (401)"
                try:
                    msg = json.loads(body).get("error", {}).get("message", body[:80])
                except Exception:
                    msg = body[:80]
                return False, "HTTP {0}: {1}".format(status, str(msg)[:70])
            except Exception as e:
                return False, str(e)[:120]

        # Local mode: list models via /api/tags.
        url = base_url.rstrip("/") + "/api/tags"
        try:
            status, body = _http_get(url, {}, timeout_ms=8000)
            if status != 200:
                return False, "Server returned HTTP {0}".format(status)
            try:
                data = json.loads(body)
                models = [m.get("name", "") for m in (data.get("models") or [])]
                model_base = model.split(":")[0]
                found = any(model_base in m for m in models)
                if found:
                    return True, "Connected  (model found)"
                elif models:
                    return True, "Connected  (model not pulled yet)"
                else:
                    return True, "Connected  (no models pulled)"
            except Exception:
                return True, "Connected"
        except Exception as e:
            return False, str(e)[:120]

    # ── Dispatch ───────────────────────────────────────────────────────────────

    def call_api(self, provider, settings, system_prompt, user_prompt, max_tokens):
        if provider == "Anthropic":
            return self.call_anthropic(
                api_key=settings.get("anthropic_key", ""),
                model=settings.get("anthropic_model", "claude-sonnet-5"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "OpenAI":
            return self.call_openai(
                api_key=settings.get("openai_key", ""),
                model=settings.get("openai_model", "gpt-5.1"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "OpenRouter":
            return self.call_openrouter(
                api_key=settings.get("openrouter_key", ""),
                model=settings.get("openrouter_model", "anthropic/claude-sonnet-5"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "Gemini":
            return self.call_gemini(
                api_key=settings.get("gemini_key", ""),
                model=settings.get("gemini_model", "gemini-2.5-flash"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "Ollama":
            # Two modes: "local" (self-hosted, no auth) and "cloud" (ollama.com,
            # API key required). Base URL defaults to the mode's conventional host.
            mode = (settings.get("ollama_mode", "local") or "local").lower()
            if mode == "cloud":
                base = settings.get("ollama_base_url", "") or "https://ollama.com"
                key  = settings.get("ollama_api_key", "")
            else:
                base = settings.get("ollama_base_url", "") or "http://localhost:11434"
                key  = None
            return self.call_ollama(
                base_url=base,
                model=settings.get("ollama_model", "qwen2.5-coder:7b"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                api_key=key,
            )
        elif provider in OAI_COMPAT_MAP:
            # DeepSeek, Kimi (Moonshot), Mistral, Groq, xAI, Z.AI, Custom — one path.
            base_default, model_default = OAI_COMPAT_MAP[provider]
            key = _settings_key(provider)
            base = settings.get(key + "_base", base_default) or base_default
            if not base:
                return ("[{0}] No Base URL set. Open Settings > {0} and enter your "
                        "gateway URL (e.g. http://litellm.internal:4000/v1), then "
                        "Test Connection.").format(provider)
            return self.call_openai_compatible(
                provider_label=provider,
                base_url=base,
                api_key=settings.get(key + "_key", ""),
                model=settings.get(key + "_model", model_default),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        else:
            return "[Error] Unknown provider: {0}".format(provider)
