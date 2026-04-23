# -*- coding: utf-8 -*-
# AgenticBurp - AI-Powered Security Analysis for Burp Suite
# api_client.py — Multi-provider LLM client
# Providers: Anthropic (Claude), OpenAI, OpenRouter, Ollama, Gemini
# Written for Jython 2.7 (Burp Suite Python extension environment)

import json
import time

# Use Java's networking stack for robust HTTPS/SSL support in Jython
from java.net import URL
from java.io import BufferedReader, InputStreamReader


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


def _http_post_with_retry(url_str, headers, body_str, timeout_ms=120000,
                           max_retries=3):
    """
    Wrapper around _http_post with exponential backoff on 429 (rate limit).
    Retries up to max_retries times: waits 2s, 4s, 8s between attempts.
    """
    last_exc = None
    for attempt in range(max_retries):
        try:
            status, body = _http_post(url_str, headers, body_str, timeout_ms)
            if status == 429:
                wait = 2 ** (attempt + 1)   # 2, 4, 8 seconds
                time.sleep(wait)
                continue
            return status, body
        except Exception as e:
            last_exc = e
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    if last_exc:
        raise last_exc
    return 429, "[Rate limited after {0} retries]".format(max_retries)


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
            return (choices[0].get("message") or {}).get("content") or ""
        except Exception as e:
            return "[OpenAI Exception] {0}".format(str(e))

    # ── OpenRouter ─────────────────────────────────────────────────────────────

    def call_openrouter(self, api_key, model, system_prompt, user_prompt, max_tokens,
                        site_url="https://burp.local", site_name="AgenticBurp"):
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
            return (choices[0].get("message") or {}).get("content") or ""
        except Exception as e:
            return "[OpenRouter Exception] {0}".format(str(e))

    # ── Ollama ─────────────────────────────────────────────────────────────────

    def call_ollama(self, base_url, model, system_prompt, user_prompt, max_tokens):
        url = base_url.rstrip("/") + "/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama",
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
            return (choices[0].get("message") or {}).get("content") or ""
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
            "X-Title": "AgenticBurp",
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

    def test_ollama(self, base_url, model):
        if not base_url:
            return False, "No base URL"
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
                model=settings.get("anthropic_model", "claude-sonnet-4-6"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "OpenAI":
            return self.call_openai(
                api_key=settings.get("openai_key", ""),
                model=settings.get("openai_model", "gpt-4o"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "OpenRouter":
            return self.call_openrouter(
                api_key=settings.get("openrouter_key", ""),
                model=settings.get("openrouter_model", "anthropic/claude-sonnet-4-6"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "Gemini":
            return self.call_gemini(
                api_key=settings.get("gemini_key", ""),
                model=settings.get("gemini_model", "gemini-2.0-flash"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        elif provider == "Ollama":
            return self.call_ollama(
                base_url=settings.get("ollama_base_url", "http://localhost:11434"),
                model=settings.get("ollama_model", "qwen2.5-coder:7b"),
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
            )
        else:
            return "[Error] Unknown provider: {0}".format(provider)
