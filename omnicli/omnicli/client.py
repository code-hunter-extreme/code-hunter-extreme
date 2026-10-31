"""
Unified HTTP / SSE client for OpenAI-compatible LLM endpoints.
Handles streaming, headers, model discovery, authentication, and error reporting.
"""

from __future__ import annotations

import json
import os
import random
import time
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Generator, List, Optional

import httpx

from omnicli.config import DEFAULT_PROVIDERS, ConfigManager


_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_MAX_CHAT_ATTEMPTS = 3


class ProviderError(Exception):
    def __init__(self, provider: str, status_code: Optional[int], message: str) -> None:
        self.provider = provider
        self.status_code = status_code
        self.message = message
        super().__init__(f"[{provider.upper()}] Error {status_code or ''}: {message}")


class OmniClient:
    def __init__(self, config_manager: Optional[ConfigManager] = None) -> None:
        self.cfg = config_manager or ConfigManager()

    def _require_api_key(self, provider_id: str) -> None:
        """Fail loud before any HTTP when the provider has no key (G8).

        An empty config dir must never degrade to an unauthenticated
        request and a bare provider 401: name the env var, the
        configured count, and the config dir that was actually used.
        """
        provider_id = provider_id.lower()
        if self.cfg.provider_requires_key(provider_id) and not (
            self.cfg.has_credential(provider_id)
        ):
            raise ProviderError(
                provider_id, None, self.cfg.missing_key_message(provider_id)
            )

    def get_headers(self, provider_id: str) -> Dict[str, str]:
        provider_id = provider_id.lower()
        key = self.cfg.get_api_key(provider_id)

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OmniCLI/1.0",
        }

        # Provider-declared transport headers. Some OpenAI-compatible
        # gateways sit behind Cloudflare and reject non-browser clients
        # with error 1010; they declare a browser User-Agent here.
        # Authorization is never overridable by provider metadata — the
        # credential must come from the key store alone.
        prov = self.cfg.data.get("providers", {}).get(provider_id, {})
        extra = prov.get("extra_headers")
        if isinstance(extra, dict):
            for name, value in extra.items():
                if (
                    isinstance(name, str)
                    and isinstance(value, str)
                    and name.strip()
                    and name.lower() != "authorization"
                ):
                    headers[name] = value

        if key:
            token = key if key.lower().startswith("bearer ") else "Bearer " + key
            headers["Authorization"] = token

        if provider_id == "monkeycode":
            headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
            cookie = self.cfg.get_monkeycode_session_cookie() or key
            if cookie:
                headers["Cookie"] = f"monkeycode_ai_session={cookie}"

        if provider_id == "openrouter":
            headers["HTTP-Referer"] = os.environ.get(
                "OMNICLI_HTTP_REFERER",
                "https://github.com/code-hunter-extreme/omnicli",
            )
            headers["X-Title"] = "OmniCLI Local Assistant"

        return headers

    def get_endpoint_url(self, provider_id: str, path: str) -> str:
        base = self.cfg.get_base_url(provider_id).rstrip("/")
        path = path.lstrip("/")
        return f"{base}/{path}"

    def provider_supports_temperature(self, provider_id: str) -> bool:
        """False when the provider/model rejects an explicit temperature.

        Defaults to True. Configs written before the flag existed fall back
        to the shipped default. Providers such as CometAPI's ``auto`` router
        return 400 for any non-default temperature, so callers omit it.
        """
        provider_id = provider_id.lower()
        prov = self.cfg.data.get("providers", {}).get(provider_id, {})
        if "supports_temperature" not in prov:
            prov = DEFAULT_PROVIDERS.get(provider_id, prov)
        return prov.get("supports_temperature") is not False

    @staticmethod
    def _retry_delay(response: Optional[httpx.Response], attempt: int) -> float:
        retry_after = response.headers.get("Retry-After") if response is not None else None
        if retry_after:
            try:
                return min(max(float(retry_after), 0.0), 10.0)
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after).timestamp()
                    return min(max(retry_at - time.time(), 0.0), 10.0)
                except (TypeError, ValueError, OverflowError):
                    pass
        return min((1.5 ** attempt) + random.uniform(0.1, 0.4), 10.0)

    def post_chat_completion(
        self,
        url: str,
        headers: Dict[str, str],
        payload: Dict[str, Any],
        timeout: float,
    ) -> httpx.Response:
        """POST a chat request with bounded retries for transient failures only."""
        with httpx.Client(timeout=timeout) as client:
            response: Optional[httpx.Response] = None
            for attempt in range(_MAX_CHAT_ATTEMPTS):
                try:
                    response = client.post(url, headers=headers, json=payload)
                except httpx.RequestError:
                    if attempt + 1 == _MAX_CHAT_ATTEMPTS:
                        raise
                    time.sleep(self._retry_delay(None, attempt))
                    continue

                if (
                    response.status_code not in _RETRYABLE_STATUS_CODES
                    or attempt + 1 == _MAX_CHAT_ATTEMPTS
                ):
                    return response
                time.sleep(self._retry_delay(response, attempt))

        if response is None:
            raise ProviderError("", None, "Chat request ended without a response")
        return response

    def list_models(self, provider_id: str, timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Fetch available models from the provider.

        Cloudflare uses a different endpoint than the OpenAI-compatible /models:
          GET /accounts/{id}/ai/models/search?task=Text+Generation&per_page=100
        MonkeyCode uses the user models endpoint:
          GET https://monkeycode-ai.net/api/v1/users/models
        All other providers use the standard /v1/models path.
        """
        provider_id = provider_id.lower()

        if provider_id == "cloudflare":
            account_id = self.cfg.get_cloudflare_account_id()
            if not account_id:
                raise ProviderError(
                    provider_id, None,
                    "Cloudflare Account ID not set. Run: omni config set-account <ACCOUNT_ID>",
                )
            return self._list_cloudflare_models(account_id, timeout=timeout)

        if provider_id == "monkeycode":
            return self._list_monkeycode_models(timeout=timeout)

        if provider_id == "databricks":
            base = self.cfg.get_base_url(provider_id).split("/serving-endpoints")[0].rstrip("/")
            url = f"{base}/api/2.0/serving-endpoints"
            headers = self.get_headers(provider_id)
            try:
                with httpx.Client(timeout=timeout) as client:
                    res = client.get(url, headers=headers)
                    if res.status_code == 200:
                        endpoints = res.json().get("endpoints", [])
                        return [{"id": ep.get("name", ""), "name": ep.get("name", "")} for ep in endpoints]
                    if res.status_code in (401, 403):
                        raise ProviderError(provider_id, res.status_code, "Authentication failed for Databricks")
                    raise ProviderError(provider_id, res.status_code, res.text[:200])
            except httpx.RequestError as e:
                raise ProviderError(provider_id, None, f"Connection error: {e}")

        # Pollinations: use /models endpoint (not /v1/models which returns HTML)
        # Returns: [{"name": "...", "description": "...", "reasoning": true, ...}]
        if provider_id == "pollinations":
            url = self.cfg.get_base_url(provider_id).rstrip("/") + "/models"
            headers = self.get_headers(provider_id)
            try:
                with httpx.Client(timeout=timeout) as client:
                    res = client.get(url, headers=headers)
                    if res.status_code in (401, 403):
                        raise ProviderError(
                            provider_id, res.status_code,
                            f"Authentication required for {provider_id}. "
                            f"Set key via: omni config set-key {provider_id} <KEY>",
                        )
                    if res.status_code != 200:
                        raise ProviderError(provider_id, res.status_code, res.text[:300])

                    data = res.json()
                    # Transform Pollinations format to OpenAI-compatible format
                    if isinstance(data, list):
                        return [
                            {
                                "id": m.get("name", ""),
                                "object": "model",
                                "owned_by": "pollinations",
                                "description": m.get("description", ""),
                                "reasoning": m.get("reasoning", False),
                                "tier": m.get("tier", ""),
                                "community": m.get("community", False),
                            }
                            for m in data
                        ]
                    return []
            except httpx.RequestError as e:
                raise ProviderError(provider_id, None, f"Network connection failed: {e}")

        url = self.get_endpoint_url(provider_id, "models")
        headers = self.get_headers(provider_id)

        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.get(url, headers=headers)
                if res.status_code in (401, 403):
                    raise ProviderError(
                        provider_id, res.status_code,
                        f"Authentication required for {provider_id}. "
                        f"Set key via: omni config set-key {provider_id} <KEY>",
                    )
                if res.status_code != 200:
                    raise ProviderError(provider_id, res.status_code, res.text[:300])

                data = res.json()
                if isinstance(data, list):
                    return data
                if isinstance(data, dict):
                    if "data" in data and isinstance(data["data"], list):
                        return data["data"]
                    if "models" in data and isinstance(data["models"], list):
                        return data["models"]
                    if "result" in data and isinstance(data["result"], list):
                        return data["result"]
                    return []
                return []
        except httpx.RequestError as e:
            raise ProviderError(provider_id, None, f"Network connection failed: {e}")

    def _list_cloudflare_models(self, account_id: str, timeout: float = 10.0) -> List[Dict[str, Any]]:
        """Cloudflare model listing via /ai/models/search — returns text-generation models only.

        The standard /ai/v1/models returns 405. Cloudflare's actual catalog endpoint is:
          GET /accounts/{id}/ai/models/search?task=Text+Generation&per_page=100
        Returns OpenAI-compatible dicts: {"id": model_name, ...}
        """
        base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
        url = f"{base}/ai/models/search"
        headers = self.get_headers("cloudflare")
        params = {"task": "Text Generation", "per_page": "100"}

        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.get(url, headers=headers, params=params)
                if res.status_code in (401, 403):
                    raise ProviderError("cloudflare", res.status_code, "Authentication failed")
                if res.status_code != 200:
                    raise ProviderError("cloudflare", res.status_code, res.text[:300])
                data = res.json()
                raw = data.get("result", []) if isinstance(data, dict) else []
                # Normalise to OpenAI-compatible shape: {"id": name, "name": name, ...}
                return [
                    {
                        "id":   m.get("name", ""),
                        "name": m.get("name", ""),
                        "description": m.get("description", ""),
                    }
                    for m in raw
                    if m.get("name")
                ]
        except httpx.RequestError as e:
            raise ProviderError("cloudflare", None, f"Network connection failed: {e}")

    def _list_monkeycode_models(self, timeout: float = 10.0) -> List[Dict[str, Any]]:
        """MonkeyCode model listing via /api/v1/users/models using session cookie."""
        url = "https://monkeycode-ai.net/api/v1/users/models"
        cookie = self.cfg.get_monkeycode_session_cookie() or self.cfg.get_api_key("monkeycode")
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        }
        if cookie:
            headers["Cookie"] = f"monkeycode_ai_session={cookie}"
        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    models = data.get("data", {}).get("models", [])
                    # Tier-aware filter: prioritize basic/free tier models with OpenAI-compatible interface
                    accessible = [
                        m for m in models
                        if (m.get("is_free") or m.get("access_level") in ("basic", "free", ""))
                        and m.get("interface_type") in ("openai_responses", "openai", "")
                    ]
                    chosen = accessible if accessible else models
                    return [
                        {
                            "id": m.get("model", ""),
                            "name": m.get("model", ""),
                            "access_level": m.get("access_level", ""),
                            "is_free": m.get("is_free", False),
                            "interface_type": m.get("interface_type", ""),
                        }
                        for m in chosen
                        if m.get("model")
                    ]
                if res.status_code in (401, 403):
                    raise ProviderError("monkeycode", res.status_code, "Authentication failed for MonkeyCode")
                raise ProviderError("monkeycode", res.status_code, res.text[:300])
        except httpx.RequestError as e:
            raise ProviderError("monkeycode", None, f"Network connection failed: {e}")

    def ping(self, provider_id: str) -> Dict[str, Any]:
        """Test provider connectivity, measure latency, and count models."""
        provider_id = provider_id.lower()
        has_key = bool(self.cfg.get_api_key(provider_id))

        if provider_id == "cloudflare" and not self.cfg.get_cloudflare_account_id():
            return {
                "status": "config_needed",
                "code": None,
                "latency_ms": None,
                "model_count": 0,
                "has_key": has_key,
                "error": "Set account ID: omni config set-account <ID>",
            }

        t0 = time.perf_counter()
        if provider_id in ("cloudflare", "monkeycode", "databricks"):
            try:
                models = self.list_models(provider_id, timeout=5.0)
                latency = round((time.perf_counter() - t0) * 1000, 1)
                return {
                    "status": "healthy",
                    "code": 200,
                    "latency_ms": latency,
                    "model_count": len(models),
                    "has_key": has_key,
                    "error": None,
                }
            except ProviderError as pe:
                latency = round((time.perf_counter() - t0) * 1000, 1)
                return {
                    "status": f"http_{pe.status_code}" if pe.status_code else "unreachable",
                    "code": pe.status_code,
                    "latency_ms": latency,
                    "model_count": 0,
                    "has_key": has_key,
                    "error": pe.message[:120],
                }
            except Exception as e:
                latency = round((time.perf_counter() - t0) * 1000, 1)
                return {
                    "status": "unreachable",
                    "code": None,
                    "latency_ms": latency,
                    "model_count": 0,
                    "has_key": has_key,
                    "error": str(e),
                }

        url = self.get_endpoint_url(provider_id, "models")
        headers = self.get_headers(provider_id)

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.get(url, headers=headers)
                latency = round((time.perf_counter() - t0) * 1000, 1)

                if res.status_code == 200:
                    try:
                        data = res.json()
                        count = len(data.get("data", data.get("result", [])))
                    except Exception:
                        count = 0
                    return {
                        "status": "healthy",
                        "code": 200,
                        "latency_ms": latency,
                        "model_count": count,
                        "has_key": has_key,
                        "error": None,
                    }
                elif res.status_code in (401, 403):
                    return {
                        "status": "unauthorized" if has_key else "missing_key",
                        "code": res.status_code,
                        "latency_ms": latency,
                        "model_count": 0,
                        "has_key": has_key,
                        "error": "Authentication failed or key missing",
                    }
                else:
                    return {
                        "status": f"http_{res.status_code}",
                        "code": res.status_code,
                        "latency_ms": latency,
                        "model_count": 0,
                        "has_key": has_key,
                        "error": res.text[:120],
                    }
        except httpx.RequestError as e:
            latency = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "status": "unreachable",
                "code": None,
                "latency_ms": latency,
                "model_count": 0,
                "has_key": has_key,
                "error": str(e),
            }

    def chat_complete(
        self,
        provider_id: str,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        timeout: float = 60.0,
    ) -> Dict[str, Any]:
        """Perform a non-streaming chat completion."""
        provider_id = provider_id.lower()
        self._require_api_key(provider_id)
        model_name = model or self.cfg.get_default_model(provider_id)
        url = self.get_endpoint_url(provider_id, "chat/completions")
        headers = self.get_headers(provider_id)

        msgs = list(messages)
        if provider_id == "monkeycode":
            secret = self.cfg.get_monkeycode_signing_secret()
            if secret:
                import hmac, hashlib
                sys_prompt = next((m.get("content", "") for m in msgs if m.get("role") in ("system", "developer")), "")
                if not sys_prompt:
                    sys_prompt = "You are a helpful assistant."
                    msgs = [{"role": "system", "content": sys_prompt}] + msgs
                sig = "v1=" + hmac.new(secret.encode("utf-8"), sys_prompt.encode("utf-8"), hashlib.sha256).hexdigest()
                headers["X-OhMyAgent-Signature"] = sig

        payload: Dict[str, Any] = {
            "model": model_name,
            "messages": msgs,
            "stream": False,
        }
        if self.provider_supports_temperature(provider_id):
            payload["temperature"] = temperature
        if max_tokens:
            payload["max_tokens"] = max_tokens

        try:
            res = self.post_chat_completion(url, headers, payload, timeout)
            if res.status_code != 200:
                # Do NOT silently substitute a different model on
                # model_not_found and return it under the requested name:
                # callers (red-team scoring) attribute the output to the model
                # they asked for, so a swap mislabels which model produced it.
                # Fail loudly and let the caller pick a valid model.
                raise ProviderError(provider_id, res.status_code, res.text)
            return res.json()
        except httpx.RequestError as e:
            raise ProviderError(provider_id, None, f"Request failed: {e}")

    def chat_stream(
        self,
        provider_id: str,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        timeout: float = 90.0,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Stream chat completions token by token.
        Yields dict with {"type": "content"|"usage"|"error", "delta": "...", "raw": ...}
        """
        provider_id = provider_id.lower()
        try:
            self._require_api_key(provider_id)
        except ProviderError as exc:
            yield {"type": "error", "status_code": None, "content": str(exc)}
            return
        model_name = model or self.cfg.get_default_model(provider_id)
        url = self.get_endpoint_url(provider_id, "chat/completions")
        headers = self.get_headers(provider_id)

        msgs = list(messages)
        if provider_id == "monkeycode":
            secret = self.cfg.get_monkeycode_signing_secret()
            if secret:
                import hmac, hashlib
                sys_prompt = next((m.get("content", "") for m in msgs if m.get("role") in ("system", "developer")), "")
                if not sys_prompt:
                    sys_prompt = "You are a helpful assistant."
                    msgs = [{"role": "system", "content": sys_prompt}] + msgs
                sig = "v1=" + hmac.new(secret.encode("utf-8"), sys_prompt.encode("utf-8"), hashlib.sha256).hexdigest()
                headers["X-OhMyAgent-Signature"] = sig

        payload: Dict[str, Any] = {
            "model": model_name,
            "messages": msgs,
            "stream": True,
        }
        if self.provider_supports_temperature(provider_id):
            payload["temperature"] = temperature
        if max_tokens:
            payload["max_tokens"] = max_tokens

        try:
            with httpx.Client(timeout=timeout) as client:
                with client.stream("POST", url, headers=headers, json=payload) as response:
                    if response.status_code != 200:
                        err_body = response.read().decode("utf-8", errors="replace")
                        # Do NOT silently substitute a different model on
                        # model_not_found: the stream would be attributed to the
                        # requested model though another produced it. Surface the
                        # error loudly so the caller picks a valid model.
                        yield {
                            "type": "error",
                            "status_code": response.status_code,
                            "content": f"Provider error ({response.status_code}): {err_body}",
                        }
                        return

                    for line in response.iter_lines():
                        if not line:
                            continue
                        line_str = line.strip()
                        if line_str.startswith("data: "):
                            data_chunk = line_str[6:].strip()
                            if data_chunk == "[DONE]":
                                break
                            try:
                                parsed = json.loads(data_chunk)
                                choices = parsed.get("choices", [])
                                if choices:
                                    delta = choices[0].get("delta", {})
                                    content = delta.get("content", "")
                                    if content is not None and content != "":
                                        yield {"type": "content", "delta": str(content), "raw": parsed}
                                if "usage" in parsed and parsed["usage"]:
                                    yield {"type": "usage", "usage": parsed["usage"]}
                            except json.JSONDecodeError:
                                continue
        except httpx.RequestError as e:
            yield {"type": "error", "content": f"Connection error: {e}"}
