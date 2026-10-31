"""Reasoning models must not answer with silence.

Some providers (AionLabs, GonkaBroker, reasoning routers) emit hidden
reasoning tokens that count against ``max_tokens``. With a small budget the
completion ends with ``finish_reason="length"`` and an EMPTY ``content``:
the model thought, then ran out before answering. The client retries once
with a larger budget instead of returning an empty string that callers
would misread as a provider failure.

These tests pin the retry envelope: only empty+length responses retry, the
budget is bounded, a failed retry never masks the original response, and a
real answer is never re-requested.
"""

from __future__ import annotations

import copy

import httpx
import pytest

from omnicli import config as cfgmod
from omnicli.client import OmniClient
from omnicli.config import DEFAULT_PROVIDERS, ConfigManager


class _Resp:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code
        self.text = "{}" if status_code == 200 else "upstream said no"

    def json(self):
        return self._data


def _payload(content: str = "", finish_reason: str = "length"):
    return {
        "choices": [
            {
                "message": {"content": content},
                "finish_reason": finish_reason,
            }
        ]
    }


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(cfgmod, "TRIO_KEYS_FILE", tmp_path / "no-trio.env")
    monkeypatch.delenv("OMNICLI_KEYS_FILE", raising=False)
    monkeypatch.delenv("OMNICLI_CONFIG_DIR", raising=False)
    mgr = ConfigManager(config_dir=tmp_path / "cfg")
    mgr.data["providers"]["aionlabs"] = copy.deepcopy(
        DEFAULT_PROVIDERS["aionlabs"]
    )
    mgr.set_api_key("aionlabs", "test-key")
    return OmniClient(mgr)


def _run(client, responses, max_tokens=32):
    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append(dict(payload))
        return responses[len(calls) - 1]

    client.post_chat_completion = fake_post
    out = client.chat_complete(
        "aionlabs",
        [{"role": "user", "content": "answer"}],
        max_tokens=max_tokens,
    )
    return calls, out


def test_empty_length_response_retries_with_bigger_budget(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, out = _run(
        client,
        [_Resp(_payload("", "length")), _Resp(_payload("real answer", "stop"))],
    )
    assert [call["max_tokens"] for call in calls] == [32, 128]
    assert out["choices"][0]["message"]["content"] == "real answer"
    assert out["_omnicli"]["reasoning_retry"] == {
        "from_max_tokens": 32,
        "to_max_tokens": 128,
    }


def test_real_content_is_never_retried(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, out = _run(client, [_Resp(_payload("answer", "stop"))])
    assert len(calls) == 1
    assert out["choices"][0]["message"]["content"] == "answer"
    assert "_omnicli" not in out


def test_empty_stop_response_is_not_retried(tmp_path, monkeypatch):
    """finish_reason=stop with empty content is a provider quirk, not budget."""
    client = _client(tmp_path, monkeypatch)
    calls, out = _run(client, [_Resp(_payload("", "stop"))])
    assert len(calls) == 1
    assert out["choices"][0]["message"]["content"] == ""


def test_budget_at_cap_is_not_retried(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, _ = _run(client, [_Resp(_payload("", "length"))], max_tokens=8192)
    assert len(calls) == 1


def test_retry_budget_is_capped(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, _ = _run(
        client,
        [_Resp(_payload("", "length")), _Resp(_payload("ok", "stop"))],
        max_tokens=4096,
    )
    assert [call["max_tokens"] for call in calls] == [4096, 8192]


def test_failed_retry_returns_original_response(tmp_path, monkeypatch):
    """A 500 on the retry must not mask the original completion."""
    client = _client(tmp_path, monkeypatch)
    original = _payload("", "length")
    calls, out = _run(
        client,
        [_Resp(original), _Resp({"error": "boom"}, status_code=500)],
    )
    assert len(calls) == 2
    assert out == original


def test_still_empty_retry_returns_retried_response(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, out = _run(
        client,
        [_Resp(_payload("", "length")), _Resp(_payload("   ", "length"))],
    )
    assert len(calls) == 2
    assert out["choices"][0]["message"]["content"] == "   "
    assert "_omnicli" not in out


def test_missing_max_tokens_does_not_retry(tmp_path, monkeypatch):
    """Without a caller budget there is nothing to raise; leave it alone."""
    client = _client(tmp_path, monkeypatch)
    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append(dict(payload))
        return _Resp(_payload("", "length"))

    client.post_chat_completion = fake_post
    out = client.chat_complete(
        "aionlabs", [{"role": "user", "content": "hi"}], max_tokens=None
    )
    assert len(calls) == 1
    assert "max_tokens" not in calls[0]
    assert out["choices"][0]["message"]["content"] == ""


def test_malformed_response_does_not_crash(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls, out = _run(client, [_Resp({"choices": []})])
    assert len(calls) == 1
    assert out == {"choices": []}


def test_retry_network_error_returns_original_response(tmp_path, monkeypatch):
    """A flaky retry must not turn a valid first response into an error."""
    client = _client(tmp_path, monkeypatch)
    original = _payload("", "length")
    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append(dict(payload))
        if len(calls) == 1:
            return _Resp(original)
        raise httpx.ConnectError("retry connection died")

    client.post_chat_completion = fake_post
    out = client.chat_complete(
        "aionlabs", [{"role": "user", "content": "hi"}], max_tokens=32
    )
    assert len(calls) == 2
    assert out == original


def test_retry_invalid_json_returns_original_response(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    original = _payload("", "length")

    class _BadJson:
        status_code = 200
        text = "{}"

        def json(self):
            raise ValueError("not json")

    calls = []

    def fake_post(url, headers, payload, timeout):
        calls.append(dict(payload))
        return _Resp(original) if len(calls) == 1 else _BadJson()

    client.post_chat_completion = fake_post
    out = client.chat_complete(
        "aionlabs", [{"role": "user", "content": "hi"}], max_tokens=32
    )
    assert len(calls) == 2
    assert out == original


def test_retry_json_must_be_an_object(tmp_path, monkeypatch):
    """A JSON array (or scalar) on retry is ignored, not merged blindly."""
    client = _client(tmp_path, monkeypatch)
    original = _payload("", "length")
    calls, out = _run(
        client,
        [_Resp(original), _Resp([{"choices": []}])],
    )
    assert len(calls) == 2
    assert out == original


@pytest.mark.parametrize("budget", [1, 2, 512])
def test_small_budgets_grow_by_factor_four(tmp_path, monkeypatch, budget):
    client = _client(tmp_path, monkeypatch)
    calls, _ = _run(
        client,
        [_Resp(_payload("", "length")), _Resp(_payload("ok", "stop"))],
        max_tokens=budget,
    )
    assert calls[1]["max_tokens"] == min(budget * 4, 8192)
