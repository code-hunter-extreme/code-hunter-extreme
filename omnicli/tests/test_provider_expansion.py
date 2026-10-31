"""Provider expansion (2026-10): definitions, headers, keys, payload flags.

The operator added 14 gateways. These tests pin the contract every provider
definition must satisfy, plus the two per-provider flags the expansion
introduced:

* ``extra_headers`` — Cloudflare-fronted gateways (aionlabs, airforce,
  tokenrouter) reject non-browser clients with error 1010. Provider metadata
  may set a browser User-Agent, but must never be able to override
  ``Authorization``.
* ``supports_temperature`` — CometAPI's ``auto`` router rejects any explicit
  temperature with 400 unsupported_value, so the client omits it.

Also pinned: ``key_required: false`` marks a public gateway (OVHcloud) whose
optional token must not fail the empty-key preflight, including for configs
written before the flag existed.
"""

import copy

import pytest

from omnicli import config as cfgmod
from omnicli.client import OmniClient
from omnicli.config import DEFAULT_PROVIDERS, ConfigManager

NEW_PROVIDERS = [
    "ovhcloud",
    "aionlabs",
    "cohere",
    "gonkabroker",
    "kilo",
    "modelscope",
    "airforce",
    "orcarouter",
    "tokenrouter",
    "haimaker",
    "publicai",
    "cometapi",
    "nanogpt",
    "requesty",
]

REQUIRED_FIELDS = [
    "name",
    "base_url",
    "default_model",
    "description",
    "requires_auth_for_models",
    "fallback_models",
    "verification_panel",
]


def _mgr(tmp_path, monkeypatch):
    monkeypatch.setattr(cfgmod, "TRIO_KEYS_FILE", tmp_path / "no-trio.env")
    monkeypatch.delenv("OMNICLI_KEYS_FILE", raising=False)
    monkeypatch.delenv("OMNICLI_CONFIG_DIR", raising=False)
    return ConfigManager(config_dir=tmp_path / "cfg")


@pytest.mark.parametrize("pid", NEW_PROVIDERS)
def test_provider_definition_complete(pid):
    prov = DEFAULT_PROVIDERS[pid]
    for field in REQUIRED_FIELDS:
        assert field in prov, f"{pid} missing {field}"
    assert prov["base_url"].startswith("https://"), pid
    assert prov["default_model"], pid
    # A provider that needs a key must declare where the key comes from.
    if prov.get("key_required") is not False:
        assert prov.get("env_key"), pid


@pytest.mark.parametrize("pid", NEW_PROVIDERS)
def test_provider_key_roundtrip(tmp_path, monkeypatch, pid):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.set_api_key(pid, "test-key-" + pid)
    assert mgr.get_api_key(pid) == "test-key-" + pid


def test_ovhcloud_is_public_without_key(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    assert mgr.provider_requires_key("ovhcloud") is False
    # A legacy config entry written before the flag existed still falls back
    # to the shipped default: absence of an optional token is not an error.
    mgr.data["providers"]["ovhcloud"] = {
        "env_key": "OVH_AI_ENDPOINTS_ACCESS_TOKEN"
    }
    assert mgr.provider_requires_key("ovhcloud") is False


def test_extra_headers_applied_but_cannot_override_authorization(
    tmp_path, monkeypatch
):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.data["providers"]["aionlabs"] = copy.deepcopy(
        DEFAULT_PROVIDERS["aionlabs"]
    )
    mgr.data["providers"]["aionlabs"]["extra_headers"]["Authorization"] = (
        "Bearer attacker-controlled"
    )
    mgr.set_api_key("aionlabs", "real-key")
    headers = OmniClient(mgr).get_headers("aionlabs")
    assert "Mozilla" in headers["User-Agent"]
    assert headers["Authorization"] == "Bearer real-key"


def test_extra_headers_absent_keeps_default_ua(tmp_path, monkeypatch):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.data["providers"]["cohere"] = copy.deepcopy(DEFAULT_PROVIDERS["cohere"])
    mgr.set_api_key("cohere", "k")
    headers = OmniClient(mgr).get_headers("cohere")
    assert headers["User-Agent"] == "OmniCLI/1.0"


class _FakeResponse:
    status_code = 200
    text = "{}"

    def json(self):
        return {"choices": [{"message": {"content": "OK"}}]}


def _capture_chat(tmp_path, monkeypatch, provider_id):
    mgr = _mgr(tmp_path, monkeypatch)
    mgr.data["providers"][provider_id] = copy.deepcopy(
        DEFAULT_PROVIDERS[provider_id]
    )
    mgr.set_api_key(provider_id, "k")
    client = OmniClient(mgr)
    captured = {}

    def fake_post(url, headers, payload, timeout):
        captured.update(payload)
        captured["__url"] = url
        return _FakeResponse()

    client.post_chat_completion = fake_post
    out = client.chat_complete(
        provider_id, [{"role": "user", "content": "hi"}], max_tokens=8
    )
    return captured, out


def test_cometapi_omits_temperature_in_payload(tmp_path, monkeypatch):
    captured, out = _capture_chat(tmp_path, monkeypatch, "cometapi")
    assert "temperature" not in captured
    assert captured["model"] == "auto"
    assert captured["__url"].endswith("/v1/chat/completions")
    assert out["choices"][0]["message"]["content"] == "OK"


def test_regular_provider_still_sends_temperature(tmp_path, monkeypatch):
    captured, _ = _capture_chat(tmp_path, monkeypatch, "cohere")
    assert captured["temperature"] == 0.7
    assert captured["__url"] == (
        "https://api.cohere.com/compatibility/v1/chat/completions"
    )


def test_legacy_config_gains_new_providers_on_load(tmp_path, monkeypatch):
    """An existing config.json (pre-expansion) is merged, never replaced."""
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.json").write_text(
        '{"default_provider": "groq", "providers": {"groq": '
        + '{"name": "Groq", "base_url": "https://api.groq.com/openai/v1", '
        + '"env_key": "GROQ_API_KEY", "default_model": "m"}}, "keys": {}}'
    )
    monkeypatch.setattr(cfgmod, "TRIO_KEYS_FILE", tmp_path / "no-trio.env")
    monkeypatch.delenv("OMNICLI_KEYS_FILE", raising=False)
    monkeypatch.delenv("OMNICLI_CONFIG_DIR", raising=False)
    mgr = ConfigManager(config_dir=cfg_dir)
    for pid in NEW_PROVIDERS:
        assert pid in mgr.data["providers"], pid
    # Existing provider untouched.
    assert mgr.data["providers"]["groq"]["name"] == "Groq"
