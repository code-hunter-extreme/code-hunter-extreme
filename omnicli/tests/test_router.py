"""Health-aware provider routing contract.

With dozens of configured gateways a red-team panel must not fan out to
every key: balance-gated, throttled and unreachable providers waste calls
and can fail a family-diversity gate. The router ranks locally known
health, remembers recent failures, and caps the default panel.

All tests are offline: health comes from a heartbeat-shaped JSON file and
the failure cache is a temp file.
"""

from __future__ import annotations

import json
from pathlib import Path

from omnicli.orchestrate import build_swarm
from omnicli.router import (
    ACCOUNT_FAILURE_TTL_S,
    DEFAULT_PANEL_CAP,
    FAILURE_TTL_S,
    ProviderRouter,
    classify_failure,
)


class FakeCfg:
    def __init__(self, providers, config_dir, keys=None, public=()):
        self.data = {"providers": providers}
        self.config_dir = Path(config_dir)
        self._keys = set(providers) if keys is None else set(keys)
        self._public = set(public)

    def has_credential(self, provider_id):
        return provider_id in self._keys

    def provider_requires_key(self, provider_id):
        return provider_id not in self._public

    def get_heartbeat_config(self):
        return {"status_file": str(self.config_dir / "heartbeat.json")}

    def get_default_model(self, provider_id):
        prov = self.data["providers"].get(provider_id)
        return prov.get("default_model", "") if prov else ""

    def get_fallback_models(self, provider_id):
        prov = self.data["providers"].get(provider_id)
        return list(prov.get("fallback_models", [])) if prov else []


MODELS = [
    "openai/gpt-4o",
    "anthropic/claude-3-5-sonnet",
    "google/gemini-1.5-pro",
    "meta/llama-3.1-70b",
    "mistral/mistral-large",
    "qwen/qwen-2.5-72b",
    "deepseek/deepseek-chat",
    "xai/grok-2",
    "cohere/command-r-plus",
    "microsoft/phi-4",
]


def _providers(count):
    return {
        f"p{i}": {
            "default_model": MODELS[i % len(MODELS)],
            "fallback_models": [],
        }
        for i in range(count)
    }


def _cfg(tmp_path, count=3, **kwargs):
    return FakeCfg(_providers(count), tmp_path, **kwargs)


def _write_heartbeat(cfg, records):
    (cfg.config_dir / "heartbeat.json").write_text(
        json.dumps({"providers": records}), encoding="utf-8"
    )


# --------------------------------------------------------------- classification


def test_classify_failure_categories():
    assert classify_failure("402 insufficient balance") == "balance"
    assert classify_failure("401 Unauthorized") == "auth"
    assert classify_failure("error code: 1010") == "auth"
    assert classify_failure("429 too many requests") == "throttle"
    assert classify_failure("connection timeout") == "unreachable"
    assert classify_failure("503 upstream error") == "server"
    assert classify_failure("something odd") == "unknown"
    assert classify_failure(None) == "unknown"


# ---------------------------------------------------------------------- health


def test_heartbeat_health_is_normalized(tmp_path):
    cfg = _cfg(tmp_path)
    _write_heartbeat(
        cfg,
        [
            {"provider": "p0", "status": "healthy"},
            {"provider": "p1", "status": "unreachable"},
            {"provider": "p2", "status": "http_429"},
        ],
    )
    health = ProviderRouter(cfg).health()
    assert health["p0"] == "healthy"
    assert health["p1"] == "unhealthy"
    assert health["p2"] == "degraded"


def test_failed_canary_marks_provider_unhealthy(tmp_path):
    """/models can answer while chat is balance-gated; trust the canary."""
    cfg = _cfg(tmp_path)
    _write_heartbeat(
        cfg,
        [
            {
                "provider": "p0",
                "status": "healthy",
                "canary": {"ok": False, "error": "402 insufficient balance"},
            },
            {
                "provider": "p1",
                "status": "healthy",
                "canary": {"ok": True, "reply": "OK"},
            },
        ],
    )
    health = ProviderRouter(cfg).health()
    assert health["p0"] == "unhealthy"
    assert health["p1"] == "healthy"


def test_unhealthy_providers_rank_last(tmp_path):
    cfg = _cfg(tmp_path)
    _write_heartbeat(
        cfg,
        [
            {"provider": "p0", "status": "unreachable"},
            {"provider": "p1", "status": "healthy"},
        ],
    )
    assert ProviderRouter(cfg).ranked_providers() == ["p1", "p2", "p0"]


def test_http_balance_status_is_unhealthy(tmp_path):
    cfg = _cfg(tmp_path)
    _write_heartbeat(
        cfg,
        [
            {"provider": "p0", "status": "http_402"},
            {"provider": "p1", "status": "http_429"},
        ],
    )
    health = ProviderRouter(cfg).health()
    assert health["p0"] == "unhealthy"
    assert health["p1"] == "degraded"


def test_ranked_providers_prefers_unique_families(tmp_path):
    providers = {
        "a": {"default_model": "openai/gpt-4o", "fallback_models": []},
        "b": {"default_model": "openai/gpt-4o-mini", "fallback_models": []},
        "c": {"default_model": "anthropic/claude-3-5-sonnet", "fallback_models": []},
        "d": {"default_model": "google/gemini-1.5-pro", "fallback_models": []},
    }
    cfg = FakeCfg(providers, tmp_path)
    assert ProviderRouter(cfg).ranked_providers() == ["a", "c", "d", "b"]


def test_primary_family_handles_unknown_provider(tmp_path):
    """ConfigManager raises KeyError for unknown ids; routing must not crash."""
    class StrictCfg(FakeCfg):
        def get_default_model(self, provider_id):
            if provider_id not in self.data["providers"]:
                raise KeyError(provider_id)
            return super().get_default_model(provider_id)

    cfg = StrictCfg(_providers(1), tmp_path)
    assert ProviderRouter(cfg)._primary_family("nope") == "other"


def test_dead_unique_family_stays_behind_healthy_duplicate(tmp_path):
    providers = {
        "a": {"default_model": "openai/gpt-4o", "fallback_models": []},
        "b": {"default_model": "openai/gpt-4o-mini", "fallback_models": []},
        "c": {"default_model": "anthropic/claude-3-5-sonnet", "fallback_models": []},
    }
    cfg = FakeCfg(providers, tmp_path)
    _write_heartbeat(
        cfg,
        [
            {"provider": "a", "status": "healthy"},
            {"provider": "b", "status": "healthy"},
            {"provider": "c", "status": "unreachable"},
        ],
    )
    assert ProviderRouter(cfg).ranked_providers() == ["a", "b", "c"]


def test_recent_failure_overrides_healthy_heartbeat(tmp_path):
    cfg = _cfg(tmp_path)
    _write_heartbeat(cfg, [{"provider": "p0", "status": "healthy"}])
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "402 insufficient balance")
    assert router.health()["p0"] == "unhealthy"
    assert router.tier("p0") == 3


# ---------------------------------------------------------------- failure memory


def test_transient_failure_expires(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "429 rate limit")
    assert "p0" in router.failures()
    later = ProviderRouter(cfg, now=1000 + FAILURE_TTL_S + 1)
    assert "p0" not in later.failures()


def test_account_failure_is_sticky_for_a_day(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "402 insufficient balance")
    later = ProviderRouter(cfg, now=1000 + FAILURE_TTL_S + 1)
    assert "p0" in later.failures()
    much_later = ProviderRouter(cfg, now=1000 + ACCOUNT_FAILURE_TTL_S + 1)
    assert "p0" not in much_later.failures()


def test_success_clears_failure_memory(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "503 upstream")
    router.record_success("p0")
    assert "p0" not in router.failures()


def test_record_results_updates_failure_memory(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p1", "429 rate limit")
    router.record_results(
        [
            {"provider": "p0", "error": "402 insufficient balance", "answer": ""},
            {"provider": "p1", "error": None, "answer": "fine"},
        ]
    )
    failures = router.failures()
    assert failures["p0"]["reason"] == "balance"
    assert "p1" not in failures


def test_corrupt_health_files_are_ignored(tmp_path):
    cfg = _cfg(tmp_path)
    (cfg.config_dir / "heartbeat.json").write_text("{not json", encoding="utf-8")
    (cfg.config_dir / "provider_failures.json").write_text("[1,2", encoding="utf-8")
    router = ProviderRouter(cfg)
    assert router.health() == {}
    assert router.failures() == {}
    assert router.ranked_providers() == ["p0", "p1", "p2"]


def test_unwritable_failure_cache_never_raises(tmp_path):
    cfg = _cfg(tmp_path)
    # Make the cache path a directory so the atomic replace fails.
    (cfg.config_dir / "provider_failures.json").mkdir()
    ProviderRouter(cfg, now=1000).record_failure("p0", "429")
    # Reaching here is the assertion: routing memory is best-effort.


# ------------------------------------------------------------------- selection


def test_default_panel_is_capped(tmp_path):
    cfg = _cfg(tmp_path, count=DEFAULT_PANEL_CAP + 4)
    panel = ProviderRouter(cfg).build_panel()
    assert len(panel) == DEFAULT_PANEL_CAP
    assert len({provider for provider, _ in panel}) == DEFAULT_PANEL_CAP


def test_explicit_size_is_honored(tmp_path):
    cfg = _cfg(tmp_path, count=5)
    panel = ProviderRouter(cfg).build_panel(size=2)
    assert len(panel) == 2


def test_failed_provider_is_skipped_when_healthy_set_fills_panel(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "402 insufficient balance")
    panel = router.build_panel(size=2)
    assert [provider for provider, _ in panel] == ["p1", "p2"]


def test_failed_provider_backfills_when_needed(tmp_path):
    cfg = _cfg(tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "402 insufficient balance")
    panel = router.build_panel(size=3)
    assert {provider for provider, _ in panel} == {"p0", "p1", "p2"}


def test_healthy_provider_extra_models_fill_before_failed_providers(tmp_path):
    providers = {
        "p0": {"default_model": "openai/gpt-4o", "fallback_models": []},
        "p1": {
            "default_model": "anthropic/claude-3-5-sonnet",
            "fallback_models": ["google/gemini-1.5-pro"],
        },
    }
    cfg = FakeCfg(providers, tmp_path)
    router = ProviderRouter(cfg, now=1000)
    router.record_failure("p0", "402 insufficient balance")
    panel = router.build_panel(size=2)
    assert [provider for provider, _ in panel] == ["p1", "p1"]


def test_provider_filter_limits_the_panel(tmp_path):
    cfg = _cfg(tmp_path)
    panel = ProviderRouter(cfg).build_panel(size=3, provider="p1")
    assert [provider for provider, _ in panel] == ["p1"]


def test_unknown_provider_filter_returns_empty(tmp_path):
    cfg = _cfg(tmp_path)
    assert ProviderRouter(cfg).build_panel(provider="nope") == []


def test_keyless_public_provider_is_usable(tmp_path):
    providers = {
        "public": {"default_model": "openai/gpt-4o", "fallback_models": []},
        "paid": {"default_model": "anthropic/claude-3-5-sonnet", "fallback_models": []},
    }
    cfg = FakeCfg(providers, tmp_path, keys={"paid"}, public={"public"})
    assert ProviderRouter(cfg).usable_providers() == ["public", "paid"]


def test_no_credentials_falls_back_to_all_providers(tmp_path):
    """Never return an empty panel just because keys are missing."""
    cfg = _cfg(tmp_path, keys=set())
    assert ProviderRouter(cfg).usable_providers() == ["p0", "p1", "p2"]


# --------------------------------------------------------------- build_swarm


def test_build_swarm_accepts_explicit_provider_list(tmp_path):
    cfg = _cfg(tmp_path)
    swarm = build_swarm(cfg, size=2, providers=["p1", "p0"])
    assert [provider for provider, _ in swarm] == ["p1", "p0"]


def test_build_swarm_dedupes_provider_list(tmp_path):
    cfg = _cfg(tmp_path)
    swarm = build_swarm(cfg, size=3, providers=["p1", "p1", "p0"])
    assert [provider for provider, _ in swarm] == ["p1", "p0"]


def test_build_swarm_ignores_unknown_provider_ids(tmp_path):
    cfg = _cfg(tmp_path)
    swarm = build_swarm(cfg, size=2, providers=["nope", "p0"])
    assert swarm == [("p0", MODELS[0])]
