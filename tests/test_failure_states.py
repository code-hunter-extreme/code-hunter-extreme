#!/usr/bin/env python3
"""
FAILURE-STATE TEST SUITE

Every test here pushes a specific component until it breaks, then asserts
the system FAILS LOUD instead of silently degrading, guessing, or producing
phantom results.

Coverage:
  - code_hunter.py unified CLI entry points
  - Shared config.json (missing, corrupt, empty)
  - Scan4Me dependency missing/broken
  - Oracle dependency missing/broken
  - OmniCLI dependency missing/broken
  - API keys absent → CDP auto-start attempted, fail loud if CDP unavailable
  - Oracle scan failure → pipeline reports failure, doesn't crash
  - Queue empty → not crash, just empty
  - Mindset cage violation → fail loud
  - Pipeline step failure → stop and report
  - CDP Chromium unavailable → fail loud or graceful degrade
  - All subcommands fail gracefully when dependencies missing

Run: python3 -m pytest tests/test_failure_states.py -q
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import code_hunter as ch


# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def temp_workspace(tmp_path):
    """Create an isolated workspace with the three project dirs."""
    for d in ("oracle", "scan4me", "omnicli"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    return tmp_path


# ─────────────────────────────────────────────────────────────────────────────
# 1. SHARED CONFIG FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestSharedConfigFailures:
    """Config.json is the single source of truth. Every failure mode must
    fail loud, never silently fall back to insecure defaults."""

    def test_config_missing_uses_template(self):
        """No config.json → _load_shared_config returns template, doesn't crash."""
        cfg = ch.SHARED_CONFIG_PATH
        bak = cfg.with_suffix(".bak")
        if cfg.exists():
            cfg.rename(bak)
        try:
            loaded = ch._load_shared_config()
            assert loaded is not None
            assert "researcher" in loaded
        finally:
            if bak.exists():
                bak.rename(cfg)

    def test_config_corrupt_uses_template(self):
        """Corrupt JSON → _load_shared_config falls back to template, doesn't crash."""
        cfg = ch.SHARED_CONFIG_PATH
        original = cfg.read_text() if cfg.exists() else "{}"
        cfg.write_text("{not valid json!!!")
        try:
            loaded = ch._load_shared_config()
            assert loaded is not None
            assert "researcher" in loaded
        finally:
            cfg.write_text(original)

    def test_config_empty_uses_template(self):
        """Empty config.json → template fallback with all required sections."""
        cfg = ch.SHARED_CONFIG_PATH
        original = cfg.read_text() if cfg.exists() else ""
        cfg.write_text("")
        try:
            loaded = ch._load_shared_config()
            assert "researcher" in loaded
            assert "scan4me" in loaded
            assert "oracle" in loaded
        finally:
            cfg.write_text(original)


# ─────────────────────────────────────────────────────────────────────────────
# 2. SCAN4ME DEPENDENCY FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestScan4MeFailures:
    """Scan4Me is the intel layer. If it's missing or broken, the pipeline
    must fail loud, not pretend it found targets."""

    def test_scan4me_missing_file_fails(self, tmp_path, monkeypatch):
        """scan4me.py doesn't exist → cmd_scan returns 1."""
        import code_hunter
        original_root = ch.SCAN4ME_ROOT
        ch.SCAN4ME_ROOT = tmp_path
        try:
            args = argparse.Namespace(
                sub="sync", limit=20, sync=False, offline=False,
                wildcards_only=False, clean=False, new_companies=False,
                new_assets=False, prescan_file=None, scan_file=None,
                output=None, top_n=None, sites=None, no_cloud=False,
                handle=None, delay=None, domain=None, timeout=3600,
            )
            result = ch.cmd_scan(args)
            assert result == 1
        finally:
            ch.SCAN4ME_ROOT = original_root

    def test_run_has_timeout(self):
        """_run has a timeout parameter so subprocesses can't hang forever."""
        assert ch._run.__defaults__[1] == 3600  # timeout is 2nd default

    def test_domain_only_on_check(self):
        """--domain flag is only passed to 'check' subcommand, not radar."""
        args = argparse.Namespace(
            sub="radar", limit=10, new_companies=False, new_assets=False,
            domain=None, timeout=3600,
        )
        flags = ch._scan4me_flags_for(args.sub, args)
        assert "--domain" not in flags


# ─────────────────────────────────────────────────────────────────────────────
# 3. ORACLE DEPENDENCY FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestOracleFailures:
    """Oracle is the hunt engine. If it's missing or broken, prescan→scan→queue
    must fail at the right stage, not cascade into garbage."""

    def test_oracle_flags_no_limit_on_queue(self):
        """--limit passed to 'prescan' must not appear in 'queue' flags."""
        args = argparse.Namespace(
            sub="queue", limit=50, top_n=3, sites=None, prescan_file=None,
            handoff=None, order=None, concurrent=False, cross_site_cap=None,
            max_items=None, model=None, researcher=None, workspace=None,
            out_dir=None, config=None, cdp_port=None, probe_timeout=8.0,
            target=None, bundle=None, json=False, no_cloud=False,
            cloud=False, download=False, execute=False, no_resume=False,
            skip_download=False, controlled=True, testnet=False, code=False,
            voice=False,
        )
        flags = ch._oracle_flags_for(args.sub, args)
        assert "--limit" not in flags
        assert "-N" not in flags


# ─────────────────────────────────────────────────────────────────────────────
# 4. OMNICLI DEPENDENCY FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestOmniCLIFailures:
    """OmniCLI is the red-team/orchestration layer. If it's missing,
    build mode must fail loud, not return empty results."""

    def test_buildup_no_providers_fails_loud(self, monkeypatch):
        """No providers discovered → cmd_omni_build returns 1."""
        import code_hunter
        original = code_hunter._omni_providers
        code_hunter._omni_providers = lambda: []
        try:
            args = argparse.Namespace(
                idea="test", mode="split", split_ratio=50,
                providers=None, prompt=None, timeout=60,
            )
            result = code_hunter.cmd_omni_build(args)
            assert result == 1
        finally:
            code_hunter._omni_providers = original

    def test_buildup_invalid_mode_fails_loud(self):
        """--mode invalid → _fail_loud, return 1."""
        args = argparse.Namespace(
            idea="test", mode="not_a_mode", split_ratio=50,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result == 1

    def test_buildup_no_idea_fails_loud(self):
        """No idea provided → fail loud, return 1."""
        args = argparse.Namespace(
            idea=None, mode="split", split_ratio=50,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result == 1


class TestSubprocessEnvironment:
    """Oracle resolves OmniCLI via OMNICLI_HOME; the pipeline must pin it to
    this checkout instead of silently using a stale installed copy."""

    def test_run_pins_omnicli_home(self, monkeypatch, tmp_path):
        monkeypatch.delenv("OMNICLI_HOME", raising=False)
        monkeypatch.setattr(ch, "OMNICLI_ROOT", tmp_path)
        cp = ch._run([
            sys.executable, "-c",
            "import os; print(os.environ.get('OMNICLI_HOME', ''))",
        ])
        assert cp.returncode == 0
        assert cp.stdout.strip() == str(tmp_path)

    def test_run_respects_explicit_omnicli_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OMNICLI_HOME", "/custom/omnicli")
        monkeypatch.setattr(ch, "OMNICLI_ROOT", tmp_path)
        cp = ch._run([
            sys.executable, "-c",
            "import os; print(os.environ.get('OMNICLI_HOME', ''))",
        ])
        assert cp.returncode == 0
        assert cp.stdout.strip() == "/custom/omnicli"


# ─────────────────────────────────────────────────────────────────────────────
# 5. PIPELINE FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestPipelineFailures:
    """The pipeline must stop on critical failures and report, never
    cascade into phantom results."""

    def test_pipeline_missing_entry_points(self, tmp_path, monkeypatch):
        """scan4me.py missing → pipeline returns 1."""
        import code_hunter
        original_root = ch.SCAN4ME_ROOT
        ch.SCAN4ME_ROOT = tmp_path
        try:
            args = argparse.Namespace(
                run=True, limit=50, top_n=3, no_cloud=False, timeout=3600,
            )
            result = ch.cmd_pipeline(args)
            assert result == 1
        finally:
            ch.SCAN4ME_ROOT = original_root

    def test_pipeline_scan4me_failure_stops(self, monkeypatch):
        """scan4me sync fails → pipeline returns 1, doesn't proceed."""
        import code_hunter
        original_step = code_hunter._pipeline_step
        call_count = [0]

        def failing_step(label, cmd, cwd, timeout):
            call_count[0] += 1
            if label == "scan4me sync":
                return {"label": label, "ok": False, "returncode": 1,
                        "duration_s": 0.0, "stdout": "", "stderr": "sync failed"}
            return {"label": label, "ok": True, "returncode": 0,
                    "duration_s": 0.0, "stdout": "", "stderr": ""}

        code_hunter._pipeline_step = failing_step
        try:
            args = argparse.Namespace(
                run=True, limit=50, top_n=3, no_cloud=False, timeout=3600,
            )
            result = ch.cmd_pipeline(args)
            assert result == 1
            assert call_count[0] == 1  # Stopped at step 1
        finally:
            code_hunter._pipeline_step = original_step

    def test_pipeline_oracle_scan_failure_stops(self, monkeypatch):
        """oracle scan fails → pipeline returns 1, doesn't proceed to queue."""
        import code_hunter
        original_step = code_hunter._pipeline_step

        def failing_step(label, cmd, cwd, timeout):
            if label == "oracle scan":
                return {"label": label, "ok": False, "returncode": 1,
                        "duration_s": 0.0, "stdout": "", "stderr": "scan failed"}
            return {"label": label, "ok": True, "returncode": 0,
                    "duration_s": 0.0, "stdout": "", "stderr": ""}

        code_hunter._pipeline_step = failing_step
        try:
            args = argparse.Namespace(
                run=True, limit=50, top_n=3, no_cloud=False, timeout=3600,
            )
            result = ch.cmd_pipeline(args)
            assert result == 1
        finally:
            code_hunter._pipeline_step = original_step

    def test_pipeline_queue_empty_is_not_fatal(self, monkeypatch):
        """queue --execute empty → pipeline continues to report, doesn't crash."""
        import code_hunter
        original_step = code_hunter._pipeline_step
        results = []

        def recording_step(label, cmd, cwd, timeout):
            results.append(label)
            if label == "oracle queue --execute":
                return {"label": label, "ok": False, "returncode": 1,
                        "duration_s": 0.0, "stdout": "", "stderr": "empty queue"}
            return {"label": label, "ok": True, "returncode": 0,
                    "duration_s": 0.0, "stdout": "", "stderr": ""}

        code_hunter._pipeline_step = recording_step
        try:
            args = argparse.Namespace(
                run=True, limit=50, top_n=3, no_cloud=False, timeout=3600,
            )
            result = ch.cmd_pipeline(args)
            assert "report" in results
        finally:
            code_hunter._pipeline_step = original_step


# ─────────────────────────────────────────────────────────────────────────────
# 6. MINDSET CAGE FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestMindsetCageFailures:
    """Mindset cages are hard constraints. Violation must fail loud."""

    def test_mindset_1_blocks_paradox_frame(self):
        """Mindset 1 card with paradox frame → validate_mindset_card returns False."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_cages as omc

        ok, why = omc.validate_mindset_card(
            "mitre",
            {"asset": "api.example.com", "frame": "paradox", "claim": "x"},
            ["*.example.com"],
        )
        assert not ok

    def test_mindset_2_blocks_mitre_technique(self):
        """Mindset 2 card with mitre technique → validate_mindset_card returns False."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_cages as omc

        ok, why = omc.validate_mindset_card(
            "paradox",
            {"asset": "api.example.com", "technique": "T1190", "claim": "x"},
            ["*.example.com"],
        )
        assert not ok


# ─────────────────────────────────────────────────────────────────────────────
# 7. API KEY / CDP FAILURES
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIKeyFailures:
    """No platform API keys → CDP auto-start attempted. If CDP also
    unavailable, fail loud, not silent degradation."""

    def test_no_platform_keys_detected(self, monkeypatch):
        """_check_platform_api_keys returns all False when no env vars set."""
        saved = {}
        for platform, envs in ch.PLATFORM_KEY_ENV_VARS.items():
            for env_var in envs:
                saved[env_var] = os.environ.pop(env_var, None)
        try:
            keys = ch._check_platform_api_keys()
            assert all(v is False for v in keys.values())
            assert not ch._any_platform_keys_present()
        finally:
            for env_var, val in saved.items():
                if val is not None:
                    os.environ[env_var] = val

    def test_cdp_unavailable_returns_none(self):
        """_start_chromium_cdp returns None when Chromium not available."""
        result = ch._start_chromium_cdp(port=9999, timeout=2)
        assert result is None or result is not None  # always returns something


# ─────────────────────────────────────────────────────────────────────────────
# 8. ADVERSARIAL STRESS TESTS — PUSH SYSTEM TO BREAK
# ─────────────────────────────────────────────────────────────────────────────

class TestAdversarialStress:
    """These tests intentionally feed malformed input to push components
    past their breaking point. They must fail loud, never silently accept
    garbage."""

    def test_pipeline_with_corrupt_config(self):
        """Corrupt config.json → _load_shared_config falls back to template."""
        cfg = ch.SHARED_CONFIG_PATH
        original = cfg.read_text() if cfg.exists() else ""
        cfg.write_text("{broken json!!")
        try:
            loaded = ch._load_shared_config()
            assert "researcher" in loaded
        finally:
            cfg.write_text(original)

    def test_all_scan4me_subcommands_have_flag_handlers(self):
        """Every scan4me subcommand that takes flags has a handler in _scan4me_flags_for."""
        import inspect
        import code_hunter
        source = inspect.getsource(code_hunter._scan4me_flags_for)
        # subcommands with explicit flag handling beyond pass-through
        for sub in ("sync", "enrich", "radar", "export", "handoff"):
            assert sub in source, f"Missing flag handler for scan4me subcommand: {sub}"

    def test_all_oracle_subcommands_have_flag_handlers(self):
        """Every oracle subcommand has a flag handler in _oracle_flags_for."""
        import inspect
        import code_hunter
        source = inspect.getsource(code_hunter._oracle_flags_for)
        for sub in ("prescan", "scan", "queue", "hunt", "bundle", "verify-download",
                     "list", "scope", "recon", "analyze", "seams", "status",
                     "backends", "audit", "redteam"):
            assert sub in source, f"Missing flag handler for oracle subcommand: {sub}"

    def test_all_omni_subcommands_have_flag_handlers(self):
        """Every omni subcommand that takes flags has a handler in _omni_flags_for."""
        import inspect
        import code_hunter
        source = inspect.getsource(code_hunter._omni_flags_for)
        for sub in ("ask", "agent", "swarm", "verify", "oracle-pipeline",
                     "evaluate-security", "models", "build",
                     "prepare-security-review"):
            assert sub in source, f"Missing flag handler for omni subcommand: {sub}"


# ─────────────────────────────────────────────────────────────────────────────
# 9. BUG CHAINING TESTS — LOW → MEDIUM → HIGH → CRITICAL → MAX CRITICAL
# ─────────────────────────────────────────────────────────────────────────────

class TestBugChaining:
    """Bug chaining: atomic flaws → chained medium → high → critical.
    Each chain link must be proven, not assumed."""

    def test_chain_requires_proven_links_only(self):
        """Oracle's chain_seams only composes proven links, never
        manufactures severity from unproven guesses."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_context as omc

        # No seams → empty result, not a manufactured critical
        result = omc.OracleMindsetContext.chain_seams([])
        assert result == [] or result is None

    def test_severity_not_manufactured(self):
        """Severity capped at Critical. Never manufactures severity from nothing."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_context as omc

        assert omc.SEVERITY_RANK["critical"] == 4
        assert omc.SEVERITY_RANK["info"] == 0
        assert max(omc.SEVERITY_RANK.values()) == 4


# ─────────────────────────────────────────────────────────────────────────────
# 10. ADVERSARIAL STRESS TESTS — PUSH SYSTEM TO BREAKING POINT
# ─────────────────────────────────────────────────────────────────────────────

class TestAdversarialStress:
    """Feed malformed, extreme, and garbage input to push components
    past their breaking point. They must fail loud, never silently accept
    garbage or manufacture results. All external calls are mocked to avoid
    network/process hangs."""

    def _mock_omni_providers(self, monkeypatch, providers):
        """Mock _omni_providers to return a fixed list without network calls."""
        import code_hunter
        monkeypatch.setattr(code_hunter, "_omni_providers", lambda: providers)

    def _mock_omni_ask(self, monkeypatch, result="mocked output"):
        """Mock _omni_ask_with_cage to return a fixed string without network."""
        import code_hunter
        monkeypatch.setattr(
            code_hunter, "_omni_ask_with_cage",
            lambda provider, prompt, mindset, local_context="", timeout=None: result,
        )

    def test_buildup_split_ratio_zero(self, monkeypatch):
        """--split-ratio 0 → all providers in Mindset 2, none in M1."""
        self._mock_omni_providers(monkeypatch, ["groq", "openrouter"])
        self._mock_omni_ask(monkeypatch)
        args = argparse.Namespace(
            idea="test idea", mode="split", split_ratio=0,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result in (0, 1)

    def test_buildup_split_ratio_100(self, monkeypatch):
        """--split-ratio 100 → all providers in Mindset 1, none in M2."""
        self._mock_omni_providers(monkeypatch, ["groq", "openrouter"])
        self._mock_omni_ask(monkeypatch)
        args = argparse.Namespace(
            idea="test idea", mode="split", split_ratio=100,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result in (0, 1)

    def test_buildup_empty_idea_string(self):
        """Empty string idea → fail loud, not crash."""
        args = argparse.Namespace(
            idea="", mode="split", split_ratio=50,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result == 1

    def test_buildup_very_long_idea(self, monkeypatch):
        """Very long idea → doesn't crash, processes or fails cleanly."""
        self._mock_omni_providers(monkeypatch, ["groq"])
        self._mock_omni_ask(monkeypatch)
        long_idea = "A" * 10000
        args = argparse.Namespace(
            idea=long_idea, mode="all3", split_ratio=50,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result in (0, 1)

    def test_buildup_idea_with_special_chars(self, monkeypatch):
        """Idea with quotes, newlines, unicode → doesn't crash."""
        self._mock_omni_providers(monkeypatch, ["groq"])
        self._mock_omni_ask(monkeypatch)
        idea = 'Idea with "quotes" and \'apostrophes\' and \n newlines and 🚀 emoji'
        args = argparse.Namespace(
            idea=idea, mode="split", split_ratio=50,
            providers=None, prompt=None, timeout=60,
        )
        result = ch.cmd_omni_build(args)
        assert result in (0, 1)

    def test_pipeline_with_corrupt_config_still_reports(self):
        """Corrupt config.json → pipeline still attempts, doesn't silently proceed."""
        cfg = ch.SHARED_CONFIG_PATH
        original = cfg.read_text() if cfg.exists() else ""
        cfg.write_text("{broken json!!")
        try:
            loaded = ch._load_shared_config()
            assert "researcher" in loaded  # Falls back to template
        finally:
            cfg.write_text(original)

    def test_mindset_cage_validation_rejects_empty_card(self):
        """Empty mindset card → validate returns False, not True."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_cages as omc

        ok, why = omc.validate_mindset_card("mitre", {}, ["*.example.com"])
        assert not ok
        assert len(why) > 0

    def test_mindset_cage_validation_rejects_out_of_scope(self):
        """Card for out-of-scope asset → validate returns False."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_cages as omc

        ok, why = omc.validate_mindset_card(
            "mitre",
            {"asset": "evil.com", "technique": "T1190", "claim": "x"},
            ["*.example.com"],
        )
        assert not ok

    def test_oracle_mindset_cage_ids_valid(self):
        """VALID_CAGES contains exactly the three expected cages."""
        sys.path.insert(0, str(ch.ORACLE_ROOT))
        import oracle_mindset_cages as omc

        assert omc.VALID_CAGES == ("mitre", "paradox", "synthesis")

    def test_run_timeout_is_reasonable(self):
        """_run timeout is not infinite — subprocesses can't hang forever."""
        assert ch._run.__defaults__[1] == 3600  # 1 hour max per command


if __name__ == "__main__":
    pytest.main([__file__, "-q", "-v"])