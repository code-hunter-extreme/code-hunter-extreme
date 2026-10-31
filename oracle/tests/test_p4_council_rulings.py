"""P4 rulings, Oracle side: consume the assessed council verdict.

Oracle's red-team audit must surface OmniCLI's assessed security conclusion
(never silently ignore it), and Oracle's Transition-Gate consumer must
validate the qualifying-run artifact with OmniCLI's own validator.
"""

import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter  # noqa: E402
from oracle_llm import ensure_omnicli_importable  # noqa: E402

_HAVE_OMNICLI = ensure_omnicli_importable()
requires_omnicli = pytest.mark.skipif(
    not _HAVE_OMNICLI, reason="omnicli checkout not importable"
)


def _gate(conclusion, evidence=(), counts=None):
    return {
        "status": "PASS_GROUNDING_ONLY",
        "security_conclusion": conclusion,
        "security_evidence": list(evidence),
        "verdict_counts": counts
        or {"uphold": 0, "kill": 0, "contested": 0, "unjudged": 0},
    }


def _evidence_item():
    return {
        "verdict": "UPHOLD",
        "category": "sql_injection",
        "file": "vuln.py",
        "line": 3,
        "quote": "db.execute(q)",
        "grounded": True,
        "judge": "fast:m2",
        "margin": 1.0,
    }


# ── (a) verdict consumption ─────────────────────────────────────────────


def test_format_upheld_findings_is_submission_visible():
    text, severity = oracle_hunter.format_council_verdict(
        _gate(
            "UPHELD_FINDINGS",
            [_evidence_item()],
            {"uphold": 1, "kill": 0, "contested": 0, "unjudged": 0},
        )
    )
    assert severity == "findings"
    assert "UPHELD_FINDINGS" in text
    assert "vuln.py" in text and "db.execute(q)" in text


def test_format_assessed_negative_is_not_a_clean_bill():
    text, severity = oracle_hunter.format_council_verdict(_gate("NO_UPHELD_FINDINGS"))
    assert severity == "clear"
    assert "not proof of safety" in text


@pytest.mark.parametrize("conclusion", ["CONTESTED", "UNJUDGED", "NOT_ASSESSED"])
def test_format_non_verdict_blocks_submission_readiness(conclusion):
    text, severity = oracle_hunter.format_council_verdict(_gate(conclusion))
    assert severity == "blocked"
    assert "do NOT treat this run" in text


@pytest.mark.parametrize("gate", [None, {}, {"status": "FAIL"}])
def test_format_missing_gate_blocks_loudly(gate):
    text, severity = oracle_hunter.format_council_verdict(gate)
    assert severity == "blocked"
    assert "NOT_ASSESSED" in text


@requires_omnicli
def test_cmd_redteam_displays_council_verdict(monkeypatch, capsys):
    import omnicli.orchestrate as orch

    gate = _gate(
        "UPHELD_FINDINGS",
        [_evidence_item()],
        {"uphold": 1, "kill": 0, "contested": 0, "unjudged": 0},
    )
    monkeypatch.setattr(
        orch,
        "run_orchestration",
        lambda *a, **k: {
            "final": "triage text",
            "evidence_gate": gate,
            "report_path": None,
        },
    )
    monkeypatch.setattr(oracle_hunter, "RICH", False)
    oracle_hunter.cmd_redteam("some-program", SimpleNamespace(finding=None))
    out = capsys.readouterr().out
    assert "Council Security Verdict" in out
    assert "UPHELD_FINDINGS" in out
    assert "db.execute(q)" in out


@requires_omnicli
def test_cmd_redteam_warns_on_blocked_verdict(monkeypatch, capsys):
    import omnicli.orchestrate as orch

    monkeypatch.setattr(
        orch,
        "run_orchestration",
        lambda *a, **k: {
            "final": "triage text",
            "evidence_gate": _gate("CONTESTED"),
            "report_path": None,
        },
    )
    monkeypatch.setattr(oracle_hunter, "RICH", False)
    oracle_hunter.cmd_redteam("some-program", SimpleNamespace(finding=None))
    out = capsys.readouterr().out
    assert "do NOT treat this run" in out


@requires_omnicli
def test_swarm_redteam_takes_no_contract():
    import omnicli.orchestrate as orch

    assert "contract" not in inspect.signature(orch.swarm_redteam).parameters


@requires_omnicli
def test_cmd_redteam_reports_actual_swarm_size(monkeypatch, capsys):
    import omnicli.orchestrate as orch

    gate = _gate("NO_UPHELD_FINDINGS")
    seen = {}
    monkeypatch.setattr(
        orch, "build_swarm", lambda cfg, **kw: [("p1", "m1"), ("p2", "m2")]
    )

    def fake_run(*args, **kwargs):
        seen["swarm"] = kwargs.get("swarm")
        seen["report_path"] = kwargs.get("report_path")
        return {"final": "triage text", "evidence_gate": gate, "report_path": None}

    monkeypatch.setattr(orch, "run_orchestration", fake_run)
    monkeypatch.setattr(oracle_hunter, "RICH", False)
    oracle_hunter.cmd_redteam("some-program", SimpleNamespace(finding=None))
    out = capsys.readouterr().out
    assert "2-model adversarial swarm" in out
    assert "10-model" not in out
    assert seen["swarm"] == [("p1", "m1"), ("p2", "m2")]
    assert seen["report_path"] == oracle_hunter.REPORTS_DIR


@requires_omnicli
def test_cmd_redteam_uses_health_aware_panel(monkeypatch, capsys):
    """A red-team audit must not fan out to every configured key."""
    try:
        import omnicli.router as router_mod
    except ImportError:
        pytest.skip("installed OmniCLI checkout predates the health-aware router")

    seen = {}

    class FakeRouter:
        def __init__(self, cfg):
            seen["cfg"] = cfg

        def build_panel(self, **kwargs):
            seen["panel_kwargs"] = kwargs
            return [("p1", "m1")]

    monkeypatch.setattr(router_mod, "ProviderRouter", FakeRouter)
    import omnicli.orchestrate as orch

    monkeypatch.setattr(
        orch,
        "run_orchestration",
        lambda *a, **k: {
            "final": "triage text",
            "evidence_gate": _gate("NO_UPHELD_FINDINGS"),
            "report_path": None,
        },
    )
    monkeypatch.setattr(oracle_hunter, "RICH", False)
    oracle_hunter.cmd_redteam("some-program", SimpleNamespace(finding=None))
    assert seen["panel_kwargs"] == {}
    assert "1-model adversarial swarm" in capsys.readouterr().out


def test_cmd_redteam_refuses_oversized_source(monkeypatch, tmp_path, capsys):
    huge = tmp_path / "huge.py"
    huge.write_text("x = 1\n" * (oracle_hunter.ORACLE_AUDIT_SOURCE_CAP // 6 + 10))
    with pytest.raises(SystemExit):
        oracle_hunter.cmd_redteam(str(huge), SimpleNamespace(finding=None))


# ── (b) qualifying-run consumer ─────────────────────────────────────────


def _scores(recall=0.95, specificity=0.96, citation=0.98):
    return {
        "recall": recall,
        "specificity": specificity,
        "citation_accuracy": citation,
    }


def _synthetic_pass_report():
    roster = [
        ("cloudflare", "meta-llama/llama-3.3-70b-instruct", "meta"),
        ("xkiro", "google/gemini-2.5-flash", "google"),
        ("apinex", "deepseek/deepseek-chat-v3-0324", "deepseek"),
    ]
    models = []
    for provider, model, _family in roster:
        for method in ("single_pass_model", "staged_redteam"):
            models.append(
                {
                    "provider": provider,
                    "model": model,
                    "method": method,
                    "repetitions": 2,
                    "errors": 0,
                    "evidence_gate_failures": 0,
                }
            )
    return {
        "models": models,
        "staged_council": {
            "method": "staged_redteam_council",
            "member_calls": 360,
            "errors": 0,
        },
        "quality_gate": {
            "status": "PASS_BOUNDED_GATE",
            "failures": [],
            "positive_cases": 30,
            "benign_cases": 30,
            "healthy_model_families": ["deepseek", "google", "meta"],
            "paired_models": [{"provider": p, "model": m} for p, m, _f in roster],
            "failed_models": [],
            "single_pass": _scores(),
            "staged": _scores(),
            "per_family": {
                family: {
                    "single_pass": _scores(),
                    "staged": _scores(),
                }
                for _p, _m, family in roster
            },
            "limitations": ["bounded gate"],
        },
    }


@requires_omnicli
def test_consumer_validator_accepts_pass_rejects_tampered():
    from omnicli.evaluation import validate_qualifying_run

    assert validate_qualifying_run(_synthetic_pass_report())["valid"] is True
    tampered = _synthetic_pass_report()
    tampered["quality_gate"]["healthy_model_families"] = ["meta"]
    result = validate_qualifying_run(tampered)
    assert result["valid"] is False
    assert result["failures"]


@requires_omnicli
def test_consumer_validates_real_artifact_when_present():
    import oracle_llm as llm

    home = llm.omnicli_home()
    assert home is not None
    artifact = Path(home) / "reports" / "redteam_qualifying_run.json"
    if not artifact.is_file():
        pytest.skip(
            "no qualifying run yet (see omnicli docs/TRANSITION_GATE_STATUS.md)"
        )
    from omnicli.evaluation import validate_qualifying_run

    result = validate_qualifying_run(json.loads(artifact.read_text()))
    assert result["valid"], result["failures"]
