import oracle_mindsets as om


def test_mindset_of_origin_maps_engine_tags():
    assert om.mindset_of_origin("cloud-paradox") == "paradox"
    assert om.mindset_of_origin("cloud-mitre") == "mitre"
    assert om.mindset_of_origin("cloud-seam-synth") == "seam"
    assert om.mindset_of_origin("local-tactic:PRIVILEGE ESCALATION") == "mitre"
    assert om.mindset_of_origin("local-paradox") == "paradox"
    assert om.mindset_of_origin(None) == "mitre"


def test_cross_compare_assembly_contract_for_cmd_hunt():
    """Pins the contract cmd_hunt relies on: seams grouped by mindset union into
    agreement-tagged candidates, with the deterministic seam retained."""
    seam_sets = {
        "mitre":   [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}],
        "paradox": [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "paradox"}],
        "seam":    [{"n": 9, "file": "a.py", "function": "f", "mindset": "seam"}],
    }
    out = om.cross_compare(seam_sets)
    corroborated = [s for s in out if s.get("agreement") == 2]
    assert corroborated and set(corroborated[0]["corroborated_by"]) == {"mitre", "paradox"}
    assert any(s.get("mindset") == "seam" for s in out)


def test_cross_compare_with_redteam_mindset():
    seam_sets = {
        "mitre":   [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "mitre"}],
        "paradox": [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "paradox"}],
        "redteam": [{"n": 1, "check": "curl -i https://app.acme.com/api", "mindset": "redteam"}],
        "seam":    [{"n": 9, "file": "a.py", "function": "f", "mindset": "seam"}],
    }
    out = om.cross_compare(seam_sets)
    corroborated = [s for s in out if s.get("agreement") == 3]
    assert corroborated and set(corroborated[0]["corroborated_by"]) == {"mitre", "paradox", "redteam"}



def test_lens_regime_block_names_the_regime():
    # Tinder post-mortem: unauth material + credential-demanding rules
    # made TARGET CLEAN rational. The prompt must name its regime so
    # public-surface contradictions stay mintable when unauthenticated.
    import types

    import oracle_hunter as oh

    ns = types.SimpleNamespace
    unauth = oh._lens_regime_block(ns(auth=None, cookie=None, account_a=None))
    assert "UNAUTHENTICATED" in unauth
    authed = oh._lens_regime_block(ns(auth=None, cookie=None, account_a="tok"))
    assert "AUTHENTICATED" in authed and "UNAUTHENTICATED" not in authed


def test_write_lens_funnel_persists_redacted_per_lens_raw(tmp_path):
    import json

    import oracle_hunter as oh

    out = oh._write_lens_funnel(
        tmp_path,
        outcomes={"cloud-mitre": "clean"},
        raw_results=[("cloud-mitre", 'TARGET CLEAN -H "Authorization: Bearer SENTINEL-X"')],
        recon_chars=123,
        asset_chars=45,
        effective=["mitre", "paradox", "seam"],
        minted=0,
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["minted"] == 0 and data["recon_chars"] == 123
    assert data["passes"][0]["origin"] == "cloud-mitre"
    assert data["passes"][0]["outcome"] == "clean"
    assert "SENTINEL-X" not in out.read_text(encoding="utf-8")


def test_cdp_port_precedence(monkeypatch):
    import types

    import oracle_hunter as oh

    monkeypatch.delenv("ORACLE_CDP_PORT", raising=False)
    assert oh._cdp_port(None) == 9227
    monkeypatch.setenv("ORACLE_CDP_PORT", "9333")
    assert oh._cdp_port(None) == 9333
    assert oh._cdp_port(types.SimpleNamespace(cdp_port=9444)) == 9444
    monkeypatch.setenv("ORACLE_CDP_PORT", "not-a-port")
    assert oh._cdp_port(None) == 9227


def test_cdp_port_wiring_no_argparse_default_shadowing():
    # scan/queue --cdp-port must default None so ORACLE_CDP_PORT can win;
    # download sites must route through _cdp_port.
    import re
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent.joinpath("oracle_hunter.py").read_text()
    blocks = re.findall(r'add_argument\(\s*"--cdp-port".*?\)', src, re.S)
    assert len(blocks) == 2
    for b in blocks:
        assert "default=None" in b, b
    assert 'getattr(args, "cdp_port", 9227)' not in src


def test_plan_synthesis_batches_covers_every_seam_within_budget():
    import oracle_hunter as oh
    import oracle_llm
    import pytest

    seams = [{"n": i, "check": "x" * 400} for i in range(1, 8)]

    def render(batch):
        return "S" * 400, "".join(s["check"] for s in batch)

    batches = oh._plan_synthesis_batches(seams, render, budget_tokens=300)

    assert [s["n"] for batch in batches for s in batch] == list(range(1, 8))
    assert len(batches) > 1
    for batch in batches:
        system, prompt = render(batch)
        assert oracle_llm.estimate_tokens(system, prompt) <= 300
    assert oh._plan_synthesis_batches([], render, budget_tokens=300) == [[]]
    with pytest.raises(ValueError, match="does not fit"):
        oh._plan_synthesis_batches(
            [{"n": 99, "check": "x" * 2000}], render, budget_tokens=300
        )


def test_synthesis_input_budget_reserves_response_without_dropping_base():
    import oracle_hunter as oh

    assert oh._synthesis_input_budget(16000, 12300) == 13952
    # If the mandatory base prompt already eats the reserve, keep the
    # base representable instead of pretending a smaller prompt was sent.
    assert oh._synthesis_input_budget(16000, 15500) == 15500
    assert oh._synthesis_input_budget(16000, 17000) is None
    assert oh._synthesis_input_budget(None, 100) is None


def test_lens_pass_budget_caps_oversized_lanes():
    import oracle_hunter as oh

    # 128k lane + modest mandatory base: pass input capped at the lens
    # quality ceiling minus the shared 2048 response reserve.
    assert oh._lens_pass_budget(128000, 30000) == 65536 - 2048
    # Small lanes behave exactly like the synthesis budget.
    assert oh._lens_pass_budget(16000, 12300) == 13952
    assert oh._lens_pass_budget(16000, 17000) is None
    assert oh._lens_pass_budget(None, 100) is None


def test_mitre_system_prompt_slices_cover_all_ttps_within_budget():
    import re

    from oracle_mindset_context import OracleMindsetContext

    ctx = OracleMindsetContext(
        program={"name": "Matomo", "platform": "HackerOne"},
        voice=True,
        ttp_mode="full",
        mindset="mitre",
    )
    slices = ctx.system_prompt_slices(max_system_chars=120_000)

    assert len(slices) > 1
    assert all(len(s) <= 120_000 for s in slices)
    assert all("ORACLE TTP REFERENCE" in s for s in slices)
    rendered = [m for s in slices for m in re.findall(r"\*\*(T\d{4}(?:\.\d{3})?) —", s)]
    expected = {r["code"] for r in ctx._selected_ttps("full")}
    assert len(rendered) == len(set(rendered))
    assert set(rendered) == expected


def test_paradox_system_prompt_slices_cover_corpus_within_budget():
    import oracle_corpus
    from oracle_mindset_context import OracleMindsetContext

    ctx = OracleMindsetContext(
        program={"name": "Matomo", "platform": "HackerOne"},
        voice=True,
        ttp_mode="auto",
        mindset="paradox",
    )
    slices = ctx.system_prompt_slices(max_system_chars=140_000)

    assert len(slices) > 1
    assert all(len(s) <= 140_000 for s in slices)
    foundations = set(oracle_corpus._FOUNDATION_IDS)
    for document in oracle_corpus.DOCUMENTS:
        text = oracle_corpus.read_document(document.identifier)
        hits = sum(1 for s in slices if text in s)
        if document.identifier in foundations:
            assert hits == len(slices), document.identifier
        else:
            assert hits == 1, document.identifier


def test_lens_systems_for_chunks_to_lane_budget(monkeypatch):
    import oracle_hunter as oh
    import oracle_llm
    from oracle_mindset_context import OracleMindsetContext

    monkeypatch.setattr(
        oracle_llm, "smallest_viable_lane_limit", lambda *a, **k: 128000
    )
    ctx = OracleMindsetContext(
        program={"name": "Matomo", "platform": "HackerOne"},
        voice=True,
        ttp_mode="full",
        mindset="mitre",
    )
    task = "TASK " + "x" * 4000
    systems = oh._lens_systems_for(ctx, task, cfg={}, env={}, no_cloud=False)

    assert len(systems) > 1, "77k-token mitre prompt must chunk under the cap"
    for system in systems:
        assert oracle_llm.estimate_tokens(system, task) <= 65536 - 2048


def test_paradox_lens_splits_a_document_larger_than_one_pass():
    """2026-10-28 Matomo rerun died here.

    paradox-impossible-crossover (41,793 chars) plus the 9,660-char
    foundations overflowed the 50,712-char block budget, so
    source_context_chunks raised and cmd_hunt crashed after both lenses
    had submitted passes — the hunt produced nothing and looked starved.
    An oversized document must be split across passes instead: every
    character still reaches the lens exactly once, nothing is truncated.
    """
    import oracle_corpus
    from oracle_mindset_context import OracleMindsetContext

    ctx = OracleMindsetContext(
        program={"name": "Matomo", "platform": "HackerOne"},
        voice=True,
        ttp_mode="auto",
        mindset="paradox",
    )
    cap = 105_306  # the pass budget the crash was raised at
    slices = ctx.system_prompt_slices(cap, corpus_split_oversized=True)

    assert len(slices) > 1
    assert all(len(s) <= cap for s in slices)
    text = oracle_corpus.read_document("paradox-impossible-crossover")
    assert not any(text in s for s in slices), "document must be split, not sent whole"
    assert any(text[:200] in s for s in slices), "head of the document was dropped"
    assert any(text[-200:] in s for s in slices), "tail of the document was dropped"
    assert sum("(part " in s for s in slices) == 2, "expected two parts"
