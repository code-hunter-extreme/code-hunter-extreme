"""Lens witness tier for _run_check — 2026-10-28 two-tier evidence decision.

The Matomo 2026-10-28 run mechanically demoted every deterministic code-sink
card because _run_check allowed only curl/slither/forge/cast, while the
template mints carry `grep ...` checks. These tests pin the fix:

- a grep check executes ONLY when the card is stamped
  ``check_provenance="lens"`` (deterministic template mint);
- model-authored/unknown-provenance checks stay on the strict list;
- grep stays read-only: unknown flags and shell metacharacters fail closed;
- nothing else widened — script interpreters stay out of the gate until a
  script-file validation path exists.

All commands are argv-only with shell=False; every fixture file lives in
tmp_path.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh


def _write_sink(tmp_path) -> str:
    f = tmp_path / "TableLogAction.php"
    f.write_text('<?php\n$sql = "SELECT * FROM log WHERE id = $id";\n')
    return str(f)


def test_grep_check_blocked_without_lens_provenance(tmp_path):
    target = _write_sink(tmp_path)
    rc, _, err = oh._run_check(f"grep -n 'SELECT' '{target}'")
    assert rc != 0
    assert err.startswith("[BLOCKED]")


def test_grep_check_executes_for_lens_mint(tmp_path):
    target = _write_sink(tmp_path)
    rc, out, err = oh._run_check(
        f"grep -n 'SELECT' '{target}'", provenance="lens"
    )
    assert rc == 0, f"grep witness failed: {err}"
    assert "SELECT" in out, out


def test_model_provenance_still_blocked_for_grep(tmp_path):
    # A provenance string that is not the deterministic-lens stamp never
    # widens the gate: prose from an LLM must not execute local witnesses.
    target = _write_sink(tmp_path)
    for prov in (None, "", "llm", "model", "unknown"):
        rc, _, err = oh._run_check(f"grep -n 'SELECT' '{target}'", provenance=prov)
        assert rc != 0 and err.startswith("[BLOCKED]"), prov


def test_grep_unsafe_flag_fails_closed(tmp_path):
    target = _write_sink(tmp_path)
    for flag in ("-r", "-R", "--include=*.php", "-Z"):
        rc, _, err = oh._run_check(
            f"grep {flag} 'SELECT' '{target}'", provenance="lens"
        )
        assert rc != 0 and "[BLOCKED]" in err, flag


def test_grep_metacharacters_fail_closed(tmp_path):
    target = _write_sink(tmp_path)
    for extra in ("'; cat /etc/passwd", "| cat", "$(cat /etc/passwd)"):
        rc, _, err = oh._run_check(f"grep -n '{extra}' '{target}'", provenance="lens")
        assert rc != 0 and "[BLOCKED]" in err, extra


def test_widen_does_not_admit_interpreters(tmp_path):
    # Script interpreters do not ride along with the grep widening: no
    # script-file validation path exists yet, so they stay fail-closed
    # even for lens mints (Tier-2 witness scripts land separately).
    script = tmp_path / "witness.py"
    script.write_text("print('hi')\n")
    for cmd in (
        f"python3 '{script}'",
        f"pytest '{script}'",
        f"php '{tmp_path / 'witness.php'}'",
    ):
        rc, _, err = oh._run_check(cmd, provenance="lens")
        assert rc != 0 and "[BLOCKED]" in err, cmd


def test_execute_confirm_threads_provenance_from_card(tmp_path):
    target = _write_sink(tmp_path)
    seam = {"check_provenance": "lens", "claim_type": ""}
    rc, out, err = oh._execute_confirm(seam, f"grep -n 'SELECT' '{target}'")
    assert rc == 0, f"witness route lost provenance: {err}"
    assert "SELECT" in out, out

    seam_no_stamp = {"claim_type": ""}
    rc, _, err = oh._execute_confirm(
        seam_no_stamp, f"grep -n 'SELECT' '{target}'"
    )
    assert rc != 0 and "[BLOCKED]" in err


def test_template_mints_are_stamped_lens(tmp_path):
    import oracle_seam_templates as T

    fixture = (
        "<?php\n"
        '$q = "SELECT id FROM log WHERE user = \'" . $uid . "\'";\n'
        "shell_exec('ls ' . $dir);\n"
        "unserialize($_GET['data']);\n"
    )
    (tmp_path / "code.php").write_text(fixture)
    (tmp_path / "code.js").write_text(
        "$row = db.query(\"SELECT id FROM log WHERE user = '\" + uid + \"'\");\n"
    )
    for mint in (T._t_code_sqli_sink, T._t_code_cmdi_sink, T._t_code_deserial_sink):
        cards = mint({"repo": tmp_path})
        assert cards, f"{mint.__name__} minted nothing on the fixture"
        for card in cards:
            assert card.get("check_provenance") == "lens", (mint.__name__, card)
            assert card.get("check", "").startswith("grep -n "), card
