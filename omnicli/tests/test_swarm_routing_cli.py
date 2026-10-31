"""CLI contract for health-aware swarm panels."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner

from omnicli.cli import main


def test_dry_run_shows_panel_without_dispatching():
    with (
        patch(
            "omnicli.orchestrate.build_swarm",
            return_value=[("p", "openai/test")],
        ),
        patch("omnicli.orchestrate.run_orchestration") as run,
    ):
        result = CliRunner().invoke(
            main,
            ["swarm", "--dry-run", "--provider", "p", "audit", "this"],
        )
    assert result.exit_code == 0, result.output
    assert "dry run" in result.output.lower()
    assert "p:test" in result.output
    assert "unknown" in result.output
    run.assert_not_called()


def test_dry_run_respects_size_cap():
    panel = [("p0", "openai/a"), ("p1", "anthropic/b")]
    with patch("omnicli.orchestrate.build_swarm", return_value=panel) as build:
        result = CliRunner().invoke(
            main, ["swarm", "--dry-run", "-n", "2", "audit", "this"]
        )
    assert result.exit_code == 0, result.output
    assert build.call_args.kwargs["size"] == 2
