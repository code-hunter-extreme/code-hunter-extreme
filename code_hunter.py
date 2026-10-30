#!/usr/bin/env python3
"""
code-hunter — Unified CLI for Scan4Me + Oracle + OmniCLI.

One entry point for the full bug-bounty pipeline:

    code-hunter scan sync                 # Scan4Me: fetch feeds (no credentials)
    code-hunter scan radar --limit 10     # Scan4Me: ranked targets
    code-hunter scan export --top 20      # Scan4Me: export for recon
    code-hunter oracle prescan --sync     # Oracle: P11 prescan sweep
    code-hunter oracle scan -N 3 --download  # Oracle: verify + P12 handoff
    code-hunter oracle queue --execute    # Oracle: P12 hunt the handoff
    code-hunter oracle hunt <program>     # Oracle: single-target 3-mindset hunt
    code-hunter omni ask "..."            # OmniCLI: red-team / orchestrate (independent)
    code-hunter omni agent --redteam "..." # OmniCLI: autonomous red-team agent
    code-hunter pipeline --run            # End-to-end: scan → oracle → report
    code-hunter status                    # Health of all 3 systems
    code-hunter report                    # Consolidated report from hunts

Mindsets (Oracle P1 doctrine §1):
  • Mindset 1 — mitre: MITRE ATT&CK TTPs + offensive Red Teaming,
    bug bounty info, assets in scope, company information
  • Mindset 2 — paradox: philosophy corpus, paradoxes, impossible problems,
    iPhone-level framing, invisible seams, Red Teaming,
    bug bounty info, assets in scope, company information
  • Mindset 3 — seam: SYNTHESIS of Mindset 1 + Mindset 2 + deterministic
    seam feed, with Adversarial Red-Team Synthesis & Chaining

Designed to go from "no credentials" to submission-ready product bundles.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

ROOT = Path(__file__).resolve().parent
ORACLE_ROOT = ROOT / "oracle"
SCAN4ME_ROOT = ROOT / "scan4me"
OMNICLI_ROOT = ROOT / "omnicli"

# ── Ensure each project is importable ───────────────────────────────────────
for _p in (str(ORACLE_ROOT), str(SCAN4ME_ROOT), str(OMNICLI_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _run(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 3600,
         capture: bool = True) -> subprocess.CompletedProcess:
    """Run a command, echoing a banner first."""
    console.print(f"[dim]$[/dim] {' '.join(cmd)}"
                  + (f"  (cwd={cwd})" if cwd else ""))
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None,
        capture_output=capture, text=True, timeout=timeout,
    )


def _check_import(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM API KEY CHECK + CDP AUTO-START
# ─────────────────────────────────────────────────────────────────────────────

# Platform API key env var names (checked in priority order)
PLATFORM_KEY_ENV_VARS = {
    "hackerone": ["HACKERONE_API_TOKEN", "HACKERONE_API_KEY", "HACKERONE_USERNAME"],
    "bugcrowd": ["BUGCROWD_API_TOKEN"],
    "intigriti": ["INTIGRITI_API_TOKEN", "INTIGRITI_JWT"],
    "yeswehack": ["YESWEHACK_API_TOKEN"],
    "hackenproof": ["HACKENPROOF_API_KEY"],
    "immunefi": ["IMMUNEFI_API_TOKEN"],
}


def _check_platform_api_keys() -> Dict[str, bool]:
    """Check which platforms have API keys configured.

    Returns a dict mapping platform → True if a key env var is set and non-empty.
    """
    result: Dict[str, bool] = {}
    for platform, env_vars in PLATFORM_KEY_ENV_VARS.items():
        has_key = any(
            os.environ.get(var, "").strip()
            for var in env_vars
        )
        result[platform] = has_key
    return result


def _any_platform_keys_present() -> bool:
    """True if at least one platform API key is configured."""
    return any(_check_platform_api_keys().values())


def _start_chromium_cdp(port: int = 9227, timeout: int = 20) -> Optional[subprocess.Popen]:
    """Start Chromium with remote debugging on the given CDP port.

    Returns the Popen process handle, or None if Chromium could not be started.
    The caller is responsible for terminating the process when done.
    """
    chromium_cmd = [
        "chromium-browser",
        f"--remote-debugging-port={port}",
        f"--user-data-dir=/tmp/chrome-cdp-{port}",
        "--no-first-run", "--no-sandbox", "--headless=new",
    ]

    try:
        proc = subprocess.Popen(
            chromium_cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        # Try chromium without -browser suffix
        chromium_cmd[0] = "chromium"
        try:
            proc = subprocess.Popen(
                chromium_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            console.print(f"[yellow]⚠ Chromium not found on PATH[/yellow]")
            return None
        except Exception as exc:
            console.print(f"[yellow]⚠ Could not start Chromium: {exc}[/yellow]")
            return None
    except Exception as exc:
        console.print(f"[yellow]⚠ Could not start Chromium: {exc}[/yellow]")
        return None

    # Wait for CDP port to respond — Chromium usually takes 2-5 seconds
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                f"http://localhost:{port}/json/version",
                headers={"User-Agent": "code-hunter/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    console.print(f"[green]✓[/green] CDP Chromium started on port {port}")
                    return proc
        except Exception:
            pass
        time.sleep(1)

    # CDP didn't respond — kill Chromium
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    console.print(f"[yellow]⚠ CDP Chromium did not respond on port {port}[/yellow]")
    return None


def _stop_chromium_cdp(proc: Optional[subprocess.Popen]) -> None:
    """Stop a previously started Chromium CDP process."""
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _health(name: str, root: Path, key_files: List[str]) -> Dict[str, Any]:
    missing = [f for f in key_files if not (root / f).is_file()]
    imports_ok = _check_import(name.split("-")[0].replace("_", ""))
    return {
        "name": name,
        "root": str(root),
        "exists": root.is_dir(),
        "missing_files": missing,
        "import_ok": imports_ok and not missing,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SCAN group (Scan4Me)
# ─────────────────────────────────────────────────────────────────────────────

def _scan4me_flags_for(sub: str, args: argparse.Namespace) -> List[str]:
    """Return CLI flags relevant to a given scan4me subcommand."""
    flags: List[str] = []

    def add(flag: str, val: Any) -> None:
        if val is True:
            flags.append(f"--{flag}")
        elif val is not None and val is not False:
            flags.extend([f"--{flag}", str(val)])

    if sub == "sync":
        add("sync", getattr(args, "sync", False))
        add("offline", getattr(args, "offline", False))
    elif sub == "enrich":
        add("limit", getattr(args, "limit", None))
        add("delay", getattr(args, "delay", None))
        add("handle", getattr(args, "handle", None))
    elif sub == "radar":
        add("limit", getattr(args, "limit", None))
        add("new-companies", getattr(args, "new_companies", False))
        add("new-assets", getattr(args, "new_assets", False))
    elif sub == "export":
        add("top", getattr(args, "top", None))
        add("wildcards-only", getattr(args, "wildcards_only", False))
        add("clean", getattr(args, "clean", False))
        add("new-companies", getattr(args, "new_companies", False))
        add("new-assets", getattr(args, "new_assets", False))
    elif sub == "handoff":
        add("prescan-file", getattr(args, "prescan_file", None))
        add("scan-file", getattr(args, "scan_file", None))
        add("output", getattr(args, "output", None))
        add("top-n", getattr(args, "top_n", None))
        add("sites", getattr(args, "sites", None))
        add("no-cloud", getattr(args, "no_cloud", False))

    return flags


def cmd_scan(args: argparse.Namespace) -> int:
    """Delegate to scan4me.py."""
    # Ensure shared config is synced to Scan4Me's config.json
    try:
        _sync_config_to_projects(_load_shared_config())
    except Exception as exc:
        console.print(f"[yellow]⚠ Config sync warning: {exc}[/yellow]")
    scan4me = SCAN4ME_ROOT / "scan4me.py"
    if not scan4me.is_file():
        console.print("[red]✗[/red] scan4me.py not found at "
                      f"{scan4me}")
        return 1
    cmd = [sys.executable, str(scan4me)]
    if args.sub:
        cmd.append(args.sub)
    cmd.extend(_scan4me_flags_for(args.sub, args))
    if args.domain and args.sub == "check":
        cmd.append(args.domain)
    try:
        cp = _run(cmd, cwd=SCAN4ME_ROOT, timeout=args.timeout)
        if cp.stdout:
            console.print(cp.stdout)
        if cp.stderr:
            console.print(cp.stderr)
        return cp.returncode
    except subprocess.TimeoutExpired:
        console.print("[red]✗[/red] scan4me timed out")
        return 124


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE group
# ─────────────────────────────────────────────────────────────────────────────

def _oracle_flags_for(sub: str, args: argparse.Namespace) -> List[str]:
    """Return CLI flags relevant to a given oracle subcommand."""
    flags: List[str] = []

    def add(flag: str, val: Any) -> None:
        if val is True:
            flags.append(f"--{flag}")
        elif val is not None and val is not False:
            flags.extend([f"--{flag}", str(val)])

    if sub == "prescan":
        add("limit", getattr(args, "limit", None))
        add("sync", getattr(args, "sync", False))
        add("no-cloud", getattr(args, "no_cloud", False))
        add("out-dir", getattr(args, "out_dir", None))
    elif sub == "scan":
        add("prescan-file", getattr(args, "prescan_file", None))
        add("top-n", getattr(args, "top_n", None))
        add("sites", getattr(args, "sites", None))
        add("no-cloud", getattr(args, "no_cloud", False))
        add("probe-timeout", getattr(args, "probe_timeout", None))
        add("download", getattr(args, "download", False))
        add("cdp-port", getattr(args, "cdp_port", None))
        add("out-dir", getattr(args, "out_dir", None))
        add("config", getattr(args, "config", None))
    elif sub == "queue":
        add("handoff", getattr(args, "handoff", None))
        add("order", getattr(args, "order", None))
        add("concurrent", getattr(args, "concurrent", False))
        add("cross-site-cap", getattr(args, "cross_site_cap", None))
        add("execute", getattr(args, "execute", False))
        add("max-items", getattr(args, "max_items", None))
        add("no-resume", getattr(args, "no_resume", False))
        add("skip-download", getattr(args, "skip_download", False))
        add("controlled", getattr(args, "controlled", True))
        add("no-controlled", getattr(args, "no_controlled", False))
        add("no-cloud", getattr(args, "no_cloud", False))
        add("model", getattr(args, "model", None))
        add("researcher", getattr(args, "researcher", None))
        add("testnet", getattr(args, "testnet", False))
        add("code", getattr(args, "code", False))
    elif sub == "bundle":
        if args.target:
            flags.append(args.target)
        add("out-dir", getattr(args, "out_dir", None))
    elif sub == "verify-download":
        if args.target:
            flags.append(args.target)
        add("json", getattr(args, "json", False))
    elif sub in ("hunt", "scope", "recon"):
        if args.target:
            flags.append(args.target)
        add("no-cloud", getattr(args, "no_cloud", False))
        add("cloud", getattr(args, "cloud", False))
    elif sub == "analyze":
        if args.target:
            flags.append(args.target)
    elif sub == "seams":
        if args.target:
            flags.append(args.target)
    elif sub == "list":
        pass
    elif sub in ("status", "backends", "audit", "redteam"):
        pass

    return flags


def cmd_oracle(args: argparse.Namespace) -> int:
    """Delegate to oracle_hunter.py."""
    # Ensure shared config is synced to Oracle's oracle.config.json
    try:
        _sync_config_to_projects(_load_shared_config())
    except Exception as exc:
        console.print(f"[yellow]⚠ Config sync warning: {exc}[/yellow]")
    hunter = ORACLE_ROOT / "oracle_hunter.py"
    if not hunter.is_file():
        console.print("[red]✗[/red] oracle_hunter.py not found at "
                      f"{hunter}")
        return 1
    cmd = [sys.executable, str(hunter)]
    if args.sub:
        cmd.append(args.sub)
    cmd.extend(_oracle_flags_for(args.sub, args))
    try:
        cp = _run(cmd, cwd=ORACLE_ROOT, timeout=args.timeout)
        if cp.stdout:
            console.print(cp.stdout)
        if cp.stderr:
            console.print(cp.stderr)
        return cp.returncode
    except subprocess.TimeoutExpired:
        console.print("[red]✗[/red] oracle timed out")
        return 124


# ─────────────────────────────────────────────────────────────────────────────
# OMNI group (OmniCLI — independent of Oracle)
# ─────────────────────────────────────────────────────────────────────────────

def _omni_flags_for(sub: str, args: argparse.Namespace) -> List[str]:
    """Return CLI flags relevant to a given omnicli subcommand."""
    flags: List[str] = []

    def add(flag: str, val: Any) -> None:
        if val is True:
            flags.append(f"--{flag}")
        elif val is not None and val is not False:
            flags.extend([f"--{flag}", str(val)])

    if sub == "ask":
        if args.prompt:
            flags.append(args.prompt)
        add("model", getattr(args, "model", None))
        add("provider", getattr(args, "provider", None))
    elif sub == "agent":
        if args.goal:
            flags.append(args.goal)
        add("model", getattr(args, "model", None))
        add("provider", getattr(args, "provider", None))
        add("allow-host", getattr(args, "hosts", None))
        add("allow-shell", getattr(args, "allow_shell", False))
        add("allow-local", getattr(args, "allow_local", False))
        add("allow-mutating-http", getattr(args, "allow_mutating_http", False))
        add("rotate-families", getattr(args, "rotate_families", False))
    elif sub == "swarm":
        if args.task:
            flags.append(args.task)
    elif sub == "verify":
        # verify http|code <target>
        if args.url:
            flags.append(args.url)
        add("function", getattr(args, "function", None))
        add("must-contain", getattr(args, "must_contain", None))
        add("consensus", getattr(args, "claim", None))  # verify consensus <claim>
    elif sub == "oracle-pipeline":
        add("oracle-root", getattr(args, "oracle_root", None))
        add("limit", getattr(args, "limit", None))
        add("count", getattr(args, "count", None))
        add("timeout", getattr(args, "timeout", None))
        add("json", getattr(args, "as_json", False) or getattr(args, "json", False))
    elif sub == "evaluate-security":
        add("dataset", getattr(args, "dataset", None))
        add("model", getattr(args, "model", None))
        add("minimum-cases", getattr(args, "minimum_cases", None))
        add("repetitions", getattr(args, "repetitions", None))
        add("static-baseline", getattr(args, "static_baseline", False))
    elif sub == "models":
        if args.provider:
            flags.append(args.provider)
    elif sub == "build":
        if args.idea:
            flags.append(args.idea)
        add("mode", getattr(args, "mode", None))
        add("split-ratio", getattr(args, "split_ratio", None))
        add("providers", getattr(args, "providers", None))
    elif sub == "prepare-security-review":
        add("dataset", getattr(args, "dataset", None))
        add("output", getattr(args, "output", None))

    return flags


def cmd_omni(args: argparse.Namespace) -> int:
    """Delegate to omnicli CLI (independent of Oracle)."""
    # Build mode is handled in-process with mindset cages.
    if args.sub == "build":
        return cmd_omni_build(args)

    omni_mod = OMNICLI_ROOT / "omnicli" / "cli.py"
    if not omni_mod.is_file():
        console.print("[red]✗[/red] omnicli/cli.py not found at "
                      f"{omni_mod}")
        return 1
    cmd = [sys.executable, "-m", "omnicli.cli"]
    if args.sub:
        cmd.append(args.sub)
    cmd.extend(_omni_flags_for(args.sub, args))
    try:
        cp = _run(cmd, cwd=OMNICLI_ROOT, timeout=args.timeout)
        if cp.stdout:
            console.print(cp.stdout)
        if cp.stderr:
            console.print(cp.stderr)
        return cp.returncode
    except subprocess.TimeoutExpired:
        console.print("[red]✗[/red] omnicli timed out")
        return 124


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE — end-to-end money pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _pipeline_step(label: str, cmd: List[str], cwd: Path,
                   timeout: int) -> Dict[str, Any]:
    """Run one pipeline step, return result dict."""
    start = time.monotonic()
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                            text=True, timeout=timeout)
        duration = round(time.monotonic() - start, 1)
        return {
            "label": label, "ok": cp.returncode == 0,
            "returncode": cp.returncode, "duration_s": duration,
            "stdout": cp.stdout, "stderr": cp.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "label": label, "ok": False, "returncode": 124,
            "duration_s": round(time.monotonic() - start, 1),
            "stdout": "", "stderr": f"Timed out after {timeout}s",
        }


def cmd_pipeline(args: argparse.Namespace) -> int:
    """End-to-end: scan4me sync → oracle prescan → scan → queue → report."""
    if not args.run:
        console.print("[yellow]Use --run to execute the full pipeline.[/yellow]")
        return 0

    # Pre-flight: verify entry points exist
    for entry, label in ((SCAN4ME_ROOT / "scan4me.py", "scan4me.py"),
                         (ORACLE_ROOT / "oracle_hunter.py", "oracle_hunter.py")):
        if not entry.is_file():
            console.print(f"[red]✗[/red] {label} not found at {entry}")
            return 1

    limit = args.limit
    top_n = args.top_n
    timeout = args.timeout
    no_cloud = args.no_cloud

    cdp_proc: Optional[subprocess.Popen] = None

    steps: List[Dict[str, Any]] = []

    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"),
        console=console, transient=False,
    ) as progress:

        # Step 1: Scan4Me sync
        t = progress.add_task("Scan4Me: sync feeds (no credentials)…", total=None)
        r = _pipeline_step(
            "scan4me sync",
            [sys.executable, "scan4me.py", "sync"]
            + (["--offline"] if no_cloud else []),
            SCAN4ME_ROOT, timeout,
        )
        steps.append(r)
        progress.update(t, completed=1)
        if not r["ok"]:
            console.print(f"[red]✗[/red] {r['label']} failed: "
                          f"{r['stderr'][:200]}")
            return 1
        console.print(f"[green]✓[/green] {r['label']} done "
                      f"({r['duration_s']}s)")

        # Step 2: Oracle prescan
        t = progress.add_task("Oracle: prescan sweep…", total=None)
        r = _pipeline_step(
            "oracle prescan",
            [sys.executable, "oracle_hunter.py", "prescan",
             "--limit", str(limit)]
            + (["--sync"] if not no_cloud else [])
            + (["--no-cloud"] if no_cloud else []),
            ORACLE_ROOT, timeout,
        )
        steps.append(r)
        progress.update(t, completed=1)
        if not r["ok"]:
            console.print(f"[red]✗[/red] {r['label']} failed: "
                          f"{r['stderr'][:200]}")
            return 1
        console.print(f"[green]✓[/green] {r['label']} done "
                      f"({r['duration_s']}s)")

        # Step 3: Oracle scan (-N deep-dive + download)
        # Decide verification strategy based on platform API keys:
        #   - Keys present → run scan normally (CDP optional for download)
        #   - No keys → run with --no-cloud (skip API re-scan that fails closed)
        #     and start CDP as fallback for page content download
        t = progress.add_task("Oracle: scan + deep-dive + download…", total=None)
        platform_keys = _check_platform_api_keys()
        has_keys = any(platform_keys.values())
        key_status = ", ".join(
            f"{p}:{'✓' if v else '✗'}" for p, v in platform_keys.items()
        )
        console.print(f"[dim]Platform API keys: {key_status}[/dim]")

        scan_cmd = [sys.executable, "oracle_hunter.py", "scan",
                    "-N", str(top_n), "--download"]

        cdp_started = False
        if not has_keys and not no_cloud:
            console.print("[yellow]⚠ No platform API keys present — "
                          "running scan with --no-cloud (API re-scan skipped), "
                          "starting CDP Chromium for download fallback[/yellow]")
            scan_cmd.append("--no-cloud")
            cdp_proc = _start_chromium_cdp(port=9227)
            if cdp_proc is not None:
                cdp_started = True
                scan_cmd.extend(["--cdp-port", "9227"])
            else:
                console.print("[red]⚠ CDP start failed — scan will use "
                              "Crawl4AI / plain GET fallback[/red]")
        elif has_keys:
            console.print("[green]✓ Platform API keys present — "
                          "CDP can stay offline[/green]")
            if not no_cloud:
                cdp_proc = _start_chromium_cdp(port=9227)
                if cdp_proc is not None:
                    cdp_started = True
                    scan_cmd.extend(["--cdp-port", "9227"])

        r = _pipeline_step(
            "oracle scan",
            scan_cmd,
            ORACLE_ROOT, timeout,
        )
        steps.append(r)
        progress.update(t, completed=1)
        if not r["ok"]:
            console.print(f"[red]✗[/red] {r['label']} failed: "
                          f"{r['stderr'][:200]}")
            _stop_chromium_cdp(cdp_proc)
            return 1
        console.print(f"[green]✓[/green] {r['label']} done "
                      f"({r['duration_s']}s)")

        # Step 4: Oracle queue --execute
        t = progress.add_task("Oracle: queue + execute hunts…", total=None)
        queue_cmd = [sys.executable, "oracle_hunter.py", "queue", "--execute",
                     "--max-items", str(top_n)]
        if not has_keys or no_cloud:
            queue_cmd.append("--no-cloud")
        r = _pipeline_step(
            "oracle queue --execute",
            queue_cmd,
            ORACLE_ROOT, timeout,
        )
        steps.append(r)
        progress.update(t, completed=1)
        if not r["ok"]:
            console.print(f"[yellow]⚠[/yellow] {r['label']} had issues: "
                          f"{r['stderr'][:200]}")
            console.print("[yellow]   Continuing to report step...[/yellow]")
        else:
            console.print(f"[green]✓[/green] {r['label']} done "
                          f"({r['duration_s']}s)")

        # Stop CDP after queue completes — hunts are done
        _stop_chromium_cdp(cdp_proc)

        # Step 5: Generate consolidated report
        t = progress.add_task("Generating consolidated report…", total=None)
        r = _pipeline_step(
            "report",
            [sys.executable, str(ROOT / "code_hunter.py"), "report"],
            ROOT, 60,
        )
        steps.append(r)
        progress.update(t, completed=1)

    # Summary table
    table = Table(title="Pipeline Summary", title_style="bold cyan")
    table.add_column("Step", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Seconds", justify="right")
    all_ok = True
    for s in steps:
        ok = s["ok"]
        all_ok = all_ok and ok
        table.add_row(
            s["label"],
            "[green]✓ ok[/green]" if ok else f"[red]✗ fail ({s['returncode']})[/red]",
            str(s["duration_s"]),
        )
    console.print(table)

    if all_ok:
        console.print("[bold green]Pipeline complete — product bundles "
                      "ready for manual review and submission.[/bold green]")
        console.print("[yellow]Remember: reports are never auto-submitted — "
                      "manual review only (Oracle doctrine).[/yellow]")
        return 0
    else:
        console.print("[bold red]Pipeline had failures. Review output above.[/bold red]")
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# STATUS — health of all 3 systems
# ─────────────────────────────────────────────────────────────────────────────

def cmd_status(args: argparse.Namespace) -> int:
    """Report health of Scan4Me, Oracle, OmniCLI."""
    checks = [
        _health("scan4me", SCAN4ME_ROOT,
                ["scan4me.py", "config.example.json", "pyproject.toml"]),
        _health("oracle", ORACLE_ROOT,
                ["oracle_hunter.py", "oracle.config.json",
                 "oracle_mindsets.py", "oracle_intake.py", "oracle_queue.py"]),
        _health("omnicli", OMNICLI_ROOT,
                ["omnicli/cli.py", "omnicli/conduct.py", "pyproject.toml"]),
    ]

    table = Table(title="System Health", title_style="bold cyan")
    table.add_column("System", style="bold")
    table.add_column("Root", style="dim")
    table.add_column("Dir", justify="center")
    table.add_column("Key Files", justify="center")
    table.add_column("Import", justify="center")

    all_healthy = True
    for c in checks:
        healthy = c["exists"] and not c["missing_files"] and c["import_ok"]
        all_healthy = all_healthy and healthy
        table.add_row(
            c["name"],
            c["root"],
            "[green]✓[/green]" if c["exists"] else "[red]✗[/red]",
            "[green]✓[/green]" if not c["missing_files"]
            else f"[red]✗ {len(c['missing_files'])} missing[/red]",
            "[green]✓[/green]" if c["import_ok"] else "[red]✗[/red]",
        )
        if c["missing_files"]:
            console.print(f"  [yellow]{c['name']} missing:[/yellow] "
                          f"{', '.join(c['missing_files'])}")

    console.print(table)

    # Test status
    console.print("\n[bold]Test status (from docs):[/bold]")
    tt = Table(title="Test Suites")
    tt.add_column("System", style="bold")
    tt.add_column("Tests", justify="right")
    tt.add_column("Status", justify="center")
    tt.add_row("Scan4Me", "121", "[green]pass[/green]")
    tt.add_row("Oracle", "1184 + 32 subtests", "[green]pass[/green]")
    tt.add_row("OmniCLI", "~305 + 53 subtests", "[yellow]mostly[/yellow] "
               "(P4 gate needs qualifying run)")
    console.print(tt)

    # Platform API key status
    console.print("\n[bold]Platform API Key Status[/bold]")
    platform_keys = _check_platform_api_keys()
    kt = Table(title="Platform Keys")
    kt.add_column("Platform", style="bold")
    kt.add_column("Key Configured", justify="center")
    any_keys = False
    for platform, has_key in sorted(platform_keys.items()):
        any_keys = any_keys or has_key
        kt.add_row(
            platform,
            "[green]✓[/green]" if has_key else "[red]✗[/red]",
        )
    console.print(kt)
    if not any_keys:
        console.print("[yellow]⚠ No platform API keys configured — "
                      "CDP Chromium will be auto-started for verification[/yellow]")
    else:
        console.print("[green]✓ Platform API keys present — "
                      "CDP can stay offline[/green]")

    if all_healthy:
        console.print("\n[bold green]All three systems present and importable.[/bold green]")
        return 0
    else:
        console.print("\n[bold red]Some systems have issues.[/bold red]")
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# REPORT — consolidated report from hunt results
# ─────────────────────────────────────────────────────────────────────────────

def _latest_file(root: Path, pattern: str) -> Optional[Path]:
    if not root.is_dir():
        return None
    files = list(root.glob(pattern))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a consolidated report from the latest hunt artifacts."""
    oracle_reports = ORACLE_ROOT / "reports"
    targets_dir = ORACLE_ROOT / "targets"

    handoff = _latest_file(oracle_reports, "handoff_*.json")
    scan_report = _latest_file(oracle_reports, "scan_*.json")
    prescan = _latest_file(oracle_reports, "prescan_*.json")
    queue_state = _latest_file(oracle_reports, "queue_state_*.json")

    report = {
        "generated_utc": _utc_now(),
        "schema": "code-hunter.report/v1",
        "artifacts": {},
        "mindsets": {
            "1_mitre": "MITRE ATT&CK TTPs + offensive Red Teaming, "
                       "bug bounty info, assets in scope, company information",
            "2_paradox": "Philosophy corpus, paradoxes, impossible problems, "
                         "iPhone-level framing, invisible seams, Red Teaming, "
                         "bug bounty info, assets in scope, company information",
            "3_seam": "SYNTHESIS of Mindset 1 + Mindset 2 + deterministic "
                      "seam feed, Adversarial Red-Team Synthesis & Chaining, "
                      "bug bounty info, assets in scope, company information",
        },
    }

    if handoff:
        try:
            data = json.loads(handoff.read_text())
            report["artifacts"]["handoff"] = {
                "path": str(handoff),
                "verified_count": len(data.get("ranked_verified", [])),
                "programs": [
                    {
                        "rank": p.get("rank"),
                        "name": p.get("name"),
                        "platform": p.get("platform"),
                        "score": p.get("score"),
                        "max_payout_usd": p.get("max_payout_usd"),
                        "verdict": p.get("verdict"),
                    }
                    for p in data.get("ranked_verified", [])
                ],
            }
        except Exception as e:
            report["artifacts"]["handoff"] = {"path": str(handoff), "error": str(e)}

    if scan_report:
        try:
            data = json.loads(scan_report.read_text())
            report["artifacts"]["scan"] = {
                "path": str(scan_report),
                "count": data.get("count"),
                "verified_count": data.get("verified_count"),
            }
        except Exception as e:
            report["artifacts"]["scan"] = {"path": str(scan_report), "error": str(e)}

    if prescan:
        report["artifacts"]["prescan"] = {"path": str(prescan)}

    if queue_state:
        report["artifacts"]["queue_state"] = {"path": str(queue_state)}

    # List downloaded workspaces
    workspaces = []
    if targets_dir.is_dir():
        for plat_dir in sorted(targets_dir.iterdir()):
            if not plat_dir.is_dir():
                continue
            for slug_dir in sorted(plat_dir.iterdir()):
                if slug_dir.is_dir():
                    workspaces.append(str(slug_dir))
    report["artifacts"]["workspaces"] = workspaces

    out_path = args.output or (oracle_reports / "CODE_HUNTER_REPORT.json")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    console.print(f"[green]✓[/green] Report written to {out_path}")
    console.print(json.dumps(report, indent=2))
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# SHARED CONFIG — one config.json at workspace root used by both Scan4Me + Oracle
# ─────────────────────────────────────────────────────────────────────────────

SHARED_CONFIG_PATH = ROOT / "config.json"

SHARED_CONFIG_TEMPLATE = {
    "_comment": "Shared bug-bounty pipeline config — used by Scan4Me + Oracle "
                "via code-hunter. Edit here; code-hunter syncs to each project.",
    "researcher": {
        "handle": "codehunterextreme",
        "note": "Researcher handle used in compliance request headers",
    },
    "api_keys": {
        "_comment": "Set real values as env vars (priority) or here. Never commit secrets.",
        "hackerone": {"username": None, "api_token": None,
                      "_env": "HACKERONE_USERNAME / HACKERONE_API_TOKEN"},
        "bugcrowd":   {"api_token": None, "_env": "BUGCROWD_API_TOKEN"},
        "intigriti":  {"api_token": None, "_env": "INTIGRITI_API_TOKEN"},
        "yeswehack":  {"api_token": None, "_env": "YESWEHACK_API_TOKEN"},
        "hackenproof":{"api_token": None, "_env": "HACKENPROOF_API_TOKEN"},
        "openrouter": {"api_key": None, "_env": "OPENROUTER_API_KEY"},
        "nvidia":     {"api_key": None, "_env": "NVIDIA_API_KEY"},
        "gemini":     {"api_key": None, "_env": "GEMINI_API_KEY"},
    },
    "scan4me": {
        "use_auth": False,
        "filters": {
            "paid_bounties_only": True,
            "fast_triage": {"enabled": True, "max_first_response_hours": 24.0},
            "attack_surface_and_scope": {
                "prefer_large_attack_surface": True,
                "prioritize_wildcards": True,
                "wildcard_multiplier": 2.5,
            },
            "freshness_and_competition": {
                "prefer_new_companies": True, "new_company_days": 90,
                "prefer_new_assets": True, "new_asset_days": 30,
                "max_rewarded_vulnerabilities": 150,
            },
            "payouts": {"min_max_payout_usd": 1000.0, "prioritize_fast_cash": True},
            "program_kind": {"web2": True, "web3": True},
        },
        "platforms": {
            "hackerone": True, "bugcrowd": True, "intigriti": True,
            "yeswehack": True, "federacy": False, "immunefi": True,
            "sherlock": True, "pd_programs": True, "bugbase": True,
            "hackenproof": True, "cantina": True, "codehawks": True,
            "patchstack": True, "huntr": True,
        },
        "ranking_weights": {
            "payout_size": 0.35,
            "attack_surface_size": 0.30,
            "freshness_and_low_saturation": 0.20,
            "triage_speed": 0.15,
        },
    },
    "oracle": {
        "scan": {"platforms": "all", "refresh_cache": False, "cdp_port": 9227},
        "filter": {
            "min_payout_usd": 500, "max_payout_usd": 0,
            "max_resolved_reports": 100, "fast_triage_only": False,
            "new_programs_only": False, "new_program_days": 90,
            "web2": True, "web3": True, "pick_per_platform": 5, "top_n": 50,
        },
        "hunt": {
            "auto": False, "verify": True, "cloud": True, "testnet": False,
            "download_assets": True, "screenshot": True, "code_lens": True,
            "max_cards_per_family": 20,
            "recon_context": {"max_hosts": 20, "max_endpoints": 30},
        },
        "queue": {
            "order": "finish-site", "concurrent": False,
            "cross_site_cap": 3, "default_count": 5,
        },
    },
}


def _load_shared_config() -> Dict[str, Any]:
    if SHARED_CONFIG_PATH.is_file():
        try:
            return json.loads(SHARED_CONFIG_PATH.read_text())
        except Exception:
            pass
    return dict(SHARED_CONFIG_TEMPLATE)


def _save_shared_config(cfg: Dict[str, Any]) -> None:
    SHARED_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")


def _sync_config_to_projects(cfg: Dict[str, Any]) -> None:
    """Write project-appropriate config files from the shared config."""
    # Scan4Me config.json in its own directory
    s4m = {
        "use_auth": cfg.get("scan4me", {}).get("use_auth", False),
        "api_keys": cfg.get("api_keys", {}),
        "filters": cfg.get("scan4me", {}).get("filters", {}),
        "platforms": cfg.get("scan4me", {}).get("platforms", {}),
        "ranking_weights": cfg.get("scan4me", {}).get("ranking_weights", {}),
        "display": {"limit": 25, "show_company_profile": True,
                    "show_assets_sample": True},
    }
    (SCAN4ME_ROOT / "config.json").write_text(json.dumps(s4m, indent=2) + "\n")

    # Oracle config.json in its own directory
    oracle_cfg = {
        "_comment": "Synced from code-hunter shared config.json",
        "scan": cfg.get("oracle", {}).get("scan",
                                          SHARED_CONFIG_TEMPLATE["oracle"]["scan"]),
        "filter": cfg.get("oracle", {}).get("filter",
                                            SHARED_CONFIG_TEMPLATE["oracle"]["filter"]),
        "hunt": cfg.get("oracle", {}).get("hunt",
                                          SHARED_CONFIG_TEMPLATE["oracle"]["hunt"]),
        "queue": cfg.get("oracle", {}).get("queue",
                                           SHARED_CONFIG_TEMPLATE["oracle"]["queue"]),
        "researcher": cfg.get("researcher",
                              SHARED_CONFIG_TEMPLATE["researcher"]),
        "quality_gates": {
            "gate_precision_min": 0.70, "gate_recall_min": 1.0,
            "gate_clean_fp_max": 0.10, "gate_cases": 60,
        },
        "platform_auth": {
            "hackerone": {"methods": ["api_key", "cdp_session", "public"],
                          "api_key_env": "HACKERONE_API_KEY"},
            "bugcrowd": {"methods": ["cdp_session", "public"]},
            "intigriti": {"methods": ["api_key", "cdp_session", "public"],
                          "api_key_env": "INTIGRITI_JWT"},
            "yeswehack": {"methods": ["public", "cdp_session"]},
            "immunefi": {"methods": ["public"]},
            "hackenproof": {"methods": ["api_key", "cdp_session", "public"],
                            "api_key_env": "HACKENPROOF_API_KEY"},
        },
    }
    (ORACLE_ROOT / "oracle.config.json").write_text(
        json.dumps(oracle_cfg, indent=2) + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG command
# ─────────────────────────────────────────────────────────────────────────────

def cmd_config(args: argparse.Namespace) -> int:
    """Manage the shared config.json used by Scan4Me + Oracle."""
    if args.init:
        cfg = _load_shared_config()
        _save_shared_config(cfg)
        _sync_config_to_projects(cfg)
        console.print(f"[green]✓[/green] Shared config initialized: "
                      f"{SHARED_CONFIG_PATH}")
        console.print("[dim]Synced to scan4me/config.json and "
                      "oracle/oracle.config.json[/dim]")
        return 0

    if args.show:
        cfg = _load_shared_config()
        console.print(json.dumps(cfg, indent=2))
        return 0

    if args.sync:
        cfg = _load_shared_config()
        _sync_config_to_projects(cfg)
        console.print("[green]✓[/green] Config synced to Scan4Me + Oracle "
                      "project directories")
        return 0

    if args.set:
        # key=value pairs like researcher.handle=codehunterextreme
        cfg = _load_shared_config()
        for kv in args.set:
            if "=" not in kv:
                console.print(f"[red]✗[/red] invalid --set: {kv} "
                              "(use key=value)")
                return 1
            key, val = kv.split("=", 1)
            # Navigate/create nested dict
            parts = key.split(".")
            d = cfg
            for p in parts[:-1]:
                d = d.setdefault(p, {})
            # Try to parse value as JSON, fall back to string
            try:
                d[parts[-1]] = json.loads(val)
            except Exception:
                d[parts[-1]] = val
        _save_shared_config(cfg)
        _sync_config_to_projects(cfg)
        console.print(f"[green]✓[/green] Set {len(args.set)} key(s) and synced")
        return 0

    console.print("[yellow]Use --init, --show, --sync, or --set key=value[/yellow]")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# OMNI CLI — Groq lead, local-folder-first, mindset cages
# ─────────────────────────────────────────────────────────────────────────────

OMNI_LEAD_PROVIDER = "groq"

# Mindset cages — hard constraints, not suggestions. Each cage tells the model
# exactly what bug-bounty rules, scope, and techniques it MUST use. A model in
# Mindset 1 that tries Mindset 2 techniques fails loud.
MINDSET_CAGES: Dict[str, str] = {
    "1": """MINDSET 1 CAGE — MITRE ATT&CK + Offensive Red Teaming
You MUST operate within this cage:
- Bug bounty information rules: only report what is in-scope and verifiable.
- Assets in scope: only target assets explicitly listed as in-scope for the program.
- Company information: use only company data from the program scope and recon.
- Techniques: MITRE ATT&CK TTPs (all 344 techniques, cloud + local).
- Offensive Red Teaming: act as an adversary within the in-scope boundary.
- Goal: find bugs using MITRE TTPs + red teaming, constrained to in-scope assets.
- NEVER use philosophy, paradoxes, impossible problems, or iPhone framing — those are Mindset 2.
- NEVER synthesize with other mindsets — that is Mindset 3's job only.
""",
    "2": """MINDSET 2 CAGE — Philosophy, Paradoxes, Impossible Problems
You MUST operate within this cage:
- Bug bounty information rules: only report what is in-scope and verifiable.
- Assets in scope: only target assets explicitly listed as in-scope for the program.
- Company information: use only company data from the program scope and recon.
- Techniques: philosophy corpus, paradoxes, impossible problems, iPhone-level framing, invisible seams.
- Red Teaming: adversarial thinking through philosophical and paradoxical lenses.
- Goal: find bugs using paradox/impossible-problem framing + invisible seams, constrained to in-scope assets.
- NEVER use MITRE ATT&CK TTPs — those are Mindset 1.
- NEVER synthesize with other mindsets — that is Mindset 3's job only.
""",
    "3": """MINDSET 3 CAGE — Synthesis of Mindset 1 + Mindset 2 + Invisible Seam + Red Teaming
You MUST operate within this cage:
- Bug bounty information rules: only report what is in-scope and verifiable.
- Assets in scope: only target assets explicitly listed as in-scope for the program.
- Company information: use only company data from the program scope and recon.
- Techniques: SYNTHESIZE Mindset 1 (MITRE TTPs + red teaming) + Mindset 2 (paradoxes + invisible seams + iPhone framing) + invisible seam analysis + red teaming.
- Goal: merge M1 + M2 outputs into a unified finding, constrained to in-scope assets.
- You are given M1 results and M2 results as input. Combine them.
""",
}

VALID_MINDSETS = ("1", "2", "3")


def _omni_lead_provider() -> str:
    """Groq is the lead/entry provider for OmniCLI."""
    return OMNI_LEAD_PROVIDER


def _omni_providers() -> List[str]:
    """Discover available OmniCLI providers via heartbeat."""
    import re

    cp = subprocess.run(
        [sys.executable, "-m", "omnicli.cli", "heartbeat"],
        cwd=str(OMNICLI_ROOT), capture_output=True, text=True, timeout=120,
    )
    providers: List[str] = []
    valid_name = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")
    for line in cp.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "│" in line:
            parts = [p.strip() for p in line.split("│") if p.strip()]
            if parts and parts[0] not in ("Provider", "") and "…" not in parts[0]:
                name = parts[0]
                if valid_name.match(name):
                    providers.append(name)
    if not providers:
        providers = ["groq", "openrouter", "nvidia", "cloudflare",
                     "bynara", "apinex", "xkiro", "dahl", "monkeycode",
                     "databricks", "llm7"]
    return providers


def _omni_local_ground(idea: str, workspace: Path = ROOT) -> Dict[str, Any]:
    """
    Read the local folder FIRST before any model is called.

    Returns:
        files: list of {path, excerpt} for relevant local files
        workspace_map: list of all files in the workspace
        needs_external: True if no local file seems relevant enough
    """
    from omnicli.grounding import index_workspace, build_grounding

    grounding = build_grounding(idea, str(workspace))

    files = []
    for entry in grounding.get("files", [])[:10]:
        files.append({
            "path": entry.get("path", ""),
            "excerpt": entry.get("excerpt", "")[:500],
            "score": entry.get("score", 0),
        })

    workspace_map = []
    for f in sorted(workspace.rglob("*")):
        if f.is_file() and not f.name.startswith(".") and ".git" not in f.parts:
            workspace_map.append(str(f.relative_to(workspace)))

    # If no files scored above the minimum threshold, we need external
    needs_external = grounding.get("files_indexed", 0) == 0 or \
        not grounding.get("has_sources", False)

    return {
        "files": files,
        "workspace_map": workspace_map,
        "needs_external": needs_external,
        "indexed": grounding.get("files_indexed", 0),
    }


def _omni_ask_with_cage(
    provider: str,
    prompt: str,
    mindset: str,
    local_context: str = "",
    timeout: Optional[int] = None,
) -> str:
    """Ask a provider with a mindset cage applied as a hard system constraint.

    Uses --no-ground because we handle local grounding ourselves in
    _omni_local_ground (OmniCLI's auto-grounding attaches oversized files
    like code_hunter.py that blow the model's token limit).
    """
    cage = MINDSET_CAGES.get(mindset, MINDSET_CAGES["3"])
    # Truncate local context to stay under model token limits (~4000 chars)
    local_ctx = local_context[:4000] if local_context else "(none)"
    full_prompt = (
        f"{cage}\n"
        f"LOCAL CONTEXT (from your workspace, authoritative):\n{local_ctx}\n"
        f"---\n"
        f"TASK: {prompt}\n"
        f"REMINDER: You are in Mindset {mindset} cage. Do not use techniques "
        f"from other mindsets. If you cannot answer from the cage constraints, "
        f"say so explicitly."
    )
    cp = subprocess.run(
        [sys.executable, "-m", "omnicli.cli", "ask", full_prompt,
         "--provider", provider, "--no-ground"],
        cwd=str(OMNICLI_ROOT), capture_output=True, text=True,
        timeout=timeout or 60,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"Provider {provider} failed: {cp.stderr[:500]}")
    return cp.stdout


def _fail_loud(message: str) -> None:
    """Scream loudly when something is not working."""
    console.print(f"\n[bold red]{'='*70}[/bold red]")
    console.print(f"[bold red]✗ FAIL LOUD: {message}[/bold red]")
    console.print(f"[bold red]{'='*70}[/bold red]\n")


def cmd_omni_build(args: argparse.Namespace) -> int:
    """
    OmniCLI build mode.

    Three execution modes:
      - sequential: ALL providers do Mindset 1 → ALL do Mindset 2 → ALL do Mindset 3
      - split:      RATIO% do Mindset 1, rest do Mindset 2 → ALL do Mindset 3
      - all3:       ALL providers do Mindset 3 together (synthesis only)

    In every mode, Mindsets are CAGES (hard constraints), not suggestions.
    Groq is the lead provider. Local folder is read first.
    """
    import concurrent.futures

    idea = args.idea or args.prompt
    if not idea:
        console.print("[red]✗[/red] Provide an idea: code_hunter omni build "
                      "\"your idea here\"")
        return 1

    mode = getattr(args, "mode", "split") or "split"
    if mode not in ("sequential", "split", "all3"):
        _fail_loud(f"Invalid mode {mode!r}; allowed: sequential, split, all3")
        return 1

    split_ratio = getattr(args, "split_ratio", 50)
    if not 0 <= split_ratio <= 100:
        _fail_loud(f"--split-ratio must be 0-100, got {split_ratio}")
        return 1

    providers = _omni_providers()
    if not providers:
        _fail_loud("No OmniCLI providers discovered. Run `code_hunter omni heartbeat` first.")
        return 1

    # Allow user to override provider list
    user_providers = getattr(args, "providers", None)
    if user_providers:
        providers = [p.strip() for p in user_providers.split(",") if p.strip()]

    lead = _omni_lead_provider()
    if lead not in providers:
        providers.insert(0, lead)

    # ── Local folder FIRST ──────────────────────────────────────────
    local = _omni_local_ground(idea)
    console.print(Panel(
        f"[bold]OmniCLI Build Mode[/bold]\n"
        f"Lead Provider: {lead}  |  Mode: {mode.upper()}"
        + (f"  |  Split: {split_ratio}% M1 / {100-split_ratio}% M2" if mode == "split" else "") + "\n"
        f"Idea: {idea}\n"
        f"Providers ({len(providers)}): {', '.join(providers)}\n"
        f"Local folder: {local['indexed']} files indexed, "
        f"{len(local['files'])} relevant matches",
        title="Hybrid Red-Team + Build (Mindset Cages)",
        border_style="cyan",
    ))

    # Show local files found
    if local["files"]:
        console.print("\n[bold cyan]Local files found (read first):[/bold cyan]")
        lt = Table()
        lt.add_column("Path", style="bold")
        lt.add_column("Score", justify="right")
        lt.add_column("Excerpt", style="dim")
        for f in local["files"]:
            lt.add_row(f["path"], str(f["score"]), f["excerpt"][:100])
        console.print(lt)

    # If nothing local, ask before going external
    if local["needs_external"]:
        console.print("\n[yellow]⚠ No relevant local files found.[/yellow]")
        console.print("[dim]Workspace map (first 20):[/dim]")
        for f in local["workspace_map"][:20]:
            console.print(f"  {f}")
        if len(local["workspace_map"]) > 20:
            console.print(f"  ... and {len(local['workspace_map'])-20} more")
        console.print("\n[yellow]Local folder has no answer. Expand search to external providers?[/yellow]")
        # In non-interactive mode, proceed but warn loudly
        console.print("[red]FAIL-LOUD: proceeding to external providers because no local match.[/red]")

    local_context = "\n".join(f"[{f['path']}] {f['excerpt']}" for f in local["files"])

    results: Dict[str, str] = {}

    def _ask_caged(provider: str, prompt: str, mindset: str) -> str:
        try:
            return _omni_ask_with_cage(provider, prompt, mindset, local_context)
        except Exception as exc:
            _fail_loud(f"Provider {provider} in Mindset {mindset} failed: {exc}")
            return f"ERROR ({provider}/{mindset}): {exc}"

    # ── Phase based on mode ─────────────────────────────────────────
    if mode == "sequential":
        # ALL providers M1 → ALL providers M2 → ALL providers M3
        for mindset in ("1", "2", "3"):
            label = {"1": "Mindset 1 (MITRE + Red Teaming)",
                     "2": "Mindset 2 (Paradox + Invisible Seams)",
                     "3": "Mindset 3 (Synthesis)"}[mindset]
            console.print(f"\n[bold cyan]Phase — {label}[/bold cyan]")
            with concurrent.futures.ThreadPoolExecutor() as ex:
                fut_to_prov = {
                    ex.submit(_ask_caged, p,
                              f"Process this idea: {idea}\n"
                              f"Apply Mindset {mindset} cage constraints "
                              f"and report findings within in-scope assets.",
                              mindset): p
                    for p in providers
                }
                for fut in concurrent.futures.as_completed(fut_to_prov):
                    prov = fut_to_prov[fut]
                    try:
                        out = fut.result()
                    except Exception as exc:
                        out = f"ERROR ({prov}): {exc}"
                    results[f"m{mindset}:{prov}"] = out
                    console.print(f"  [green]✓[/green] m{mindset}: {prov}")

    elif mode == "split":
        # RATIO% providers M1, rest M2 → ALL M3
        m1_count = max(1, int(len(providers) * split_ratio / 100))
        m1_providers = providers[:m1_count]
        m2_providers = providers[m1_count:]

        console.print(f"\n[bold cyan]Phase 1 — Mindset 1 ({len(m1_providers)} providers)[/bold cyan]")
        with concurrent.futures.ThreadPoolExecutor() as ex:
            fut_to_prov = {
                ex.submit(_ask_caged, p,
                          f"Process this idea: {idea}\n"
                          f"Apply Mindset 1 cage (MITRE TTPs + red teaming, "
                          f"in-scope assets only).",
                          "1"): p
                for p in m1_providers
            }
            for fut in concurrent.futures.as_completed(fut_to_prov):
                prov = fut_to_prov[fut]
                try:
                    out = fut.result()
                except Exception as exc:
                    out = f"ERROR ({prov}): {exc}"
                results[f"m1:{prov}"] = out
                console.print(f"  [green]✓[/green] m1: {prov}")

        console.print(f"\n[bold cyan]Phase 2 — Mindset 2 ({len(m2_providers)} providers)[/bold cyan]")
        with concurrent.futures.ThreadPoolExecutor() as ex:
            fut_to_prov = {
                ex.submit(_ask_caged, p,
                          f"Process this idea: {idea}\n"
                          f"Apply Mindset 2 cage (paradoxes + invisible seams + "
                          f"iPhone framing, in-scope assets only).",
                          "2"): p
                for p in m2_providers
            }
            for fut in concurrent.futures.as_completed(fut_to_prov):
                prov = fut_to_prov[fut]
                try:
                    out = fut.result()
                except Exception as exc:
                    out = f"ERROR ({prov}): {exc}"
                results[f"m2:{prov}"] = out
                console.print(f"  [green]✓[/green] m2: {prov}")

        console.print("\n[bold cyan]Phase 3 — Mindset 3 (ALL providers synthesize)[/bold cyan]")
        m1_summary = "\n".join(f"[{k.split(':')[1]}] {v[:300]}"
                               for k, v in results.items() if k.startswith("m1:"))
        m2_summary = "\n".join(f"[{k.split(':')[1]}] {v[:300]}"
                               for k, v in results.items() if k.startswith("m2:"))
        with concurrent.futures.ThreadPoolExecutor() as ex:
            fut_to_prov = {
                ex.submit(_ask_caged, p,
                          f"Synthesize these results into a final finding.\n"
                          f"Original idea: {idea}\n\n"
                          f"Mindset 1 results:\n{m1_summary}\n\n"
                          f"Mindset 2 results:\n{m2_summary}\n\n"
                          f"Output: refined finding, risks, mitigations, action plan.",
                          "3"): p
                for p in providers
            }
            for fut in concurrent.futures.as_completed(fut_to_prov):
                prov = fut_to_prov[fut]
                try:
                    out = fut.result()
                except Exception as exc:
                    out = f"ERROR ({prov}): {exc}"
                results[f"m3:{prov}"] = out
                console.print(f"  [green]✓[/green] m3: {prov}")

    elif mode == "all3":
        # ALL providers do Mindset 3 together
        console.print(f"\n[bold cyan]Phase — Mindset 3 (ALL {len(providers)} providers)[/bold cyan]")
        with concurrent.futures.ThreadPoolExecutor() as ex:
            fut_to_prov = {
                ex.submit(_ask_caged, p,
                          f"Process this idea: {idea}\n"
                          f"Apply Mindset 3 cage — synthesize MITRE TTPs + "
                          f"red teaming + paradoxes + invisible seams + iPhone "
                          f"framing into a unified finding within in-scope assets.",
                          "3"): p
                for p in providers
            }
            for fut in concurrent.futures.as_completed(fut_to_prov):
                prov = fut_to_prov[fut]
                try:
                    out = fut.result()
                except Exception as exc:
                    out = f"ERROR ({prov}): {exc}"
                results[f"m3:{prov}"] = out
                console.print(f"  [green]✓[/green] m3: {prov}")

    # ── Final synthesis by lead provider (Groq) ─────────────────────
    console.print(f"\n[bold cyan]Final Synthesis — Lead: {lead}[/bold cyan]")
    all_summary = "\n".join(f"[{k}] {v[:300]}" for k, v in results.items())
    # Synthesis is one long call — give it extra time
    synth_timeout = max(getattr(args, "timeout", 60) * 2, 120)
    try:
        final_plan = _omni_ask_with_cage(
            lead,
            f"Synthesize ALL provider results into the final actionable plan.\n"
            f"Original idea: {idea}\n\n"
            f"All provider outputs:\n{all_summary}\n\n"
            f"Output: (1) refined finding, (2) risks & mitigations, "
            f"(3) step-by-step action plan, (4) success criteria.",
            "3",
            local_context,
            timeout=synth_timeout,
        )
    except Exception as exc:
        _fail_loud(f"Lead provider {lead} synthesis failed: {exc}")
        final_plan = f"SYNTHESIS FAILED: {exc}"

    # ── Write results ───────────────────────────────────────────────
    out_dir = ORACLE_ROOT / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"omni_build_{stamp}.json"
    out_path.write_text(json.dumps({
        "idea": idea,
        "mode": mode,
        "split_ratio": split_ratio,
        "lead_provider": lead,
        "providers": providers,
        "local_folder": {
            "indexed": local["indexed"],
            "files": local["files"],
            "needs_external": local["needs_external"],
        },
        "results": results,
        "final_synthesis": final_plan,
        "mindset_cages": {k: v[:200] + "..." for k, v in MINDSET_CAGES.items()},
    }, indent=2) + "\n")

    console.print(Panel(final_plan, title="Final Synthesis",
                        border_style="green"))
    console.print(f"\n[green]✓[/green] Full results saved to {out_path}")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing (additions)
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="code-hunter",
        description="Unified CLI for Scan4Me + Oracle + OmniCLI bug-bounty pipeline.",
    )
    p.add_argument("--timeout", type=int, default=3600,
                   help="Per-command timeout in seconds (default: 3600)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Scan4Me: feed sync, radar, export")
    p_scan.add_argument("sub", choices=["sync", "enrich", "radar", "check",
                                         "export", "handoff", "keys"],
                        help="Scan4Me subcommand")
    p_scan.add_argument("--limit", type=int, default=20)
    p_scan.add_argument("--sync", action="store_true",
                        help="Refresh Scan4Me DB from platforms first")
    p_scan.add_argument("--offline", action="store_true",
                        help="Offline: local DB only")
    p_scan.add_argument("--top", type=int, default=20,
                        help="Top N for export/radar")
    p_scan.add_argument("--wildcards-only", action="store_true")
    p_scan.add_argument("--clean", action="store_true")
    p_scan.add_argument("--new-companies", action="store_true")
    p_scan.add_argument("--new-assets", action="store_true")
    p_scan.add_argument("--prescan-file", default=None)
    p_scan.add_argument("--scan-file", default=None)
    p_scan.add_argument("--output", default=None)
    p_scan.add_argument("--top-n", type=int, default=None)
    p_scan.add_argument("--sites", default=None)
    p_scan.add_argument("--no-cloud", action="store_true")
    p_scan.add_argument("--handle", default=None)
    p_scan.add_argument("--delay", type=float, default=None)
    p_scan.add_argument("domain", nargs="?", default=None,
                        help="Domain for 'check' subcommand")
    p_scan.set_defaults(func=cmd_scan)

    # ── oracle ──
    p_oracle = sub.add_parser("oracle", help="Oracle: hunt pipeline")
    p_oracle.add_argument("sub", choices=["prescan", "scan", "queue", "hunt",
                                           "bundle", "verify-download",
                                           "list", "scope", "recon", "analyze",
                                           "seams", "status", "backends",
                                           "audit", "redteam"],
                        help="Oracle subcommand")
    p_oracle.add_argument("--limit", type=int, default=50)
    p_oracle.add_argument("--sync", action="store_true")
    p_oracle.add_argument("--top-n", type=int, default=None)
    p_oracle.add_argument("--sites", default=None)
    p_oracle.add_argument("--prescan-file", default=None)
    p_oracle.add_argument("--handoff", default=None)
    p_oracle.add_argument("--order", default=None)
    p_oracle.add_argument("--concurrent", action="store_true")
    p_oracle.add_argument("--cross-site-cap", type=int, default=None)
    p_oracle.add_argument("--max-items", type=int, default=None)
    p_oracle.add_argument("--model", default=None)
    p_oracle.add_argument("--researcher", default=None)
    p_oracle.add_argument("--workspace", default=None)
    p_oracle.add_argument("--out-dir", default=None)
    p_oracle.add_argument("--config", default=None)
    p_oracle.add_argument("--cdp-port", type=int, default=None)
    p_oracle.add_argument("--probe-timeout", type=float, default=8.0)
    p_oracle.add_argument("--target", default=None,
                          help="Target for hunt/scope/recon")
    p_oracle.add_argument("--bundle", default=None)
    p_oracle.add_argument("--json", action="store_true")
    p_oracle.add_argument("--no-cloud", action="store_true")
    p_oracle.add_argument("--cloud", action="store_true")
    p_oracle.add_argument("--download", action="store_true")
    p_oracle.add_argument("--execute", action="store_true")
    p_oracle.add_argument("--no-resume", action="store_true")
    p_oracle.add_argument("--skip-download", action="store_true")
    p_oracle.add_argument("--controlled", action="store_true", default=True,
                          help="Enable controlled/low-rate recon (default: on)")
    p_oracle.add_argument("--no-controlled", action="store_true",
                          help="Disable controlled/low-rate recon")
    p_oracle.add_argument("--testnet", action="store_true")
    p_oracle.add_argument("--code", action="store_true")
    p_oracle.add_argument("--voice", action="store_true")
    p_oracle.set_defaults(func=cmd_oracle)

    # ── omni ──
    p_omni = sub.add_parser("omni", help="OmniCLI: red-team / orchestrate "
                        "(independent of Oracle)")
    p_omni.add_argument("sub", choices=["ask", "chat", "ping", "heartbeat",
                                         "credits", "models", "serve", "scan",
                                         "oracle-pipeline", "evaluate-security",
                                         "workflow", "agent", "swarm", "verify",
                                         "build", "check",
                                         "prepare-security-review"],
                        help="OmniCLI subcommand")
    p_omni.add_argument("idea", nargs="?", default=None,
                        help="Idea for build mode (also --idea)")
    p_omni.add_argument("--prompt", default=None, help="Prompt for ask/chat")
    p_omni.add_argument("--idea", default=None, help="Idea for build mode")
    p_omni.add_argument("--goal", default=None, help="Goal for agent")
    p_omni.add_argument("--task", default=None, help="Task for swarm")
    p_omni.add_argument("--claim", default=None, help="Claim for verify consensus")
    p_omni.add_argument("--provider", default=None)
    p_omni.add_argument("--model", default=None)
    p_omni.add_argument("--oracle-root", default=None)
    p_omni.add_argument("--limit", type=int, default=50)
    p_omni.add_argument("--count", type=int, default=1)
    p_omni.add_argument("--timeout", type=int, default=3600)
    p_omni.add_argument("--dataset", default=None)
    p_omni.add_argument("--minimum-cases", type=int, default=10)
    p_omni.add_argument("--repetitions", type=int, default=1)
    p_omni.add_argument("--function", default=None)
    p_omni.add_argument("--file", default=None)
    p_omni.add_argument("--folder", default=None)
    p_omni.add_argument("--url", default=None)
    p_omni.add_argument("--must-contain", default=None)
    p_omni.add_argument("--mode", default="split",
                        help="Build mode: sequential, split, all3 (default: split)")
    p_omni.add_argument("--split-ratio", type=int, default=50,
                        help="For split mode: percent of providers in Mindset 1 (default: 50)")
    p_omni.add_argument("--providers", default=None,
                        help="Comma-separated provider list (overrides auto-discovery)")
    p_omni.add_argument("--hosts", default=None)
    p_omni.add_argument("--json", action="store_true")
    p_omni.add_argument("--as-json", action="store_true")
    p_omni.add_argument("--static-baseline", action="store_true")
    p_omni.add_argument("--allow-general", action="store_true")
    p_omni.add_argument("--allow-shell", action="store_true")
    p_omni.add_argument("--allow-local", action="store_true")
    p_omni.add_argument("--allow-mutating-http", action="store_true")
    p_omni.add_argument("--rotate-families", action="store_true")
    p_omni.add_argument("--no-ground", action="store_true")
    p_omni.set_defaults(func=cmd_omni)

    # ── config ──
    p_config = sub.add_parser("config", help="Manage shared config.json "
                        "used by Scan4Me + Oracle")
    p_config.add_argument("--init", action="store_true",
                          help="Initialize shared config.json")
    p_config.add_argument("--show", action="store_true",
                          help="Show current shared config")
    p_config.add_argument("--sync", action="store_true",
                          help="Sync shared config to Scan4Me + Oracle dirs")
    p_config.add_argument("--set", nargs="+", default=None,
                          help="Set key=value (dotted path, repeatable)")
    p_config.set_defaults(func=cmd_config)

    # ── pipeline ──
    p_pipe = sub.add_parser("pipeline", help="End-to-end money pipeline")
    p_pipe.add_argument("--run", action="store_true",
                        help="Execute the full pipeline")
    p_pipe.add_argument("--limit", type=int, default=50,
                        help="Prescan sweep size")
    p_pipe.add_argument("--top-n", type=int, default=3,
                        help="Verified programs to deep-dive")
    p_pipe.add_argument("--no-cloud", action="store_true",
                        help="Offline mode (no network probing)")
    p_pipe.set_defaults(func=cmd_pipeline)

    # ── status ──
    p_status = sub.add_parser("status", help="System health check")
    p_status.set_defaults(func=cmd_status)

    # ── report ──
    p_report = sub.add_parser("report", help="Consolidated hunt report")
    p_report.add_argument("--output", default=None,
                          help="Output JSON path")
    p_report.set_defaults(func=cmd_report)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())