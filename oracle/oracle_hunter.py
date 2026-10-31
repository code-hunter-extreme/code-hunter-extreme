#!/usr/bin/env python3
# LAYER: seal
# DEST: vortex
# ENDPOINTS: ProgramScopeGate, run_reflexes, verify_seams, teardown_poc, recon, cmd_hunt, cmd_bundle, cmd_verify_download, cmd_recon, cmd_analyze, cmd_redteam, main  # noqa: E501
# TOPICS: none
"""
Oracle Hunter — Program → Recon → Oracle 8-Reflex → Finding Cards
──────────────────────────────────────────────────────────────────
Takes a bug bounty program, pulls its scope, runs recon, then feeds
everything through the Oracle mindset. The active interface model is the
controller; Oracle's configured providers supply bounded research passes.

The supported pipeline is three commands:
    oracle-hunter prescan --sync                       # no-login Scan4Me sweep
    oracle-hunter scan -N 1 --download                 # Oracle re-scan + handoff
    oracle-hunter queue --execute                      # hunt the handoff

Usage:
    oracle-hunter prescan [--sync] [--limit N]         # P11: raw Scan4Me sweep
    oracle-hunter scan [-N 5 | --sites a,b]            # P11: verify + P12 handoff
    oracle-hunter queue [--execute]                    # P12: schedule/execute
    oracle-hunter bundle <workspace>                   # product bundle + SHA-256 manifest
    oracle-hunter verify-download <zip|dir>            # integrity + submission gate
    oracle-hunter list                                 # ranked programs from cache
    oracle-hunter hunt <program-name-or-url>           # one-off hunt (no chain flags)
    oracle-hunter recon <program-name>                 # recon only, no analysis
    oracle-hunter analyze <recon-dir>                  # run reflexes on existing recon
    oracle-hunter seams <recon-dir>                    # print seam cards only
    oracle-hunter scope <program-name>                 # print scope assets
    oracle-hunter status                               # check tools + models

Examples:
    oracle-hunter prescan --sync
    oracle-hunter scan -N 1 --download
    oracle-hunter queue --execute
    oracle-hunter bundle targets/HackerOne/matomo
    oracle-hunter verify-download targets/HackerOne/matomo/reports/product_<stamp>.zip
    oracle-hunter hunt hackerone/nodejs
    oracle-hunter hunt "Shopify" --cloud
    oracle-hunter hunt https://bugcrowd.com/programs/shopify
    oracle-hunter list --min-payout 1000 --fast-triage --web2
"""

import hashlib
import os
import re
import sys
import json
import atexit
import shlex
import shutil
import argparse
import socket
import subprocess
import tempfile
import textwrap
import time
import traceback
import http.client
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# ── Paths ──────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
RECON_DIR = _HERE / "recon"
REPORTS_DIR = _HERE / "reports"
TARGETS_DIR = _HERE / "targets"
GO_BIN = Path.home() / "go" / "bin"

# Inject go/bin into this process PATH immediately so shutil.which finds tools
os.environ["PATH"] = f"{GO_BIN}:{os.environ.get('PATH', '')}"

RECON_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ── Oracle document paths ──────────────────────────────────────────────────────
_SYSTEM_PROMPT = _HERE / "ORACLE_SYSTEM_PROMPT.md"
_FRAMEWORK = _HERE / "ORACLE_FRAMEWORK.md"
_VOICE = _HERE / "ORACLE_VOICE.md"
_ALEX_VOICE = _HERE / "ALEX_VOICE.md"

# ── Local model ────────────────────────────────────────────────────────────────
# Keep direct local calls aligned with the router configuration. The router owns
# model selection; these defaults only cover legacy direct-Ollama call sites.
from oracle_llm import estimate_tokens, load_backend_config
from oracle_runlog import RunLog  # noqa: E402  (after path setup, like above)

_BACKEND_CONFIG = load_backend_config()
LOCAL_MODEL = _BACKEND_CONFIG["local_model"]
FALLBACK_MODEL = _BACKEND_CONFIG["light_local_model"]

# ── Rich ───────────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None  # type: ignore[assignment]


# ─────────────────────────────────────────────────────────────────────────────
# Oracle system prompt — ALL 4 docs concatenated verbatim, no summaries
# ─────────────────────────────────────────────────────────────────────────────


def _load_oracle_prompt(
    voice: bool = True, query: str = "", source_max_chars: int = 320_000
) -> str:
    """
    Concatenate the operational Oracle documents and every original packaged
    source text verbatim (a cap too small for the full corpus fails loud in
    source_context naming the dropped documents — never a silent subset):
      1. ORACLE_SYSTEM_PROMPT.md  — the 8 paradox→reflex worked examples
      2. ORACLE_FRAMEWORK.md      — the 16-file philosophy + all patterns
      3. ORACLE_VOICE.md          — hunting voice layer + register switch
      4. ALEX_VOICE.md            — the one-move structure, named moves, rhythm

    The canonical corpus lives in ``corpus/`` inside this application.  It is
    included verbatim and in full, never read from an external Documents folder and never
    replaced by a generated summary.
    """
    from oracle_corpus import corpus_inventory, source_context

    docs = [_SYSTEM_PROMPT, _FRAMEWORK]
    if voice:
        docs += [_VOICE, _ALEX_VOICE]
    parts = []
    for doc in docs:
        try:
            parts.append(doc.read_text(encoding="utf-8"))
        except FileNotFoundError:
            _warn(f"Oracle doc not found: {doc}")
    parts.extend(
        [
            corpus_inventory(),
            source_context(query, max_chars=source_max_chars),
        ]
    )
    return "\n\n---\n\n".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Tool helpers
# ─────────────────────────────────────────────────────────────────────────────


def _bin(name: str) -> str:
    """Return full path to a binary, checking go/bin first."""
    gobin = GO_BIN / name
    if gobin.exists():
        return str(gobin)
    found = shutil.which(name)
    return found or name


def _run(
    cmd: List[str],
    timeout: int = 120,
    cwd: Optional[Path] = None,
    env: Optional[Dict] = None,
) -> Tuple[int, str, str]:
    merged = {**os.environ, **(env or {})}
    merged["PATH"] = f"{GO_BIN}:{merged.get('PATH', '')}"
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=merged,
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 1, "", f"not found: {cmd[0]}"
    except Exception as e:
        return 1, "", str(e)


def _tool_ok(name: str) -> bool:
    return (GO_BIN / name).exists() or bool(shutil.which(name))


def _direct_probe_fallback(
    hosts: List[str], scope_gate=None, timeout: int = 10, headers=None
) -> List[str]:
    """Direct urllib live-host probe — fallback when httpx hangs/empty.

    Every candidate is scope-gated BEFORE any packet is sent and must pass
    _is_dns_target. No redirects followed (unapproved probe targets).
    Fail-closed: with no scope gate, nothing is probed.
    Returns ["https://host [status]", ...] for hosts that answered.
    ``headers`` ("Name: value" strings, the _recon_headers shape) ride
    every probe so a returned status was served under the same
    authenticated regime as httpx/katana — regime receipts read these
    status tags, anonymous answers must not impersonate them.
    """
    import urllib.request
    import ssl

    if scope_gate is None:
        return []

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )
    _probe_headers = {"User-Agent": "oracle-recon/1.0"}
    for _h in headers or []:
        _name, _, _value = str(_h).partition(":")
        if _name.strip() and _value.strip():
            _probe_headers[_name.strip()] = _value.strip()
    live = []
    for h in hosts or []:
        h = (h or "").strip().lower().split()[0].rstrip("/")
        if not h or not _is_dns_target(h):
            continue
        url = h if h.startswith("http") else f"https://{h}"
        ok, _ = scope_gate.is_in_scope(url)
        if not ok:
            continue
        try:
            req = urllib.request.Request(
                url, method="HEAD", headers=dict(_probe_headers)
            )
            with opener.open(req, timeout=timeout) as r:
                live.append(f"{url} [{r.status}]")
        except Exception:
            # HEAD rejected? One GET try before giving up on this host.
            try:
                req = urllib.request.Request(
                    url, headers=dict(_probe_headers)
                )
                with opener.open(req, timeout=timeout) as r:
                    live.append(f"{url} [{r.status}]")
            except Exception:
                continue
    return live


TRIO_KEYS_FILE = Path.home() / ".config" / "trio" / "keys.env"
ORACLE_KEYS_FILE = _HERE / "ORACLE_KEYS.env"
_CREDENTIAL_SUFFIXES = ("_API_KEY", "_API_TOKEN", "_TOKEN", "_JWT", "_SECRET")


def _load_env() -> Dict[str, str]:
    """Unified key loader, lowest to highest precedence:

    trio central < ORACLE_KEYS.env < repo .env < system environment.

    Platform API keys live split across those files (HackerOne/Intigriti
    keys exist only in ORACLE_KEYS.env), so every layer is read or the
    API-first tiers silently never fire. Empty file values are
    placeholders and never clobber a real key from a lower layer.
    """
    env: Dict[str, str] = {}
    for env_file in (TRIO_KEYS_FILE, ORACLE_KEYS_FILE, _HERE / ".env"):
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    v = v.strip().strip('"').strip("'")
                    # Multi-word sentences in credential slots are
                    # placeholder notes, not keys: read as unset so API
                    # tiers skip instead of firing doomed requests.
                    if v and not (
                        k.strip().endswith(_CREDENTIAL_SUFFIXES)
                        and any(c.isspace() for c in v)
                    ):
                        env[k.strip()] = v
    # Empty process values never clobber a real file key.
    env.update({k: v for k, v in os.environ.items() if v})
    for k in [k for k in env if k.endswith(_CREDENTIAL_SUFFIXES)]:
        if any(c.isspace() for c in env[k]):
            del env[k]
    return env


# ── --no-cloud enforcement ──────────────────────────────────────────────────
# _no_cloud(args) is True ONLY when --no-cloud was explicitly passed
# (args.cloud is False via action="store_false"; default None means "auto").
# _apply_no_cloud() enforces it end to end:
#   1. oracle_llm router → local-only backends (fail-closed RuntimeError when
#      no local backend answers — never a silent cloud call);
#   2. oracle_programs → Firecrawl cloud scrape step skipped.
# Call it at the top of every command that accepts --no-cloud.


def _no_cloud(args) -> bool:
    return getattr(args, "cloud", None) is False


def _config_hunt_cloud(args) -> None:
    """Honor oracle.config.json ``hunt.cloud`` when the CLI left it auto.

    CLI --cloud/--no-cloud always wins. Only an explicit config
    ``false`` changes anything: it pins the hunt local-only, exactly
    like --no-cloud. (Config ``true``/absent = router auto, unchanged.)
    """
    if getattr(args, "cloud", None) is not None:
        return
    path = getattr(args, "config", None) or str(_HERE / "oracle.config.json")
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return
    hunt_cfg = data.get("hunt") if isinstance(data, dict) else None
    if isinstance(hunt_cfg, dict) and hunt_cfg.get("cloud") is False:
        args.cloud = False


def _cdp_port(args=None) -> int:
    """Signed-in Chrome CDP port: --cdp-port > ORACLE_CDP_PORT > 9227."""
    port = getattr(args, "cdp_port", None)
    if port:
        return int(port)
    env_port = os.environ.get("ORACLE_CDP_PORT", "").strip()
    if env_port.isdigit():
        return int(env_port)
    return 9227


def _die_on_unserved_mindsets(unserved) -> None:
    """Fail the hunt loud when requested mindsets minted nothing.

    Owner decision 2026-10-25 (fail loud, no template-only shrug): the
    yield ledger already forced a SYSTEM FAILURE banner; the process
    now actually fails. Called only after the report is written, so
    template/code findings on disk are preserved — but the hunt's
    verdict is failure, never TARGET CLEAN.
    """
    if unserved:
        _die(
            f"LENS-STARVED HUNT: mindset(s) {', '.join(unserved)} minted "
            f"0 cards — the design never fired, so this verdict is a "
            f"system failure, not a clean target. Report preserved on "
            f"disk. Fix lens plumbing/yield; do not submit a partial "
            f"mindset run as the complete product."
        )


def _pin_local_model(args) -> str:
    """Pin --model into the router (hunt/analyze/verify parity, Step 1).

    Returns the effective model name. Every entry point that accepts
    --model must call this, or the flag silently misses local routing.
    """
    model = getattr(args, "model", LOCAL_MODEL)
    import oracle_llm as _ollm

    _ollm.set_preferred_local_model(model)
    return model


def _reject_verify_account_flags(args) -> None:
    """Verify never consumes dual-account CLI values — refuse loudly.

    The standalone verify path reuses only a pre-saved sessions.json for
    IDOR placeholders; accepting --account-a/--account-b/--prompt-login
    there silently dropped operator intent (Step-1 flag matrix).
    """
    given = [
        flag
        for flag, present in (
            ("--account-a", getattr(args, "account_a", None)),
            ("--account-b", getattr(args, "account_b", None)),
            ("--prompt-login", getattr(args, "prompt_login", False)),
        )
        if present
    ]
    if given:
        _die(
            f"verify does not consume {'/'.join(given)} — dual-account "
            f"material is hunt-only. Re-run via `oracle-hunter hunt`, or "
            f"drop the flag(s); verify reuses a saved sessions.json when present."
        )


def _apply_no_cloud(args) -> bool:
    nc = _no_cloud(args)
    if nc:
        import oracle_llm

        oracle_llm.set_no_cloud(True)
        try:
            import oracle_programs as _op

            _op.NO_CLOUD = True
        except Exception:
            pass
        _warn("--no-cloud: cloud backends disabled — local model only, no Firecrawl")
    return nc


# ─────────────────────────────────────────────────────────────────────────────
# Print helpers
# ─────────────────────────────────────────────────────────────────────────────


def _flush() -> None:
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass


_ACTIVE_RUNLOG: Optional[RunLog] = None
_JSON_STDOUT = False
_ORIG_EXCEPTHOOK = sys.excepthook


def _runlog_console(level: str, msg: str) -> None:
    if _ACTIVE_RUNLOG is not None:
        try:
            _ACTIVE_RUNLOG.event("console", level=level, message=msg)
            if level == "warning":
                _ACTIVE_RUNLOG.event("warning", message=msg)
            elif level == "error":
                _ACTIVE_RUNLOG.event("error", message=msg)
        except Exception:
            # Observability must never break the hunt.
            pass


def _runlog_event(event: str, **data) -> None:
    if _ACTIVE_RUNLOG is not None:
        try:
            _ACTIVE_RUNLOG.event(event, **data)
        except Exception:
            # A bad artifact value or unwritable log is not a product failure.
            pass


def _runlog_artifact(path, kind: str = "file", **meta) -> None:
    if _ACTIVE_RUNLOG is not None:
        try:
            _ACTIVE_RUNLOG.artifact(path, kind=kind, **meta)
        except Exception:
            # Run logging is observability, never a gate.
            pass


def _runlog_excepthook(exc_type, exc, tb) -> None:
    if _ACTIVE_RUNLOG is not None:
        _ACTIVE_RUNLOG.event(
            "run.exception",
            error=f"{exc_type.__name__}: {exc}",
            traceback="".join(traceback.format_exception(exc_type, exc, tb)),
        )
        _ACTIVE_RUNLOG.finish(
            "failed", f"{exc_type.__name__}: {exc}", exit_code=1
        )
    _ORIG_EXCEPTHOOK(exc_type, exc, tb)


def _finish_runlog() -> None:
    if _ACTIVE_RUNLOG is not None and _ACTIVE_RUNLOG.finished_at is None:
        if _ACTIVE_RUNLOG.status == "failed":
            _ACTIVE_RUNLOG.finish("failed", _ACTIVE_RUNLOG.error, exit_code=1)
        else:
            _ACTIVE_RUNLOG.finish(
                "incomplete", "process exited without a final status"
            )


sys.excepthook = _runlog_excepthook
atexit.register(_finish_runlog)


def _info(msg: str):
    _runlog_console("info", msg)
    if _JSON_STDOUT:
        print(f"→ {msg}", file=sys.stderr)
    elif RICH:
        console.print(f"[cyan]→[/cyan] {msg}")
    else:
        print(f"→ {msg}")
    _flush()


def _ok(msg: str):
    _runlog_console("ok", msg)
    if _JSON_STDOUT:
        print(f"✓ {msg}", file=sys.stderr)
    elif RICH:
        console.print(f"[green]✓[/green] {msg}")
    else:
        print(f"✓ {msg}")
    _flush()


def _warn(msg: str):
    _runlog_console("warning", msg)
    if _JSON_STDOUT:
        print(f"⚠  {msg}", file=sys.stderr)
    elif RICH:
        console.print(f"[yellow]⚠[/yellow]  {msg}")
    else:
        print(f"⚠  {msg}", file=sys.stderr)
    _flush()


def _die(msg: str):
    _runlog_console("error", msg)
    if _ACTIVE_RUNLOG is not None:
        # Mark, do not finish: queue --execute catches this SystemExit per
        # item and keeps hunting under the same runlog. Finishing here
        # would freeze the whole queue run as failed at the first death.
        # main()/atexit own the final finish.
        _ACTIVE_RUNLOG.set_status("failed", msg)
    if _JSON_STDOUT:
        print(f"✗ {msg}", file=sys.stderr)
    elif RICH:
        console.print(f"[red]✗[/red] {msg}")
    else:
        print(f"✗ {msg}", file=sys.stderr)
    sys.exit(1)


def _resolve_secret_arg(value, flag: str):
    """Resolve a secret-bearing CLI value without accepting literal secrets.

    Literal tokens on argv leak into shell history and ``/proc`` cmdlines,
    defeating the argv hygiene applied to spawned checks. Accepted forms:
    ``env:VAR_NAME`` (read from the environment), ``@FILE`` (read a local
    file, ideally mode 0600), and ``prompt`` (hidden getpass prompt).
    Anything else is refused loudly, never silently accepted.
    """
    if value is None:
        return None
    val = str(value)
    if val.startswith("env:"):
        name = val[4:].strip()
        resolved = os.environ.get(name)
        if not resolved:
            _die(f"{flag}: environment variable {name!r} is unset or empty")
        return resolved
    if val.startswith("@"):
        path = Path(val[1:]).expanduser()
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            _die(f"{flag}: cannot read secret file {path}: {exc}")
    if val == "prompt":
        import getpass

        entered = getpass.getpass(f"{flag} value (hidden): ")
        return entered or None
    _die(
        f"{flag}: literal secrets on the command line are refused "
        f"(shell history / /proc exposure). Use env:VAR_NAME, @FILE, or "
        f"'prompt' instead."
    )


def _resolve_secret_args(args) -> None:
    """Resolve every secret flag present on parsed CLI args, in place."""
    for attr, flag in (
        ("auth", "--auth"),
        ("cookie", "--cookie"),
        ("account_a", "--account-a"),
        ("account_b", "--account-b"),
    ):
        if hasattr(args, attr):
            setattr(args, attr, _resolve_secret_arg(getattr(args, attr), flag))


def _banner(msg: str):
    _runlog_console("banner", msg)
    if RICH:
        console.rule(f"[bold cyan]{msg}[/bold cyan]")
    else:
        print(f"\n{'─'*60}\n{msg}\n{'─'*60}")
    _flush()


# ─────────────────────────────────────────────────────────────────────────────
# Scope / program helpers
# ─────────────────────────────────────────────────────────────────────────────


def _sanitize(name: str) -> str:
    name = re.sub(r"https?://[^/]+/", "", name)
    return re.sub(r"[^\w.\-]", "_", name)[:80]


def _scope_from_programs(name: str) -> Dict:
    """Try saved program.json first, then Scan4Me DB, then oracle_programs cache.

    Priority:
      1. targets/ workspace program.json (live scopes from previous hunt)
      2. Scan4Me SQLite DB — live indexed scope for 1,200+ programs (fastest cash ranking)
      3. Legacy programs/ dir
      4. programs_cache.json
    """
    nl = name.lower()

    # ── 1. Check targets/ workspace (written by the P11 download path) ──────────
    targets_dir = _HERE / "targets"
    if targets_dir.exists():
        for p_file in targets_dir.glob("**/program.json"):
            try:
                d = json.loads(p_file.read_text())
                if nl in d.get("name", "").lower() or nl in p_file.parent.name.lower():
                    if d.get("structured_scopes"):
                        return d
            except Exception:
                pass

    # ── 2. Scan4Me DB — 1,200 programs, scored, scope-indexed ─────────────────
    try:
        import oracle_scan4me as _s4m

        match = _s4m.resolve(name)
        if match:
            return match
    except Exception:
        pass

    # ── 3. Legacy programs/ dir ────────────────────────────────────────────────
    programs_dir = _HERE / "programs"
    if programs_dir.exists():
        for p_file in programs_dir.glob("**/program.json"):
            if nl in p_file.parent.name.lower() or nl in str(p_file).lower():
                try:
                    return json.loads(p_file.read_text())
                except Exception:
                    pass

    # ── 4. Cache fallback ──────────────────────────────────────────────────────
    cache = _HERE / "programs_cache.json"
    if not cache.exists():
        return {}
    try:
        data = json.loads(cache.read_text())
        programs = data.get("programs", data) if isinstance(data, dict) else data
        match = next(
            (
                p
                for p in programs
                if nl in p.get("name", "").lower() or nl in p.get("url", "").lower()
            ),
            None,
        )
        if match:
            slug = re.sub(r"[^\w.\-]", "_", match["name"].lower())[:60]
            saved = targets_dir / match.get("platform", "") / slug / "program.json"
            if saved.exists():
                try:
                    d = json.loads(saved.read_text())
                    if d.get("structured_scopes"):
                        return d
                except Exception:
                    pass
        return match or {}
    except Exception:
        return {}


def _extract_domains(scope_text: str) -> List[str]:
    """Pull domain/IP targets out of scope text (shared DNS predicate)."""
    domains = []
    for line in scope_text.splitlines():
        line = line.strip().lstrip("*.")
        # bare domain or wildcard
        if _is_dns_target(line):
            domains.append(line)
        # URL
        m = re.search(r"https?://([A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+)", line)
        if m:
            host = m.group(1).lstrip("*.")
            if _is_dns_target(host):
                domains.append(host)
    return sorted(set(domains))


# ── Target derivation + DNS-target filtering (2026-10-01) ────────────────────
# The Wolt run derived target=hackerone.com: prog["scope"] is a LIST (not a
# string), so str(list) produced a repr _extract_domains couldn't parse, and
# the fallback used prog["url"] — the PLATFORM url. Mobile app IDs
# (com.wolt.android, 943905271) must never enter DNS/recon lists.

# Last labels that mark a mobile app ID, never a DNS name. (The old
# 36-entry TLD allowlist rejected real targets — *.superbet.ro/.gr/.rs,
# *.work, *.gg, *.nz, *.finance all failed verify with no_probe_hosts.)
_APP_ID_LAST_LABELS = {
    "android",
    "apk",
    "ios",
    "iphone",
    "ipad",
    "appstore",
    "googleplay",
    "playstore",
}

# Reverse-DNS package roots. A real hostname can theoretically begin with
# one of these labels, but in scope/target derivation fail-closed is safer:
# typed GOOGLE_PLAY/APPLE assets are already filtered upstream, and an
# untyped com.acme.mobile string is overwhelmingly a package ID.
_REVERSE_PACKAGE_ROOTS = {"co", "com", "io", "net", "org"}


def _is_dns_target(host: str) -> bool:
    """True only for real DNS-resolvable hostnames (or IPv4 literals).

    Syntax-based, not TLD-allowlisted: valid DNS labels, an alphabetic
    (or punycode) final label, and no app-ID markers. Rejects mobile
    app IDs — Android reverse-DNS packages (com.wolt.android) via the
    last-label denylist, numeric iOS store IDs (943905271) via the
    single-label/numeric rules — and underscore labels, which are not
    legal DNS hostnames.
    """
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    h = h.lstrip(".")
    if not h or len(h) > 253 or any(c in h for c in " /@:_"):
        return False
    parts = h.split(".")
    if len(parts) < 2:
        return False
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return all(str(int(p)) == p and 0 <= int(p) <= 255 for p in parts)
    if parts[-1] in _APP_ID_LAST_LABELS:
        return False
    if len(parts) >= 3 and parts[0] in _REVERSE_PACKAGE_ROOTS and parts[-1] != parts[0]:
        return False
    tld = parts[-1]
    if not (tld.startswith("xn--") or (tld.isalpha() and len(tld) >= 2)):
        return False
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    return all(label_re.match(p) for p in parts)


def _normalized_structured_scopes(raw: Any) -> List[Dict[str, Any]]:
    """Normalize scope data to a list of dicts.

    Feeds and hand-written workspace JSON occasionally carry scopes as a
    bare string or a list of strings. Consumers must never crash on (or
    silently iterate characters of) those shapes.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
        elif isinstance(item, str) and item.strip():
            out.append({"asset_identifier": item.strip()})
    return out


def _derive_target(prog: Optional[dict], name: str) -> str:
    """Derive the phase-1 recon target from program scope.

    Prefers bounty-eligible URL/DOMAIN/WILDCARD assets from structured_scopes,
    then the scope/targets fields (list or string). Mobile app IDs are
    excluded. NEVER falls back to the platform URL (hackerone.com) — falls
    back to the program name itself.
    """
    candidates: List[str] = []
    if prog:
        for s in _normalized_structured_scopes(prog.get("structured_scopes")):
            if not s.get("eligible_for_bounty", True):
                continue
            atype = (s.get("asset_type") or "").upper()
            if atype in ("ANDROID", "IOS", "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"):
                continue
            host = ProgramScopeGate.extract_host(
                (s.get("asset_identifier") or "").strip()
            )
            if host:
                host = host.lstrip("*.")
                if _is_dns_target(host) and host not in candidates:
                    candidates.append(host)
        scope_raw = prog.get("scope") or prog.get("targets") or ""
        if isinstance(scope_raw, list):
            scope_raw = "\n".join(str(x) for x in scope_raw)
        for d in _extract_domains(str(scope_raw)):
            if _is_dns_target(d) and d not in candidates:
                candidates.append(d)
    nl = (name or "").lower()
    for c in candidates:
        if nl and nl in c.lower():
            return c
    if candidates:
        return candidates[0]
    return re.sub(r"https?://", "", name or "localhost").rstrip("/").split("/")[0]


# ─────────────────────────────────────────────────────────────────────────────
# Program Scope & Testnet Safe-Mode Gate
# ─────────────────────────────────────────────────────────────────────────────

# curl/wget flags that change WHERE the connection actually goes. A check like
# `curl --connect-to victim.com:443:evil.com:443 https://victim.com/` passes
# URL-based scope validation (the only URL is in-scope) but the TCP/TLS
# connection lands on the attacker's host. These are hard-blocked in
# validate_check: there is no legitimate bug-bounty check that needs them.
_CONN_HIJACK_FLAGS = (
    "--resolve",
    "--connect-to",
    "--proxy",
    "--preproxy",
    "--socks4",
    "--socks4a",
    "--socks5",
    "--socks5-hostname",
    "--unix-socket",
    "--dns-servers",
    "--doh-url",
)


def _conn_hijack_flag(cmd: str) -> Optional[str]:
    """Return the first connection-hijacking flag found in cmd, else None.

    Token-based via shlex (handles --flag=value and glued -xVALUE forms);
    falls back to a raw substring scan when the command doesn't parse
    (_run_check rejects unparseable commands anyway — this is defense in
    depth so validate_check never blesses one).
    """
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = []
    if parts:
        for p in parts:
            # Long flags are lowercase in curl; the short proxy flag is
            # lowercase -x — uppercase -X is the (legitimate) request-method
            # flag and must NOT match.
            if p.split("=", 1)[0].lower() in _CONN_HIJACK_FLAGS:
                return p
            if p == "-x" or (p.startswith("-x") and len(p) > 2):
                return p
        return None
    low = cmd.lower()
    for f in _CONN_HIJACK_FLAGS:
        if f in low:
            return f
    if re.search(r"(?:^|\s)-x(?:\s|$|=)", cmd):
        return "-x"
    return None


# Local mirror of Scan4Me/bridge public-suffix guard (keep in sync with
# scan4me.py and oracle_scan4me.py until S4 unifies the three matchers).
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    "ac.uk", "co.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au", "co.nz", "org.nz",
    "com.br", "com.cn", "com.tw", "com.hk", "com.sg",
    "co.jp", "co.kr", "co.in", "com.mx", "com.ar",
    "co.za", "com.tr", "com.pl", "com.ru", "co.il",
})


def _wildcard_base_is_registrable(rest: str) -> bool:
    """True when post-star text anchors at a registrable domain (S3)."""
    cand = (rest or "").lstrip("-.").lower().rstrip(".")
    if not cand or ".." in cand:
        return False
    labels = [part for part in cand.split(".") if part]
    if len(labels) != len(cand.split(".")) or len(labels) < 2:
        return False
    if cand in _MULTI_LABEL_PUBLIC_SUFFIXES:
        return False
    if ".".join(labels[-2:]) in _MULTI_LABEL_PUBLIC_SUFFIXES and len(labels) < 3:
        return False
    return True


_PLACEHOLDER_SCOPE_RE = re.compile(
    r"[*$][A-Za-z0-9_$*.-]*\.[A-Za-z]{2,}"
)


_SCOPE_NEGATION_PHRASES = (
    "out of scope",
    "not in scope",
    "excluded",
    "exclude",
    "never",
    "do not test",
    "don't test",
    "do not",
    "not allowed",
    "not eligible",
    "ineligible",
    "prohibited",
    "off limits",
    "off-limits",
    "no longer",
)
_SCOPE_CLAUSE_SPLIT_RE = re.compile(r";|\.\s+|\bbut\b|\bhowever\b", re.IGNORECASE)


def _instruction_scope_tokens(text: str) -> Tuple[List[str], List[str]]:
    """Pull wildcard/placeholder scope grants out of program instructions.

    Platforms often express a wildcard in prose rather than a structured
    asset, e.g. HackerOne/Matomo: ``*$username.matomo.cloud* is also in
    scope``. The old parser ignored it, so ``foo.matomo.cloud`` fell out of
    scope. Only tokens containing ``*`` or ``$`` are taken here; plain
    domains are already handled by the existing instruction-line parser.
    Classification is per clause, never per line: an exclusion clause on a
    line that also says "in scope" can never become a grant, and when the
    same token is both granted and excluded, exclusion wins.
    Returns (in_scope_tokens, out_of_scope_tokens).
    """
    in_tokens: List[str] = []
    out_tokens: List[str] = []
    for line in str(text or "").splitlines():
        for clause in _SCOPE_CLAUSE_SPLIT_RE.split(line):
            low = clause.lower()
            if any(phrase in low for phrase in _SCOPE_NEGATION_PHRASES):
                target = out_tokens
            elif "in scope" in low:
                target = in_tokens
            else:
                continue
            for raw in _PLACEHOLDER_SCOPE_RE.findall(clause):
                token = raw.strip("*").strip(".,;:()[]")
                if raw.startswith("*.") and token and "*" not in token and "$" not in token:
                    # The strips above eat a leading "*." wildcard
                    # ("*.example.com" -> "example.com"); restore it.
                    token = "*." + token.lstrip(".")
                if not token or ("*" not in token and "$" not in token):
                    continue
                token = re.sub(r"\$[A-Za-z0-9_]+", "*", token)
                token = token.lstrip("*") if token.count("*") > 1 else token
                if token.startswith("*.") or token.startswith("."):
                    target.append(token)
                elif "*" in token:
                    target.append(token)
    out_set = set(out_tokens)
    in_tokens = [t for t in in_tokens if t not in out_set]
    return in_tokens, out_tokens


class ProgramScopeGate:
    """
    Deterministic Program Scope & Testnet Safe-Mode Gate.
    Parses and enforces bug bounty program boundaries (in-scope wildcards,
    explicit out-of-scope assets, and third-party blocklists) to guarantee
    zero out-of-scope probes and safe non-destructive testing.
    """

    GLOBAL_OUT_OF_SCOPE_DOMAINS = {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "facebook.com",
        "facebook.net",
        "twitter.com",
        "x.com",
        "github.com",
        "githubassets.com",
        "gitlab.com",
        "branch.io",
        "appsflyer.com",
        "zendesk.com",
        "intercom.io",
        "sentry.io",
        "datadoghq.com",
        "imgix.net",
        "creatoriq.com",
        "bootstrapcdn.com",
        "jsdelivr.net",
        "unpkg.com",
        "w3.org",
        "schema.org",
        "cloudflare.com",
    }

    def __init__(self, prog: Optional[Dict] = None, target_fallback: str = ""):
        self.prog = prog or {}
        self.target_fallback = target_fallback.strip()
        self.in_scope_patterns: List[Tuple[str, re.Pattern, str]] = []
        self.out_of_scope_patterns: List[Tuple[str, re.Pattern, str]] = []
        # S4: host-level twins (paths dropped) + CIDR networks — the
        # bridge's host questions and IP-range assets judge here too.
        self.in_host_patterns: List[Tuple[str, re.Pattern]] = []
        self.out_host_patterns: List[Tuple[str, re.Pattern]] = []
        self.in_cidrs: List[Tuple[str, Any]] = []
        self.out_cidrs: List[Tuple[str, Any]] = []
        self.raw_in_scope: List[str] = []
        self.raw_out_of_scope: List[str] = []
        self._parse_scope()

    @staticmethod
    def extract_host(target: str) -> str:
        """Extract clean lowercase hostname without protocol, port, or path."""
        target = target.strip()
        if "://" in target:
            try:
                parsed = urllib.parse.urlparse(target)
                host = parsed.netloc or parsed.path
            except ValueError:
                # Malformed URL (e.g. invalid IPv6) — strip scheme manually
                host = target.split("://", 1)[1].split("/")[0]
        else:
            host = target.split("/")[0]
        if "@" in host:
            host = host.split("@")[-1]
        if host.startswith("[") and "]" in host:
            # Bracketed IPv6, optionally with port: keep the address only.
            host = host[1:].split("]", 1)[0]
        elif host.count(":") == 1:
            host = host.split(":")[0]
        # >=2 colons: bare IPv6 — keep whole; ip parsing downstream
        # rejects anything invalid (fail-closed).
        return host.strip().lower()

    def _compile_pattern(
        self, identifier: str, drop_path: bool = False, subdomains: bool = False
    ):
        """Compile a scope identifier to (regex, kind).

        kind='host': matches a hostname (wildcards supported).
        kind='path': the identifier carried a URL path — matches host+path
            prefix, so https://wolt.com/en/x blocks that path and deeper,
            NOT the whole wolt.com host. (2026-10-01: the old code stripped
            the path, turning a path-scoped exclusion into a host nuke that
            rejected https://wolt.com itself.)
        In-scope URL assets retain their path constraint. A host-wide grant
        must be explicit in the source scope.
        subdomains=True (out-of-scope rules only): an exact host also covers
        its subdomains — excluding secret.bank.com excludes deep.secret too.
        Path rules keep an exact host (widening risks another host nuke).
        """
        if any(
            ord(ch) < 32 or ord(ch) == 127 or ch.isspace()
            for ch in (identifier or "")
        ):
            return None
        clean = identifier.strip().lower()
        clean = re.sub(r"^https?://", "", clean)
        if "/" in clean:
            hostport, _, path = clean.partition("/")
            path = "/" + path
        else:
            hostport, path = clean, ""
        if hostport.startswith("[") and "]" in hostport:
            host = hostport[1:].split("]", 1)[0]
        elif hostport.count(":") == 1:
            host = hostport.split(":")[0]
        else:
            host = hostport  # bare IPv6 identifier: keep whole
        if not host or host.startswith("#"):
            return None
        if " " in host or host.isdigit():
            return None
        if host.startswith("*."):
            # S3: registry-wide wildcards (*.com, *.co.uk) never compile —
            # the execution gate fails closed exactly like ingest/bridge.
            # S4: '*.base' means proper subdomains ONLY (never the apex) —
            # one semantics across gate, bridge, and Scan4Me check. Apex
            # coverage requires an explicit apex asset or the target
            # fallback's explicit host pattern.
            if not _wildcard_base_is_registrable(host[2:]):
                return None
            host_re = rf"(?:[a-zA-Z0-9_\-]+\.)+{re.escape(host[2:])}"
        elif host.startswith("."):
            if not _wildcard_base_is_registrable(host[1:]):
                return None
            host_re = rf"(?:[a-zA-Z0-9_\-]+\.)+{re.escape(host[1:])}"
        elif "*" in host:
            # Glued wildcard ('*-cdn.acme.com'): one '*' covering a single
            # label segment (no dots) — the common Scan4Me form, kept
            # stricter than its endswith (multi-label prefixes stay out).
            if host.count("*") != 1:
                return None
            _pre, _suf = host.split("*", 1)
            _base = _suf.split(".", 1)[1] if "." in _suf else ""
            if not _base or not _wildcard_base_is_registrable(_base):
                return None
            host_re = rf"{re.escape(_pre)}[a-zA-Z0-9_\-]+{re.escape(_suf)}"
        elif subdomains and not path:
            host_re = rf"(?:[a-zA-Z0-9_\-]+\.)*{re.escape(host)}"
        else:
            host_re = re.escape(host)
        if path and path != "/" and not drop_path:
            path_re = re.escape(path.rstrip("/"))
            return (re.compile(rf"^{host_re}{path_re}(?:/|$)", re.IGNORECASE), "path")
        return (re.compile(rf"^{host_re}$", re.IGNORECASE), "host")

    def _parse_scope(self):
        in_identifiers = set()
        out_identifiers = set()

        for s in _normalized_structured_scopes(self.prog.get("structured_scopes")):
            ident = str(s.get("asset_identifier", "") or "").strip()
            if not ident:
                continue
            atype = str(s.get("asset_type", "") or "").upper()
            if atype in ("GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID"):
                continue
            eligible = s.get("eligible_for_submission", True) and s.get(
                "eligible_for_bounty", True
            )
            if eligible:
                in_identifiers.add(ident)
            else:
                out_identifiers.add(ident)

            instr = s.get("instruction", "")
            if not isinstance(instr, str):
                instr = str(instr or "")
            if instr:
                instr_in, instr_out = _instruction_scope_tokens(instr)
                in_identifiers.update(instr_in)
                out_identifiers.update(instr_out)
                for line in instr.splitlines():
                    line = line.strip().lstrip("* -")
                    if re.match(r"^[\w\-]+(\.[\w\-]+)+$", line):
                        out_identifiers.add(line)

        scope_field = self.prog.get("scope", "")
        if isinstance(scope_field, list):
            for item in scope_field:
                in_identifiers.add(str(item).strip())
        elif isinstance(scope_field, str):
            for line in scope_field.splitlines():
                ident = line.strip()
                if ident and not ident.startswith("#"):
                    in_identifiers.add(ident)

        targets_field = self.prog.get("targets", "")
        if isinstance(targets_field, str) and targets_field.strip():
            for t in targets_field.splitlines():
                if t.strip():
                    in_identifiers.add(t.strip())

        oos_field = self.prog.get("out_of_scope", "")
        if isinstance(oos_field, list):
            for item in oos_field:
                out_identifiers.add(str(item).strip())
        elif isinstance(oos_field, str):
            for line in oos_field.splitlines():
                ident = line.strip()
                if ident and not ident.startswith("#"):
                    out_identifiers.add(ident)

        if not in_identifiers and self.target_fallback:
            clean_tb = self.extract_host(self.target_fallback)
            # Only treat fallback as a domain/host if it contains a dot or is a loopback IP,
            # never for bare program handles/names (e.g. "uniswap", "makerdao").
            if clean_tb and ("." in clean_tb or clean_tb in ("localhost", "127.0.0.1")):
                in_identifiers.add(f"*.{clean_tb}")
                in_identifiers.add(clean_tb)

        def _cidr_of(raw: str):
            text = raw.strip()
            if "://" in text:
                text = text.split("://", 1)[1]
            if "/" not in text:
                return None
            try:
                return ipaddress.ip_network(text.split("/")[0] + "/" + text.split("/", 1)[1].split("/")[0], strict=False)
            except ValueError:
                return None

        for raw in sorted(in_identifiers):
            net = _cidr_of(raw)
            if net is not None:
                self.in_cidrs.append((raw, net))
                self.raw_in_scope.append(raw)
                continue
            p = self._compile_pattern(raw)
            if p:
                self.in_scope_patterns.append((raw, p[0], p[1]))
                self.raw_in_scope.append(raw)
            hp = self._compile_pattern(raw, drop_path=True)
            if hp:
                self.in_host_patterns.append((raw, hp[0]))

        for raw in sorted(out_identifiers):
            net = _cidr_of(raw)
            if net is not None:
                self.out_cidrs.append((raw, net))
                self.raw_out_of_scope.append(raw)
                continue
            p = self._compile_pattern(raw, subdomains=True)
            if p:
                self.out_of_scope_patterns.append((raw, p[0], p[1]))
                self.raw_out_of_scope.append(raw)
            hp = self._compile_pattern(raw, subdomains=True, drop_path=True)
            if hp:
                self.out_host_patterns.append((raw, hp[0]))

    @staticmethod
    def _split_path(target: str) -> str:
        """Path of target, "" when unparseable (fail-closed: garbage
        matches no scope pattern, so the gate falls through to BLOCK)."""
        try:
            return (
                urllib.parse.urlsplit(
                    target if "://" in target else f"https://{target}"
                ).path
                or "/"
            )
        except ValueError:
            return ""

    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """
        Deterministic Scope Verification Gate:
        - If target matches explicit out-of-scope pattern -> BLOCK
        - If target matches global third-party CDN/analytics -> BLOCK
        - If target matches program in-scope pattern -> ALLOW
        - If no match -> BLOCK
        """
        if "://" in target:
            try:
                scheme = urllib.parse.urlsplit(target).scheme.lower()
            except ValueError:
                return False, "BLOCKED: unparseable target"
            if scheme not in ("http", "https"):
                return False, f"BLOCKED: unsupported scheme '{scheme}'"
        host = self.extract_host(target)
        if not host:
            return False, "Empty or invalid target host"

        if host in ("localhost", "127.0.0.1", "0.0.0.0"):  # nosec B104
            scope_grants_local = any(
                pat.match(host)
                for _, pat, kind in self.in_scope_patterns
                if kind == "host"
            )
            if (
                "localhost" in self.target_fallback
                or "127.0.0.1" in self.target_fallback
                or scope_grants_local
            ):
                return True, "in_scope: local testbench allowed"
            return False, "out_of_scope: localhost leak on external program"

        # CIDR assets (S4): IP targets judge against networks first.
        _ip = None
        try:
            _ip = ipaddress.ip_address(host)
        except ValueError:
            _ip = None
        if _ip is not None:
            for raw, net in self.out_cidrs:
                if _ip in net:
                    return False, f"EXPLICIT_OUT_OF_SCOPE: matched CIDR '{raw}'"
            for raw, net in self.in_cidrs:
                if _ip in net:
                    return True, f"in_scope: matched CIDR '{raw}'"

        for raw, pat, kind in self.out_of_scope_patterns:
            if kind == "path":
                # Path-scoped exclusion: match against host+path, never the
                # bare host. https://wolt.com/en/x must not nuke wolt.com.
                tpath = self._split_path(target)
                if pat.match(host + tpath):
                    return False, f"EXPLICIT_OUT_OF_SCOPE: matched rule '{raw}'"
            elif pat.match(host):
                return False, f"EXPLICIT_OUT_OF_SCOPE: matched rule '{raw}'"

        matched_in_scope = False
        matched_rule = ""
        for raw, pat, kind in self.in_scope_patterns:
            tpath = self._split_path(target)
            if kind == "path" and pat.match(host + tpath):
                matched_in_scope = True
                matched_rule = raw
                break
            if kind == "host" and pat.match(host):
                matched_in_scope = True
                matched_rule = raw
                break

        for oos_domain in self.GLOBAL_OUT_OF_SCOPE_DOMAINS:
            if host == oos_domain or host.endswith(f".{oos_domain}"):
                if not matched_in_scope:
                    return (
                        False,
                        f"GLOBAL_3RD_PARTY_BLOCKED: '{host}' is an external CDN/analytics domain",
                    )

        if matched_in_scope:
            return True, f"in_scope: matched '{matched_rule}'"

        return False, f"UNRECOGNIZED_HOST: '{host}' is not covered by program scope"

    def is_host_in_scope(self, target: str) -> Tuple[bool, str]:
        """Host-level verdict (paths ignored) — the bridge's question.

        S4: verify_in_scope delegates here so host pre-checks can never
        disagree with this gate. URL probing still uses is_in_scope,
        where path-scoped assets keep their path constraint. Known
        fail-closed asymmetries vs is_in_scope: a path-scoped OOS rule
        denies the whole host at this level, and a gate built with a
        target_fallback admits that explicit host while the bridge
        (fallback="") does not. Both err toward denial on pre-checks.
        """
        host = self.extract_host(target)
        if not host:
            return False, "Empty or invalid target host"
        try:
            _ip = ipaddress.ip_address(host)
        except ValueError:
            _ip = None
        if _ip is not None:
            for raw, net in self.out_cidrs:
                if _ip in net:
                    return False, f"EXPLICIT_OUT_OF_SCOPE: matched CIDR '{raw}'"
        for raw, pat in self.out_host_patterns:
            if pat.match(host):
                return False, f"EXPLICIT_OUT_OF_SCOPE: matched rule '{raw}'"
        if _ip is not None:
            for raw, net in self.in_cidrs:
                if _ip in net:
                    return True, f"in_scope: matched CIDR '{raw}'"
        for raw, pat in self.in_host_patterns:
            if pat.match(host):
                return True, f"in_scope: matched '{raw}'"
        for oos_domain in self.GLOBAL_OUT_OF_SCOPE_DOMAINS:
            if host == oos_domain or host.endswith(f".{oos_domain}"):
                return (
                    False,
                    f"GLOBAL_3RD_PARTY_BLOCKED: '{host}' is an external CDN/analytics domain",
                )
        return False, f"UNRECOGNIZED_HOST: '{host}' is not covered by program scope"

    def validate_check(
        self, check_cmd: str, is_testnet: bool = False
    ) -> Tuple[bool, str, str]:
        """
        Pre-Flight Wire Gate:
        Extracts targets from check command, enforces scope gate, and applies safe testnet isolation.
        Returns: (allowed: bool, validated_command: str, reason: str)
        """
        cmd = check_cmd.strip()
        if not cmd:
            return False, cmd, "Empty check command"

        try:
            parts = shlex.split(cmd)
        except ValueError:
            return False, cmd, "Unparseable check command"
        urls = []
        skip_value = False
        for part in parts[1:]:
            if skip_value:
                skip_value = False
                continue
            if part in (
                "-H",
                "--header",
                "-X",
                "--request",
                "--connect-timeout",
                "--max-time",
            ):
                skip_value = True
                continue
            if part.startswith(("http://", "https://")):
                urls.append(part)
        if not urls:
            m = re.search(r"curl\s+(?:-[^\s]+\s+)*([a-zA-Z0-9_\-\.]+)", cmd)
            if m and "." in m.group(1):
                urls = [m.group(1)]

        if not urls:
            return False, cmd, "No valid target URL or host found in check command"

        for u in urls:
            allowed, reason = self.is_in_scope(u)
            if not allowed:
                return False, cmd, f"Scope Gate BLOCKED: {reason}"

        # Connection-hijack flags defeat URL-based validation: the validated
        # URL is in-scope but the connection goes elsewhere. Hard block.
        hijack = _conn_hijack_flag(cmd)
        if hijack:
            return (
                False,
                cmd,
                (
                    f"Scope Gate BLOCKED: connection-hijack flag '{hijack}' "
                    f"would send the probe to a host other than the validated URL"
                ),
            )

        is_mutating = bool(
            re.search(r"-X\s+(?:POST|PUT|DELETE|PATCH)", cmd, re.IGNORECASE)
            or re.search(r"--request\s+(?:POST|PUT|DELETE|PATCH)", cmd, re.IGNORECASE)
            or re.search(
                r"(?:-d|--data|--data-raw|--data-binary|--data-urlencode)\s+", cmd
            )
        )

        if is_mutating:
            is_staging_asset = any(
                w in u.lower()
                for u in urls
                for w in [
                    "staging",
                    "dev",
                    "testnet",
                    "sandbox",
                    "test.",
                    "-test",
                    "localhost",
                    "127.0.0.1",
                ]
            )
            if not is_testnet and not is_staging_asset:
                try:
                    parts = shlex.split(cmd)
                    new_parts = []
                    skip = False
                    for i, p in enumerate(parts):
                        if skip:
                            skip = False
                            continue
                        if (
                            p in ("-X", "--request")
                            and i + 1 < len(parts)
                            and parts[i + 1].upper()
                            in ("POST", "PUT", "DELETE", "PATCH")
                        ):
                            new_parts.extend(["-X", "GET"])
                            skip = True
                            continue
                        if p in (
                            "-d",
                            "--data",
                            "--data-raw",
                            "--data-binary",
                            "--data-urlencode",
                        ):
                            skip = True
                            continue
                        new_parts.append(p)
                    safe_cmd = shlex.join(new_parts)
                except Exception:
                    safe_cmd = re.sub(
                        r"-X\s+(?:POST|PUT|DELETE|PATCH)",
                        "-X GET",
                        cmd,
                        flags=re.IGNORECASE,
                    )
                    safe_cmd = re.sub(
                        r"--request\s+(?:POST|PUT|DELETE|PATCH)",
                        "--request GET",
                        safe_cmd,
                        flags=re.IGNORECASE,
                    )
                    safe_cmd = re.sub(
                        r'(?:-d|--data|--data-raw|--data-binary)\s+[\'"][^\'"]*[\'"]',
                        "",
                        safe_cmd,
                    )
                    safe_cmd = re.sub(
                        r"(?:-d|--data|--data-raw|--data-binary)\s+[^\s]+", "", safe_cmd
                    )
                return (
                    True,
                    safe_cmd,
                    "PRODUCTION SAFE MODE: Downgraded state-mutating probe to non-destructive GET probe",
                )

        return True, cmd, "VALIDATED"


# ─────────────────────────────────────────────────────────────────────────────
# Recon
# ─────────────────────────────────────────────────────────────────────────────


def _crtsh_subdomains(domain: str) -> List[str]:
    """Certificate-transparency subdomain source (crt.sh).

    ADDITIVE to subfinder, not an empty-only fallback: hosts behind a
    wildcard cert never appear here, so this is a supplement to — never
    a replacement for — scope-listed seed hosts.
    """
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "oracle-recon/1.0"},
        )
        raw = urllib.request.urlopen(req, timeout=30)  # nosec B310
        data = json.loads(raw.read().decode("utf-8", "replace"))
    except Exception:
        return []
    names = set()
    for e in data:
        for n in str(e.get("name_value") or "").split("\n"):
            n = n.strip().lower()
            if n and "*" not in n and (n == domain or n.endswith("." + domain)):
                names.add(n)
    return sorted(names)


def _lens_regime_block(args) -> str:
    """Name the auth regime inside lens prompts (Tinder post-mortem).

    The dual-engine rules demand identity-varying discriminating checks.
    Unauthenticated, those are impossible and a strict model rationally
    answers TARGET CLEAN for everything. Naming the regime keeps
    public-surface contradictions mintable without lowering the
    discriminating bar for authenticated hunts.
    """
    if _effective_recon_auth(args) or getattr(args, "cookie", None):
        return (
            "REGIME: AUTHENTICATED — identity-varying checks are available; "
            "prefer them (drop/swap the session, cross-account IDs)."
        )
    return (
        "REGIME: UNAUTHENTICATED — no credentials available, so "
        "identity-varying checks are out of reach. Mint from "
        "public-surface contradictions instead: 200-returning endpoints "
        "whose bodies contradict a cited claim, shipped JS/config claims "
        "vs wire behavior, CORS/open-redirect/cache contradictions. "
        "Do not answer TARGET CLEAN merely because authenticated "
        "surfaces are walled — judge the public surface on its own claims."
    )


def _write_lens_funnel(
    reports_dir,
    *,
    outcomes: Dict,
    raw_results: List,
    recon_chars: int,
    asset_chars: int,
    effective: List[str],
    minted: int,
) -> Path:
    """Persist per-lens diagnostics so a lens-zero hunt is debuggable.

    Tinder's zero required log archaeology across 5 MB of output; the
    funnel now records material sizes, per-pass outcomes, and redacted
    raw responses beside funnel.json. Diagnostics only — callers treat
    write failure as a warning, never a hunt failure.
    """
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    passes = []
    for origin, raw in raw_results or []:
        text = _redact_creds(raw or "")
        passes.append(
            {
                "origin": origin,
                "outcome": (outcomes or {}).get(origin),
                "raw_chars": len(raw or ""),
                "raw": text[:20000],
                "raw_truncated": len(text) > 20000,
            }
        )
    payload = {
        "effective_mindsets": list(effective or []),
        "recon_chars": recon_chars,
        "asset_chars": asset_chars,
        "minted": minted,
        "passes": passes,
    }
    out = reports_dir / "lens_funnel.json"
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return out


def _snapshot_seams(ws, seams, stage: str, **meta: Any) -> Optional[Path]:
    """Best-effort seam checkpoint; diagnostics never kill the hunt.

    Checkpoints happen before engine-dependent synthesis/verification so a
    later provider, context, or synthesis failure cannot erase candidates
    already minted by deterministic or lens passes.
    """
    saver = getattr(ws, "save_seam_snapshot", None)
    if not callable(saver):
        _warn(f"seam snapshot ({stage}) unavailable on workspace")
        return None
    try:
        candidate_list = list(seams or [])
        out = saver(candidate_list, stage=stage, meta=dict(meta))
    except Exception as exc:
        _warn(f"seam snapshot ({stage}) not written: {exc}")
        return None
    _ok(f"Seam snapshot ({stage}): {len(candidate_list)} candidate(s) → {out}")
    return Path(out)


_SYNTHESIS_RESPONSE_RESERVE_TOKENS = 2048


def _synthesis_input_budget(
    lane_limit,
    minimum_tokens: int,
    reserve_tokens: int = _SYNTHESIS_RESPONSE_RESERVE_TOKENS,
) -> Optional[int]:
    """Input budget inside a lane limit, reserving room for its response.

    If the mandatory base prompt already consumes the reserve, use the
    base size as the floor rather than pretending the base was cut. The
    batch planner then fails loudly if even one candidate cannot fit.
    """
    try:
        limit = int(lane_limit)
        minimum = int(minimum_tokens)
        reserve = max(0, int(reserve_tokens))
    except (TypeError, ValueError):
        return None
    if limit <= 0 or minimum < 0 or minimum > limit:
        return None
    return max(minimum, min(limit, limit - reserve))


def _plan_synthesis_batches(seams, render_call, budget_tokens: int) -> List[List[Dict]]:
    """Partition candidates so every rendered synthesis call fits.

    ``render_call(batch)`` returns the exact ``(system, prompt)`` pair
    that would be submitted. Greedy in-order packing covers each seam
    exactly once and never truncates a card: an individually oversized
    seam raises instead of being silently sliced out of Mindset 3.
    """
    items = list(seams or [])
    if not items:
        return [[]]
    try:
        budget = int(budget_tokens)
    except (TypeError, ValueError) as exc:
        raise ValueError("synthesis budget must be a positive token count") from exc
    if budget <= 0:
        raise ValueError("synthesis budget must be a positive token count")

    def _need(batch: List[Dict]) -> int:
        system, prompt = render_call(batch)
        return estimate_tokens(system, prompt)

    batches: List[List[Dict]] = []
    current: List[Dict] = []
    for seam in items:
        candidate = current + [seam]
        need = _need(candidate)
        if need <= budget:
            current = candidate
            continue
        if current:
            batches.append(current)
            current = [seam]
            need = _need(current)
            if need <= budget:
                continue
        raise ValueError(
            f"synthesis seam {seam.get('n', '?')} does not fit budget: "
            f"need~{need}tok > budget {budget}tok"
        )
    if current:
        batches.append(current)
    return batches


# Lens passes above this input size produced empty/unparseable card
# output from the answering lanes (Matomo full hunt 2026-10-27:
# 72k/92k-token mitre/paradox prompts, both lenses minted 0). Packing
# never drops library content: every TTP/corpus document is delivered
# exactly once across passes (see OracleMindsetContext.system_prompt_slices).
_LENS_PASS_CAP_TOKENS = 65536


def _lens_pass_budget(
    lane_limit,
    mandatory_tokens: int,
    reserve_tokens: int = _SYNTHESIS_RESPONSE_RESERVE_TOKENS,
) -> Optional[int]:
    """Input budget for one lens pass inside a lane limit.

    Mirrors _synthesis_input_budget (response reserve, mandatory base
    as floor) after capping the effective lane at
    _LENS_PASS_CAP_TOKENS unless the mandatory base itself needs more.
    """
    try:
        lane = int(lane_limit)
        mandatory = int(mandatory_tokens)
        reserve = max(0, int(reserve_tokens))
    except (TypeError, ValueError):
        return None
    capped = min(lane, max(_LENS_PASS_CAP_TOKENS, mandatory + reserve))
    return _synthesis_input_budget(capped, mandatory, reserve)


def _lens_systems_for(ctx, task: str, cfg=None, env=None, no_cloud: bool = False) -> List[str]:
    """Return the system prompts for one lens's Engine-A passes.

    One prompt when the full system + task fits the pass budget on the
    smallest viable reflex lane; otherwise library slices (full TTP /
    corpus coverage across passes, skeleton repeated). Raises when no
    viable lane fits even the mandatory skeleton + task — fail loud
    before submitting a pass the fleet cannot serve.
    """
    import oracle_llm

    full = ctx.system_prompt()
    task_tok = estimate_tokens("", task)
    mandatory = estimate_tokens(ctx.skeleton_system(), task)
    lane_limit = oracle_llm.smallest_viable_lane_limit(
        "reflex", cfg=cfg, env=env, no_cloud=no_cloud,
        minimum_tokens=mandatory,
    )
    budget = _lens_pass_budget(lane_limit, mandatory)
    if lane_limit is None or budget is None:
        raise RuntimeError(
            f"no viable {ctx.mindset} lens lane fits the mandatory "
            f"base prompt (~{mandatory}tok skeleton+task)"
        )
    if estimate_tokens(full, task) <= budget:
        return [full]
    max_system_chars = max(0, (budget - task_tok) * 4 - 8)
    # A single corpus document that cannot fit one pass budget must be split
    # across passes, not raised out of cmd_hunt. Default fail-loud here cost
    # the 2026-10-28 Matomo rerun: paradox-impossible-crossover (41,793 chars)
    # plus the 9,660-char foundations overflowed a 50,712-char block budget,
    # and the ValueError killed the hunt after both lenses had submitted
    # passes. Splitting keeps the packing law (every character reaches the
    # lens exactly once); it only changes how many passes carry it.
    systems = ctx.system_prompt_slices(
        max_system_chars, corpus_split_oversized=True
    )
    for system in systems:
        need = estimate_tokens(system, task)
        if need > budget:
            raise RuntimeError(
                f"{ctx.mindset} lens slice need~{need}tok exceeds "
                f"planned pass budget {budget}tok"
            )
    return systems


def _local_lens_systems(
    ctx, task: str, local_ctx_tokens: int, reserve_tokens: int = 1024
) -> List[str]:
    """System prompts for one LOCAL lens pass set, sliced to fit.

    Returns [full] when it fits the local window (minus a response
    reserve); otherwise library slices via ctx.system_prompt_slices so
    every TTP/corpus unit is delivered exactly once. Raises RuntimeError
    when even the mandatory skeleton + task cannot fit — the caller
    records an explicit failed pass instead of silently not submitting.
    """
    budget = int(local_ctx_tokens) - max(0, int(reserve_tokens))
    full = ctx.system_prompt()
    if estimate_tokens(full, task) <= budget:
        return [full]
    task_tok = estimate_tokens("", task)
    max_system_chars = max(0, (budget - task_tok) * 4 - 8)
    if max_system_chars <= 0:
        raise RuntimeError(
            f"{ctx.mindset} local task alone needs ~{task_tok}tok of the "
            f"{budget}tok local budget; no room for the mandatory skeleton"
        )
    systems = ctx.system_prompt_slices(
        max_system_chars,
        corpus_repeat_foundations=False,
        corpus_split_oversized=True,
    )
    for system in systems:
        need = estimate_tokens(system, task)
        if need > budget:
            raise RuntimeError(
                f"{ctx.mindset} local slice need~{need}tok exceeds local "
                f"budget {budget}tok"
            )
    return systems


def _effective_recon_auth(args) -> Optional[str]:
    """Auth value for recon: explicit --auth wins, else Account A.

    Dual-account material is resolved before hunt (main secret-ref
    resolution) but the harness that consumes it is built after recon;
    without this derivation, an --account-a-only hunt recons
    unauthenticated while the session gate counts auth as present (M4).
    Normalization mirrors the harness: bare tokens gain a Bearer prefix.
    """
    auth = getattr(args, "auth", None)
    if auth:
        return auth
    acct_a = getattr(args, "account_a", None)
    if not acct_a:
        return None
    return acct_a if acct_a.lower().startswith("bearer ") else f"Bearer {acct_a}"


_STATUS_TOKEN_RE = re.compile(r"^\[(\d{3})\]$")


_LENS_OUTCOME_TOKENS = {"clean", "empty", "error", "seams", "refusal"}


def complete_lens_outcomes(recorded, submitted) -> Dict[str, str]:
    """Fill every submitted pass origin missing from the outcome map.

    Failed passes are deliberately withheld from _lens_outcomes during
    collection (so build_seam_sets/ladder treat them as missing), but
    the yield ledger aggregates only recorded slices — a withheld
    cage-rejected slice would vanish and its lens could aggregate to
    clean over the surviving slices. At the accounting boundary every
    submitted origin must be present: with its recorded fallback
    outcome when the submit record carries one (failed-pass and
    escalation-attempt records do), else "error"."""
    out = dict(recorded or {})
    for rec in submitted or []:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin") or "")
        if not origin or origin in out:
            continue
        fallback = str(rec.get("outcome") or "").strip().lower()
        out[origin] = fallback if fallback in _LENS_OUTCOME_TOKENS else "error"
    return out


def count_served_200_lines(lines, hosts=None) -> int:
    """Count recon live-host lines whose observed status token is [200].

    httpx-style output is ``url [status] [len] [title] ...``: the FIRST
    bracketed 3-digit token is the status. Substring counting would
    credit "[403] [200]" (200 = content length) and URLs whose path
    contains "[200]". When ``hosts`` is given, only lines whose host
    token was actually injected into lens context count. Untagged
    lines count for nothing."""
    host_filter = None
    if hosts is not None:
        host_filter = {str(h).strip() for h in hosts if str(h).strip()}
    count = 0
    for ln in lines or []:
        tokens = str(ln).split()
        if not tokens:
            continue
        if host_filter is not None and tokens[0] not in host_filter:
            continue
        status = None
        for tok in tokens[1:]:
            m = _STATUS_TOKEN_RE.match(tok)
            if m:
                status = m.group(1)
                break
        if status == "200":
            count += 1
    return count


def _recon_headers(
    auth: Optional[str] = None, cookie: Optional[str] = None
) -> List[str]:
    """Build sanitized "Name: value" headers for authenticated recon.

    Same injection rule as verify_seams: values pass through
    sanitize_header_val (CR/LF stripped) so a hostile --cookie cannot
    break header framing. Callers must log presence only, never values.
    """
    headers: List[str] = []
    if auth:
        headers.append(f"Authorization: {_sanitize_header_val(auth)}")
    if cookie:
        headers.append(f"Cookie: {_sanitize_header_val(cookie)}")
    return headers


def _merge_line_file(path: Path, new_text: str) -> int:
    """Union-merge newline records into a recon artifact file.

    Later recon producers (hakrawler) must never clobber earlier ones
    (JS mining): existing lines keep order, new lines append deduped.
    Returns the total line count after merge.
    """
    existing: List[str] = []
    if path.exists():
        existing = path.read_text(errors="ignore").splitlines()
    merged = list(dict.fromkeys([*existing, *(new_text or "").splitlines()]))
    merged = [ln for ln in merged if ln.strip()]
    path.write_text("\n".join(merged) + ("\n" if merged else ""))
    return len(merged)


def recon(
    target: str,
    out_dir: Optional[Path] = None,
    scope_gate: Optional["ProgramScopeGate"] = None,
    seed_hosts: Optional[List[str]] = None,
    controlled: bool = False,
    auth: Optional[str] = None,
    cookie: Optional[str] = None,
) -> Path:
    """
    Run the full recon pipeline against target (domain or URL).
    Returns path to the recon directory with all output files.

    seed_hosts: concrete in-scope hostnames taken from the program's scope
    list (not discovery). They are merged into subdomains.txt BEFORE any
    probing so hosts invisible to subfinder/crt.sh (wildcard-cert cover)
    are never dropped. The scope gate still filters everything pre-probe.

    auth/cookie: session material for AUTHENTICATED discovery (katana crawl
    + JS mining + spec discovery + ffuf). Without it, login-walled surfaces
    (DVWA /vulnerabilities/*, pygoat labs) are undiscoverable and recall on
    those benches is structurally zero. Values never hit logs or artifacts.

    Tools used (all in ~/go/bin):
      subfinder  → subdomains
      crt.sh     → additive subdomain source (merged with subfinder output)
      httpx      → live hosts + tech fingerprint
      gau/waybackurls → known URLs
      katana     → crawl
      (nuclei removed — CVE templates contradict Oracle's A/B seam architecture)
      hakrawler  → JS endpoint extraction
      dnsx       → DNS records
    """
    slug = _sanitize(target)
    out = out_dir or (RECON_DIR / slug)
    out.mkdir(parents=True, exist_ok=True)

    # Check if target is a Web3 contract (address or .sol file)
    try:
        from oracle_web3_recon import is_eth_address, recon_contract

        is_w3 = (
            is_eth_address(target)
            or target.endswith(".sol")
            or (":" in target and is_eth_address(target.split(":", 1)[1]))
        )
        if is_w3:
            _banner(f"Web3 Contract Recon: {target}")
            try:
                res = recon_contract(target, out)
                _ok(
                    f"Web3 recon complete: {res.get('detectors_count', 0)} detector(s) identified"
                )
                return out
            except Exception as _e_w3:
                _warn(f"Web3 recon error ({_e_w3}) — continuing with standard recon")
    except Exception:
        pass

    # Strip protocol for tools that don't want it
    domain = re.sub(r"https?://", "", target).rstrip("/").split("/")[0]

    _banner(f"Recon: {domain}")
    if controlled:
        _info(
            "controlled recon: low request rates, no content fuzzing, health checks enabled"
        )
    # Authenticated discovery: same session verify_seams injects into checks.
    # Presence is logged; values never are (not here, not in tool argv echoes).
    _rheaders = _recon_headers(auth, cookie)
    if _rheaders:
        _info(
            "authenticated recon: "
            + "+".join(h.split(":", 1)[0] for h in _rheaders)
            + " attached to crawl + mining + fuzz"
        )

    def target_is_healthy() -> bool:
        """Fail closed when a controlled target no longer responds."""
        if not controlled:
            return True
        # Reuse the scheme httpx already confirmed for bare targets. This is
        # essential for loopback benchmarks that intentionally serve HTTP.
        health_url = (
            clean_urls[0]
            if clean_urls
            else (
                target
                if target.startswith(("http://", "https://"))
                else f"https://{domain}"
            )
        )
        try:
            request = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(request, timeout=10):  # nosec B310
                return True
        except urllib.error.HTTPError:
            # Any HTTP status proves the service is responding. API
            # targets routinely 404 at the root while fully alive;
            # treating that as death stopped all remaining discovery.
            return True
        except Exception as exc:
            _warn(
                f"controlled recon: target health check failed ({exc}); stopping remaining probes"
            )
            return False

    # 1. Subdomain enumeration — scope-listed seed hosts are merged in FIRST
    # so discovery-blind hosts (wildcard-cert cover, no subfinder API keys)
    # are never dropped. Everything is still scope-gated before probing.
    subs_file = out / "subdomains.txt"
    is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+(?::\d+)?$", domain))
    discovered: List[str] = []
    if _tool_ok("subfinder") and not is_ip:
        _info("subfinder: passive subdomain enum")
        _, stdout, _ = _run(
            [_bin("subfinder"), "-d", domain, "-silent", "-all"],
            timeout=120,
        )
        if stdout and stdout.strip():
            discovered = [raw.strip() for raw in stdout.splitlines() if raw.strip()]
            _ok(f"subfinder: {len(discovered)} subdomains")
    if not is_ip:
        # crt.sh is ADDITIVE: it runs whether or not subfinder found
        # anything, and only adds names subfinder missed. Partial subfinder
        # output must not suppress the certificate-transparency source.
        crt = _crtsh_subdomains(domain)
        if crt:
            new = [h for h in crt if h not in discovered]
            if new:
                _ok(f"crt.sh: {len(crt)} subdomains ({len(new)} new)")
            discovered = discovered + new
        elif not discovered:
            _info("crt.sh: no certificate-transparency results")
    seeds = [s.strip().lower() for s in (seed_hosts or []) if s and s.strip()]
    if seeds:
        _info(f"scope seeds: {len(seeds)} in-scope hosts from program scope list")
    merged: List[str] = []
    for h in seeds + discovered + [domain]:
        if h and h not in merged:
            merged.append(h)
    subs_file.write_text("\n".join(merged) + "\n")
    _ok(f"subdomains.txt: {len(merged)} total ({len(seeds)} scope-seeded)")

    # 2. DNS records
    if _tool_ok("dnsx") and not is_ip:
        _info("dnsx: DNS records")
        _, stdout, _ = _run(
            [
                _bin("dnsx"),
                "-l",
                str(subs_file),
                "-silent",
                "-a",
                "-cname",
                "-mx",
                "-resp",
            ],
            timeout=120,
        )
        if stdout:
            (out / "dns.txt").write_text(stdout)
            _ok(f"dnsx: {len(stdout.splitlines())} records")

    # 3. Live host probing + fingerprint — SCOPE-FIRST: the scope gate filters
    # the probe inputs BEFORE httpx sends a single packet. An out-of-scope
    # host must never be probed.
    live_file = out / "live_hosts.txt"
    # Fresh run, fresh live-hosts: a stale live_hosts.txt from a previous
    # run (e.g. r3's https://hackerone.com) must never survive into this
    # run's pipeline. (2026-10-01: stale file skipped the httpx fallback
    # because "non-empty" looked like success.)
    if live_file.exists():
        live_file.unlink()

    def _scope_probe_list(candidates):
        """Fail-closed scope filter for httpx probe inputs."""
        kept = []
        for c in candidates:
            c = c.strip()
            if not c:
                continue
            if scope_gate:
                ok, reason = scope_gate.is_in_scope(c)
                if not ok:
                    _warn(f"scope gate: skipping out-of-scope httpx target — {reason}")
                    continue
            kept.append(c)
        return kept

    if target.startswith("http://") or target.startswith("https://"):
        probe = _scope_probe_list([target])
        if not probe:
            _warn("httpx: direct target is out of scope — skipping live host probe")
        else:
            _info(f"httpx: probing direct target URL ({target})")
            # NOTE: no -follow-redirects. Following redirects would probe
            # wherever the target redirects to — including out-of-scope
            # hosts the gate never approved. -location still shows the
            # redirect target for recon without probing it.
            _httpx_cmd = [
                _bin("httpx"),
                "-u",
                target,
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-location",
            ]
            # Authenticated regime: the probe that produces live_hosts
            # status tags must carry the hunt's auth, or a [200] proves
            # only anonymous reachability (regime receipts read these).
            for _h in _rheaders:
                _httpx_cmd += ["-H", _h]
            _httpx_cmd += ["-o", str(live_file)]
            _, stdout, _ = _run(_httpx_cmd, timeout=60)
            if not live_file.exists() or live_file.stat().st_size == 0:
                # Untagged: the target stays a probe candidate, but no
                # status was observed — never fabricate a [200].
                live_file.write_text(f"{target}\n")
            lines = len(live_file.read_text().splitlines())
            _ok(f"httpx: {lines} live hosts")
    elif _tool_ok("httpx"):
        raw_subs = subs_file.read_text().splitlines() if subs_file.exists() else []
        in_scope_subs = _scope_probe_list(raw_subs)
        scoped_subs_file = out / "in_scope_subs.txt"
        scoped_subs_file.write_text("\n".join(in_scope_subs) + "\n")
        if not in_scope_subs:
            _warn("httpx: no in-scope probe targets — skipping live host probe")
        else:
            _info("httpx: probing live hosts + fingerprinting (scope-filtered)")
            # NOTE: no -follow-redirects here either (see above): redirect
            # chains are unapproved probe targets.
            _httpx_cmd = [
                _bin("httpx"),
                "-l",
                str(scoped_subs_file),
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-location",
            ]
            for _h in _rheaders:
                _httpx_cmd += ["-H", _h]
            _httpx_cmd += ["-o", str(live_file)]
            _, stdout, _ = _run(_httpx_cmd, timeout=180)
            lines = len(live_file.read_text().splitlines()) if live_file.exists() else 0
            _ok(f"httpx: {lines} live hosts")
    else:
        _warn("httpx not found — skipping live host probe")
        live_file.write_text(f"https://{domain}\n")

    # 3b. Fallback probe: httpx hangs outright on some networks (v1.12.0 hung
    # even on https://example.com, 2026-10-01) — _run's timeout fires but the
    # pipeline then starves on an empty live_hosts.txt. When httpx produced
    # nothing, probe each scope-gated seed host directly with urllib (short
    # timeouts, no redirects) so katana/hakrawler still get live targets.
    _live_lines = live_file.read_text().splitlines() if live_file.exists() else []
    if not any(existing.strip() for existing in _live_lines):
        _warn("httpx produced no live hosts — falling back to direct urllib probe")
        _fallback_live = _direct_probe_fallback(
            [s for s in (seed_hosts or [])] or [domain],
            scope_gate,
            headers=_rheaders,
        )
        if not _fallback_live:
            _subs = subs_file.read_text().splitlines() if subs_file.exists() else []
            _fallback_live = _direct_probe_fallback(
                _subs[:25], scope_gate, headers=_rheaders
            )
        if _fallback_live:
            live_file.write_text("\n".join(_fallback_live) + "\n")
            _ok(f"fallback probe: {len(_fallback_live)} live hosts")
        else:
            live_file.write_text(f"https://{domain}\n")
            _warn("fallback probe found nothing — using raw target")

    # 4. Known URLs (Wayback + OTX + CommonCrawl)
    urls_file = out / "known_urls.txt"
    if _tool_ok("gau"):
        _info("gau: pulling known URLs from archives")
        _, stdout, _ = _run(
            [_bin("gau"), "--subs", domain],
            timeout=120,
        )
        if stdout:
            urls_file.write_text(stdout)
            _ok(f"gau: {len(stdout.splitlines())} URLs")
    elif _tool_ok("waybackurls"):
        _info("waybackurls: pulling Wayback URLs")
        _, stdout, _ = _run([_bin("waybackurls"), domain], timeout=90)
        if stdout:
            urls_file.write_text(stdout)
            _ok(f"waybackurls: {len(stdout.splitlines())} URLs")

    # 5. Clean live hosts for tooling (strip [200], titles, tech tags)
    clean_live_file = out / "clean_live_hosts.txt"
    clean_urls = []
    if live_file.exists():
        for line in live_file.read_text().splitlines():
            if line.strip():
                clean_urls.append(line.split()[0].strip())
    if scope_gate:
        clean_urls = [u for u in clean_urls if scope_gate.is_in_scope(u)[0]]
    if not clean_urls:
        # Fail-closed fallback: only reuse the raw target when the scope gate
        # allows it — never reintroduce an out-of-scope host into the probe
        # pipeline (katana/hakrawler run off clean_live_hosts.txt).
        fallback = target if target.startswith("http") else f"https://{domain}"
        if not scope_gate or scope_gate.is_in_scope(fallback)[0]:
            clean_urls = [fallback]
        else:
            _warn("scope gate: all live hosts out of scope — no fallback target used")
    clean_live_file.write_text("\n".join(clean_urls) + "\n")

    # 5. Crawl
    if _tool_ok("katana"):
        _info("katana: crawling live hosts")
        crawl_file = out / "crawl.txt"
        from oracle_foundation import LOGOUT_PATH_PATTERN as _logout_pat

        _katana_cmd = [
            _bin("katana"),
            "-list",
            str(clean_live_file),
            "-silent",
            "-depth",
            "2" if controlled else "3",
            "-js-crawl",
            # Logout-shaped URLs are out of crawl scope: requesting one
            # with a session cookie destroys the session (DVWA logout.php
            # GET → session_destroy), silently 302ing every later probe.
            "-cos",
            _logout_pat,
            *(["-rl", "5"] if controlled else []),
        ]
        for _h in _rheaders:
            _katana_cmd += ["-H", _h]
        _katana_cmd += ["-o", str(crawl_file)]
        _, stdout, _ = _run(_katana_cmd, timeout=180)
        if crawl_file.exists():
            _ok(f"katana: {len(crawl_file.read_text().splitlines())} paths")

    # 5b. Deep recon — JS mining, API spec discovery, content discovery.
    # Native implementations (no hakrawler needed): scope-gated, fail-closed
    # with no scope gate, polite (short timeouts, sequential, capped).
    # Feeds js_endpoints.txt / api_specs.txt / fuzzed_paths.txt, which
    # _collect_recon prioritizes into the model prompt.
    try:
        from oracle_deeprecon import (
            mine_js,
            mine_crawled_pages,
            discover_api_specs,
            fuzz_hidden_paths,
            harvest_listings,
        )

        if clean_urls and scope_gate:
            # controlled mode still runs deep recon — rate-limiting (-rl 5 on
            # katana/nuclei) is the controlled behaviour, not skipping the pass.
            # Skipping it left queued hunts (which always pass controlled=True)
            # with zero JS endpoints, zero API specs, and zero fuzzed paths.
            _info("deep recon: JS mining on live hosts")
            try:
                mine_js(clean_urls, scope_gate, out, extra_headers=_rheaders or None)
            except Exception as e:
                _warn(f"js mining failed — continuing: {e}")
            _info("deep recon: crawled-page mining (inline JS navigation)")
            try:
                mine_crawled_pages(out, scope_gate, extra_headers=_rheaders or None)
            except Exception as e:
                _warn(f"crawled-page mining failed — continuing: {e}")
            _info("deep recon: API spec discovery")
            try:
                discover_api_specs(
                    clean_urls, scope_gate, out, extra_headers=_rheaders or None
                )
            except Exception as e:
                _warn(f"api spec discovery failed — continuing: {e}")
            if not controlled:
                _info("deep recon: content discovery (ffuf)")
                try:
                    fuzz_hidden_paths(
                        clean_urls, scope_gate, out, extra_headers=_rheaders or None
                    )
                except Exception as e:
                    _warn(f"content discovery failed — continuing: {e}")
            else:
                _info(
                    "controlled recon: skipping ffuf content fuzzing (rate-sensitive)"
                )
            _info("deep recon: directory-listing harvest")
            try:
                harvest_listings(out, scope_gate, extra_headers=_rheaders or None)
            except Exception as e:
                _warn(f"listing harvest failed — continuing: {e}")
        elif not scope_gate:
            _warn("deep recon: no scope gate — skipping (fail-closed)")
    except ImportError as e:
        _warn(f"deep recon module unavailable — skipping: {e}")

    # 6. JS endpoint extraction
    # NOTE: nuclei (CVE-template scanner) was deliberately removed.
    # Oracle's three-mindset architecture finds logic flaws by asserting
    # wire behavior against documented claims (Assertion A vs B + live check).
    # Nuclei pattern-matches known CVE signatures — no concept of A/B seams,
    # no program-specific context, produces only noise the program's security
    # team has already seen. It belongs to a Basilisk-style detector engine,
    # not Oracle. All recon surface is fed to the engines via recon_text.
    if target_is_healthy() and _tool_ok("hakrawler") and clean_urls:
        _info("hakrawler: JS endpoint extraction")
        js_file = out / "js_endpoints.txt"
        # Run against ALL live hosts, not just clean_urls[0]. A target with
        # 12 live hosts previously got JS extraction on one host only.
        _hak_total = 0
        for _hak_url in clean_urls:
            _, stdout, _ = _run(
                [_bin("hakrawler"), "-url", _hak_url, "-depth", "3", "-js", "-plain"],
                timeout=120,
            )
            if stdout:
                _hak_total = _merge_line_file(js_file, stdout)
        if _hak_total:
            _ok(f"hakrawler: {_hak_total} JS endpoints total ({len(clean_urls)} hosts)")

    # 8. Write recon summary
    _write_recon_report(out, domain)
    _ok(f"Recon complete → {out}")
    return out


def _write_recon_report(out: Path, domain: str):
    lines = [
        f"# Recon Report: {domain}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]
    for fname in [
        "subdomains.txt",
        "live_hosts.txt",
        "known_urls.txt",
        "dns.txt",
        "crawl.txt",
        "js_endpoints.txt",
        "js_secrets.txt",
        "api_specs.txt",
        "fuzzed_paths.txt",
    ]:
        f = out / fname
        if f.exists():
            n = len(f.read_text().splitlines())
            lines.append(f"- **{fname}**: {n} lines")
    (out / "RECON_REPORT.md").write_text("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
# Oracle analysis — local model
# ─────────────────────────────────────────────────────────────────────────────

# ── MITRE heatmap path ────────────────────────────────────────────────────────
_MITRE_HEATMAP = _HERE / "recon" / "bugbase_mitre" / "mitre_heatmap_api.json"

# ── Fused paradox+TTP hunt templates (oracle_ttp_fuse.py output) ───────────────
_FUSED_TTPS_PATH = _HERE / "oracle_ttps_fused.json"
_FUSED_TTPS_CACHE: Optional[Dict[str, Dict]] = None


def _load_fused_ttps() -> Dict[str, Dict]:
    """Load the fused paradox+TTP templates keyed by MITRE code. Cached.
    Fail-soft: returns {} when the file is missing/unreadable (heatmap-only)."""
    global _FUSED_TTPS_CACHE
    if _FUSED_TTPS_CACHE is not None:
        return _FUSED_TTPS_CACHE
    try:
        records = json.loads(_FUSED_TTPS_PATH.read_text(encoding="utf-8"))
        # First-wins (R3 / full-weight MITRE): the appended Reflex 9/10/11
        # overlay stubs (T1078/T1083/T1133/T1190, idx 342+) duplicate real
        # codes with one-line text. Last-wins let them clobber the full
        # ATT&CK definitions, corrupting every T1078/T1190 lookup
        # prompt-wide. Real records come first. 348 records → 344 unique.
        fused: Dict[str, Dict] = {}
        for r in records:
            if isinstance(r, dict) and r.get("code"):
                fused.setdefault(r["code"], r)
        _FUSED_TTPS_CACHE = fused
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError):
        _FUSED_TTPS_CACHE = {}
    return _FUSED_TTPS_CACHE


def _format_ttp_line(t: Dict, fused: Dict[str, Dict]) -> str:
    """Format one selected technique for the reflex prompt. When a fused record
    exists, frame it with its paradox + reflex move + 'you never said' seed as
    hunt AGENDA the model reasons FROM (never copies). Else fall back to the
    heatmap description."""
    code = t.get("code", "?")
    rec = fused.get(code)
    if rec:
        seed = (rec.get("you_never_said") or "").strip()
        return (
            f"**{code} ({t.get('tactic', '?')}) — {t.get('name', '?')}**  "
            f"[Reflex {rec.get('primary_reflex', '?')}: {rec.get('reflex_name', '?')} · "
            f"Paradox: {rec.get('paradox', '?')}]\n"
            f"Reflex move: {rec.get('reflex_move', '').strip()}\n"
            f"Seam seed (reason FROM this, do NOT copy the label into output): {seed}\n"
        )
    perms = t.get("permissions_required", "N/A")
    sentences = re.split(r"(?<=[.!?])\s+", (t.get("description", "") or "").strip())
    short_desc = " ".join(sentences[:2])
    return (
        f"**{code} ({t.get('tactic', '?')}) — {t.get('name', '?')}**\n"
        f"Permissions claimed: {perms}\n"
        f"{short_desc}\n"
    )


# Recon signal → MITRE tactic mapping
# Keys are strings we look for in recon output; values are tactic names in heatmap
_RECON_TACTIC_SIGNALS: List[tuple] = [
    # (recon signal pattern, [tactic keys in heatmap])
    (
        r"login|auth|password|signin|credential|oauth|jwt|bearer|token",
        ["credential-access", "initial-access"],
    ),
    (
        r"admin|dashboard|manage|portal|console|config",
        ["privilege-escalation", "defense-evasion", "persistence"],
    ),
    (
        r"upload|file|attachment|import|export",
        ["execution", "persistence", "exfiltration"],
    ),
    (
        r"api|rest|graphql|endpoint|swagger|openapi",
        ["initial-access", "credential-access", "collection"],
    ),
    (r"redirect|callback|oauth|sso|saml", ["credential-access", "initial-access"]),
    (r"search|query|filter|id=|uid=|user_id|account", ["collection", "discovery"]),
    (r"payment|cart|order|price|checkout|coupon", ["impact", "collection"]),
    (
        r"email|smtp|notification|webhook",
        ["collection", "exfiltration", "command-and-control"],
    ),
    (r"s3|bucket|blob|storage|cdn|download", ["collection", "exfiltration"]),
    (r"ssh|rdp|vnc|telnet|ftp|smb", ["lateral-movement", "initial-access"]),
    (
        r"aws|gcp|azure|cloud|iam|role|assume",
        ["privilege-escalation", "credential-access", "discovery"],
    ),
    (
        r"cve-|severity.*critical",
        ["initial-access", "execution", "privilege-escalation"],
    ),
    # Exposed internals / tech-stack fingerprints (ports, CMS, VCS, backups)
    (
        r"\.git|\.env|backup\.|\.sql|phpinfo|debug|swagger\.json",
        ["initial-access", "collection"],
    ),
    (
        r"wordpress|wp-content|drupal|joomla|magento",
        ["initial-access", "execution", "privilege-escalation"],
    ),
    (
        r":22\b|:3389\b|:5900\b|:21\b|:445\b",
        ["lateral-movement", "initial-access", "credential-access"],
    ),
]


def _map_ttps_to_recon(
    recon_dir: Path, max_ttps: int = 30, kind: Optional[str] = None
) -> str:
    """
    Read recon output, detect which MITRE tactics/techniques are relevant,
    and return a focused TTP context block for the Oracle reflex pass.

    Technique data comes from oracle_ttps_fused.json (committed, 348
    paradox-fused ATT&CK records / 344 unique codes) — no external
    heatmap file required.
    Selection is driven by THIS hunt's recon signals: open ports, detected
    technologies, URL/JS surface, and the program kind (web2/web3/ai).

    This gives Oracle the "you never said" ammunition per technique:
    - The paradox + reflex move fused to the technique
    - Mapped specifically to signals found in THIS recon

    Returns empty string if the fused TTP file is unavailable.
    """
    fused = _load_fused_ttps()
    if not fused:
        _warn("Fused MITRE TTPs not found — skipping TTP mapping")
        return ""

    # Collect all recon text for signal detection
    recon_text = ""
    for fname in [
        "live_hosts.txt",
        "known_urls.txt",
        "js_endpoints.txt",
        "js_secrets.txt",
        "crawl.txt",
    ]:
        f = recon_dir / fname
        if f.exists():
            recon_text += f.read_text(encoding="utf-8", errors="ignore")[:5000]

    recon_lower = recon_text.lower()

    # Detect which tactics are relevant
    relevant_tactics: Dict[str, int] = {}  # tactic → hit count
    for pattern, tactics in _RECON_TACTIC_SIGNALS:
        if re.search(pattern, recon_lower):
            for t in tactics:
                relevant_tactics[t] = relevant_tactics.get(t, 0) + 1

    # Always include initial-access and credential-access as baseline
    for t in ["initial-access", "credential-access"]:
        relevant_tactics[t] = relevant_tactics.get(t, 0) + 1

    # Program-kind bias: web3 and ai targets get tactic weight from their
    # attack surface even when recon text is thin.
    if kind == "web3":
        for t in ["execution", "privilege-escalation", "impact", "defense-evasion"]:
            relevant_tactics[t] = relevant_tactics.get(t, 0) + 2
    elif kind == "ai":
        for t in [
            "initial-access",
            "exfiltration",
            "collection",
            "command-and-control",
        ]:
            relevant_tactics[t] = relevant_tactics.get(t, 0) + 2

    # Sort by hit count, take top tactics
    top_tactics = sorted(relevant_tactics, key=lambda t: -relevant_tactics[t])[:6]

    # Pull the most relevant techniques from each tactic, straight from the
    # fused records (heatmap slug -> fused display name, e.g.
    # "credential-access" -> "CREDENTIAL ACCESS").
    by_tactic: Dict[str, List[Dict]] = {}
    for rec in fused.values():
        by_tactic.setdefault((rec.get("tactic") or "").upper(), []).append(rec)

    selected: List[Dict] = []
    per_tactic = max(2, max_ttps // len(top_tactics))

    for tactic in top_tactics:
        techniques = by_tactic.get(tactic.replace("-", " ").upper(), [])
        # Prioritise techniques whose description mentions web-relevant terms —
        # easier to aim at a live web target. Deterministic tiebreak on code.
        scored = []
        for rec in techniques:
            desc = (rec.get("description") or "").lower()
            score = 0
            if any(w in desc for w in ["web", "api", "http", "browser", "application"]):
                score += 3
            if any(w in desc for w in ["user", "authenticated", "credential"]):
                score += 2
            scored.append((score, rec.get("code", ""), rec))
        scored.sort(key=lambda s: (-s[0], s[1]))
        for _, code, rec in scored[:per_tactic]:
            selected.append(
                {"tactic": tactic, "code": code, "name": rec.get("name", "?")}
            )

    if not selected:
        return ""

    # Format as Oracle context — compact, actionable
    lines = [
        "## APPLICABLE MITRE ATT&CK TECHNIQUES",
        "These techniques are relevant based on recon signals.",
        "For each: apply the Oracle reflex — 'You claimed this is blocked.",
        "You never said WHERE it is enforced. Find the gap.'\n",
    ]

    fused = _load_fused_ttps()  # cached; same data selected from above
    for t in selected[:max_ttps]:
        lines.append(_format_ttp_line(t, fused))

    _ok(
        f"MITRE mapping: {len(selected)} techniques across {len(top_tactics)} "
        f"tactics (all paradox-fused)"
    )
    return "\n".join(lines)


def _distill_endpoints(text: str, max_items: int = 60) -> List[str]:
    """Filter out static assets and prioritize high-signal attack surface endpoints."""
    static_exts = re.compile(
        r"\.(?:png|jpg|jpeg|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|webm|webp|pdf|map)(?:\?.*)?$",
        re.IGNORECASE,
    )
    priority_patterns = re.compile(
        r"api|v[1-9]|auth|login|token|admin|internal|user|account|debug|secret|config|stage|graphql|gql|upload|download|\?",  # noqa: E501
        re.IGNORECASE,
    )

    high_priority = []
    regular = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        path_part = line.split("?")[0].split("#")[0]
        if static_exts.search(path_part):
            continue

        if priority_patterns.search(line):
            high_priority.append(line)
        else:
            regular.append(line)

    seen = set()
    combined = []
    for item in high_priority + regular:
        if item not in seen:
            seen.add(item)
            combined.append(item)
        if len(combined) >= max_items:
            break
    return combined


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes that tools like dnsx/httpx embed in output."""
    return _ANSI_RE.sub("", text)


def _collect_recon(
    recon_dir: Path,
    max_chars: int = 20000,
    scope_gate: Optional["ProgramScopeGate"] = None,
) -> str:
    """
    Collect the most signal-dense recon output into a single text block.
    Filters out static assets and prioritizes live_hosts > JS secrets > API routes > spidered paths.
    Enforces scope gate: drops 3rd-party CDNs, external analytics, and out-of-scope hosts.
    Strips ANSI escape codes so LLMs receive clean text.
    """
    order = [
        "clean_live_hosts.txt",
        "live_hosts.txt",
        "known_urls.txt",
        "js_endpoints.txt",
        "js_secrets.txt",
        "api_specs.txt",
        "fuzzed_paths.txt",
        "crawl.txt",
        "traffic_evidence.jsonl",
        "subdomains.txt",
        "dns.txt",
    ]
    from oracle_foundation import sanitize_prompt_text as _san_prompt

    chunks = []
    total = 0
    for fname in order:
        f = recon_dir / fname
        if not f.exists():
            continue
        # Phase 5: recon files are target-controlled — strip control chars
        # at ingestion (delimiting happens at prompt construction).
        text = _san_prompt(_strip_ansi(f.read_text(encoding="utf-8", errors="ignore")))
        if not text.strip():
            continue

        # Ingress Scope Filter: strip out-of-scope hosts and 3rd party assets
        if scope_gate:
            kept = []
            for line in text.splitlines():
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                urls = re.findall(r'https?://[^\s\'"<>`]+', clean)
                if urls:
                    # ALL URLs on the line must be in scope: a single in-scope
                    # token must not launder out-of-scope hosts into the prompt.
                    if all(scope_gate.is_in_scope(u)[0] for u in urls):
                        kept.append(clean)
                else:
                    first_tok = clean.split()[0]
                    if not scope_gate.is_in_scope(first_tok)[0]:
                        continue
                    # First-token-in-scope must not launder trailing hosts:
                    # every domain-like token on the line must be in scope.
                    _doms = re.findall(
                        r"(?<![\w.-])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]+))(?![\w-])",
                        clean,
                        flags=re.IGNORECASE,
                    )
                    if all(scope_gate.is_in_scope(dm)[0] for dm in _doms):
                        kept.append(clean)
            text = "\n".join(kept)
            if not text.strip():
                continue

        # Distill large endpoint files — bump max_items for richer signal
        if fname in (
            "known_urls.txt",
            "crawl.txt",
            "js_endpoints.txt",
            "fuzzed_paths.txt",
            "api_specs.txt",
        ):
            distilled = _distill_endpoints(text, max_items=120)
            text = "\n".join(distilled)

        remaining = max_chars - total
        if remaining <= 0:
            break
        chunk = text[:remaining]
        chunks.append(f"### {fname}\n{chunk}")
        total += len(chunk)
    return "\n\n".join(chunks)


# ─────────────────────────────────────────────────────────────────────────────
# Intake helpers — downloaded assets → model context, repo auto-clone
# ─────────────────────────────────────────────────────────────────────────────

_ASSET_TEXT_EXTS = {
    ".html",
    ".htm",
    ".js",
    ".json",
    ".md",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _html_to_text(html: str) -> str:
    """Crude HTML→text that preserves link targets (needed so the model can
    cite real asset URLs under HARD RULE 1)."""
    t = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    t = re.sub(
        r"""(?i)<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""",
        lambda m: f" {m.group(2).strip()} [ {m.group(1).strip()} ] ",
        t,
    )
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = re.sub(r"[ \t\xa0]+", " ", t)
    t = re.sub(r"\n\s*\n+", "\n", t)
    return t.strip()


def _collect_asset_context(
    assets_dir: Optional[Path],
    per_asset_chars: int = 8000,
    total_chars: int = 30000,
    kept_hosts: Optional[Set[str]] = None,
) -> str:
    """Read downloaded program assets into a prompt-safe context block.

    Per-asset and total caps keep the prompt from exploding; binary and
    oversized files are skipped. Returns "" when there is nothing usable.

    M1: when a hunt filter is active, only files belonging to kept assets
    are included. kept_hosts may be passed explicitly; otherwise it is read
    from the workspace's hunt_scope.json (assets_dir/../hunt_scope.json).
    Without filter metadata every file is included, as before.
    """
    if not assets_dir or not assets_dir.is_dir():
        return ""
    if kept_hosts is None:
        try:
            from oracle_mindset_context import _kept_hosts_of

            hs = assets_dir.parent / "hunt_scope.json"
            if hs.exists():
                kept_hosts = _kept_hosts_of(json.loads(hs.read_text(encoding="utf-8")))
        except Exception:
            kept_hosts = None
    host_of = None
    manifest: Dict[str, str] = {}
    if kept_hosts is not None:
        try:
            from oracle_mindset_context import _manifest_of, _downloaded_file_host

            manifest = _manifest_of(assets_dir)
            host_of = _downloaded_file_host
        except Exception:
            kept_hosts = None
    blocks: List[str] = []
    total = 0
    for f in sorted(assets_dir.iterdir()):
        if not f.is_file():
            continue
        if f.name == "_manifest.json":
            continue
        if (
            kept_hosts is not None
            and host_of is not None
            and host_of(f.name, manifest) not in kept_hosts
        ):
            continue
        if f.suffix.lower() not in _ASSET_TEXT_EXTS:
            continue
        try:
            if f.stat().st_size > 2_000_000 or f.stat().st_size < 50:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if f.suffix.lower() in (".html", ".htm"):
            text = _html_to_text(text)
        from oracle_foundation import sanitize_prompt_text as _san_prompt

        text = _san_prompt(text.strip())
        if len(text) < 50:
            continue
        chunk = text[:per_asset_chars]
        if len(text) > per_asset_chars:
            chunk += "\n[…truncated…]"
        if total + len(chunk) > total_chars:
            break
        blocks.append(f"--- asset: {f.name} ---\n{chunk}")
        total += len(chunk)
    return "\n\n".join(blocks)


_REPO_URL_RE = re.compile(
    r"(?:https?://|(?<![/\w.\-]))github\.com/([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?=[/\"'\s?#]|$)"
)


def _extract_repo_urls(prog: Dict, assets_dir: Optional[Path]) -> List[str]:
    """Pull github repo URLs from the program dict and downloaded page HTML.
    Returns normalized, de-duplicated https://github.com/<owner>/<repo> URLs."""
    texts: List[str] = []
    for key in ("url", "scope", "targets", "repo_url"):
        v = prog.get(key)
        if isinstance(v, str) and "github.com" in v:
            texts.append(v)
    for s in (prog.get("structured_scopes") or []):
        if not isinstance(s, dict):
            continue
        if s.get("eligible_for_submission", True) is False:
            continue
        ident = s.get("asset_identifier")
        if isinstance(ident, str) and "github.com" in ident.lower():
            texts.append(ident)
    raw = prog.get("raw")
    if isinstance(raw, dict):
        for v in raw.values():
            if isinstance(v, str) and "github.com" in v:
                texts.append(v)
    if assets_dir and assets_dir.is_dir():
        for pat in ("*.html", "*.htm"):
            for f in sorted(assets_dir.glob(pat)):
                try:
                    t = f.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                if "github.com" in t:
                    texts.append(t)
    seen = set()
    found: List[str] = []
    for t in texts:
        for m in _REPO_URL_RE.finditer(t):
            owner, repo = m.group(1), m.group(2)
            if "*" in owner or "*" in repo:
                continue
            url = f"https://github.com/{owner}/{repo}"
            if url not in seen:
                seen.add(url)
                found.append(url)
    return found


def _clone_program_repos(
    repo_urls: List[str],
    dest_base: Path,
    prog: Optional[Dict] = None,
    timeout: int = 300,
) -> List[Path]:
    """Shallow-clone in-scope program repos (additive — repo-less live-asset
    targets are unaffected). A repo counts as in-scope when its owner/repo
    tokens overlap the program name tokens or the owner is named in the
    program scope text; anything else is skipped, never cloned blindly.
    Returns the list of checkout dirs (existing ones included)."""
    prog = prog or {}
    name_tokens = set(re.split(r"[^a-z0-9]+", str(prog.get("name") or "").lower())) - {
        ""
    }
    structured_idents = " ".join(
        str(s.get("asset_identifier") or "")
        for s in (prog.get("structured_scopes") or [])
        if isinstance(s, dict) and s.get("eligible_for_submission", True) is not False
    )
    scope_text = (
        str(prog.get("scope") or "")
        + " "
        + str(prog.get("url") or "")
        + " "
        + structured_idents
    ).lower()
    cloned: List[Path] = []
    try:
        dest_base.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        _warn(f"repo clone: cannot create {dest_base}: {e}")
        return cloned
    for url in repo_urls:
        m = re.match(r"https?://github\.com/([\w.\-]+)/([\w.\-]+)$", url)
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        repo_tokens = set(re.split(r"[^a-z0-9]+", f"{owner} {repo}".lower())) - {""}
        in_scope = bool(repo_tokens & name_tokens) or owner.lower() in scope_text
        if not in_scope:
            _info(f"repo {owner}/{repo} not matched to program scope — skipping clone")
            continue
        dest = dest_base / f"{owner}_{repo}"
        if dest.exists():
            cloned.append(dest)
            continue
        rc, _out, err = _run(
            ["git", "clone", "--depth", "1", "--", url, str(dest)],
            timeout=timeout,
        )
        if rc == 0 and dest.exists():
            _ok(f"cloned in-scope repo {owner}/{repo} → {dest}")
            cloned.append(dest)
        else:
            _warn(f"repo clone failed for {url}: {err[:150]}")
    return cloned


def _query_local(
    prompt: str, system: str, model: str = LOCAL_MODEL, timeout: Optional[int] = None
) -> str:
    """Send prompt to local Ollama model with Oracle system prompt via HTTP API.
    timeout=None allows large models on CPU or large contexts without artificial client aborts.
    """
    import requests

    url = "http://localhost:11434/api/generate"
    try:
        r = requests.post(
            url,
            json={
                "model": model,
                "system": system,
                "prompt": prompt,
                "stream": False,
            },
            timeout=timeout,
        )
        if r.ok:
            return r.json().get("response", "").strip()
        if model != FALLBACK_MODEL:
            _warn(f"{model} failed ({r.status_code}), trying {FALLBACK_MODEL}")
            return _query_local(prompt, system, FALLBACK_MODEL, timeout)
        return f"[ollama error] {r.text}"
    except Exception as e:
        if model != FALLBACK_MODEL:
            _warn(f"{model} request error ({e}), trying {FALLBACK_MODEL}")
            return _query_local(prompt, system, FALLBACK_MODEL, timeout)
        return f"[ollama error] {e}"


def _query_openrouter(prompt: str, system: str, timeout: int = 25) -> Optional[str]:
    """Deprecated shim — routes through oracle_llm.complete (task 'assess').
    Kept for backward compatibility with any external caller; the old hardcoded
    free-model list is gone (models are discovered live). Returns None on failure."""
    import oracle_llm

    try:
        return oracle_llm.complete(prompt, system, task_type="assess", timeout=timeout)
    except RuntimeError:
        return None


def _deterministic_block(recon_dir: Path, scope_gate=None) -> str:
    """Run the deterministic web-surface engine against the live hosts and
    render its findings block. Independent re-observation of the wire —
    grounds LLM reflexes in code-verified facts. Additive; an engine
    failure degrades to a note, never fails the hunt."""
    try:
        from oracle_deterministic import run_deterministic, render_findings_block

        live_f = recon_dir / "clean_live_hosts.txt"
        if not live_f.exists() or live_f.stat().st_size == 0:
            live_f = recon_dir / "live_hosts.txt"
        _det_hosts = []
        if live_f.exists() and live_f.stat().st_size > 0:
            _det_hosts = [
                host_line.strip().split()[0]
                for host_line in live_f.read_text().splitlines()
                if host_line.strip()
            ]
        if scope_gate is None:
            # No gate = no unfiltered live probing. Loopback testbeds
            # still work; anything else needs an explicit scope gate.
            _det_hosts = [
                h
                for h in _det_hosts
                if ProgramScopeGate.extract_host(h)
                in ("127.0.0.1", "localhost", "::1", "[::1]")
            ]
        return render_findings_block(
            run_deterministic(_det_hosts, scope_gate=scope_gate)
        )
    except Exception as _det_e:
        return f"--- DETERMINISTIC FINDINGS ---\n(engine unavailable: {_det_e})\n"


def run_reflexes(
    recon_dir: Path,
    model: str = LOCAL_MODEL,
    target: str = "",
    cloud: bool = False,
    scope_gate: Optional["ProgramScopeGate"] = None,
    no_cloud: bool = False,
    kept_hosts: Optional[Set[str]] = None,
) -> str:
    """
    Load the full Oracle prompt (all 4 docs) + mapped MITRE TTPs and run
    all 8 reflexes against the recon data. Returns the raw model output.

    The MITRE TTP context tells Oracle WHICH techniques to aim "you never said"
    at — same data BugBase's copilot uses, but Oracle applies its mindset
    instead of mechanical checks.

    no_cloud=True forces local-only routing (fail-closed when no local
    backend answers). The legacy `cloud` parameter is ignored — routing is
    decided by the oracle_llm router plus no_cloud.
    """
    recon_text = _collect_recon(recon_dir, max_chars=20000, scope_gate=scope_gate)
    if not recon_text.strip():
        return "[no recon data found]"

    # Map recon signals to relevant MITRE TTPs (top 12 techniques)
    ttp_context = _map_ttps_to_recon(recon_dir, max_ttps=12)

    # Downloaded program assets (additive — absent for repo-less/legacy workspaces)
    # M1: scope-filtered to kept assets when a hunt filter is active.
    _assets_dir = recon_dir.parent / "assets" if recon_dir.name == "recon" else None
    _asset_text = _collect_asset_context(_assets_dir, kept_hosts=kept_hosts)
    _asset_block = _asset_text if _asset_text else "(no program assets downloaded)"

    system = _load_oracle_prompt(voice=False, query=recon_text)

    target_base = (
        f"https://{target}" if target and not target.startswith("http") else target
    )
    live_f = recon_dir / "clean_live_hosts.txt"
    if not live_f.exists() or live_f.stat().st_size == 0:
        live_f = recon_dir / "live_hosts.txt"
    if live_f.exists() and live_f.stat().st_size > 0:
        for _line in live_f.read_text().splitlines():
            if not _line.strip():
                continue
            _cand = _line.split()[0]
            # Never let an out-of-scope first line name the Live Target Host.
            if scope_gate is None or scope_gate.is_in_scope(_cand)[0]:
                target_base = _cand
                break
    if not target_base:
        target_base = f"https://{recon_dir.name}"

    from oracle_foundation import INSTRUCTION_HIERARCHY_REMINDER as _IER
    from oracle_foundation import sanitize_prompt_text as _san
    from oracle_foundation import untrusted_block as _untrusted

    _safe_target = _san(target or recon_dir.name, 300, oneline=True)
    _recon_block = _untrusted(recon_text, "recon-data")
    _assets_block = _untrusted(_asset_block, "program-assets")
    task = textwrap.dedent(
        f"""
        Target: {_safe_target}
        Live Target Host: {target_base}

        Below is recon output for this in-scope bug bounty target, followed by
        the MITRE ATT&CK techniques relevant to what was found.

        YOUR JOB:
        Run all 8 Oracle reflexes against this target. For every reflex, ask:
        "You claimed X is enforced. You never said WHERE. Find the gap."

        A SEAM is a BINARY CONFLICT — two irreconcilable assertions where one must be false.
        A 401/403 response is NOT a seam. It is confirmation the boundary works.
        Only emit a card when the wire behavior CONTRADICTS the claim.

        For every genuine seam, output EXACTLY this format:

        **SEAM [N]**
        - Assertion A: [what docs/policy/robots/UI explicitly claims]
        - Assertion A source: [exact in-scope URL or evidence filename containing Assertion A]
        - Assertion B: [what the wire actually does — cite the exact URL from RECON DATA]
        - Reflex: [Reflex number and name, e.g. "Reflex 2 — DECOUPLE"]
        - MITRE: [TTP code or N/A]
        - Frame: [paradox | impossible | iphone — required for the paradox/philosophy lens; omit for the technique lens]
        - Reproducible check: `curl -i -s [REAL URL from RECON DATA]`
        - Expected: [machine-readable prediction, e.g. 'status 200, body contains "users"']
        - Chain output: [optional exact value expected in this check's observed output]
        - Chain precondition: [optional exact value required from a prior confirmed finding]
        - Impact: [one sentence — real harm to a real user]

        HARD RULES:
        1. Every Assertion A MUST cite an exact source from the RECON DATA or DOWNLOADED PROGRAM ASSETS below. No invented policy claims.  # noqa: E501
        2. Every check URL MUST appear verbatim in the RECON DATA or DOWNLOADED PROGRAM ASSETS below. No invented paths.
        3. Do NOT emit a SEAM card for a surface that returned 401/403/530 (enforcement confirmed).
        4. If ALL surfaces are genuinely clean, output exactly: TARGET CLEAN
        5. Look hardest at: 200-returning endpoints, stage/dev subdomains, open APIs, unauthenticated paths.
        6. Do not describe what you are doing. Output seam cards only, or TARGET CLEAN.
        7. {_IER}

        Rank by real user harm: account takeover > data exposure > logic flaw > info leak.

        --- RECON DATA ---
        {_recon_block}

        --- DOWNLOADED PROGRAM ASSETS ---
        {_assets_block}

        {ttp_context}
    """
    ).strip()

    # Deterministic engine: rule-based web-surface checks (MITRE-mapped,
    # scope-gated, paradox-lensed). Independent re-observation of the live
    # hosts — grounds the reflexes in code-verified facts. Additive; an
    # engine failure degrades to a note, never fails the hunt.
    det_block = _deterministic_block(recon_dir, scope_gate=scope_gate)

    task = task + "\n\n" + det_block

    import oracle_llm

    _info("Running Oracle 8 reflexes via backend router…")
    # 360s total router budget so the circuit breaker and lane deadlines in
    # oracle_llm actually fire. timeout=None bypasses them entirely — a hung
    # cloud lane would block the whole hunt indefinitely.
    try:
        return oracle_llm.complete(
            task, system, task_type="reflex", timeout=360, no_cloud=no_cloud
        )
    except RuntimeError as e:
        return f"[no backend produced output] {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Cloud escalation — via the backend router only (no direct bypass)
# ─────────────────────────────────────────────────────────────────────────────



def _cloud_escalate(
    seam_card: str,
    target: str,
    provider: str = "auto",
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
    mindset_compact: Optional[str] = None,
) -> str:
    """
    Send a single seam card through the backend router (task "poc") for
    deep PoC synthesis. Returns the expanded analysis with a
    submission-ready finding.

    provider: legacy name accepted for caller compatibility and ignored —
    lane choice is the router's configured multi-API policy (S5), never a
    hardcoded single-provider direct call. An explicit provider therefore
    changes nothing.
    no_cloud=True routes local-only (fail-closed when no local backend
    answers).
    mindset_system: fused mindset context (philosophy + TTP + scope wall);
    when given it replaces the base prompt so every model call reasons from
    the same grounding. mindset_compact: lean reporting prompt for the
    router leg — the full system starves 16k local models (hunt-4c).
    """
    import oracle_llm

    effective_no_cloud = bool(no_cloud or oracle_llm.no_cloud_enabled())

    system = mindset_system or _load_oracle_prompt(
        voice=False, query=seam_card
    )  # clean technical register for PoC
    router_system = mindset_compact or system

    task = textwrap.dedent(
        f"""
        Target: {target}

        A local model identified the following candidate seam.
        Your job:
        1. Verify the logic — is the binary conflict real?
        2. If real, write the full PoC (curl chain or script) that proves it.
        3. Write the submission-ready finding in this format:
           - Title: [one line]
           - Severity: [Critical/High/Medium/Low]
           - Assertion A: [claim]
           - Assertion B: [wire behavior]
           - Steps to reproduce: [numbered, minimal]
           - PoC: [curl/script]
           - Impact: [one paragraph]
           - Remediation: [one sentence]
        4. If the seam is NOT real (false positive), say so clearly and why.

        --- CANDIDATE SEAM ---
        {seam_card}
    """
    ).strip()

    # Every lane flows through the router (task_type "poc") — no direct
    # single-provider bypass exists anymore.
    try:
        return oracle_llm.complete(
            task, router_system, task_type="poc", no_cloud=effective_no_cloud
        )
    except RuntimeError as e:
        return f"[no backend produced a PoC] {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Interactive verify — run the check, confirm the seam is real
# ─────────────────────────────────────────────────────────────────────────────

# ── Check execution hardening ────────────────────────────────────────────────
# _run_check previously used shell=True on model-derived command strings:
# remote command execution via prompt injection. The shell is gone now —
# commands are parsed with shlex and executed as argv with shell=False, the
# binary is allow-listed, and anything else fails closed.

_SHELL_METACHARS = (";", "|", "`", "$(", "&", "&&")
_ALLOWED_CHECK_BINS = ("curl", "slither", "forge", "cast")
# Lens witness tier (2026-10-28 two-tier evidence decision): deterministic
# template mints only — a card stamped check_provenance="lens" by
# oracle_seam_templates may run a read-only grep over the downloaded target
# source inside the workspace. Never tokens from model prose: a check string
# that came out of an LLM stays on the strict curl/web3 list.
_LENS_CHECK_BINS = ("grep",)
_SAFE_GREP_FLAGS = {"-n", "-i", "-w", "-c", "-E", "-F", "-l"}
_SAFE_CURL_FLAGS = {
    "-i",
    "-I",
    "-s",
    "-S",
    "--silent",
    "--show-error",
}
_SAFE_CURL_VALUE_FLAGS = {
    "--connect-timeout",
    "--max-time",
    "-H",
    "--header",
    "-X",
    "--request",
}
_MUTATING_CURL_VALUE_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--json",
}
_MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_SAFE_SLITHER_FLAGS = {
    "--json",
    "--detect",
    "--solc-select",
    "--compile-force-framework",
    "--checklist",
    "--filter-paths",
    "--exclude-informational",
    "--exclude-low",
    "--exclude-medium",
    "--exclude-high",
}
_SAFE_FORGE_FLAGS = {
    "test",
    "build",
    "inspect",
    "--match-test",
    "-mt",
    "--match-contract",
    "-mc",
    "--match-path",
    "-mp",
    "--root",
    "-vvv",
    "-vvvv",
    "--gas-report",
}
_SAFE_CAST_FLAGS = {
    "call",
    "balance",
    "code",
    "storage",
    "--rpc-url",
    "--block",
    "--from",
}


def _sanitize_header_val(val: str) -> str:
    """Strip CR/LF and quotes so auth/cookie values can't break header quoting."""
    from oracle_foundation import sanitize_header_val as _san

    return _san(val)


def _redact_creds(check_cmd: str) -> str:
    """Redact credential-bearing material for display/logging/model prompts.

    Covers Authorization/Cookie headers via -H/--header in single quotes,
    double quotes, or bare; -u/--user user:pass; and common secret query
    params (?api_key=, &token=, ...). Display-only: the executed command
    still carries the real values (moved out of argv, see
    _extract_secret_headers).
    """
    # Header injection stores shell-escaped quotes in the command string.
    # Normalize them for display before applying quote-aware redaction.
    red = (check_cmd or "").replace(r"\"", '"').replace(r"\'", "'")
    # Quoted header values: -H "Authorization: Bearer xxx" (spaces allowed
    # inside the quotes, so match up to the closing quote).
    red = re.sub(
        r"((?:-H|--header)\s*[\"'](?:Authorization|Cookie):\s*)[^\"']+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    # Bare header values: -H Authorization:Bearer_xxx
    red = re.sub(
        r"((?:-H|--header)\s+(?:Authorization|Cookie):\s*)\S+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    # -u user:pass / --user user:pass
    red = re.sub(
        r"((?:-u|--user)\s+)[^\"'\s]+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    # Secret-ish query params: ?api_key=.. &token=.. etc.
    red = re.sub(
        r"([?&](?:api_key|apikey|access_token|auth_token|client_secret|token|secret|key|auth)=)[^&\"'\s]+",
        r"\1[REDACTED]",
        red,
        flags=re.IGNORECASE,
    )
    return red


def _redact_known_secrets(text: str, secrets: List[str]) -> str:
    """Scrub known credential values (and derived reflections) from text.

    Used when a server reflects our injected auth/cookie back: exact
    values, individual cookie-pair values, and URL-encoded forms are
    replaced before output is displayed, sent to a model, or written
    to a report. Values shorter than 4 chars are skipped, and cookie
    *names* survive — only secret values scrub (S6 residual closure;
    arbitrary transforms like base64 of combined strings remain out
    of reach and are covered by never sending raw wire output onward
    unfiltered at higher layers).
    """
    red = text or ""
    variants: List[str] = []
    for s in secrets or []:
        if not s:
            continue
        bases = [str(s)]
        # Individual cookie values: "sid=tok; theme=dark" -> "tok".
        for pair in str(s).split(";"):
            if "=" in pair:
                bases.append(pair.split("=", 1)[1].strip())
        for b in bases:
            variants.append(b)
            quoted = urllib.parse.quote(b, safe="")
            if quoted != b:
                variants.append(quoted)
    for v in variants:
        if v and len(v) >= 4:
            red = red.replace(v, "[REDACTED]")
    return red


def _extract_secret_headers(argv: List[str]) -> Optional[str]:
    """Move Authorization/Cookie -H values out of argv into a 0600 curl -K file.

    Subprocess argv is visible via /proc, so credential header values must
    never ride in argv. Extracted headers are written (mode 0600) to a temp
    curl config file and referenced with `-K <path>` instead. Returns the
    config path — the caller must delete it after the run — or None when
    there was nothing to extract. Only applies to curl; the other
    allow-listed binaries never receive injected credentials.

    Raises ValueError when a secret value contains CR/LF: the value is
    written into a line-oriented config file, so a newline would break out
    into a new curl directive (arbitrary file write). The caller fails
    closed on it.
    """
    if not argv or os.path.basename(argv[0]) != "curl":
        return None
    secret_lines: List[str] = []
    filtered: List[str] = []
    i, extracted = 0, False
    while i < len(argv):
        a = argv[i]
        if (
            a in ("-H", "--header")
            and i + 1 < len(argv)
            and re.match(r"(?i)^(authorization|cookie)\s*:", argv[i + 1])
        ):
            if "\r" in argv[i + 1] or "\n" in argv[i + 1]:
                raise ValueError("secret header value contains CR/LF")
            esc = argv[i + 1].replace("\\", "\\\\").replace('"', '\\"')
            secret_lines.append(f'header = "{esc}"')
            extracted = True
            i += 2
            continue
        filtered.append(a)
        i += 1
    if not extracted:
        return None
    fd, path = tempfile.mkstemp(prefix="oracle_hdr_", suffix=".cfg")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(secret_lines) + "\n")
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        return None
    argv[:] = filtered[:1] + ["-K", path] + filtered[1:]
    return path


def _attribution_curl_argv(argv: List[str]) -> List[str]:
    """Insert the mandatory program-attribution header into curl argvs.

    Tinder BBP Program Terms (2026-10-21, live policy fetch): ``Include
    the HTTP header ``x-hackerone: <your_hackerone_username>`` on all
    testing traffic``. Runs only AFTER the allow-list/metachar gate, so
    the appended pair is inert to it (constant value from env, strict
    regex-validated username). No env or an existing x-hackerone header
    (case-insensitive) = no-op, never duplicated.
    """
    if not argv or argv[0].rsplit("/", 1)[-1] != "curl":
        return argv
    user = (os.environ.get("HACKERONE_USERNAME") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,48}", user or ""):
        return argv
    for tok in argv:
        if tok.lower().strip(" '\"") .startswith("x-hackerone"):
            return argv
    return argv + ["-H", f"x-hackerone: {user}"]


def _run_check(
    check_cmd: str,
    timeout: int = 30,
    is_testnet: bool = False,
    provenance: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Execute the reproducible check command from a seam card.
    The shell is NEVER invoked: the command is parsed with shlex and run as
    argv with shell=False. The binary must be allow-listed and every token
    validated; anything else fails closed. Returns (returncode, stdout, stderr).

    provenance="lens" additionally admits the read-only witness bins above —
    but only for deterministic template/carved mints, never model-authored
    text (prompt-injection remote-execution boundary, S6 family).

    Metachar gate is token-position-aware (Phase 3): a blanket raw-string
    scan confused DATA with CONTROL and blocked all authenticated hunting
    (Cookie values contain ';', query strings and POST bodies contain '&').
    Since shell=False, no argv content can reach a shell — so metachars
    inside curl URL tokens and consumed flag values are inert data and pass,
    while metachars in structural position (bare tokens, non-curl
    positionals) keep failing closed via the per-token validation below.
    """
    from oracle_foundation import strip_safe_truncation as _strip_trunc

    check_cmd = _strip_trunc(check_cmd)
    try:
        argv = shlex.split(check_cmd)
    except ValueError:
        return 1, "", "[BLOCKED] check rejected: unparseable command"
    if not argv:
        return 1, "", "[BLOCKED] check rejected: empty command"
    bins = _ALLOWED_CHECK_BINS + (_LENS_CHECK_BINS if provenance == "lens" else ())
    if os.path.basename(argv[0]) not in bins:
        return 1, "", "[BLOCKED] check rejected: binary not allow-listed"
    bin_name = os.path.basename(argv[0])
    if bin_name == "curl":
        i = 1
        while i < len(argv):
            arg = argv[i]
            if (
                arg in _SAFE_CURL_FLAGS
                or arg.startswith("http://")
                or arg.startswith("https://")
            ):
                i += 1
                continue
            if arg in _SAFE_CURL_VALUE_FLAGS and i + 1 < len(argv):
                value = argv[i + 1]
                if arg in ("-X", "--request"):
                    m = value.upper()
                    if is_testnet:
                        if (
                            m not in ("GET", "HEAD", "OPTIONS")
                            and m not in _MUTATING_HTTP_METHODS
                        ):
                            return (
                                1,
                                "",
                                f"[BLOCKED] check rejected: unsupported HTTP method '{value}'",
                            )
                    else:
                        if m not in ("GET", "HEAD", "OPTIONS"):
                            return 1, "", "[BLOCKED] check rejected: unsafe HTTP method"
                i += 2
                continue
            if arg in _MUTATING_CURL_VALUE_FLAGS and i + 1 < len(argv):
                if not is_testnet:
                    return 1, "", "[BLOCKED] check rejected: unsafe HTTP method"
                val = argv[i + 1]
                if val.startswith("@"):
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: file upload via @ not allowed",
                    )
                if arg == "--data-urlencode" and "@" in val:
                    # curl reads name@file mid-value here (not just a
                    # leading @): the file lands in the POST body. Plain -d
                    # treats @ as literal data, so this stays narrow.
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: file upload via @ not allowed",
                    )
                i += 2
                continue
            if any(arg.startswith(f"{f}=") for f in _MUTATING_CURL_VALUE_FLAGS):
                if not is_testnet:
                    return 1, "", "[BLOCKED] check rejected: unsafe HTTP method"
                val = arg.split("=", 1)[1]
                if val.startswith("@"):
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: file upload via @ not allowed",
                    )
                if arg.split("=", 1)[0] == "--data-urlencode" and "@" in val:
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: file upload via @ not allowed",
                    )
                i += 1
                continue
            return 1, "", f"[BLOCKED] check rejected: unsafe curl argument '{arg}'"
    elif bin_name == "grep":
        # Read-only witness: flags limited to the safe set, no shell
        # metacharacters in pattern or path tokens, no file-list flags.
        for arg in argv[1:]:
            if arg.startswith("-"):
                if arg not in _SAFE_GREP_FLAGS:
                    return 1, "", f"[BLOCKED] check rejected: unsafe grep flag '{arg}'"
                continue
            if any(m in arg for m in _SHELL_METACHARS):
                return 1, "", "[BLOCKED] check rejected: shell metacharacters not allowed"
    elif bin_name == "slither":
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in _SAFE_SLITHER_FLAGS:
                if arg in (
                    "--json",
                    "--detect",
                    "--solc-select",
                    "--compile-force-framework",
                    "--filter-paths",
                ):
                    if i + 1 >= len(argv):
                        return (
                            1,
                            "",
                            f"[BLOCKED] check rejected: missing value for {arg}",
                        )
                    i += 2
                    continue
                i += 1
                continue
            if not arg.startswith("-"):
                if any(m in arg for m in _SHELL_METACHARS):
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: shell metacharacters not allowed",
                    )
                i += 1
                continue
            return 1, "", f"[BLOCKED] check rejected: unsafe slither argument '{arg}'"
    elif bin_name == "forge":
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in _SAFE_FORGE_FLAGS:
                if arg in (
                    "--match-test",
                    "-mt",
                    "--match-contract",
                    "-mc",
                    "--match-path",
                    "-mp",
                    "--root",
                ):
                    if i + 1 >= len(argv):
                        return (
                            1,
                            "",
                            f"[BLOCKED] check rejected: missing value for {arg}",
                        )
                    i += 2
                    continue
                i += 1
                continue
            if not arg.startswith("-"):
                if any(m in arg for m in _SHELL_METACHARS):
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: shell metacharacters not allowed",
                    )
                i += 1
                continue
            return 1, "", f"[BLOCKED] check rejected: unsafe forge argument '{arg}'"
    elif bin_name == "cast":
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in _SAFE_CAST_FLAGS:
                if arg in ("--rpc-url", "--block", "--from"):
                    if i + 1 >= len(argv):
                        return (
                            1,
                            "",
                            f"[BLOCKED] check rejected: missing value for {arg}",
                        )
                    i += 2
                    continue
                i += 1
                continue
            if not arg.startswith("-"):
                if any(m in arg for m in _SHELL_METACHARS):
                    return (
                        1,
                        "",
                        "[BLOCKED] check rejected: shell metacharacters not allowed",
                    )
                i += 1
                continue
            return 1, "", f"[BLOCKED] check rejected: unsafe cast argument '{arg}'"
    # Credential containment: pull Authorization/Cookie header values out of
    # argv (visible via /proc) into a 0600 curl -K config file.
    try:
        cfg_path = _extract_secret_headers(argv)
    except ValueError:
        return 1, "", "[BLOCKED] check rejected: secret header contains newline"
    if bin_name == "curl":
        # Program-attribution compliance (x-hackerone) — post-gate so the
        # appended pair is outside the allow-list sweep by construction.
        argv = _attribution_curl_argv(argv)
    foundry_bin = os.path.expanduser("~/.foundry/bin")
    phantom_bin = os.path.expanduser("~/PhantomCore/PhantomCore/bin")
    exec_env = {
        **os.environ,
        "PATH": f"{foundry_bin}:{phantom_bin}:{GO_BIN}:{os.environ.get('PATH', '')}",
    }
    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=exec_env,
        )
        if bin_name == "slither":
            combined = (result.stdout + "\n" + result.stderr).strip()
            return result.returncode, combined, result.stderr.strip()
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"[timeout after {timeout}s]"
    except Exception as e:
        return 1, "", str(e)
    finally:
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass


def _execute_confirm(
    seam: Dict,
    check: str,
    is_testnet: bool = False,
    timeout_ms: int = 15000,
    scope_gate: Any = None,
) -> Tuple[int, str, str]:
    """Route a seam's check to its confirmer (wall gap 4.1/4.3).

    curl by default. Claims whose proof needs more than one HTTP leg
    execute in their engine instead — each returns (rc, stdout, stderr)
    shaped like ``curl -i`` output so downstream verify gates apply
    unchanged. The engine fetches ONLY the scope-approved check URL.
    """
    claim = (seam or {}).get("claim_type", "")
    if claim == "dom-xss-rendered-differential":
        from oracle_rendered import confirm_rendered_output

        return confirm_rendered_output(
            check, (seam or {}).get("render_marker") or None, timeout_ms
        )
    if claim == "csrf-form-replay-sqli":
        from oracle_harvest import confirm_form_replay

        return confirm_form_replay(
            check,
            (seam or {}).get("csrf_field") or None,
            scope_gate=scope_gate,
            allow_mutation=is_testnet,
        )
    return _run_check(
        check, is_testnet=is_testnet, provenance=(seam or {}).get("check_provenance")
    )


def _assess_response(
    check_cmd: str,
    stdout: str,
    stderr: str,
    seam: Dict,
    model: str = LOCAL_MODEL,
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
) -> str:
    """
    Deterministic evaluation first: if check output proves Assertion B directly,
    confirm it immediately. Otherwise, ask the model via the backend router.

    no_cloud=True forces local-only routing. mindset_system threads the fused
    mindset context (philosophy + TTP + scope wall) in front of the triager
    role so the verdict reasons from the same grounding as the reflex pass.
    """
    out_lower = (stdout + " " + stderr).lower()
    b_text = seam.get("assertion_b", "").lower()

    # Deterministic proofs & false-positive filters
    # 1. Sensitive data/config leaks on debug/admin endpoints
    if any(
        k in out_lower
        for k in ["aws_secret", "akia", "password", "secret", "debug_mode", "root:"]
    ) and any(w in check_cmd for w in ["debug", "config", "env", "metrics", ".git"]):
        return "CONFIRMED (deterministic) — Sensitive configuration or credential exposed in wire response."

    # 2. Known invariant breaks (e.g. coupon state or role headers)
    if (
        '"status": "authorized"' in out_lower
        or '"status": "discount_applied"' in out_lower
    ) and any(w in b_text for w in ["authorized", "discount", "role", "coupon"]):
        return "CONFIRMED (deterministic) — State transition or invariant violation verified on wire."

    # 3. Standard access control enforcement is NOT a vulnerability
    if any(
        code in out_lower
        for code in [
            "401 unauthorized",
            "403 forbidden",
            "access denied",
            "attention required! | cloudflare",
            "error 530",
            "status 401",
            "status 403",
            "http/1.1 401",
            "http/1.1 403",
            "http/2 401",
            "http/2 403",
        ]
    ):
        return "FALSE_POSITIVE — Target returned access denial (401/403/Cloudflare); authorization barrier is actively enforced."  # noqa: E501

    # 4. Standard 404 on normal checks is NOT a vulnerability unless explicitly asserting route deletion
    if (
        "404 not found" in out_lower
        or "http/1.1 404" in out_lower
        or "http/2 404" in out_lower
    ) and "404" not in b_text:
        return "FALSE_POSITIVE — Endpoint returned 404 Not Found."

    # 5. Public HTML landing page / SPA fallback on API endpoints is NOT a vulnerability
    if any(
        tag in out_lower for tag in ["<!doctype html", "<html", "<head>", "<title>"]
    ) and any(
        w in check_cmd
        for w in ["/api/", "/v1/", "/v2/", "/auth/", "/userinfo", "/graphql"]
    ):
        if not any(
            k in out_lower for k in ["aws_secret", "password", "token", "jwt", "apikey"]
        ):
            return "FALSE_POSITIVE — Target returned standard public HTML landing page/SPA fallback, not API data disclosure."  # noqa: E501

    # Triage via the backend router (route decides cloud vs local).
    # The fused mindset context (when threaded in) grounds the verdict in the
    # same philosophy + scope wall as the reflex pass; the triager role stays
    # last so the task framing is not lost inside the grounding.
    _triager_role = "You are a strict, senior bug bounty triager. Evaluate if the STDOUT objectively proves an actionable security vulnerability (Assertion B), or if it is a benign/false positive response (e.g., standard login page, normal 401/403 access denial, standard 404, or normal public content)."  # noqa: E501
    system = (
        (mindset_system + "\n\n---\n\n" + _triager_role)
        if mindset_system
        else _triager_role
    )
    # Credential containment: the triager reasons about the HTTP response and
    # the command shape — it must never receive our auth token / session
    # cookie. Redact credential-bearing material from the command shown.
    redacted_cmd = _redact_creds(check_cmd)
    prompt = textwrap.dedent(
        f"""
        Assess whether this HTTP check response PROVES a genuine security vulnerability or is a FALSE POSITIVE.

        SEAM:
        - Assertion A: {seam.get('assertion_a', '')}
        - Assertion B: {seam.get('assertion_b', '')}
        - Claimed Impact: {seam.get('impact', '')}

        COMMAND RUN:
        {redacted_cmd}

        HTTP RESPONSE / STDOUT:
        {stdout[:2000]}

        STRICT TRIAGE RULES:
        1. If the server returned 401 Unauthorized or 403 Forbidden blocking access, answer FALSE_POSITIVE.
        2. If the server returned normal public HTML (like a homepage or documentation) with HTTP 200, answer FALSE_POSITIVE.  # noqa: E501
        3. Only answer CONFIRMED if the response reveals private internal data, bypasses authentication, or proves an invariant violation.  # noqa: E501

        VERDICT (start with exactly one):
        CONFIRMED — [state exact proof in output]
        FALSE_POSITIVE — [state why it is benign or expected behavior]
        INCONCLUSIVE — [need more specific parameters]
    """
    ).strip()

    import oracle_llm

    try:
        return oracle_llm.complete(
            prompt, system, task_type="assess", timeout=None, no_cloud=no_cloud
        )
    except RuntimeError:
        return "INCONCLUSIVE — no backend available to assess this response."


def _vary_check(check: str) -> str:
    """Produce a fresh variation of a curl/wget check for a single retry.

    Appends a cache-buster query param to the first URL and rotates the
    User-Agent, so a retry is not a byte-identical repeat of a check that
    already came back INCONCLUSIVE. Returns the check unchanged when no
    variation is possible (the caller then skips the retry).
    """
    m = re.search(r'https?://[^\s"\']+', check)
    if not m:
        return check
    url = m.group(0)
    sep = "&" if "?" in url else "?"
    varied = check.replace(url, f"{url}{sep}oracle_retry=1", 1)
    if (
        varied.startswith("curl")
        and "-A " not in varied
        and "--user-agent" not in varied
    ):
        varied = re.sub(r"^(curl\s+)", r'\1-A "Oracle-Retry/1.0" ', varied, count=1)
    return varied


def _write_funnel_artifact(ws, confirmed, mined_wave1, followups_queued):
    """Build funnel counts and persist funnel.json into the workspace reports dir.

    Counts come from entry keys (det_verdict/kill_gate), not log scraping,
    so every hunt leaves a machine-checkable stage ledger. Best-effort I/O:
    a write failure warns but never fails the hunt.
    """
    from oracle_foundation import build_funnel_counts as _funnel_of

    funnel = _funnel_of(confirmed, mined_wave1, followups_queued)
    try:
        path = ws.reports_dir / "funnel.json"
        path.write_text(json.dumps(funnel, indent=2), encoding="utf-8")
    except OSError as e:
        _warn(f"funnel.json not written: {e}")
        return None
    _info(
        f"Funnel: mined={funnel['mined_wave1']} "
        f"followups={funnel['followups_queued']} "
        f"attempted={funnel['verify_attempted']} "
        f"det_reject={funnel['det_rejected']} "
        f"postgate={sum(funnel['postgate_killed'].values())} "
        f"final={funnel['final_confirmed']}"
    )
    return path


def _lens_prompt_for(
    seam: Dict,
    default: Optional[str],
    by_lens: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """System prompt for a downstream model call on one seam.

    The call reasons in the lens that produced the seam (mitre cards get
    the technique-indexed prompt, paradox cards the corpus prompt) instead
    of every seam inheriting the paradox prompt regardless of origin.
    Deterministic (seam) cards and unknown origins fall back to `default`,
    the shared downstream context. by_lens=None keeps the old behavior
    (default for all) — standalone paths pass none.
    """
    if not by_lens:
        return default
    lens = (seam.get("mindset") or "").strip().lower()
    if not lens:
        from oracle_mindsets import mindset_of_origin

        lens = mindset_of_origin(seam.get("origin"))
    return by_lens.get(lens, default)


def verify_seams(
    seams: List[Dict],
    target: str,
    recon_dir: Path,
    model: str = LOCAL_MODEL,
    auto: bool = False,
    scope_gate: Optional["ProgramScopeGate"] = None,
    is_testnet: bool = False,
    auth: Optional[str] = None,
    cookie: Optional[str] = None,
    no_cloud: bool = False,
) -> Dict[int, Dict]:
    """
    Interactively verify each seam:
    1. Show the seam card
    2. Run the reproducible check command
    3. Show raw response
    4. Verdict deterministically — CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE
    5. Ask user to confirm (or auto-confirm if --auto)
    6. Return dict of confirmed seams with their evidence

    Verification is deterministic (the wire decides, not a model), so it
    takes no mindset prompt: the old mindset_system parameter was dead
    (accepted, never read) and was cut. Model reasoning downstream (PoC,
    escalation, sweep triage) picks its prompt per seam lens via
    _lens_prompt_for. no_cloud=True forces local-only model routing
    wherever a model leg still runs.

    Returns: {seam_n: {"seam": ..., "check": ..., "output": ..., "verdict": ...,
              "confirmed": bool, "inconclusive": bool, "retried": bool,
              "det_verdict": "CONFIRMED"|"REJECTED"|None,
              "kill_gate": str|None}}
    INCONCLUSIVE verdicts are retried once with a varied check and then
    preserved (never dropped). Check-less and operator-skipped seams are
    recorded as CANDIDATE entries rather than silently skipped.
    """
    confirmed: Dict[Any, Dict[str, Any]] = {}
    _transport_fails = 0

    for s in seams:
        # Dead-target circuit breaker (hunt-4a: 319 checks burned
        # against a dead target, all curl exit 7). Ten consecutive
        # transport failures means the target is gone, not the cards.
        if _transport_fails >= 10:
            _remaining_seams = [x for x in seams if x.get("n") not in confirmed]
            _banner(
                f"TARGET UNREACHABLE — aborting verify "
                f"({_transport_fails} consecutive transport failures; "
                f"{len(_remaining_seams)} seam(s) left unexecuted)"
            )
            # Never silently dropped: record each unexecuted seam as a CANDIDATE
            # so the report pipeline accounts for it (matches the check-less and
            # operator-skip paths below).
            for _rs in _remaining_seams:
                confirmed[_rs["n"]] = {
                    "seam": _rs,
                    "check": _rs.get("check", ""),
                    "output": "",
                    "verdict": "CANDIDATE — target unreachable; never executed (circuit breaker)",
                    "confirmed": False,
                    "inconclusive": False,
                    "retried": False,
                    "check_missing": False,
                    "det_verdict": None,
                    "kill_gate": "target_unreachable",
                }
            break
        check = s.get("check", "").strip()
        if not check:
            # Never silently dropped: a check-less seam is a CANDIDATE that was
            # never executed, recorded so the report pipeline can show it.
            _warn(f"Seam {s['n']} has no check command — recording as candidate")
            confirmed[s["n"]] = {
                "seam": s,
                "check": "",
                "output": "",
                "verdict": "CANDIDATE — no check command supplied by model; never executed",
                "confirmed": False,
                "inconclusive": False,
                "retried": False,
                "check_missing": True,
                "det_verdict": None,
                "kill_gate": "check_missing",
            }
            continue

        # Resolve target base URL if model used placeholder, relative URL, or localhost leak
        is_external_target = not any(
            h in str(target)
            for h in ["127.0.0.1", "localhost", "0.0.0.0"]  # nosec B104
        )
        has_local_leak = is_external_target and (
            "127.0.0.1" in check or "localhost" in check
        )

        # Gate is built BEFORE the URL rewrite so leak-correction can ask it:
        # a program scoped to localhost is local — its URLs are never "fixed".
        gate = scope_gate or ProgramScopeGate(
            _scope_from_programs(target), target_fallback=target
        )
        _lab_local = gate.is_in_scope("http://localhost/")[0]
        has_local_leak = has_local_leak and not _lab_local

        if (
            "target.example.com" in check
            or "example.com" in check
            or has_local_leak
            or ("https://" not in check and "http://" not in check)
        ):
            live_f = recon_dir / "clean_live_hosts.txt"
            if not live_f.exists() or live_f.stat().st_size == 0:
                live_f = recon_dir / "live_hosts.txt"
            target_host = ""
            if live_f.exists() and live_f.stat().st_size > 0:
                lines = [ln for ln in live_f.read_text().splitlines() if ln.split()]
                if lines:
                    target_host = lines[0].split()[0].rstrip("/")
            if not target_host:
                target_host = f"https://{target}"

            if has_local_leak:
                check = re.sub(
                    r"https?://(?:127\.0\.0\.1|localhost)(?::\d+)?", target_host, check
                )
            if "target.example.com" in check or "example.com" in check:
                check = re.sub(
                    r"https?://(?:target\.)?example\.com(?::\d+)?", target_host, check
                )
            elif re.search(r"curl\s+.*?\s+(/[^\s]+)", check):
                check = re.sub(
                    r"(curl\s+.*?)\s+(/[^\s]+)", rf"\1 {target_host}\2", check
                )
            elif check.startswith("curl") and not re.search(r"https?://", check):
                check = f"{check} {target_host}"

        # ── Safe-truncation strip: `| head -N` / `| tail -N` cannot execute
        # (no shell ever runs) but would trip Op1. Strip once and rewrite the
        # card so Gates see the executed check. Compound pipes still drop.
        from oracle_foundation import strip_safe_truncation as _strip_trunc

        check = _strip_trunc(check)
        s["check"] = check

        # ── Op1 shape check: malformed cards never execute. A broken
        # instrument is not a rejected premise — no reframes breed here.
        from oracle_foundation import validate_card_shape as _shape_of

        _shape_reason = _shape_of({**s, "check": check})
        if _shape_reason is not None:
            _warn(f"Op1: DROPPED Seam {s['n']} — {_shape_reason}")
            confirmed[s["n"]] = {
                "seam": s,
                "check": check,
                "output": f"[MALFORMED CARD] {_shape_reason}",
                "verdict": f"FALSE_POSITIVE — Op1: {_shape_reason}",
                "confirmed": False,
                "det_verdict": None,
                "kill_gate": "op1_shape",
            }
            continue

        # ── Pre-Flight Scope & Safety Gate ─────────────────────────────────────
        # (gate was built above, before the URL rewrite, so leak-correction
        # could consult it — reuse it here, do not rebuild.)
        allowed, safe_cmd, reason = gate.validate_check(check, is_testnet=is_testnet)
        if not allowed:
            _warn(f"Scope Gate: DROPPED Seam {s['n']} probe — {reason}")
            confirmed[s["n"]] = {
                "seam": s,
                "check": check,
                "output": f"[SCOPE GATE BLOCKED] {reason}",
                "verdict": f"FALSE_POSITIVE — Scope Gate: {reason}",
                "confirmed": False,
                "det_verdict": None,
                "kill_gate": "scope_gate",
            }
            continue
        if safe_cmd != check:
            _info(f"Scope Gate: {reason}")
            check = safe_cmd

        # ── Auth & Cookie Injection ───────────────────────────────────────────
        # Header values are sanitized (no CR/LF/quotes) so a credential can't
        # break out of the -H quoting; the check string itself is never shelled.
        # The exact injected values are tracked so a server that reflects them
        # back can be scrubbed from the output (see below).
        injected_secrets: List[str] = []
        # C2: resolve stored IDOR placeholders at execution time only. The
        # resolved values ride into _run_check (which moves them into a 0600
        # -K config) and are tracked for output scrubbing. Unresolvable
        # placeholders fail closed — never executed.
        _harness_for_placeholders = None
        if s.get("origin") == "dual-account-idor" and any(
            p in check
            for p in (
                "__ORACLE_ACCOUNT_A_AUTH__",
                "__ORACLE_ACCOUNT_A_COOKIES__",
                "__ORACLE_ACCOUNT_B_AUTH__",
                "__ORACLE_ACCOUNT_B_COOKIES__",
            )
        ):
            try:
                from oracle_auth_session import DualAccountHarness as _DAH
                from oracle_auth_session import substitute_probe_placeholders as _sub

                _sess = recon_dir / "sessions.json"
                if _sess.is_file():
                    _harness_for_placeholders = _DAH.from_session_file(_sess)
                    check, _ph_secrets = _sub(
                        check, _harness_for_placeholders, as_account="b"
                    )
                    injected_secrets.extend(_ph_secrets)
                    if any(
                        p in check
                        for p in (
                            "__ORACLE_ACCOUNT_A_AUTH__",
                            "__ORACLE_ACCOUNT_A_COOKIES__",
                            "__ORACLE_ACCOUNT_B_AUTH__",
                            "__ORACLE_ACCOUNT_B_COOKIES__",
                        )
                    ):
                        _warn(
                            f"Seam {s['n']} has unresolvable credential placeholders — recording as candidate"
                        )
                        confirmed[s["n"]] = {
                            "seam": s,
                            "check": check,
                            "output": "[CREDENTIAL PLACEHOLDER UNRESOLVED] no live secret available — never executed",
                            "verdict": "CANDIDATE — credential placeholder unresolvable; never executed",
                            "confirmed": False,
                            "inconclusive": False,
                            "retried": False,
                            "check_missing": True,
                            "det_verdict": None,
                            "kill_gate": "cred_unresolved",
                        }
                        continue
            except Exception as _e:
                _warn(
                    f"Seam {s['n']} placeholder resolution failed ({_e}) — recording as candidate"
                )
                confirmed[s["n"]] = {
                    "seam": s,
                    "check": check,
                    "output": f"[CREDENTIAL PLACEHOLDER ERROR] {_e} — never executed",
                    "verdict": "CANDIDATE — credential placeholder error; never executed",
                    "confirmed": False,
                    "inconclusive": False,
                    "retried": False,
                    "check_missing": True,
                    "det_verdict": None,
                    "kill_gate": "cred_error",
                }
                continue
        if auth and "authorization:" not in check.lower():
            auth_val = (
                auth
                if auth.lower().startswith(("bearer ", "basic "))
                else f"Bearer {auth}"
            )
            auth_val = _sanitize_header_val(auth_val)
            injected_secrets.append(auth_val)
            check = re.sub(r"^(curl\s+)", rf'\1-H "Authorization: {auth_val}" ', check)
        if cookie and "cookie:" not in check.lower():
            cookie_val = _sanitize_header_val(cookie)
            injected_secrets.append(cookie_val)
            check = re.sub(r"^(curl\s+)", rf'\1-H "Cookie: {cookie_val}" ', check)

        _banner(f"Verify Seam {s['n']}: {s.get('reflex', '?')[:40]}")

        if RICH:
            console.print(
                Panel(
                    f"[bold]A:[/bold] {s['assertion_a']}\n"
                    f"[bold]B:[/bold] {s['assertion_b']}\n"
                    f"[bold]Impact:[/bold] {s['impact']}\n"
                    f"[bold]MITRE:[/bold] {s.get('mitre', '?')}",
                    title=f"Seam {s['n']}",
                )
            )
        else:
            print(f"  A: {s['assertion_a']}")
            print(f"  B: {s['assertion_b']}")
            print(f"  Impact: {s['impact']}")

        # Confirm before running (credentials redacted in what we display)
        if not auto:
            try:
                ans = (
                    input(f"\n  Run check? [{_redact_creds(check)[:80]}] (y/n/skip): ")
                    .strip()
                    .lower()
                )
            except (EOFError, KeyboardInterrupt):
                ans = "n"
            if ans not in ("y", "yes", ""):
                _info("Skipped.")
                confirmed[s["n"]] = {
                    "seam": s,
                    "check": check,
                    "output": "",
                    "verdict": "CANDIDATE — skipped by operator; never executed",
                    "confirmed": False,
                    "inconclusive": False,
                    "retried": False,
                    "det_verdict": None,
                    "kill_gate": "op_skip",
                    "skipped": True,
                }
                continue

        _info(f"Running: {_redact_creds(check)[:100]}")
        rc, stdout, stderr = _execute_confirm(
            s, check, is_testnet=is_testnet, scope_gate=gate
        )
        if rc in (6, 7, 28) or stderr.startswith("[timeout"):
            _transport_fails += 1
        else:
            _transport_fails = 0

        # Credential containment: if the server reflected our injected
        # auth/cookie values in its response, scrub the exact values here —
        # before display, model assessment, storage, or report writing.
        stdout = _redact_known_secrets(stdout, injected_secrets)
        stderr = _redact_known_secrets(stderr, injected_secrets)

        # Show output
        output = stdout or stderr or "(no output)"
        if RICH:
            console.print(
                Panel(
                    output[:2000] + ("…" if len(output) > 2000 else ""),
                    title=f"Check output (exit {rc})",
                )
            )
        else:
            print(f"\n--- Check output (exit {rc}) ---")
            print(output[:2000])
            print("---")

        # ── Deterministic verdict: no debate about reality ──────────────────
        # The seam card is a test case (Assertion A vs B + Expected line).
        # Code runs the test. CONFIRMED or REJECTED — the wire decides,
        # not a model assessment, not a debate. Human review happens later
        # at the report stage (submit/skip = impact judgment, not reality).
        _info("Verifying deterministically…")
        from oracle_deterministic import (
            verify_seam_card,
            extract_status_from_curl_output,
        )
        from oracle_foundation import reframe_rejected

        _recon_urls: List[str] = []
        for _rf in ("clean_live_hosts.txt", "live_hosts.txt", "known_urls.txt"):
            _rp = recon_dir / _rf
            if _rp.exists():
                for _line in _rp.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines():
                    _line = _line.strip()
                    if not _line or _line.startswith("#"):
                        continue
                    _recon_urls.append(_line.split()[0])
                    _recon_urls.extend(re.findall(r"https?://[^\s'\"<>`]+", _line))
        _obs_status = extract_status_from_curl_output(stdout)
        try:
            _dverdict = verify_seam_card(
                s,
                _recon_urls,
                scope_gate=gate,
                status=_obs_status,
                body=stdout,
            )
        except Exception as e:
            _dverdict = {
                "verdict": "REJECTED",
                "reason": f"Seam {s.get('n', '?')}: verifier errored ({e}) — failing closed",
                "url": "",
                "expected": {},
                "observed": {},
            }
        verdict = f"{_dverdict['verdict']} — {_dverdict['reason']}"
        if RICH:
            color = "green" if _dverdict["verdict"] == "CONFIRMED" else "red"
            console.print(f"\n[{color}]Deterministic verdict:[/{color}] {verdict}")
        else:
            print(f"\nDeterministic verdict: {verdict}")

        is_confirmed = _dverdict["verdict"] == "CONFIRMED"
        is_inconclusive = False
        retried = False
        _kill: Optional[str] = None  # funnel tag: which post-gate killed this seam

        # ── Gate 6a: variation differential (reframe cards). A "varied"
        # request proves nothing unless its wire output DIFFERS from the
        # unvaried parent's recorded output. (hunt-2: 25 vacuous
        # header-spoof CONFIRMEDs — 401 byte-identical with/without header.)
        # ── Gate 6b: SPA-fallback control (unvaried HTML-200 cards). A bare
        # GET returning an app shell is not an exposed file/route: refetch a
        # random sibling path — identical (modulo digits) means the server
        # 200s everything. (hunt-2: /.env + 6 siblings on the juice shell.)
        if is_confirmed:
            from oracle_foundation import build_spa_control as _spa_ctl
            from oracle_foundation import grade_strength as _grade_of
            from oracle_foundation import build_variation_control as _var_ctl
            from oracle_foundation import build_spelling_twin as _twin_ctl
            from oracle_foundation import normalize_wire_output as _norm
            from oracle_deterministic import VARIATION_CLAIM_RES as _var_res
            from oracle_deterministic import VARIATION_CLAIM_PHRASES as _var_phr

            _b_low = str(s.get("assertion_b", "")).lower()

            if s.get("reframe_transform"):
                _base = confirmed.get(s.get("reframe_of"), {}).get("output", "")
                if not _base or _base == "(no output)":
                    is_confirmed = False
                    _kill = "6a_nobaseline"
                    verdict = (
                        f"REJECTED — Seam {s['n']}: variation has no recorded "
                        f"baseline (parent #{s.get('reframe_of')} never executed)"
                    )
                else:
                    _st_now = extract_status_from_curl_output(stdout)
                    _st_base = extract_status_from_curl_output(str(_base))
                    if _st_now == _st_base and _norm(output) == _norm(str(_base)):
                        is_confirmed = False
                        _kill = "6a_noeffect"
                        verdict = (
                            f"REJECTED — Seam {s['n']}: variation had no "
                            f"observable effect (output identical to unvaried baseline)"
                        )
            elif (
                _obs_status == 200
                and not _grade_of({**s, "check": check}).startswith("strong")
                and re.search(r"<!doctype html|<html[\s>]", output[:2000], re.I)
            ):
                _ctl = _spa_ctl(check)
                if _ctl:
                    _c_rc, _c_out, _c_err = _run_check(_ctl, is_testnet=is_testnet)
                    _c_out = _redact_known_secrets(_c_out, injected_secrets)
                    if extract_status_from_curl_output(_c_out) == 200 and _norm(
                        _c_out
                    ) == _norm(output):
                        is_confirmed = False
                        _kill = "6b_spa"
                        verdict = (
                            f"REJECTED — Seam {s['n']}: SPA fallback (random "
                            f"sibling path returns byte-identical 200)"
                        )

            # ── Gate 7-B1: original-card variation differential. Gate 6a
            # covers reframes (parent baseline recorded); an ORIGINAL
            # card with an executed header variation needs its unvaried
            # control run now (hunt-3 seam 69: X-Original-Role CONFIRMED
            # with no control — the header did nothing).
            if (
                is_confirmed
                and not s.get("reframe_transform")
                and (
                    any(p in _b_low for p in _var_phr)
                    or any(r.search(_b_low) for r in _var_res)
                )
            ):
                _vctl = _var_ctl(
                    check, f"{s.get('assertion_b', '')} {s.get('impact', '')}"
                )
                if _vctl:
                    _v_rc, _v_out, _v_err = _run_check(_vctl, is_testnet=is_testnet)
                    _v_out = _redact_known_secrets(_v_out, injected_secrets)
                    _v_disp = _v_out or _v_err or "(no output)"
                    if extract_status_from_curl_output(
                        _v_out
                    ) == extract_status_from_curl_output(stdout) and _norm(
                        _v_disp
                    ) == _norm(
                        output
                    ):
                        is_confirmed = False
                        _kill = "7B1_noeffect"
                        verdict = (
                            f"REJECTED — Seam {s['n']}: variation had no "
                            f"observable effect (original-card control "
                            f"identical to varied request)"
                        )

            # ── Gate 7-C: spelling-twin differential. A path-confusion
            # claim quotes two spellings but the check fetches one —
            # fetch the twin and require a difference (hunt-3 seam 7:
            # single public-200 confirmed a "middleware binds one only"
            # story that was never tested).
            if is_confirmed and not s.get("reframe_transform"):
                _c_low = f"{_b_low} {str(s.get('impact', '')).lower()}"
                if (
                    "spelling" in _c_low
                    or "trailing slash" in _c_low
                    or "case-sensitive" in _c_low
                    or "case sensitivity" in _c_low
                    or "trailing dot" in _c_low
                ):
                    _tw = _twin_ctl(
                        check, f"{s.get('assertion_b', '')} {s.get('impact', '')}"
                    )
                    if _tw:
                        _tw_m = re.search(r"https?://[^\s'\"<>`]+", _tw)
                        try:
                            _tw_ok = (
                                gate.is_in_scope(_tw_m.group(0))[0]
                                if gate is not None and _tw_m
                                else True
                            )
                        except Exception:
                            _tw_ok = False
                        if _tw_ok:
                            _t_rc, _t_out, _t_err = _run_check(
                                _tw, is_testnet=is_testnet
                            )
                            _t_out = _redact_known_secrets(_t_out, injected_secrets)
                            _t_disp = _t_out or _t_err or "(no output)"
                            if extract_status_from_curl_output(
                                _t_out
                            ) == extract_status_from_curl_output(stdout) and _norm(
                                _t_disp
                            ) == _norm(
                                output
                            ):
                                is_confirmed = False
                                _kill = "7C_twinsame"
                                verdict = (
                                    f"REJECTED — Seam {s['n']}: spelling "
                                    f"twin identical (both spellings behave "
                                    f"the same — no differential)"
                                )

            if not is_confirmed and _dverdict["verdict"] == "CONFIRMED":
                _warn(f"Post-gate verdict: {verdict}")

        confirmed[s["n"]] = {
            "seam": s,
            "check": check,
            "output": output,
            "verdict": verdict,
            "confirmed": is_confirmed,
            "inconclusive": is_inconclusive,
            "retried": retried,
            "det_verdict": _dverdict["verdict"],
            "kill_gate": _kill,
        }

        if is_confirmed:
            _ok(f"Seam {s['n']} CONFIRMED — queued for PoC synthesis")
            if not s.get("reframed"):
                from oracle_harvest import followups_for_verdict as _h_follow

                _next_n = max([x.get("n", 0) for x in seams] + [0]) + 1
                _harvested = _h_follow(
                    s,
                    check,
                    output,
                    True,
                    recon_dir,
                    _next_n,
                    gate=gate,
                    is_testnet=is_testnet,
                )
                if _harvested:
                    _info(
                        f"Seam {s['n']} weak-confirm → "
                        f"{len(_harvested)} harvest follow-up(s) queued"
                    )
                    seams.extend(_harvested)
        elif is_inconclusive:
            _warn(
                f"Seam {s['n']} INCONCLUSIVE after {'retry' if retried else 'no retry possible'} — preserved for the report"  # noqa: E501
            )
        else:
            _info(f"Seam {s['n']} not confirmed — moving on")
            # Frame rewrite (Mind That Does Not Wait): a rejected premise
            # triggers reframing, not silence. One bounded generation —
            # reframed cards never reframe again. The for loop picks up
            # appended cards; interactive mode still asks per check.
            if not s.get("reframed"):
                _next_n = max([x.get("n", 0) for x in seams] + [0]) + 1
                _reframes = reframe_rejected(s, _next_n)
                if _reframes:
                    _info(
                        f"Seam {s['n']} reframed → "
                        f"{len(_reframes)} follow-up(s) queued"
                    )
                    seams.extend(_reframes)
                from oracle_harvest import followups_for_verdict as _h_follow

                _harvested = _h_follow(
                    s,
                    check,
                    output,
                    False,
                    recon_dir,
                    _next_n + len(_reframes),
                    gate=gate,
                    is_testnet=is_testnet,
                )
                if _harvested:
                    _info(
                        f"Seam {s['n']} harvest → "
                        f"{len(_harvested)} follow-up(s) queued"
                    )
                    seams.extend(_harvested)

    n_confirmed = sum(1 for v in confirmed.values() if v["confirmed"])
    n_inconclusive = sum(1 for v in confirmed.values() if v.get("inconclusive"))
    _banner(
        f"Verify complete — {n_confirmed}/{len(seams)} confirmed, {n_inconclusive} inconclusive (preserved)"
    )
    return confirmed


def _run_variant_sweep(
    plan: List[Dict],
    scope_gate,
    target: str,
    recon_dir: Path,
    model: str = LOCAL_MODEL,
    auto: bool = False,
    auth: Optional[str] = None,
    cookie: Optional[str] = None,
    is_testnet: bool = False,
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
    mindset_system_by_lens: Optional[Dict[str, str]] = None,
) -> Dict[int, Dict]:
    """Phase-2 fast money: re-fire each confirmed check, retargeted at the
    remaining in-scope assets (variant_sweep_plan output).

    Every probe goes through the full-program scope gate and the same
    check → assess pipeline as verify_seams. In interactive mode the
    operator approves the whole sweep once, not per probe. Returns
    {new_int_key: {"seam":..., "check":..., "output":..., "verdict":...,
    "confirmed": bool, "variant_of": parent_n, "origin": "variant-sweep"}}.
    Only CONFIRMED hits are returned (sweep misses are noise, not findings).
    """
    hits: Dict[int, Dict] = {}
    if not plan:
        return hits

    _banner(f"Variant Sweep — {len(plan)} probe(s) on remaining assets")
    if not auto:
        try:
            ans = (
                input(f"  Fire {len(plan)} retargeted probe(s)? (y/n): ")
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        if ans not in ("y", "yes", ""):
            _info("Variant sweep skipped by operator.")
            return hits

    from oracle_foundation import parse_verdict as _verdict_of

    next_key = 10**6  # sweep keys live far above seam numbers; no collisions
    for item in plan:
        check = item["check"]
        allowed, safe_cmd, reason = scope_gate.validate_check(
            check, is_testnet=is_testnet
        )
        if not allowed:
            _warn(f"Sweep probe DROPPED by scope gate — {reason}")
            continue
        check = safe_cmd

        # Same auth/cookie injection as verify_seams (sanitized, no shelling)
        if auth and "authorization:" not in check.lower():
            auth_val = (
                auth
                if auth.lower().startswith(("bearer ", "basic "))
                else f"Bearer {auth}"
            )
            auth_val = _sanitize_header_val(auth_val)
            check = re.sub(
                r"^(curl\s+)", rf"\1-H \"Authorization: {auth_val}\" ", check
            )
        if cookie and "cookie:" not in check.lower():
            cookie_val = _sanitize_header_val(cookie)
            check = re.sub(r"^(curl\s+)", rf"\1-H \"Cookie: {cookie_val}\" ", check)

        _info(
            f"Sweep: seam {item['parent_seam']} [{item['claim']}] → {item['asset_ident']}"
        )
        rc, stdout, stderr = _run_check(check, is_testnet=is_testnet)
        injected_secrets = [auth, cookie]
        stdout = _redact_known_secrets(stdout, injected_secrets)
        stderr = _redact_known_secrets(stderr, injected_secrets)
        output = stdout or stderr or "(no output)"

        # Assess against a synthetic seam: parent's claim, retargeted assertion.
        # MEDIUM-1: "n" is assigned only on confirmation, from the unique
        # sweep key — the hit never reuses the parent's seam number, so
        # save_finding/PoC/cloud_results can no longer overwrite the
        # parent's files. variant_of + asset_ident preserve the lineage.
        parent_seam = {
            "claim_type": item["claim"],
            "assertion_a": f"Same issue class as confirmed seam {item['parent_seam']}",
            "assertion_b": f"Retargeted probe reproduces on {item['asset_ident']}",
            "impact": "variant of confirmed finding",
            "reflex": "variant-sweep",
            # Sweep hits inherit the confirmed parent's lens for triage.
            "mindset": item.get("parent_mindset") or "",
        }
        verdict = _assess_response(
            check,
            stdout,
            stderr,
            parent_seam,
            model,
            no_cloud=no_cloud,
            mindset_system=_lens_prompt_for(
                parent_seam, mindset_system, mindset_system_by_lens
            ),
        )
        verdict_token = _verdict_of(verdict)
        is_confirmed = (rc == 0) and verdict_token == "CONFIRMED"
        if is_confirmed:
            next_key += 1
            sweep_seam = {
                **parent_seam,
                "n": next_key,
                "variant_of": item["parent_seam"],
                "asset_ident": item["asset_ident"],
                # Credential containment: the live check carries
                # injected Authorization/Cookie values. The seam
                # dict feeds PoC prompts, finding files and the
                # report — it gets the redacted check only.
                "check": _redact_creds(check),
            }
            hits[next_key] = {
                "seam": sweep_seam,
                "check": check,
                "output": output,
                "verdict": verdict,
                "confirmed": True,
                "inconclusive": False,
                "retried": False,
                "variant_of": item["parent_seam"],
                "origin": "variant-sweep",
                "asset_ident": item["asset_ident"],
            }
            _ok(
                f"Sweep CONFIRMED on {item['asset_ident']} (variant of seam {item['parent_seam']})"
            )
        elif verdict_token == "INCONCLUSIVE":
            _warn(
                f"Sweep INCONCLUSIVE on {item['asset_ident']} — backend could not "
                f"decide; this is not a miss, re-probe manually if it matters"
            )
        else:
            _info(f"Sweep: no reproduction on {item['asset_ident']} (confirmed miss)")

    _banner(f"Variant sweep complete — {len(hits)}/{len(plan)} reproduced")
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# PoC teardown — attack OUR proof, not the target (schema v2, strict)
# ─────────────────────────────────────────────────────────────────────────────

TEARDOWN_REPLAYS = 3


def _swap_check_ids(check: str) -> Optional[str]:
    """Negative-control mutation: 9-fill digit runs in URL path/query.

    Hosts and ports are never touched — only path/query digits change,
    so the control probes object identity on the same endpoint. Returns
    None when the check carries no swappable digits.
    """
    urls = re.findall(r"https?://[^\s'\"]+", check)
    if not urls:
        return None
    swapped = check
    changed = False
    for url in urls:
        m = re.match(r"(https?://[^/]+)(/.*)?$", url)
        if not m:
            continue
        host, rest = m.group(1), m.group(2) or ""
        if not re.search(r"\d", rest):
            continue
        new_rest = re.sub(r"\d+", lambda d: "9" * len(d.group(0)), rest)
        swapped = swapped.replace(url, host + new_rest, 1)
        changed = True
    return swapped if changed else None


def _load_recon_urls(recon_dir: Path) -> List[str]:
    """Collect grounding URL tokens from recon host files."""
    urls: List[str] = []
    for name in ("clean_live_hosts.txt", "live_hosts.txt", "known_urls.txt"):
        path = recon_dir / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.append(line.split()[0])
            urls.extend(re.findall(r"https?://[^\s'\"<>`]+", line))
    return urls


def teardown_poc(
    seam: Dict,
    check: str,
    *,
    recon_urls: Optional[List[str]] = None,
    gate=None,
    is_testnet: bool = False,
    replays: int = TEARDOWN_REPLAYS,
    runner: Optional[Callable[[str], Tuple[int, str, str]]] = None,
    evaluator: Optional[Callable[[Dict, str], Dict]] = None,
) -> Dict:
    """Adversarially validate a sealed-candidate proof. Strict: any
    executed attack that fails → verdict FAIL and the seal is blocked.

    Attacks (each recorded; SKIP never fails):
      replay — run the check N times; every run must re-confirm.
      evaluator_sanity — empty output must NOT confirm (vacuous?).
      id_swap — 9-filled object IDs must NOT confirm (isolating?).
      fix_mutation — SKIP: no fix-artifact producer exists yet.

    runner executes a check command (default: _run_check, same flags as
    verify). evaluator maps (seam, body) to a verdict dict (default:
    verify_seam_card). Both injectable for tests; production replays are
    live but bounded (N replays + 1 control per confirmed seam).
    """
    from oracle_deterministic import (
        extract_status_from_curl_output,
        verify_seam_card,
    )
    from oracle_foundation import generate_proof_packet

    urls = list(recon_urls or [])
    if runner is None:

        def _default_runner(cmd: str) -> Tuple[int, str, str]:
            return _run_check(
                cmd, is_testnet=is_testnet, provenance=seam.get("check_provenance")
            )

        runner = _default_runner
    if evaluator is None:

        def _default_evaluator(card: Dict, body: str) -> Dict:
            try:
                return verify_seam_card(
                    card,
                    urls,
                    scope_gate=gate,
                    status=extract_status_from_curl_output(body),
                    body=body,
                )
            except Exception as e:
                return {
                    "verdict": "REJECTED",
                    "reason": f"teardown evaluator errored ({e})",
                }

        evaluator = _default_evaluator

    def _confirmed(body: str) -> bool:
        try:
            return evaluator(seam, body).get("verdict") == "CONFIRMED"
        except Exception:
            return False

    attacks: List[Dict] = []

    # 1. replay — the proof must reproduce, every time.
    rep_runs = []
    for _ in range(max(1, replays)):
        _rc, _out, _err = runner(check)
        rep_runs.append(_confirmed(_out or _err))
    rep_ok = all(rep_runs)
    attacks.append(
        {
            "name": "replay",
            "result": "PASS" if rep_ok else "FAIL",
            "detail": f"{sum(rep_runs)}/{len(rep_runs)} replays re-confirmed",
        }
    )

    # 2. evaluator sanity — a vacuous verdict confirms even nothing.
    try:
        _sanity_bad = evaluator(seam, "").get("verdict") == "CONFIRMED"
    except Exception:
        _sanity_bad = False
    attacks.append(
        {
            "name": "evaluator_sanity",
            "result": "FAIL" if _sanity_bad else "PASS",
            "detail": (
                "empty output confirmed — verdict is vacuous"
                if _sanity_bad
                else "empty output rejected"
            ),
        }
    )

    # 3. id_swap — the proof must isolate THIS object, not any object.
    _swapped = _swap_check_ids(check)
    if _swapped is None:
        attacks.append(
            {
                "name": "id_swap",
                "result": "SKIP",
                "detail": "no swappable digits in check URLs",
            }
        )
    else:
        _control = _swapped
        if gate is not None:
            _allowed, _safe, _reason = gate.validate_check(
                _swapped, is_testnet=is_testnet
            )
            if not _allowed:
                attacks.append(
                    {
                        "name": "id_swap",
                        "result": "SKIP",
                        "detail": f"control blocked by scope gate: {_reason}",
                    }
                )
                _control = ""
            else:
                _control = _safe
        if _control:
            _rc, _cout, _cerr = runner(_control)
            _swap_confirms = _confirmed(_cout or _cerr)
            attacks.append(
                {
                    "name": "id_swap",
                    "result": "FAIL" if _swap_confirms else "PASS",
                    "detail": (
                        "swapped-ID control still confirmed — "
                        "proof does not isolate the object"
                        if _swap_confirms
                        else "swapped-ID control rejected"
                    ),
                }
            )

    # 4. fix_mutation — uncovered until a fix producer exists. Stated,
    # never silent: the verdict shows exactly what was not attacked.
    attacks.append(
        {
            "name": "fix_mutation",
            "result": "SKIP",
            "detail": "no fix artifact (producer not built)",
        }
    )

    failed = [a for a in attacks if a["result"] == "FAIL"]
    if failed:
        notes = (
            "Teardown FAILED: "
            + "; ".join(f"{a['name']}: {a['detail']}" for a in failed)
            + ". Re-isolate and re-prove."
        )
    else:
        notes = "Teardown passed: proof reproduced and discriminated."
    return {
        "verdict": "FAIL" if failed else "PASS",
        "attacks": attacks,
        "notes": notes,
        "broke_proof": bool(failed),
        "proof_packet": generate_proof_packet(
            seam=seam,
            verification_result={
                "verdict": "FAIL" if failed else "PASS",
                "reason": notes,
                "observed": {"attacks": [a["name"] for a in attacks if a["result"] == "PASS"]},
                "expected": {},
                "url": check,
                "strength": "standard",
            },
            scope_gate=gate,
        ),
        # Outcome Engineering spec (Product.ai Axiomatic Intelligence)
        "outcome_engineering": {
            "precondition": "Seam check URL is in-scope and executable",
            "postcondition": "Proof reproduced and discriminated against controls",
            "invariant": "Scope gate validation never bypassed; all attacks recorded",
            "metric": {
                "replay_consistency": sum(1 for a in attacks if a["name"] == "replay" and a["result"] == "PASS"),
                "control_discrimination": sum(1 for a in attacks if a["name"] in ("id_swap", "evaluator_sanity") and a["result"] == "PASS"),
                "attack_coverage": len([a for a in attacks if a["result"] != "SKIP"]),
            },
            "rollback": "Demote to candidate with teardown notes attached; re-isolate and re-prove",
        },
    }


def _teardown_confirmed(
    verify_results: Dict[int, Dict],
    target: str,
    recon_dir: Path,
    *,
    is_testnet: bool = False,
    runner: Optional[Callable[[str], Tuple[int, str, str]]] = None,
    evaluator: Optional[Callable[[Dict, str], Dict]] = None,
) -> None:
    """Strict teardown gate over verify results. Every CONFIRMED proof is
    attacked; FAIL demotes to candidate with teardown notes attached.
    Nothing is dropped. Mutates verify_results in place."""
    gate = ProgramScopeGate(_scope_from_programs(target), target_fallback=target)
    urls = _load_recon_urls(recon_dir)
    for n, v in verify_results.items():
        if not v.get("confirmed"):
            v["teardown"] = None
            continue
        s = v.get("seam", {})
        td = teardown_poc(
            s,
            v.get("check", "") or s.get("check", ""),
            recon_urls=urls,
            gate=gate,
            is_testnet=is_testnet,
            runner=runner,
            evaluator=evaluator,
        )
        v["teardown"] = td
        if td["verdict"] == "FAIL":
            v["confirmed"] = False
            v["demoted_by_teardown"] = True
            v["verdict"] = f"TEARDOWN-FAILED — {td['notes']}"
            _warn(f"Seam {n} demoted by teardown: {td['notes'][:120]}")
        else:
            _ok(f"Seam {n} survived teardown ({len(td['attacks'])} attacks)")


def _finalize_verify(
    verify_results: Dict[int, Dict],
    seams: List[Dict],
    target: str,
    ws,
    recon_dir: Path,
    raw_analysis: str = "",
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
    mindset_compact: Optional[str] = None,
    mindset_system_by_lens: Optional[Dict[str, str]] = None,
    chain_seams_fn=None,
    model_info: Optional[str] = None,
    is_testnet: bool = False,
    teardown_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None,
    teardown_evaluator: Optional[Callable[[Dict, str], Dict]] = None,
    hunt_meta: Optional[Dict] = None,
) -> Dict:
    """Shared post-verify pipeline for `cmd_hunt` and the standalone `verify` command.

    mindset_system_by_lens (hunt path): per-lens system prompts so PoC
    synthesis reasons in the lens that produced each seam; None keeps the
    single shared prompt for all (standalone path).

    Both paths run the same steps after `verify_seams`:
    0. Strict PoC teardown: attack every CONFIRMED proof; FAIL demotes to
       candidate with teardown notes (seal blocked, nothing dropped).
    1. Persist EVERY result to the workspace — CONFIRMED, INCONCLUSIVE and
       CANDIDATE alike. INCONCLUSIVE findings are preserved, never dropped.
    2. Save a machine-readable verify-results snapshot to the reports dir.
    3. Synthesize PoCs for confirmed seams (saved to the workspace).
    4. Run the chain engine + compound correlation when >= 2 seams confirm
       (chain engine only when `chain_seams_fn` is supplied, i.e. the hunt path).
    5. Write the final report with per-seam verdicts (CONFIRMED / CANDIDATE /
       INCONCLUSIVE) and wire evidence, saved to the workspace.

    Scope-wall enforcement, the fail-closed `_parse_seams` rules, verdict
    labels and wire-evidence inclusion are unchanged — they live in
    `verify_seams` / `_write_report`, which this pipeline calls.

    Returns {"cloud_results": {n: poc}, "correlation": dict|None, "report": Path}.
    """
    # ── 0. Strict teardown BEFORE anything downstream sees CONFIRMED ──────────
    _teardown_confirmed(
        verify_results,
        target,
        recon_dir,
        is_testnet=is_testnet,
        runner=teardown_runner,
        evaluator=teardown_evaluator,
    )
    confirmed_list = [v for v in verify_results.values() if v.get("confirmed")]
    inconclusive = [v for v in verify_results.values() if v.get("inconclusive")]

    # A chain output is usable only if the declared literal is present in the
    # captured verification output. Model wording alone never creates an edge.
    for result in confirmed_list:
        seam = result.get("seam", {})
        observed = str(result.get("output", ""))
        result["chain_outputs"] = [
            value
            for value in seam.get("chain_output_candidates", [])
            if value and value in observed
        ]

    # ── 1. Persist every result — nothing silently dropped ────────────────────
    for n, v in verify_results.items():
        s = v.get("seam", {})
        ws.save_finding(
            {
                **s,
                "verify_verdict": v.get("verdict", ""),
                "verify_confirmed": bool(v.get("confirmed", False)),
                "verify_inconclusive": bool(v.get("inconclusive", False)),
                "verify_retried": bool(v.get("retried", False)),
                "poc_teardown": v.get("teardown"),
            },
            evidence=str(v.get("output", "")),
        )
    snapshot = {
        "target": target,
        "summary": {
            "confirmed": len(confirmed_list),
            "inconclusive": len(inconclusive),
            "total": len(verify_results),
            # Machine-readable hunt verdict: zero-confirmed is an explicit
            # flag, not an inference from counts. (Exit-code wiring for
            # zero-confirmed needs owner approval — flagged, not changed.)
            "verdict": "zero-confirmed" if not confirmed_list else "confirmed",
        },
        "results": {
            str(n): {
                "verdict": v.get("verdict", ""),
                "confirmed": bool(v.get("confirmed", False)),
                "inconclusive": bool(v.get("inconclusive", False)),
                "retried": bool(v.get("retried", False)),
                # Credential containment: v["check"] carries the
                # injected -H "Authorization:"/"Cookie:" values;
                # never serialize them to the report file.
                "check": _redact_creds(v.get("check", "")),
                "output": str(v.get("output", ""))[:3000],
            }
            for n, v in verify_results.items()
        },
    }
    if hunt_meta:
        # Hunt-path observability: lens outcomes, tactic coverage,
        # escalation attempts, M3 gate state. Standalone verify passes
        # none of this (no lenses ran there) — the verdict above still holds.
        snapshot["hunt"] = dict(hunt_meta)
    ws.save_report(json.dumps(snapshot, indent=2), label="verify_results")
    if inconclusive:
        _warn(
            f"{len(inconclusive)} INCONCLUSIVE seam(s) preserved in report — re-run verify to retry"
        )

    # ── 2. Bug chain engine (hunt path supplies ctx.chain_seams) ───────────────
    all_results = list(confirmed_list)
    chains_out = []
    if chain_seams_fn and len(confirmed_list) >= 2:
        _banner(
            f"Bug Chain Engine — composing {len(confirmed_list)} confirmed finding(s)"
        )
        all_results = chain_seams_fn(confirmed_list)
        chains_out = [r for r in all_results if r.get("type") == "chain"]
        # Rank best-first: highest compounded severity, then longest chain. The
        # top chain becomes the ONE headline compound submission.
        _SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        chains_out.sort(
            key=lambda c: (
                _SEV_RANK.get(str(c.get("combined_severity", "")).lower(), 0),
                c.get("depth", len(c.get("links", []))),
            ),
            reverse=True,
        )
        if chains_out:
            for ch in chains_out:
                _ok(
                    f"Chain found: Seams {ch['links']} → {ch['combined_severity']} "
                    f"| {ch['chain_impact'][:80]}"
                )
        else:
            _info("No composable chains found — findings are independent")

    # ── 3. PoC synthesis for confirmed seams (always via _synthesize_poc, which
    #      honors no_cloud — never a direct cloud call) ────────────────────────
    cloud_results: Dict[int, str] = {}
    if confirmed_list:
        _banner(f"PoC Synthesis — {len(confirmed_list)} confirmed seam(s)")
        # Precision floor: a CONFIRMED seam below medium severity (reachability /
        # informational) is recorded as a finding but gets NO submission draft —
        # a benign confirmation auto-drafted and submitted is worse than nothing
        # on a real program (triage reject + reputation risk). Human reviews these.
        _LOW_SEV = {"low", "info", "informational", "none", ""}
        for v in confirmed_list:
            s = v["seam"]
            _sev = str(s.get("severity", "medium")).lower()
            if _sev in _LOW_SEV:
                _info(
                    f"Seam {s['n']} CONFIRMED but severity={_sev or 'none'} — "
                    f"recorded as a finding; no submission draft (precision floor)"
                )
                note = (
                    f"# Seam {s['n']} — CONFIRMED (severity: {_sev or 'none'})\n\n"
                    f"Recorded as a finding. No submission draft generated: below the "
                    f"medium-severity floor for auto-PoC. Review manually before any "
                    f"submission.\n\nCheck: `{s.get('check', '')}`\n"
                )
                cloud_results[s["n"]] = note
                ws.save_report(note, label=f"seam_{s['n']}")
                continue
            _info(f"Synthesizing PoC for seam {s['n']} [{s.get('bug_type', '?')}]…")
            poc = _synthesize_poc(
                s,
                v["output"],
                target,
                no_cloud=no_cloud,
                mindset_system=_lens_prompt_for(
                    s, mindset_system, mindset_system_by_lens
                ),
                mindset_compact=mindset_compact,
            )
            cloud_results[s["n"]] = poc
            ws.save_report(poc, label=f"seam_{s['n']}")
            if RICH:
                console.print(
                    Panel(poc[:2000], title=f"Seam {s['n']} — Submission-Ready PoC")
                )
            else:
                print(f"\n=== Seam {s['n']} PoC ===\n{poc[:2000]}")

        # ONE massive compounded report: the top chain (highest severity, longest)
        # is the headline submission; additional chains are recorded, not drafted.
        if chains_out:
            top = chains_out[0]
            chain_report = _format_chain_report(top, target)
            ws.save_report(chain_report, label="compound_chain_TOP")
            if RICH:
                console.print(
                    Panel(
                        chain_report[:2000],
                        title=f"TOP CHAIN {top['links']} — {top['combined_severity']} (headline)",
                    )
                )
            else:
                print(
                    f"\n=== TOP CHAIN {top['links']} ({top['combined_severity']}) ===\n{chain_report[:2000]}"
                )
            if len(chains_out) > 1:
                _info(
                    f"{len(chains_out) - 1} more chain(s) composed — top chain is the headline submission"
                )

    # ── 4. Compound threat model (>= 2 confirmed) — printed AND saved ──────────
    correlation_report = None
    if len(confirmed_list) >= 2:
        _banner(f"Compound Threat Modeling ({len(confirmed_list)} confirmed seams)")
        correlation_report = _correlate_seams(
            confirmed_list,
            target,
            no_cloud=no_cloud,
            mindset_system=mindset_system,
            mindset_compact=mindset_compact,
        )
        if correlation_report and correlation_report.get("summary"):
            _corr_counts = _correlation_counts_line(correlation_report)
            ws.save_report(
                (
                    f"{_corr_counts}\n\n"
                    if _corr_counts
                    else ""
                )
                + correlation_report["summary"],
                label="correlation",
            )
            if RICH:
                console.print(
                    Panel(
                        correlation_report["summary"], title="Compound Threat Analysis"
                    )
                )
            else:
                print(
                    f"\n=== Compound Threat Analysis ===\n{correlation_report['summary']}"
                )
        elif correlation_report:
            # Skipped/failed correlation still persists its counted
            # omission accounting — never only a transient warning.
            _corr_counts = _correlation_counts_line(correlation_report)
            if _corr_counts:
                ws.save_report(
                    f"Compound Threat Analysis not produced.\n{_corr_counts}",
                    label="correlation",
                )

    # ── 5. Final report: per-seam verdicts + wire evidence ─────────────────────
    report = _write_report(
        target,
        recon_dir,
        raw_analysis,
        seams,
        cloud_results,
        correlation=correlation_report,
        verify_results=verify_results,
        model_info=model_info,
    )
    if hasattr(report, "exists") and report.exists():
        ws.save_report(report.read_text(), label="full")
    elif isinstance(report, str) and report:
        ws.save_report(report, label="full")
    _ok(f"Report → {report}")
    _ok(f"Workspace → {ws.base}")

    n_confirmed = len(confirmed_list)
    if n_confirmed:
        _ok(f"{n_confirmed} confirmed finding(s) — workspace: {ws.base}")
    elif seams:
        _info(
            f"{len(seams)} seams identified — all results preserved in workspace: {ws.base}"
        )
    return {
        "cloud_results": cloud_results,
        "correlation": correlation_report,
        "report": report,
    }


def _synthesize_poc(
    seam: Dict,
    check_output: str,
    target: str,
    provider: str = "auto",
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
    mindset_compact: Optional[str] = None,
) -> str:
    """
    Given a confirmed seam + its check output, synthesize a complete
    submission-ready PoC report.

    no_cloud=True forces local-only routing (no direct Claude/Gemini API
    calls, router local-only). mindset_system threads the fused mindset
    context (philosophy + TTP + scope wall) as the system prompt so the PoC
    reasons from the same grounding as the reflex pass. mindset_compact is
    the lean reporting prompt for the router leg: the full 106KB system
    starves 16k local models (hunt-4c: 600s idle timeout, zero bytes).
    """

    prompt = textwrap.dedent(
        f"""
        A security seam has been CONFIRMED by executing the reproducible check.
        Write a complete, submission-ready bug bounty report.

        TARGET: {target}

        CONFIRMED SEAM:
        - Assertion A: {seam.get('assertion_a', '')}
        - Assertion B: {seam.get('assertion_b', '')}
        - Oracle Reflex: {seam.get('reflex', '')}
        - MITRE TTP: {seam.get('mitre', 'N/A')}
        - Impact: {seam.get('impact', '')}

        CHECK COMMAND THAT PROVED IT:
        {seam.get('check', '')}

        ACTUAL OUTPUT (evidence):
        {check_output[:2000]}

        Write the report in this exact format:

        ## Title
        [one line, specific and technical]

        ## Severity
        [Critical / High / Medium / Low — with brief justification]

        ## Summary
        [2-3 sentences — what the bug is, why it matters]

        ## Steps to Reproduce
        [numbered, minimal, copy-pasteable]

        ## Proof of Concept
        [complete curl chain or script that any triager can run and reproduce]

        ## Impact
        [what a real attacker can do, specific harm to real users]

        ## Remediation
        [one sentence — what needs to change and where]
    """
    ).strip()

    return _cloud_escalate(
        prompt,
        target,
        provider,
        no_cloud=no_cloud,
        mindset_system=mindset_system,
        mindset_compact=mindset_compact,
    )


def _correlation_counts_line(correlation) -> str:
    """One-line omission accounting for saved reports (empty when the
    correlation result carries no counts)."""
    if not isinstance(correlation, dict):
        return ""
    count = correlation.get("count")
    omitted = correlation.get("omitted")
    total = correlation.get("total")
    if not all(isinstance(v, int) for v in (count, omitted, total)):
        return ""
    line = (
        f"Correlation coverage: {count} of {total} confirmed finding(s) "
        f"included, {omitted} omitted"
    )
    if correlation.get("skipped"):
        line += f" (skipped: {correlation['skipped']})"
    if correlation.get("error"):
        line += f" (backend error: {correlation['error']})"
    return line


def _correlate_seams(
    confirmed_seams: List[Dict],
    target: str,
    no_cloud: bool = False,
    mindset_system: Optional[str] = None,
    mindset_compact: Optional[str] = None,
) -> Optional[Dict]:
    """
    Compound Risk & Threat Modeling Engine:
    Analyzes multiple verified seams on the target to evaluate if disjoint low/medium
    findings intersect into a compound architectural vulnerability (e.g. Info Leak + Auth Gap).

    no_cloud=True forces local-only routing. mindset_system threads the fused
    mindset context (philosophy + TTP + scope wall) in front of the architect
    role so correlation reasons from the same grounding as the reflex pass.
    Local-routed calls use mindset_compact instead: the full 106KB system
    starves 16k local models (hunt-4c: 600s idle timeout, zero bytes).
    """
    if len(confirmed_seams) < 2:
        return None

    import oracle_llm as _ollm

    _local_only = bool(no_cloud or _ollm.no_cloud_enabled())
    _base = mindset_compact if (_local_only and mindset_compact) else mindset_system
    _architect_role = (
        "You are a principal application security architect and threat modeling specialist. "
        "Analyze whether the provided confirmed security findings intersect into a compound "
        "architectural vulnerability. Focus on business logic invariants, trust boundary "
        "breakage, and defense-in-depth remediation."
    )
    system = (_base + "\n\n---\n\n" + _architect_role) if _base else _architect_role

    seam_summaries = []
    for i, cs in enumerate(confirmed_seams, 1):
        s = cs.get("seam", cs)
        seam_summaries.append(
            f"Finding {i} (Reflex: {s.get('reflex', '')}) [Seam #{s.get('n', i)}]:\n"
            f"  - Assertion A (Claim): {s.get('assertion_a', '')}\n"
            f"  - Assertion B (Wire Reality): {s.get('assertion_b', '')}\n"
            f"  - Observed Evidence: {cs.get('output', '')[:350]}\n"
            f"  - Claimed Impact: {s.get('impact', '')}"
        )

    # Budget the correlation prompt to the lane that will serve it.
    # Findings beyond the budget are omitted *and counted* in the result
    # — correlation is advisory compound analysis, never a reason to
    # submit an oversized prompt for silent server truncation.
    _budget = 16000 if _local_only else 65536
    _included = list(seam_summaries)
    _omitted = 0

    def _build_prompt(summaries):
        return textwrap.dedent(
            f"""
        Target: {target}

        Below are {len(summaries)} verified security findings discovered on this target:

        {"\n\n".join(summaries)}

        Analyze whether these findings can be correlated into a compound risk scenario:
        1. Can the data or state exposed in one finding satisfy a prerequisite for another?
        2. Does their combination cause a higher severity breach (e.g. from Info/Low to High/Critical)?
        3. What is the combined threat scenario and the comprehensive defense-in-depth fix?

        Output your analysis strictly in this format:
        ## Compound Threat Analysis
        - **Composite Severity:** [Critical / High / Medium / Low]
        - **Correlated Findings:** [e.g. Finding 1 + Finding 2]
        - **Compound Impact:** [2-3 sentences explaining how the combined flaws break system invariants]
        - **Defensive Remediation:** [Comprehensive fix to address the underlying architectural gap]
    """
        ).strip()

    prompt = _build_prompt(_included)
    while len(_included) > 2 and estimate_tokens(system, prompt) > _budget:
        _included.pop()
        _omitted += 1
        prompt = _build_prompt(_included)
    if estimate_tokens(system, prompt) > _budget:
        _warn(
            "correlation: even 2 findings exceed the "
            f"{_budget}tok lane budget — skipping compound analysis"
        )
        # Counted skip, not a bare None: the omission total is part of
        # the result (and the saved report) on every path.
        return {
            "summary": None,
            "count": 0,
            "omitted": len(confirmed_seams),
            "total": len(confirmed_seams),
            "skipped": "over-budget",
        }
    if _omitted:
        _warn(
            f"correlation: {_omitted} finding(s) omitted to fit the "
            f"{_budget}tok budget (counted, not hidden)"
        )

    import oracle_llm

    try:
        analysis = oracle_llm.complete(
            prompt, system, task_type="correlate", no_cloud=no_cloud
        )
    except RuntimeError as e:
        _warn(f"correlation: all backends failed — {e}")
        return {
            "summary": None,
            "count": len(_included),
            "omitted": _omitted,
            "total": len(confirmed_seams),
            "error": str(e),
        }

    return {
        "summary": analysis,
        "count": len(_included),
        "omitted": _omitted,
        "total": len(confirmed_seams),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Seam parsing + report
# ─────────────────────────────────────────────────────────────────────────────


_TARGET_CLEAN_RE = re.compile(r"(?im)^\s*TARGET\s+CLEAN\s*\.?\s*$")


def is_target_clean(raw: Optional[str]) -> bool:
    """True when the model emitted the literal TARGET CLEAN verdict.

    Matched as a full line so prose like "report clean findings"
    never counts — only the exact verdict the task prompt demands.
    """
    return bool(raw) and bool(_TARGET_CLEAN_RE.search(raw))


_REFUSAL_RE = re.compile(
    r"(?i)\b(?:i can't|i cannot|i won't|i am unable to|i'm unable to|"
    r"i must decline|i can't assist|i cannot assist)\b"
    r"[^.]{0,100}\b(?:help|assist|comply|provide|generate|that|this)\b"
)


def lens_outcome(raw: Optional[str], parsed: Optional[List[Dict]]) -> str:
    """Classify one engine pass into clean / empty / error / refusal / seams.

    Causes used to collapse into one `[]`: an explicit TARGET CLEAN
    verdict, unparseable-but-harmless prose, a model refusal, an engine
    failure, and a real seam list. The return value keeps them distinct:
      - "seams": cards parsed (whatever the prose around them says);
      - "clean": explicit TARGET CLEAN verdict, no cards;
      - "refusal": the model declined the task (no cards);
      - "empty": prose with neither cards nor a verdict;
      - "error": no output object at all (None, blank, or a backend
        placeholder like "[no engines available]").
    """
    if parsed:
        return "seams"
    if raw is None or not str(raw).strip() or str(raw).strip().startswith("[no "):
        return "error"
    if is_target_clean(raw):
        return "clean"
    if _REFUSAL_RE.search(str(raw)):
        return "refusal"
    return "empty"


def _lens_outcome_after_cage(raw: Optional[str], admitted, rejected) -> str:
    """A pass whose every parsed card was cage-rejected is a failed pass.

    The raw text may also contain a TARGET CLEAN line or prose; neither can
    erase the fact that the producer emitted only ungrounded cards. This
    outcome is deliberately ``empty`` (pass_failed) so the ladder retries
    and the yield ledger never credits the lens.
    """
    if rejected and not admitted:
        return "empty"
    return lens_outcome(raw, admitted)


def pass_failed(outcome: Optional[str]) -> bool:
    """True when an engine pass must be ladder-retried, not credited.

    "empty" (prose with zero parsed cards and no TARGET CLEAN verdict)
    is a failed pass: the model answered off-format (truncated,
    analysis-only, or otherwise unparseable), which is
    indistinguishable from a loss. Crediting it as "lens ran" once let
    a Databricks OK response silently zero the paradox lens (hunt7).
    Only explicit "clean" and card-bearing "seams" count as ran. A
    "refusal" is likewise a failed pass (distinctly named so yield
    accounting and diagnostics never confuse it with empty prose).
    """
    return outcome in ("error", "empty", "refusal")


def _persist_raw_response(recon_dir, origin: str, raw_out) -> Optional[Path]:
    """Persist one engine pass's raw output under recon/raw/.

    Diagnosis material for parse losses (hunt7 paradox-empty was
    undiagnosable post-hoc because no raw output was saved). Returns
    the path, or None when no recon dir is available. Observability
    only — callers must not let a failed write kill the hunt, so
    OSError returns None loudly via the caller's outcome accounting.
    """
    if not recon_dir:
        return None
    try:
        raw_dir = Path(recon_dir) / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(origin or "unknown"))
        p = raw_dir / f"{safe}.txt"
        p.write_text(str(raw_out or ""), encoding="utf-8")
        return p
    except OSError:
        return None


def tactic_coverage(futures_meta, lens_outcomes) -> Dict[str, List[str]]:
    """Attempted-vs-returned account of the local MITRE tactic sweep.

    A tactic counts as returned when its pass produced an output object
    (any outcome except "error" — clean/empty/seams all ran). Dropped =
    attempted minus returned (exception or collection-deadline drop).
    Pure — recomputed after ladder retries so the report shows the
    final account, not the first-round one.
    """
    attempted = []
    for m in futures_meta or []:
        origin = (m or {}).get("origin", "")
        if origin.startswith("local-tactic:"):
            tactic = origin.split(":", 1)[1].split("#", 1)[0]
            if tactic not in attempted:
                attempted.append(tactic)
    outcomes = lens_outcomes or {}
    returned = []
    for t in attempted:
        slice_outcomes = [
            v
            for o, v in outcomes.items()
            if o == f"local-tactic:{t}" or o.startswith(f"local-tactic:{t}#")
        ]
        if slice_outcomes and any(v != "error" for v in slice_outcomes):
            returned.append(t)
    dropped = [t for t in attempted if t not in returned]
    return {"attempted": attempted, "returned": returned, "dropped": dropped}


def mitre_coverage_ledger(records, futures_meta, lens_outcomes, seams) -> Dict:
    """Per-TTP-code coverage ledger for one hunt's MITRE sweep.

    Every fused record gets exactly one disposition, derived only from
    recorded hunt facts (never from a whole-pass claim alone without
    naming its basis):
      * minted       — a seam card cites this code;
      * served-clean — a pass whose system prompt contained this code
                       returned TARGET CLEAN;
      * served       — such a pass returned (seams/empty) without citing it;
      * error / refusal / not-submitted — the serving pass failed that way;
      * not-served   — no submitted pass contained this code.
    ``complete`` requires every code minted or served-clean/served with
    no failed serving pass. Pure — no network, no models.
    """
    outcomes = lens_outcomes or {}
    # code -> best serving-pass outcome (priority: clean > seams/empty >
    # refusal > error), from pass system prompts / tactic origins.
    _rank = {"clean": 3, "seams": 2, "empty": 2, "refusal": 1, "error": 0}
    served: Dict[str, str] = {}
    served_origin: Dict[str, str] = {}
    code_re = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    by_tactic: Dict[str, List[str]] = {}
    for rec in records or []:
        by_tactic.setdefault(
            str(rec.get("tactic") or "").upper(), []
        ).append(str(rec.get("code") or ""))
    for m in futures_meta or []:
        if not isinstance(m, dict):
            continue
        origin = str(m.get("origin") or "")
        outcome = str(outcomes.get(origin, "error") or "error").lower()
        if origin.startswith("local-tactic:"):
            tactic = origin.split(":", 1)[1].split("#", 1)[0].upper()
            codes = by_tactic.get(tactic, [])
            # Sliced tactic passes carry only part of the tactic: narrow
            # to codes actually present when the system text is recorded.
            system = str(m.get("system") or "")
            if system and "#" in origin:
                present = set(code_re.findall(system))
                codes = [c for c in codes if c in present]
        elif "mitre" in origin.lower():
            codes = code_re.findall(str(m.get("system") or ""))
        else:
            continue
        for code in codes:
            if _rank.get(outcome, 0) >= _rank.get(served.get(code, ""), -1):
                served[code] = outcome
                served_origin[code] = origin
    minted_codes = set()
    for s in seams or []:
        if isinstance(s, dict):
            minted_codes.update(code_re.findall(str(s.get("mitre") or "")))
    entries = []
    for rec in records or []:
        code = str(rec.get("code") or "")
        if code in minted_codes:
            disposition = "minted"
        elif code in served:
            oc = served[code]
            disposition = {
                "clean": "served-clean",
                "seams": "served",
                "empty": "served",
                "refusal": "refusal",
                "error": "error",
            }.get(oc, "error")
        else:
            disposition = "not-served"
        entries.append(
            {
                "code": code,
                "tactic": str(rec.get("tactic") or ""),
                "disposition": disposition,
                "origin": served_origin.get(code, ""),
            }
        )
    complete = bool(entries) and all(
        e["disposition"] in ("minted", "served-clean", "served")
        for e in entries
    )
    return {
        "schema": "oracle.mitre-coverage/v1",
        "total": len(entries),
        "complete": complete,
        "entries": entries,
    }


def slice_coverage_ledger(futures_meta, lens_outcomes, lens: str) -> Dict:
    """Per-pass coverage account for one sliced lens (paradox/mitre).

    Complete only when at least one pass was submitted for the lens and
    every pass outcome is clean/seams. Error, refusal, empty, and
    missing outcomes are all named per pass — a partial slice set can
    never read as a served lens.
    """
    outcomes = lens_outcomes or {}
    passes: Dict[str, str] = {}
    for m in futures_meta or []:
        if not isinstance(m, dict):
            continue
        origin = str(m.get("origin") or "")
        low = origin.lower()
        if lens == "paradox" and "paradox" not in low:
            continue
        if lens == "mitre" and "mitre" not in low and "tactic" not in low:
            continue
        passes[origin] = str(outcomes.get(origin, "error") or "error").lower()
    complete = bool(passes) and all(
        v in ("clean", "seams") for v in passes.values()
    )
    return {
        "schema": "oracle.slice-coverage/v1",
        "lens": lens,
        "passes": passes,
        "complete": complete,
    }


def _raise_on_tactic_drops(coverage, allow_incomplete: bool = False) -> None:
    """Fail loud when tactic passes dropped.

    A bench or live hunt that silently sweeps 9 of 14 tactics reports a partial
    sweep as full. Drops are fatal; the internal allow_incomplete parameter
    exists for isolated harness tests, not for the operator CLI.
    """
    dropped = (coverage or {}).get("dropped", [])
    if dropped and not allow_incomplete:
        raise RuntimeError(
            f"Tactic sweep incomplete: {len(dropped)} tactic "
            f"pass(es) dropped ({', '.join(dropped)}) — partial sweep "
            f"refused; re-run when the engine answers"
        )


def _raise_on_tactic_drops_no_cloud(
    coverage, no_cloud: bool, allow_incomplete: bool = False
) -> None:
    """Fail loud under --no-cloud when tactic passes dropped."""
    dropped = (coverage or {}).get("dropped", [])
    if no_cloud and dropped and not allow_incomplete:
        raise RuntimeError(
            f"--no-cloud tactic sweep incomplete: {len(dropped)} tactic "
            f"pass(es) dropped ({', '.join(dropped)}) — partial sweep "
            f"refused; re-run when the local engine answers"
        )


_ESCALATION_ROUND_BUDGET_S = 180


def plan_ladder_l2(effective, futures_meta, cloud_up, ollama_up):
    """Decide L2 widen passes: one full-lens pass per effective LLM lens.

    Each lens runs on the engine that did NOT serve it in the main round
    when one exists (true widening); otherwise on whichever engine is up
    with the FULL prompt shape (for mitre this differs from the
    per-tactic sweep that already ran). Never plans a cloud pass when
    cloud is down — under --no-cloud _cloud_up is False, so local-only
    is automatic. Pure — no network, no models.
    Returns [{"lens": "mitre"|"paradox", "engine": "cloud"|"local"}].
    """
    from oracle_mindsets import mindset_of_origin as _mindset_of

    served = {}  # lens -> set of engines that served it in the main round
    for m in futures_meta or []:
        label = (m or {}).get("label", "")
        if label.startswith("openrouter-"):
            engine = "cloud"
        elif label.startswith("local-"):
            engine = "local"
        else:
            continue
        served.setdefault(_mindset_of((m or {}).get("origin", "")), set()).add(engine)
    plans = []
    for lens in effective or []:
        if lens not in ("mitre", "paradox"):
            continue
        engines_up = (["cloud"] if cloud_up else []) + (["local"] if ollama_up else [])
        if not engines_up:
            continue
        used = served.get(lens, set())
        fresh = [e for e in engines_up if e not in used]
        plans.append({"lens": lens, "engine": fresh[0] if fresh else engines_up[0]})
    return plans


def run_ladder_passes(pass_specs, complete_fn, budget_s=_ESCALATION_ROUND_BUDGET_S):
    """Execute one escalation round's passes concurrently.

    pass_specs: [{label, origin, prompt, system, no_cloud}].
    complete_fn(prompt, system, no_cloud) -> (raw_text, model_id).
    Returns [(spec, raw_or_None, model_id_or_error)] in completion order;
    raw None means the pass failed or the round budget hit. Pending
    futures are cancelled — a hung engine never stalls the ladder past
    the budget.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

    if not pass_specs:
        return []
    out = []
    seen = set()
    fut_to_spec = {}
    ex = ThreadPoolExecutor(max_workers=min(16, len(pass_specs)))
    try:
        fut_to_spec = {
            ex.submit(
                complete_fn, s["prompt"], s.get("system", ""), s.get("no_cloud", True)
            ): s
            for s in pass_specs
        }
        try:
            for fut in as_completed(list(fut_to_spec), timeout=budget_s):
                spec = fut_to_spec[fut]
                seen.add(id(spec))
                try:
                    res = fut.result()
                    raw, model = res if isinstance(res, tuple) else (res, "unknown")
                    out.append((spec, raw, str(model)))
                except Exception as e:
                    out.append((spec, None, f"error: {e}"))
        except TimeoutError:
            pass
        for spec in pass_specs:
            if id(spec) not in seen:
                out.append((spec, None, "error: round budget hit"))
    finally:
        for fut in fut_to_spec:
            fut.cancel()
        ex.shutdown(wait=False)
    return out


def corroborate_synth_seams(rt_seams, existing_seams, allow_new: bool = False):
    """Enforce the M3 no-invention rule on the §7c synthesis pass.

    The synthesis pass may only corroborate/rank seams the lenses or the
    deterministic feed already produced: an rt seam is kept iff it is
    bound to a known candidate — identical probe-bound URL subject
    (restated prose on the identical probe is synthesis; the wire still
    verifies that probe), or, for non-URL subjects, an exact claim
    content match (normalized Assertion A/B + expected + check). New
    probes/subjects and rewritten non-URL assertions are dropped
    (returned separately for the ledger). The allow_new parameter exists
    only for isolated pure-function tests; the operator CLI has no
    invention toggle. Pure — no network.
    Returns (kept, dropped).
    """
    from oracle_mindsets import seam_subject_key as _skey

    rt_seams = list(rt_seams or [])
    if allow_new:
        return rt_seams, []
    # Content-bound, not merely subject-labelled:
    #  * URL subjects are already probe-bound (subject key = method +
    #    URL + auth-header signature), so a synth card on the identical
    #    probe may restate/compound Assertions — that is synthesis of a
    #    produced seam, not a new one.
    #  * src:/code: subjects bind only file/function/source, so there a
    #    synth card must reproduce a known candidate's normalized
    #    Assertion A/B/check content exactly; rewriting Assertion B on a
    #    borrowed source is invention and is dropped.
    # (Originals are preserved by _merge_seams regardless, so a dropped
    # rephrase loses nothing the lenses actually produced.)
    # Non-URL corroboration keys on claim content only — normalized
    # Assertion A/B + expected + check. Production synthesis cards come
    # from _parse_seams and carry none of the provenance fields the
    # candidate key embeds (file/function/source/check_output, lens),
    # so keying on seam_candidate_key dropped every faithful
    # restatement of a src/code candidate on the real path. Content is
    # the seam: identical A/B/expected/check is the produced seam,
    # any rewrite of them is invention.
    import hashlib as _hashlib

    def _content_key(s) -> str:
        if not isinstance(s, dict):
            return ""

        def _norm(value) -> str:
            return " ".join(str(value or "").lower().split())

        material = "\x1f".join(
            [
                _norm(s.get("assertion_a")),
                _norm(s.get("assertion_b")),
                _norm(s.get("expected")),
                " ".join(str(s.get("check") or "").split()),
            ]
        )
        if not material.strip("\x1f "):
            return ""
        return _hashlib.md5(
            material.encode("utf-8"), usedforsecurity=False
        ).hexdigest()

    known_content = {_content_key(s) for s in (existing_seams or [])}
    known_subjects = {_skey(s) for s in (existing_seams or [])}

    def _is_corroborated(s) -> bool:
        if not isinstance(s, dict):
            return False
        if not (
            str(s.get("assertion_a") or "").strip()
            or str(s.get("assertion_b") or "").strip()
        ):
            return False
        subject = _skey(s)
        if subject.startswith("url:"):
            return subject in known_subjects
        key = _content_key(s)
        return bool(key) and key in known_content

    kept = [s for s in rt_seams if _is_corroborated(s)]
    dropped = [s for s in rt_seams if not _is_corroborated(s)]
    return kept, dropped


def _parse_seams(
    raw: str, target_base: str = "", recon_dir: Optional[Path] = None
) -> List[Dict]:
    """Extract SEAM cards from Oracle model output.

    Fail-closed on checks: a card keeps a check ONLY when the model supplied
    an explicit reproducible check (a backticked curl command or a
    Check:/Reproducible check: label). An endpoint, URL, or path mentioned in
    prose is never synthesized into a check — inventing one lets an
    unverified claim ride into verification looking tested. Cards without a
    supplied check are kept with ``check`` empty and ``check_missing`` True,
    so the report renders them as unverified candidates, never confirmed.

    ``target_base`` is retained for call-site compatibility; it is no longer
    used to fabricate checks. Likewise, cards that state neither assertion
    keep empty A/B and are tagged ``unparseable`` — the parser never invents
    assertion text (#11).

    The literal TARGET CLEAN verdict is matched explicitly below: it is a
    clean verdict, not unparseable garbage. Call sites that need the
    distinction use lens_outcome(); this function keeps returning the
    card list ([] for a clean verdict).
    """

    seams: List[Dict] = []
    # Strip <think>...</think> reasoning blocks emitted by some backends
    # (e.g. DeepSeek on dahl) before any structural parsing.  If the model
    # mentions "SEAM 1" inside its chain-of-thought the split below would
    # otherwise create a spurious empty card.
    raw = re.sub(r"<think>.*?</think>", "", raw, flags=re.S | re.I).strip()
    # Split on any variation of SEAM header at line start: bold (**SEAM 1**),
    # heading (# SEAM 1), or a bare `SEAM 1` with no marker. The mandatory digit
    # (\d+) keeps prose like "SEAM cards below" from being treated as a header.
    blocks = re.split(
        r"(?im)^\s*(?:\*\*|#{1,3}\s*)?SEAM(?:\s+CARD)?\s*[#:]?\s*\[?\d+\]?[^\n\r]*", raw
    )
    if len(blocks) <= 1 and is_target_clean(raw):
        return []  # explicit clean verdict — distinct from garbage (see lens_outcome)
    for block in blocks[1:]:
        card = block.strip()
        if not card:
            continue
        a_match = re.search(
            r"(?:Assertion A|A|Claims?|Documented)[:\s\*]+([^\n\r]+)", card
        )
        b_match = re.search(
            r"(?:Assertion B|B|Reality|Wire|You never said)[:\s\*]+([^\n\r]+)", card
        )

        check = ""
        # Match backtick curl command first
        curl_tick_m = re.search(r"`(curl\s+[^`]+)`", card)
        if curl_tick_m:
            check = curl_tick_m.group(1).strip()
        if not check:
            # Fenced code block: ```bash\n curl ... \n``` (models vary on fencing)
            fence_m = re.search(
                r"```[a-zA-Z]*\s*\n?\s*(curl\s[^`]+?)\s*```", card, re.S
            )
            if fence_m:
                check = fence_m.group(1).strip()
        if not check:
            check_match = re.search(
                r"(?:Reproducible check|Check)[:\s\*]+(?:`([^`]+)`|([^\n\r]+))", card
            )
            if check_match:
                check = (check_match.group(1) or check_match.group(2) or "").strip()
        if not check:
            # Bare curl line anywhere in the card (no backticks, no label)
            bare_m = re.search(r"(?m)^\s*(curl\s+[^\n\r]*https?://[^\n\r]+)", card)
            if bare_m:
                check = bare_m.group(1).strip()

        if check:
            check = check.strip("`").strip("*").strip()
            if "curl " in check and not check.startswith("curl"):
                check = check[check.index("curl") :]
            check = check.rstrip("`").rstrip("*").strip()

        # Fail closed: no supplied check → record it missing, never invent one.
        # (An Endpoint:/URL/path mentioned in prose is not a reproducible check.)
        check_missing = not check

        assertion_a = a_match.group(1).strip() if a_match else ""
        assertion_b = b_match.group(1).strip() if b_match else ""
        source_match = re.search(
            r"(?:Assertion A source|Claim source)[:\s\*]+([^\n\r]+)", card, re.I
        )
        if not source_match:
            source_match = re.search(r"\(\s*source\s*:\s*([^)]+)\)", assertion_a, re.I)

        # #11: resilient rescues reuse MODEL text only (a cited TTP code,
        # a "You never said" line). Anything else stays empty — the old
        # fabricated defaults ("Service assumes …", "Wire reality …") made
        # every garbage card identical, so the merge collapsed them into one
        # and Op1 passed them as valid binary cards. Cards that state
        # neither assertion are tagged unparseable, honestly.
        if not assertion_a:
            ttp_m = re.search(r"(T\d{4}[^\n\r]*)", card)
            assertion_a = ttp_m.group(1).strip() if ttp_m else ""
        if not assertion_b:
            yns_m = re.search(r"(?:You never said|Oracle reflex)[:\s]+([^\n\r]+)", card)
            assertion_b = yns_m.group(1).strip() if yns_m else ""
        unparseable = not assertion_a and not assertion_b

        impact_match = re.search(r"(?:Impact|User harm)[:\s]+([^\n\r]+)", card)
        reflex_match = re.search(
            r"(?:Reflex|Oracle Reflex Analysis|Reflex Analysis|Oracle reflex)[:\s]+([^\n\r]+)",
            card,
        )
        mitre_match = re.search(r"(?:MITRE|TTP)[:\s]+([^\n\r]+)", card)
        mitre_val = mitre_match.group(1).strip() if mitre_match else ""
        if not mitre_val or mitre_val.upper() in ("N/A", "?", "NONE", "UNKNOWN"):
            t_match = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", card)
            mitre_val = t_match.group(1).strip() if t_match else "N/A"
        frame_match = re.search(
            r"(?:Frame|Philosophy frame|Paradox frame)[:\s\*]+([^\n\r]+)",
            card,
            re.I,
        )
        expected_match = re.search(r"(?:Expected)[:\s\*]+([^\n\r]+)", card)
        chain_output_match = re.search(
            r"(?:Chain output)[:\s\*]+([^\n\r]+)", card, re.I
        )
        chain_precondition_match = re.search(
            r"(?:Chain precondition)[:\s\*]+([^\n\r]+)", card, re.I
        )

        seams.append(
            {
                "n": len(seams) + 1,
                "assertion_a": assertion_a,
                "assertion_a_source": (
                    source_match.group(1).strip().strip("`").strip("*")
                    if source_match
                    else ""
                ),
                "assertion_b": assertion_b,
                "unparseable": unparseable,
                "check": check,
                "check_missing": check_missing,
                "expected": (
                    expected_match.group(1).strip().strip("`").strip("*")
                    if expected_match
                    else ""
                ),
                "impact": impact_match.group(1).strip() if impact_match else "",
                # #20: no model-cited reflex → empty, never a self-certifying
                # default. A filled default here used to mint unearned
                # "mindset-invisible-seam" provenance downstream.
                "reflex": (
                    reflex_match.group(1).strip() if reflex_match else ""
                ),
                "mitre": mitre_val,
                "frame": (
                    frame_match.group(1).strip().strip("*")
                    if frame_match
                    else ""
                ),
                "chain_output_candidates": (
                    [chain_output_match.group(1).strip()] if chain_output_match else []
                ),
                "chain_preconditions": (
                    [chain_precondition_match.group(1).strip()]
                    if chain_precondition_match
                    else []
                ),
                "raw": card,
            }
        )
    return seams


def _attribute_candidate_lenses(seam: Dict) -> Dict:
    """Attach the evidence lenses that produced a candidate.

    Tags are granted ONLY for model-cited evidence on the card: an explicit
    reflex line earns the mindset tag, an explicit MITRE/TTP code earns the
    MITRE tag. Parser defaults and empty fields earn nothing — a card that
    cites no lens is "unattributed", never self-certified. Code-lens cards
    keep their deterministic origin. These tags are evidence provenance,
    not proof of exploitability; verification still owns the verdict.
    """
    origin = str(seam.get("origin") or "")
    seam.setdefault("lens", origin)
    seam.setdefault("template_id", "")
    lenses = []
    if origin == "invisible-seam":
        lenses.append("deterministic-invisible-seam")
    if seam.get("mitre") and seam["mitre"] != "N/A":
        lenses.append("mitre-invisible-seam")
    _reflex = (seam.get("reflex") or "").strip()
    # "Oracle Reflex" is the retired parser default: cards persisted before
    # #20 carry it without any model citation, so it earns no lens tag.
    if _reflex and _reflex not in ("N/A", "Oracle Reflex"):
        lenses.append("mindset-invisible-seam")
    seam["reasoning_lenses"] = lenses or ["unattributed"]
    seam.setdefault("candidate_status", "CANDIDATE")
    return seam


def _norm(s: str) -> str:
    """Normalizer for dedupe keys: lowercase, collapse whitespace, strip edges."""
    return re.sub(r"\s+", " ", (s or "").lower()).strip(" \t\n\r.-*`\"'")


def _extract_check_url(check: str) -> str:
    """Extract the first http/https URL from a check command, normalised for
    secondary dedup. Returns "" when no URL is present (e.g. forge/cast checks)."""
    m = re.search(r"""https?://[^\s'"\\]+""", check or "")
    return _norm(m.group(0)) if m else ""


def _cage_admit_parsed(
    parsed: List[Dict], origin: str, scope_gate, packet: Optional[Dict] = None
):
    """Admit one lens pass's parsed cards through its mindset cage.

    Returns (admitted, rejected). Rejected cards carry the reasons and are
    excluded from the seam deck — a card that cannot be grounded does not
    exist. If a pass's every card is rejected, the pass's outcome becomes
    ``empty`` (lens_outcome) and the retry ladder picks it up instead of
    crediting the lens for prose.
    """
    from oracle_mindset_cages import admit_seam_card
    from oracle_mindsets import mindset_of_origin

    mindset = mindset_of_origin(origin)
    admitted: List[Dict] = []
    rejected: List[Dict] = []
    for seam in parsed or []:
        seam.setdefault("origin", origin)
        ok, reasons, receipt = admit_seam_card(
            mindset, seam, scope_gate, packet=packet
        )
        if ok:
            seam["cage_receipt"] = receipt
            admitted.append(seam)
        else:
            rejected.append(
                {
                    "origin": origin,
                    "mindset": mindset,
                    "reasons": list(reasons),
                    "claim": str(seam.get("assertion_a") or "")[:160],
                    "check": str(seam.get("check") or "")[:200],
                }
            )
    return admitted, rejected


def _merge_seams(recon_seams: List[Dict], code_seams: List[Dict]) -> List[Dict]:
    """Merge recon-lens and code-lens seam cards onto one list: tag origins,
    dedupe within a mindset on (A, B, check), renumber n. First occurrence
    wins (recon before code).

    Primary key: (lens, A, B, check) full-string match — catches exact
    duplicates from the same lens. Explicit Mindset 1/2/3 twins survive:
    they are separate candidates until their separate red-team gates and
    Mindset 3's agreement pass have judged them. Legacy untagged cards
    share one dedupe lane, preserving the historical recon/code collapse.
    Secondary key: probe identity (check URL + probe signature via
    seam_subject_key) — collapses duplicate probes to the same endpoint
    within that lane that differ only in assertion wording (DVWA seams 1+6
    pattern: same /.git/config URL, different A/B text — only the first
    survives), while DISTINCT probes at one URL (plain GET vs header
    injection) both survive: URL-only dedup once swallowed the
    X-Original-Role card for /api/v1/admin/metrics behind its plain-GET
    exposure card.

    #11: unparseable cards (neither assertion stated) dedupe on their raw
    card text instead — distinct garbage stays distinct, byte-identical
    garbage still collapses, and garbage never merges with a parsed card.
    Unparseable cards are exempt from URL-only dedup (no check field to extract).
    """
    for s in recon_seams:
        s.setdefault("origin", "recon-reflex")

    def _lens_key(seam: Dict) -> str:
        mindset = str(seam.get("mindset") or "").strip().lower()
        if mindset in ("mitre", "paradox", "seam"):
            return mindset
        if mindset == "redteam":
            return "seam"
        origin = str(seam.get("origin") or "").strip().lower()
        if origin.startswith(("cloud-", "local-", "ladder-")) or "seam-synth" in origin:
            from oracle_mindsets import mindset_of_origin as _mindset_of_origin

            return _mindset_of_origin(origin)
        return ""

    merged: List[Dict] = []
    seen_primary: set = set()
    seen_url: set = set()
    for s in list(recon_seams) + list(code_seams):
        lens_key = _lens_key(s)
        if s.get("unparseable"):
            key = ("__unparseable__", lens_key, _norm(s.get("raw", "")))
            if key in seen_primary:
                continue
            seen_primary.add(key)
        else:
            key = (
                lens_key,
                _norm(s.get("assertion_a", "")),
                _norm(s.get("assertion_b", "")),
                _norm(s.get("check", "")),
            )
            if key in seen_primary:
                continue
            seen_primary.add(key)
            # Secondary dedup: same probe (URL + signature) within one
            # lens → drop even if A/B text differs; distinct probes and
            # explicit cross-mindset twins survive.
            if _extract_check_url(s.get("check", "")):
                from oracle_mindsets import seam_subject_key as _probe_key

                url_key = (
                    lens_key,
                    str(s.get("claim_type") or "").strip().lower(),
                    _probe_key(s),
                )
                if url_key in seen_url:
                    continue
                seen_url.add(url_key)
        merged.append(s)
    for i, s in enumerate(merged, 1):
        s["n"] = i
        _attribute_candidate_lenses(s)
    return merged


_SOURCE_EXTS = (".sol", ".rs", ".py", ".js", ".ts")


_MIN_SOURCE_MATCH = 0.6  # minimum token-overlap ratio to accept a checkout


# Mutation trigger mapping from program_changes.change_type to seam card mutation_triggers
_PROGRAM_CHANGE_TO_MUTATION_TRIGGER = {
    "scope_added": "firmware_release",
    "scope_removed": "firmware_release",
    "scope_updated": "firmware_release",
    "payout_changed": "price_change",
    "currency_changed": "price_change",
    "rules_changed": "sentiment_shift",
    "submission_state_changed": "sentiment_shift",
    "offers_bounties_changed": "sentiment_shift",
    "tombstone_resurrected": "contradictory_signal",
    "oos_resurrected": "contradictory_signal",
    "oos_removed": "contradictory_signal",
    "oos_added": "contradictory_signal",
}


def load_mutation_triggers(scan4me_db_path: str, program_name: str) -> set:
    """Load program changes from Scan4Me database and map to mutation triggers.

    Returns a set of mutation trigger names that should be activated for the
    given program based on recent program_changes.
    """
    import sqlite3

    triggers = set()
    try:
        # Read-only: the hunt never writes Scan4Me's DB (bridge law).
        _db_uri = f"{Path(scan4me_db_path).resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(_db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Get program_id for the program name
        cur.execute(
            "SELECT id FROM programs WHERE name = ? OR handle = ?",
            (program_name, program_name),
        )
        prog = cur.fetchone()
        if not prog:
            conn.close()
            return triggers

        program_id = prog["id"]

        # Load recent program changes (last 30 days)
        from datetime import datetime, timezone, timedelta
        cutoff = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp())

        cur.execute(
            """
            SELECT change_type FROM program_changes
            WHERE program_id = ? AND detected_at >= ?
            """,
            (program_id, cutoff),
        )
        for row in cur.fetchall():
            change_type = row["change_type"]
            if change_type in _PROGRAM_CHANGE_TO_MUTATION_TRIGGER:
                triggers.add(_PROGRAM_CHANGE_TO_MUTATION_TRIGGER[change_type])

        conn.close()
    except Exception:
        # Silently ignore database errors - mutation triggers are best-effort
        pass

    return triggers


def apply_mutation_triggers(seams: List[Dict], triggers: set) -> List[Dict]:
    """Mark seam cards as mutation_triggered if their mutation_triggers intersect.

    Modifies seams in place and returns the list for chaining.
    """
    for seam in seams:
        seam_triggers = seam.get("mutation_triggers", [])
        if isinstance(seam_triggers, list):
            # Check if any of the seam's mutation triggers are active
            if any(t in triggers for t in seam_triggers):
                seam["mutation_triggered"] = True
                seam["last_triggered"] = datetime.now(timezone.utc).isoformat()
    return seams


class SeamPrepassUnavailableError(RuntimeError):
    """Seam pre-pass cannot run (missing source / import / scan error).

    Distinguishes "the seam feed is unavailable" (raise) from "the
    seam feed ran and legitimately found nothing" (empty lists, no
    raise). Always chained from the original error.
    """


def seam_prepass(
    repo_path,
    recon_dir,
    program,
    scope_gate,
    errors=None,
    auth=None,
    max_per_family=None,
):
    """Run code/template/web3 seam scans once; raise when unavailable.

    Returns ``(code_seams, template_seams, web3_seams)`` as raw scan
    output (callers stamp bug_type/mindset). A scanner raising means
    unavailable, wrapped as SeamPrepassUnavailableError from the
    original. A clean empty scan returns empty lists and never raises.
    Template-level errors keep flowing through ``errors`` (the #15
    ledger) — one broken template is a recorded coverage gap, not an
    unavailable feed.
    """
    if recon_dir is not None and not Path(recon_dir).is_dir():
        raise SeamPrepassUnavailableError(
            f"recon dir missing: {recon_dir}"
        ) from FileNotFoundError(f"recon dir missing: {recon_dir}")
    code_seams: List[Dict] = []
    if repo_path is not None:
        if not Path(repo_path).is_dir():
            raise SeamPrepassUnavailableError(
                f"source repo missing: {repo_path}"
            ) from FileNotFoundError(f"source repo missing: {repo_path}")
        try:
            from oracle_code_seam import scan_repository_seams as _scan_repo

            code_seams = list(_scan_repo(repo_path, program=program))
        except Exception as exc:
            raise SeamPrepassUnavailableError(
                f"code lens unavailable: {exc}"
            ) from exc
    try:
        from oracle_seam_templates import scan_template_seams as _scan_tpl

        template_seams = list(
            _scan_tpl(
                recon_dir=recon_dir,
                repo_path=repo_path,
                program=program,
                scope_gate=scope_gate,
                errors=errors,
                auth=auth,
                max_per_family=max_per_family,
            )
        )
    except Exception as exc:
        raise SeamPrepassUnavailableError(
            f"template engine unavailable: {exc}"
        ) from exc
    try:
        from oracle_seam_templates_web3 import scan_web3_seams as _scan_w3

        web3_seams = list(
            _scan_w3(
                recon_dir=recon_dir,
                repo_path=repo_path,
                scope_gate=scope_gate,
            )
        )
    except Exception as exc:
        raise SeamPrepassUnavailableError(
            f"web3 template engine unavailable: {exc}"
        ) from exc
    return code_seams, template_seams, web3_seams


def _locate_target_source(
    program: str, explicit: Optional[str], kept_repo_dirs: Optional[Set[str]] = None
) -> Optional[Path]:
    """Find the target's on-disk source tree. Explicit --code wins; else
    best-effort scan of targets/*/. Returns None when there is no code OR
    when no candidate meets the minimum match score — never silently
    returns the wrong program's checkout.

    kept_repo_dirs: when a hunt filter is active, auto-selection is
    restricted to repo dirs attributed to kept assets (owner_repo names
    derived from kept github idents). Exact attribution replaces the fuzzy
    program-name token match in this mode, and the attributed repo dir
    itself is returned (not its workspace container). Repos belonging to
    filtered-out assets are never auto-picked. Explicit --code bypasses
    this — passing it is the operator's deliberate semantic decision.
    """
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            _die(f"--code path not found or not a directory: {explicit}")
        return p

    targets_root = _HERE / "targets"
    if not targets_root.exists():
        return None

    if kept_repo_dirs is not None:
        # M3: hunt filter active — attributed selection only.
        for parent in sorted(targets_root.glob("*")):
            if not parent.is_dir():
                continue
            for sub in sorted(parent.glob("*")):
                if not sub.is_dir() or sub.name == "screenshots":
                    continue
                repo_dirs: List[Path] = []
                if (sub / ".git").exists():
                    repo_dirs.append(sub)
                try:
                    repo_dirs.extend(sorted(g.parent for g in sub.glob("*/.git")))
                    repo_dirs.extend(sorted(g.parent for g in sub.glob("*/*/.git")))
                except Exception:
                    pass
                for rd in repo_dirs:
                    if rd.name.lower() in kept_repo_dirs:
                        _info(f"code lens: auto-selected kept-asset repo {rd.name}/")
                        return rd.resolve()
        _info(
            "code lens: no on-disk repo attributed to a kept hunt-filter "
            "asset — Type-1 code lens skipped (repos for filtered-out "
            "assets are never auto-selected)"
        )
        return None

    slug_tokens = set(re.split(r"[^a-z0-9]+", program.lower())) - {""}
    if not slug_tokens:
        return None

    def _has_source(d: Path) -> bool:
        if (d / ".git").exists():
            return True
        for f in d.rglob("*"):
            if f.is_file() and f.suffix.lower() in _SOURCE_EXTS:
                return True
        return False

    candidates = []
    for parent in sorted(targets_root.glob("*")):
        if not parent.is_dir():
            continue
        for sub in sorted(parent.glob("*")):
            if not sub.is_dir() or sub.name == "screenshots":
                continue
            if _has_source(sub):
                cand_tokens = (
                    set(re.split(r"[^a-z0-9]+", parent.name.lower()))
                    | set(re.split(r"[^a-z0-9]+", sub.name.lower()))
                ) - {""}
                overlap = len(slug_tokens & cand_tokens)
                score = overlap / len(slug_tokens)
                if score >= _MIN_SOURCE_MATCH:
                    candidates.append((score, sub))
    if not candidates:
        _info(
            f"no on-disk source met minimum match score ({_MIN_SOURCE_MATCH}) "
            f"for '{program}' — Type-1 code lens skipped"
        )
        return None
    candidates.sort(key=lambda t: -t[0])
    return candidates[0][1].resolve()


def _report_verdict(s: Dict, verify_results: Optional[Dict[int, Dict]]) -> tuple:
    """Resolve the report verdict for one seam card.

    CONFIRMED only when the verify pass marked it confirmed (wire proof).
    INCONCLUSIVE verdicts are preserved, never dropped. Everything else —
    including seams never sent through verification — is a CANDIDATE.
    Returns (verdict_label, wire_evidence).
    """
    n = s.get("n")
    if verify_results and n in verify_results:
        v = verify_results[n] or {}
        if v.get("confirmed"):
            return "CONFIRMED", str(v.get("output", ""))
        if "INCONCLUSIVE" in str(v.get("verdict", "")).upper():
            return "INCONCLUSIVE", str(v.get("output", ""))
        return "CANDIDATE", str(v.get("output", ""))
    return "CANDIDATE", ""


def _write_report(
    target: str,
    recon_dir: Path,
    raw_analysis: str,
    seams: List[Dict],
    cloud_results: Optional[Dict] = None,
    correlation: Optional[Dict] = None,
    verify_results: Optional[Dict[int, Dict]] = None,
    model_info: Optional[str] = None,
) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = _sanitize(target)
    report_file = REPORTS_DIR / f"{slug}_{ts}.md"

    verdicts = [_report_verdict(s, verify_results)[0] for s in seams]

    # MEDIUM-2: variant-sweep hits live in verify_results under million-plus
    # keys with origin == "variant-sweep". They are confirmed findings and
    # belong in the human report, not just the machine snapshot.
    sweep_hits = [
        (k, v)
        for k, v in (verify_results or {}).items()
        if isinstance(v, dict)
        and v.get("origin") == "variant-sweep"
        and v.get("confirmed")
    ]
    sweep_hits.sort(key=lambda kv: kv[0])

    lines = [
        f"# Oracle Hunt Report: {target}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Recon: {recon_dir}",
        "",
        "## Summary",
        f"- **Seams found:** {len(seams)}",
        f"- **Confirmed:** {verdicts.count('CONFIRMED')}",
        f"- **Candidates (unverified):** {verdicts.count('CANDIDATE')}",
        f"- **Inconclusive:** {verdicts.count('INCONCLUSIVE')}",
        f"- **Variant sweep confirmed (remaining assets):** {len(sweep_hits)}",
        f"- **Model:** {model_info or 'unknown'}",
        "",
    ]

    if correlation and correlation.get("summary"):
        _corr_counts = _correlation_counts_line(correlation)
        if _corr_counts:
            lines.append(f"*{_corr_counts}*")
            lines.append("")
        lines += [
            correlation["summary"],
            "",
            "---",
            "",
        ]
    elif correlation:
        _corr_counts = _correlation_counts_line(correlation)
        if _corr_counts:
            lines += [
                "## Compound Threat Analysis",
                f"*{_corr_counts}; no compound analysis produced.*",
                "",
                "---",
                "",
            ]

    if seams:
        lines.append("## Finding Cards\n")
        for s, verdict in zip(seams, verdicts):
            _, wire = _report_verdict(s, verify_results)
            check = (s.get("check") or "").strip()
            # n is merge order (stable identity); synthesis_rank is the
            # verdict-first rank. Show both so the display order reads
            # as a ranking, not an accident.
            _rank = s.get("synthesis_rank")
            _head = f"### Seam {s['n']}" + (
                f" (synthesis rank {_rank})" if _rank else ""
            )
            lines += [
                _head,
                f"**Verdict:** {verdict}",
                f"**Origin:** {s.get('origin', 'recon-reflex')}",
                f"**Reflex:** {s.get('reflex') or '(none cited)'}",
                f"**Assertion A:** {s.get('assertion_a') or '(not stated by model)'}",
                f"**Assertion B:** {s.get('assertion_b') or '(not stated by model)'}",
                (
                    f"**Check:** `{check}`"
                    if check
                    else "**Check:** (none supplied by model — unverified)"
                ),
                f"**Impact:** {s['impact']}",
            ]
            if wire.strip():
                ev = wire[:3000] + ("…[truncated]" if len(wire) > 3000 else "")
                lines += ["", "**Wire evidence:**", "```", ev, "```"]
            elif verdict == "CONFIRMED":
                # Defensive: confirmed requires wire proof, so this should be
                # unreachable — fail loud rather than print a bare CONFIRMED.
                lines += [
                    "",
                    "**Wire evidence:** (missing — confirmation invalid, treat as candidate)",
                ]
            if cloud_results and s["n"] in cloud_results:
                lines += ["", "#### Cloud Escalation (PoC)", cloud_results[s["n"]]]
            lines.append("")

    if sweep_hits:
        lines.append(
            "## Variant Sweep Findings (phase 2 — same bug class on remaining assets)\n"
        )
        for k, v in sweep_hits:
            s = v.get("seam", {}) if isinstance(v.get("seam"), dict) else {}
            # Credential containment: v["check"] carries the injected
            # Authorization/Cookie values — never print it raw.
            check = _redact_creds(v.get("check", "")).strip()
            lines += [
                f"### Sweep variant of seam {v.get('variant_of')} → {v.get('asset_ident')}",
                "**Verdict:** CONFIRMED",
                "**Origin:** variant-sweep",
                f"**Claim:** {s.get('claim_type', '?')}",
                f"**Assertion:** {s.get('assertion_b', '')}",
                f"**Check:** `{check}`" if check else "**Check:** (none)",
                f"**Impact:** {s.get('impact', '')}",
            ]
            wire = str(v.get("output", "")).strip()
            if wire:
                ev = wire[:3000] + ("…[truncated]" if len(wire) > 3000 else "")
                lines += ["", "**Wire evidence:**", "```", ev, "```"]
            if cloud_results and k in cloud_results:
                lines += ["", "#### PoC", cloud_results[k]]
            lines.append("")

    lines += ["## Raw Oracle Analysis", "```", raw_analysis, "```"]
    report_file.write_text("\n".join(lines))
    return report_file


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────


def cmd_status():
    _banner("Oracle Hunter — Status")
    tools = [
        "subfinder",
        "httpx",
        "ffuf",
        "gau",
        "waybackurls",
        "katana",
        "hakrawler",
        "dnsx",
        "dalfox",
    ]
    if RICH:
        tbl = Table(show_header=True)
        tbl.add_column("Tool")
        tbl.add_column("Status")
        tbl.add_column("Path")
        for t in tools:
            p = _bin(t)
            ok = Path(p).exists() or shutil.which(t) is not None
            tbl.add_row(
                t,
                "[green]✓[/green]" if ok else "[red]✗[/red]",
                p if ok else "not found",
            )
        console.print(tbl)
    else:
        for t in tools:
            ok = _tool_ok(t)
            print(f"{'✓' if ok else '✗'} {t}")

    print()
    # Check Ollama models
    rc, out, err = _run(["ollama", "list"], timeout=10)
    if rc == 0:
        for model in [LOCAL_MODEL, FALLBACK_MODEL]:
            found = model.split(":")[0] in out
            status = "✓ available" if found else "✗ not pulled"
            print(f"  model {model}: {status}")
    else:
        err_msg = err or out or ""
        if "AI_DRIVE" in err_msg or "permission denied" in err_msg:
            _warn(
                "ollama: external AI_DRIVE unmounted (auto-cascading to OpenRouter free models)"
            )
        else:
            _warn(f"ollama not running ({err_msg[:40]})")

    # ── Credential cascade status ──────────────────────────────────────────────
    env = _load_env()
    handle = (
        env.get("RESEARCHER_HANDLE")
        or env.get("HACKERONE_USERNAME")
        or "codehunterextreme"
    )
    email = env.get("RESEARCHER_EMAIL") or f"{handle}@gmail.com"
    print("\n  researcher identity & accounts:")
    print(f"    • Handle:          {handle}")
    print(f"    • Primary Email:   {email}")
    print(f"    • HackerOne:       {handle}@wearehackerone.com")
    print(f"    • Bugcrowd:        {handle}@bugcrowdninja.com")
    print("    • Intigriti:       code_hunter_extreme@intigriti.me")
    print(f"    • Account A (Live): {handle}@gmail.com")
    print(f"    • Account B (IDOR): {handle}+2@gmail.com")

    print("\n  credential cascade (in priority order):")
    creds = [
        ("HACKERONE_API_KEY", "HackerOne REST API"),
        ("INTIGRITI_JWT", "Intigriti JWT"),
        ("OPENROUTER_API_KEY", "OpenRouter LLM"),
        ("NVIDIA_API_KEY", "NVIDIA NIM LLM"),
        ("ANTHROPIC_API_KEY", "Claude direct API"),
        ("GEMINI_API_KEY", "Gemini direct API"),
        ("HACKENPROOF_API_KEY", "HackenProof API"),
        ("FIRECRAWL_API_KEY", "Firecrawl JS scrape"),
    ]
    for key, label in creds:
        val = env.get(key)
        if val:
            # Never print key fragments; "set" is not live-validated.
            print(f"    ✓ {label:<28} ({key} set, not live-validated)")
        else:
            print(f"    ✗ {label:<28} ({key} not set) — falls back to CDP session")

    # CDP session check
    _port = _cdp_port()
    try:
        import urllib.request as _ur
        import json as _jj

        tabs = _jj.loads(
            _ur.urlopen(f"http://localhost:{_port}/json", timeout=2).read()  # nosec B310
        )  # nosec B310
        print(f"    ✓ CDP session (Chromium port {_port}) — {len(tabs)} tab(s) open")
    except Exception:
        print(f"    ✗ CDP session (Chromium port {_port} not responding)")

    # Backend router: which backends are live per task
    import oracle_llm

    cfg = oracle_llm.load_backend_config()
    print("\n  backends by task (live probe):")
    for task in cfg["routes"]:
        avail = [
            b.name
            for b in oracle_llm.build_backends_for(task, cfg, env)
            if b.available()
        ]
        print(f"    {task}: {', '.join(avail) or '(none available)'}")

    # Mindset docs check
    from oracle_mindset_context import _HERE as _ctx_here

    print("\n  oracle mindset docs:")
    for docname in [
        "ORACLE_SYSTEM_PROMPT.md",
        "ORACLE_FRAMEWORK.md",
        "ORACLE_VOICE.md",
        "ALEX_VOICE.md",
        "oracle_ttps_fused.json",
    ]:
        p = _ctx_here / docname
        print(f"    {'✓' if p.exists() else '✗'} {docname}")


def cmd_backends_test(args):
    """Run one sample prompt through each available backend for a task and
    print name / latency / ok-or-error side by side (the compare mode)."""
    import time as _t
    import oracle_llm

    cfg = oracle_llm.load_backend_config()
    env = _load_env()
    task = getattr(args, "task", "reflex")
    sample_sys = "You are a terse security analyst."
    sample = "Reply with one line beginning 'SEAM 1' describing a test finding."
    _banner(f"backends test — task '{task}'")
    for b in oracle_llm.build_backends_for(task, cfg, env):
        if not b.available():
            print(f"  {b.name}: unavailable (skipped)")
            continue
        t0 = _t.time()
        try:
            out = b.complete(sample_sys, sample, timeout=120)
            print(f"  {b.name}: OK {(_t.time()-t0):.1f}s :: {out[:400]}")
        except oracle_llm.BackendError as e:
            print(f"  {b.name}: FAIL {(_t.time()-t0):.1f}s :: {e}")


def cmd_list(args):
    """List programs from oracle_programs cache, ranked by payout."""
    try:
        from oracle_programs import (
            fetch_all_programs,
            filter_programs,
            _load_cache,
            _save_cache,
        )
    except ImportError:
        _die("oracle_programs.py not found — run from oracle-main directory")

    programs = _load_cache()
    if not programs or getattr(args, "refresh", False):
        _info("Fetching programs (this may take a minute)…")
        programs = fetch_all_programs()
        _save_cache(programs)

    programs = filter_programs(
        programs,
        min_payout=getattr(args, "min_payout", 0),
        platform=getattr(args, "platform", None),
        fast_triage=getattr(args, "fast_triage", False),
        web2_only=getattr(args, "web2", False),
        web3_only=getattr(args, "web3", False),
    )[: getattr(args, "top", 50)]

    if RICH:
        tbl = Table(show_header=True, title="Programs — ranked by payout")
        tbl.add_column("#", style="dim")
        tbl.add_column("Platform")
        tbl.add_column("Program")
        tbl.add_column("Max Payout", justify="right")
        tbl.add_column("Kind")
        tbl.add_column("URL")
        for i, p in enumerate(programs, 1):
            payout = f"${p['max_payout']:,}" if p.get("max_payout") else "?"
            tbl.add_row(
                str(i),
                p["platform"],
                p["name"][:40],
                payout,
                p.get("kind", "?"),
                p["url"],
            )
        console.print(tbl)
    else:
        for i, p in enumerate(programs, 1):
            payout = f"${p['max_payout']:,}" if p.get("max_payout") else "?"
            print(
                f"{i:<4} {p['platform']:<14} {p['name'][:38]:<40} {payout:>12} {p['url']}"
            )

    print(f'\n  {len(programs)} programs. Hunt one: oracle-hunter hunt "<name>"')


def cmd_scope(name: str):
    prog = _scope_from_programs(name)
    if prog:
        _info(f"Program: {prog.get('name', name)} ({prog.get('platform', 'unknown')})")
        gate = ProgramScopeGate(prog, target_fallback=name)
        print(f"\n[IN-SCOPE ASSETS] ({len(gate.raw_in_scope)} rules):")
        for r in gate.raw_in_scope:
            print(f"  + {r}")
        if gate.raw_out_of_scope:
            print(f"\n[EXPLICIT OUT-OF-SCOPE] ({len(gate.raw_out_of_scope)} rules):")
            for r in gate.raw_out_of_scope:
                print(f"  - {r}")
        domains = _extract_domains(str(prog.get("scope") or prog.get("targets") or ""))
        if domains:
            print(f"\nExtracted root targets: {', '.join(domains)}")
    else:
        _warn(f"Program '{name}' not in cache. Run: oracle-hunter list --refresh")


def cmd_prescan(args):
    """P11: fast Scan4Me sweep → prescan report (raw, untrusted)."""
    no_cloud = _apply_no_cloud(args)
    try:
        import oracle_intake as _intake
    except ImportError:
        _die("oracle_intake.py not found — run from oracle-main directory")
    out_dir = getattr(args, "out_dir", None)
    _limit = getattr(args, "limit", 50)
    if _limit is None:
        _limit = 50
    if isinstance(_limit, bool) or not isinstance(_limit, int) or _limit < 0:
        _die(f"--limit must be an integer >= 0, got {_limit!r}")
    try:
        report = _intake.run_prescan(
            limit=_limit,
            sync=getattr(args, "sync", False),
            no_cloud=no_cloud,
            out_dir=Path(out_dir) if out_dir else None,
        )
    except _intake.FeedTrustError as exc:
        if exc.report_path:
            _runlog_event(
                "prescan.rejected",
                report=exc.report_path,
                issues=exc.report.get("feed_trust", {}).get("issues", []),
                count=exc.report.get("count"),
            )
            _runlog_artifact(
                exc.report_path,
                "prescan_report",
                count=exc.report.get("count"),
            )
        _die(str(exc))
    except (ValueError, RuntimeError) as exc:
        _die(str(exc))
    _ok(f"Prescan: {report['count']} programs (raw, untrusted)")
    _ok(f"Prescan report: {report['_report_path']}")
    _runlog_event(
        "prescan.complete",
        count=report["count"],
        report=str(report["_report_path"]),
        sync=bool(getattr(args, "sync", False)),
        no_cloud=no_cloud,
    )
    _runlog_artifact(
        report["_report_path"], "prescan_report", count=report["count"]
    )
    return report


def cmd_scan(args):
    """P11: verify pass over a prescan → scan report + P12 handoff."""
    no_cloud = _apply_no_cloud(args)
    try:
        import oracle_intake as _intake
    except ImportError:
        _die("oracle_intake.py not found — run from oracle-main directory")
    out_dir = getattr(args, "out_dir", None)
    out_path = Path(out_dir) if out_dir else None
    prescan_file = getattr(args, "prescan_file", None) or _intake.latest_report(
        out_path, "prescan"
    )
    if prescan_file is None:
        _die("No prescan report found — run: oracle-hunter prescan (or --prescan)")

    # ── preflight: a credential path must exist for HackerOne programs ─────
    # The verify pass re-scans each program from the platform's own source.
    # HackerOne re-scan uses Oracle's authenticated API when keys are set;
    # otherwise the operator's signed-in CDP browser (persistent profile at
    # ~/.oracle-chromium-cdp) is the credential. With neither path, every
    # HackerOne program would land unverified — fail loud before dispatch.
    if not no_cloud:
        _prescan_progs: list = []
        try:
            _prescan_progs = json.loads(
                Path(prescan_file).read_text(encoding="utf-8")
            ).get("programs", [])
        except (OSError, ValueError):
            _prescan_progs = []
        _has_h1 = any(
            str((p or {}).get("platform") or "").strip().lower() == "hackerone"
            for p in _prescan_progs
            if isinstance(p, dict)
        )
        if _has_h1:
            import oracle_h1_api as _h1

            _user, _token = _h1.credentials()
            if not _user or not _token:
                _cdp_tabs = _intake._cdp_tabs(_intake._CDP_DEFAULT_PORT)
                if _cdp_tabs is None:
                    _cdp_tabs = _intake._cdp_ensure_browser()
                if not _cdp_tabs:
                    _die(
                        "No Oracle re-scan credential path: HackerOne API keys "
                        "are not set (HACKERONE_USERNAME / HACKERONE_API_TOKEN) "
                        "and no CDP browser is reachable on port 9227.\n"
                        "Either set the API keys, or start a browser, sign in "
                        "to HackerOne, and re-run:\n"
                        "  chromium-browser --remote-debugging-port=9227 "
                        f"--user-data-dir={Path.home() / '.oracle-chromium-cdp'} "
                        "https://hackerone.com"
                    )

    _info(f"Verifying prescan: {prescan_file}")
    try:
        report = _intake.run_scan(
            prescan_file,
            timeout=getattr(args, "probe_timeout", 8.0) or 8.0,
            no_cloud=no_cloud,
            out_dir=out_path,
            require_trusted_prescan=True,
            rescan_fn=None if no_cloud else _intake.oracle_rescan,
        )
    except _intake.FeedTrustError as exc:
        _runlog_event(
            "scan.rejected",
            prescan=str(prescan_file),
            reason=str(exc),
        )
        _runlog_artifact(str(prescan_file), "prescan_report")
        _die(str(exc))
    except (ValueError, RuntimeError) as exc:
        _die(str(exc))
    _rescan = report.get("oracle_rescan") or {}
    if no_cloud:
        _warn(
            "--no-cloud: independent platform re-scan skipped (offline); "
            "no program from this scan can verify until re-scanned with "
            "cloud enabled."
        )
    elif not _rescan.get("independent"):
        _warn(
            "Not every program had an independent Oracle re-scan. "
            "HackerOne uses Oracle's authenticated API; platforms without "
            "an Oracle adapter cannot verify (the Scan4Me bridge never "
            "corroborates itself)."
        )
    for v in report["verdicts"]:
        mark = "✓" if v["verdict"] == "verified" else "✗"
        failed = ",".join(v.get("failed_checks", []))
        _info(
            f"  [{mark}] {v['name']} [{v['platform']}] — {v['verdict']}"
            + (f" (failed: {failed})" if failed else "")
        )
    _ok(
        f"Scan: {report['verified_count']}/{report['count']} verified"
        + (" (offline: liveness unprobed)" if no_cloud else "")
    )
    _ok(f"Scan report: {report['_report_path']}")
    _runlog_event(
        "scan.complete",
        count=report["count"],
        verified=report["verified_count"],
        report=str(report["_report_path"]),
        no_cloud=no_cloud,
        independent_rescan=bool(_rescan.get("independent")),
    )
    _runlog_artifact(
        report["_report_path"],
        "scan_report",
        count=report["count"],
        verified=report["verified_count"],
    )
    sites_raw = getattr(args, "sites", None)
    sites = (
        [s.strip() for s in sites_raw.split(",") if s.strip()] if sites_raw else None
    )
    top_n = getattr(args, "top_n", None)
    if sites:
        _info(f"Deep-dive: named sites override count ({', '.join(sites)})")
    elif top_n is not None:
        _info(f"Deep-dive: top {top_n} verified")
    else:
        # P12 doctrine §4: no -N and no --sites → queue.default_count
        # (CLI -N > config default_count > built-in 5).
        try:
            import oracle_queue as _queue
        except ImportError:
            _die("oracle_queue.py not found — run from oracle-main directory")
        try:
            qcfg = _queue.load_queue_config(getattr(args, "config", None))
            top_n = _queue.resolve_queue(config=qcfg).default_count
        except _queue.QueueConfigError as exc:
            _die(f"Bad queue config: {exc}")
        _info(f"Deep-dive: top {top_n} verified (queue.default_count)")
    prescan = _intake.load_prescan(prescan_file)
    try:
        selection = _intake.select_deep_dive(
            report,
            prescan_programs=prescan.get("programs", []),
            top_n=top_n,
            sites=sites,
            # Deep-dive consumes the scan verdicts' embedded independent
            # fresh scope. It never re-resolves through the Scan4Me DB.
            resolve_fn=None,
        )
    except ValueError as exc:
        _die(str(exc))
    if getattr(args, "download", False) and selection["ranked_verified"]:
        _info(
            f"Downloading {len(selection['ranked_verified'])} workspace(s) "
            "for the selected verified programs…"
        )
        _intake.download_selected_workspaces(
            selection, cdp_port=_cdp_port(args)
        )
        for r in selection["ranked_verified"]:
            _ws = r.get("workspace") or {}
            _info(
                f"  workspace {r['name']}: {_ws.get('status', '?')} "
                f"{_ws.get('path', '')} {_ws.get('detail', '')}".rstrip()
            )
    handoff = _intake.write_handoff(
        selection,
        scan_report_path=report["_report_path"],
        prescan_report_path=str(prescan_file),
        top_n=top_n,
        sites=sites,
        no_cloud=no_cloud,
        out_dir=out_path,
    )
    for r in selection["ranked_verified"]:
        _info(f"  #{r['rank']} {r['name']} [{r['platform']}] score={r['score']:.1f}")
    for e in selection["excluded_named"]:
        _warn(f"  excluded named site '{e.get('site')}': {e.get('reason')}")
    if not selection["ranked_verified"]:
        _warn("Handoff is EMPTY (fail-closed): no verified programs to hand to P12")
    _ok(f"P12 handoff: {handoff['_report_path']}")
    _runlog_event(
        "handoff.complete",
        count=len(selection["ranked_verified"]),
        excluded=len(selection["excluded_named"]),
        report=str(handoff["_report_path"]),
        top_n=top_n,
        sites=sites,
    )
    _runlog_artifact(
        handoff["_report_path"],
        "handoff",
        count=len(selection["ranked_verified"]),
    )
    for _r in selection["ranked_verified"]:
        _ws = _r.get("workspace") or {}
        _ws_path = _ws.get("path")
        if not _ws_path:
            continue
        _runlog_event(
            "workspace.download",
            program=_r.get("name"),
            status=_ws.get("status"),
            path=str(_ws_path),
            detail=_ws.get("detail"),
        )
        for _name in ("program.json", "program_brief.md"):
            _p = Path(_ws_path) / _name
            if _p.is_file():
                _runlog_artifact(_p, _name, program=_r.get("name"))
    return report, handoff


def cmd_bundle(args):
    """Package one hunt workspace into a verifiable product bundle."""
    try:
        import oracle_bundle as _bundle
    except ImportError:
        _die("oracle_bundle.py not found — run from oracle-main directory")
    workspace = Path(getattr(args, "workspace", "") or "")
    out_dir = getattr(args, "out_dir", None)
    try:
        result = _bundle.build_bundle(
            workspace,
            out_dir=Path(out_dir) if out_dir else None,
        )
    except _bundle.BundleError as exc:
        _die(f"Bundle failed: {exc}")
    readiness = result["readiness"]
    _runlog_event(
        "bundle.complete",
        workspace=str(workspace),
        bundle=result["zip_path"],
        status=readiness.get("status"),
        ready_for_submission=bool(readiness.get("ready_for_submission")),
        confirmed=readiness.get("confirmed_count"),
        reasons=list(readiness.get("reasons") or []),
    )
    _runlog_artifact(
        result["zip_path"],
        "product_bundle",
        status=readiness.get("status"),
        ready_for_submission=bool(readiness.get("ready_for_submission")),
    )
    _ok(f"Bundle: {result['zip_path']}")
    _ok(f"Manifest: {Path(result['bundle_dir']) / _bundle.MANIFEST_NAME}")
    _info(
        f"Readiness: {readiness.get('status')} "
        f"(confirmed={readiness.get('confirmed_count')})"
    )
    for reason in readiness.get("reasons") or []:
        _warn(f"  not ready: {reason}")
    if not readiness.get("ready_for_submission"):
        _die(
            "PRODUCT NOT READY FOR SUBMISSION: "
            + "; ".join(readiness.get("reasons") or ["readiness gate failed"])
            + f". Bundle preserved: {result['zip_path']}"
        )
    return result


def cmd_verify_download(args):
    """Offline SHA-256 + submission-readiness verification of a product bundle."""
    try:
        import oracle_bundle as _bundle
    except ImportError:
        _die("oracle_bundle.py not found — run from oracle-main directory")
    path = Path(getattr(args, "bundle", "") or "")
    try:
        result = _bundle.verify_bundle(path)
    except _bundle.BundleError as exc:
        _die(f"Bundle verification failed: {exc}")
    _runlog_event(
        "bundle.verify",
        bundle=str(path),
        integrity_ok=bool(result.get("integrity_ok")),
        ready_for_submission=bool(result.get("ready_for_submission")),
        status=result.get("status"),
        errors=list(result.get("errors") or []),
    )
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))
    else:
        _info(
            f"Bundle: {path} [{result.get('kind')}]"
        )
        _ok("Integrity: OK" if result.get("integrity_ok") else "Integrity: FAILED")
        _info(
            f"Readiness: {result.get('status')} "
            f"(ready={bool(result.get('ready_for_submission'))})"
        )
        for err in result.get("errors") or []:
            _warn(f"  integrity: {err}")
        for reason in result.get("reasons") or []:
            _warn(f"  not ready: {reason}")
    if not result.get("integrity_ok"):
        _die(
            "BUNDLE INTEGRITY FAILED: "
            + "; ".join(result.get("errors") or ["unknown error"])
        )
    if not result.get("ready_for_submission"):
        _die(
            "PRODUCT NOT READY FOR SUBMISSION: "
            + "; ".join(result.get("reasons") or ["readiness gate failed"])
        )
    return result


def cmd_queue(args):
    """P12: schedule a P11 handoff → ordered work list and optionally execute it."""
    try:
        import oracle_queue as _queue
    except ImportError:
        _die("oracle_queue.py not found — run from oracle-main directory")
    out_dir = getattr(args, "out_dir", None)
    if getattr(args, "execute", False):
        _max_items = getattr(args, "max_items", None)
        if _max_items is not None and (
            isinstance(_max_items, bool)
            or not isinstance(_max_items, int)
            or _max_items < 0
        ):
            _die(f"--max-items must be an integer >= 0, got {_max_items!r}")
    try:
        qcfg = _queue.load_queue_config(getattr(args, "config", None))
        sched = _queue.build_schedule(
            getattr(args, "handoff", None),
            order=getattr(args, "order", None),
            concurrent=getattr(args, "concurrent", None),
            cross_site_cap=getattr(args, "cross_site_cap", None),
            config=qcfg,
            out_dir=Path(out_dir) if out_dir else None,
            require_trusted_handoff=True,
        )
    except _queue.QueueConfigError as exc:
        _die(f"Queue scheduling failed: {exc}")
    q = sched["queue"]
    _info(
        f"Queue: {sched['count']} programs, {sched['waves']} wave(s) "
        f"[order={q['order']} concurrent={q['concurrent']} "
        f"cap={q['effective_cap']}]"
    )
    for it in sched["items"]:
        co = it["company"]
        dd = it["deep_dive"]
        _info(
            f"  wave{it['wave']} #{it['position']} {co['name']} "
            f"[site={it['site']}] score={it['score']:.1f} "
            f"assets={dd['asset_count']} {dd['website']}"
        )
    if not sched["items"]:
        _warn("Schedule is EMPTY (fail-closed): handoff had no verified programs")
    _ok(f"Queue schedule: {sched['_report_path']}")
    _runlog_event(
        "queue.schedule",
        count=sched["count"],
        waves=sched["waves"],
        order=q["order"],
        concurrent=q["concurrent"],
        cap=q["effective_cap"],
        report=str(sched["_report_path"]),
        handoff=str(sched.get("handoff_report") or ""),
    )
    _runlog_artifact(
        sched["_report_path"], "queue_schedule", count=sched["count"]
    )
    if getattr(args, "execute", False):
        if not sched["items"]:
            _die("Queue schedule is EMPTY — nothing to execute")
        try:
            summary = _execute_queue_schedule(args, sched, out_dir)
        except _queue.QueueConfigError as exc:
            _die(f"Queue execution failed: {exc}")
        sched["_execution"] = {
            k: v for k, v in summary.items() if k != "records"
        }
        _runlog_event("queue.execute", **sched["_execution"])
    return sched


def _queue_hunt_args(qargs, schedule_path: str, position: int):
    """Build the cmd_hunt namespace for one queued item.

    Queued hunts are unattended: verify runs with auto-confirm (wire
    checks only — report submission stays manual) and the target comes
    from the schedule item's position, never from an auto-pick path.
    """
    import types as _types

    return _types.SimpleNamespace(
        cloud=getattr(qargs, "cloud", None),
        model=getattr(qargs, "model", LOCAL_MODEL),
        verify=True,
        auto=True,
        # Step-1 flag matrix: hunt modes the queue parser accepts must
        # reach the hunt namespace, never reset silently.
        testnet=bool(getattr(qargs, "testnet", False)),
        code=getattr(qargs, "code", None),
        code_only=bool(getattr(qargs, "code_only", False)),
        # M4: carry the operator's resolved auth material into queued
        # hunts (main() secret-ref resolution already ran on qargs).
        # Interactive prompt-login stays off: queued hunts are unattended.
        auth=getattr(qargs, "auth", None),
        cookie=getattr(qargs, "cookie", None),
        account_a=getattr(qargs, "account_a", None),
        account_b=getattr(qargs, "account_b", None),
        prompt_login=False,
        auto_provision=None,
        researcher=getattr(qargs, "researcher", None),
        mindset=getattr(qargs, "mindset", None),
        handoff=None,
        schedule=schedule_path,
        pick=position,
        controlled=getattr(qargs, "controlled", True),
        config=getattr(qargs, "config", None),
    )


def _bundle_hunt_product(result):
    """Build the verifiable product bundle for a completed queued hunt.

    A zero-confirmed hunt still packages its report (so the emptiness is
    auditable), but it is never called submission-ready. Bundle construction
    failure is a failed queue item: the pipeline's product artifact is part
    of the run, not an optional afterthought.
    """
    if not isinstance(result, dict):
        return None
    workspace = result.get("workspace")
    if not workspace:
        return None
    root = Path(workspace)
    if not root.is_dir():
        _warn(f"Product bundle skipped: workspace missing ({root})")
        return None
    try:
        import oracle_bundle as _bundle
    except ImportError:
        raise RuntimeError("oracle_bundle.py not found")
    try:
        bundle = _bundle.build_bundle(root)
    except _bundle.BundleError as exc:
        raise RuntimeError(f"Product bundle failed for {root}: {exc}") from exc
    readiness = bundle["readiness"]
    _runlog_event(
        "product.bundle",
        workspace=str(root),
        bundle=bundle["zip_path"],
        status=readiness.get("status"),
        ready_for_submission=bool(readiness.get("ready_for_submission")),
        confirmed=readiness.get("confirmed_count"),
        reasons=list(readiness.get("reasons") or []),
    )
    _runlog_artifact(
        bundle["zip_path"],
        "product_bundle",
        status=readiness.get("status"),
        ready_for_submission=bool(readiness.get("ready_for_submission")),
    )
    if readiness.get("ready_for_submission"):
        _ok(f"Product bundle: {bundle['zip_path']} (ready)")
    else:
        _warn(
            f"Product bundle: {bundle['zip_path']} "
            f"({readiness.get('status')}; NOT submission-ready)"
        )
        for reason in readiness.get("reasons") or []:
            _warn(f"  not ready: {reason}")
    return bundle


def _execute_queue_schedule(args, sched, out_dir):
    """Run a built schedule: ensure workspace → hunt, per item, resumable."""
    import oracle_intake as _intake
    import oracle_queue as _queue

    unverified_items = []
    for item in sched.get("items") or []:
        company = item.get("company") if isinstance(item, dict) else None
        company = company if isinstance(company, dict) else {}
        pseudo_entry = {
            "name": company.get("name", ""),
            "handle": company.get("handle", ""),
            "verdict": item.get("verdict") if isinstance(item, dict) else None,
            "failed_checks": (
                item.get("failed_checks", []) if isinstance(item, dict) else []
            ),
            "oracle_rescan": (
                item.get("oracle_rescan") if isinstance(item, dict) else None
            ),
        }
        if not _intake.is_independently_verified_entry(pseudo_entry):
            name = (
                company.get("name")
                or (
                    item.get("position", "<unnamed>")
                    if isinstance(item, dict)
                    else "<unnamed>"
                )
            )
            unverified_items.append(str(name))
    if unverified_items:
        raise _queue.QueueConfigError(
            "schedule items are not independently verified by Oracle: "
            + ", ".join(unverified_items)
        )
    schedule_path = str(sched.get("_report_path", ""))
    out_path = Path(out_dir) if out_dir else None
    # Re-join schedule items to their full handoff entries (by rank) so
    # workspace downloads use the verified deep-dive scope, not the
    # schedule's display fields.
    by_rank = {}
    handoff_report = sched.get("handoff_report")
    if handoff_report:
        # Only the schedule's own handoff may feed downloads. Never fall
        # back to "latest handoff" here: that can download a different
        # program than the one being hunted.
        try:
            loaded = _queue.load_handoff(handoff_report, out_dir=out_path)
        except _queue.QueueConfigError as exc:
            _die(f"Queue execution handoff load failed: {exc}")
        for entry in loaded.get("ranked_verified", []):
            if isinstance(entry, dict) and type(entry.get("rank")) is int:
                by_rank[entry["rank"]] = entry
        # The schedule item and its re-joined handoff entry must both be
        # strict-verified before anything downloads or hunts. Checking
        # here (not inside _ensure) matters: the generic executor records
        # ensure failures and still hunts, by design for download errors.
        bad_entries = [
            str(entry.get("name") or entry.get("handle") or "<unnamed>")
            for entry in by_rank.values()
            if not _intake.is_independently_verified_entry(entry)
        ]
        if bad_entries:
            raise _queue.QueueConfigError(
                "handoff entries are not independently verified by Oracle: "
                + ", ".join(bad_entries)
            )
        def _norm_id(s):
            return re.sub(r"[^a-z0-9]+", "", str(s or "").lower())
        mismatched = []
        for item in sched.get("items") or []:
            if not isinstance(item, dict):
                continue
            entry = by_rank.get(item.get("handoff_rank"))
            company = item.get("company") or {}
            company = company if isinstance(company, dict) else {}
            label = str(
                company.get("name") or item.get("position", "<unnamed>")
            )
            if entry is None:
                mismatched.append(f"{label} (rank missing from handoff)")
                continue
            item_ids = {
                _norm_id(company.get("name")),
                _norm_id(company.get("handle")),
            } - {""}
            entry_ids = {
                _norm_id(entry.get("name")),
                _norm_id(entry.get("handle")),
            } - {""}
            if not item_ids or not entry_ids or not (item_ids & entry_ids):
                mismatched.append(label)
        if mismatched:
            raise _queue.QueueConfigError(
                "handoff entry does not match schedule item: "
                + ", ".join(mismatched)
            )

    def _ensure(item):
        entry = by_rank.get(item.get("handoff_rank"))
        if entry is not None:
            company = item.get("company") or {}
            _norm = lambda s: re.sub(r"[^a-z0-9]+", "", str(s or "").lower())
            item_ids = {
                _norm(company.get("name")),
                _norm(company.get("handle")),
            } - {""}
            entry_ids = {_norm(entry.get("name")), _norm(entry.get("handle"))} - {""}
            if item_ids and entry_ids and not (item_ids & entry_ids):
                raise ValueError(
                    "handoff entry does not match schedule item "
                    f"(rank={item.get('handoff_rank')!r}); refusing download"
                )
        if entry is None:
            company = item.get("company") or {}
            deep = item.get("deep_dive") or {}
            entry = {
                "name": company.get("name", ""),
                "handle": company.get("handle", ""),
                "platform": item.get("site", ""),
                "url": item.get("program_url", ""),
                # Copied from the schedule item (which copied the handoff
                # entry at build time and was strict-gated above) — never
                # minted here.
                "verdict": item.get("verdict", ""),
                "failed_checks": item.get("failed_checks", []),
                "oracle_rescan": item.get("oracle_rescan", {}),
                "deep_dive": {
                    "assets": deep.get("assets", []),
                    "out_of_scope": deep.get("out_of_scope", []),
                    "company": {"website": deep.get("website", "")},
                },
            }
        sel = {"ranked_verified": [entry]}
        _intake.download_selected_workspaces(
            sel, cdp_port=_cdp_port(args)
        )
        return entry.get("workspace") or {}

    def _hunt(item):
        hunt_args = _queue_hunt_args(args, schedule_path, item.get("position", 1))
        result = cmd_hunt("", hunt_args)
        bundle = _bundle_hunt_product(result)
        out = dict(result) if isinstance(result, dict) else {}
        if isinstance(bundle, dict):
            readiness = bundle.get("readiness") or {}
            out["product"] = {
                "bundle": bundle.get("zip_path"),
                "status": readiness.get("status"),
                "ready_for_submission": bool(
                    readiness.get("ready_for_submission")
                ),
                "reasons": list(readiness.get("reasons") or []),
            }
        return out

    _info(
        f"Executing queue: {sched['count']} item(s), "
        f"max_items={getattr(args, 'max_items', None)}, "
        f"resume={getattr(args, 'resume', True)}"
    )
    summary = _queue.execute_schedule(
        schedule_path or sched,
        hunt_fn=_hunt,
        ensure_workspace_fn=None if getattr(args, "skip_download", False) else _ensure,
        out_dir=out_path,
        max_items=getattr(args, "max_items", None),
        resume=getattr(args, "resume", True),
    )
    _ok(
        f"Queue execution: attempted={summary['attempted_this_run']} "
        f"done={summary['done_total']}/{summary['items_total']} "
        f"failed={summary['failed_total']} skipped={summary['skipped_done']}"
    )
    _ok(f"Queue state: {summary['state_path']}")
    _ready_products = sum(
        1
        for _r in summary.get("records", {}).values()
        if isinstance((_r.get("result") or {}).get("product"), dict)
        and (_r["result"]["product"].get("ready_for_submission") is True)
    )
    _ok(f"Queue products: {_ready_products} submission-ready bundle(s)")
    if summary["done_total"] and not _ready_products:
        _warn(
            "Queued hunts completed with ZERO submission-ready products — "
            "inspect each product bundle's readiness reasons; a done hunt is "
            "not a finished product."
        )
    if summary["failed_total"]:
        _warn("Some queued hunts FAILED — see the state file for per-item detail")
    return summary


def cmd_recon(name: str, args):
    prog = _scope_from_programs(name)
    # _derive_target: structured_scopes first, mobile IDs excluded, never the
    # platform URL (2026-10-01: the old inline logic derived hackerone.com).
    target = (
        _derive_target(prog, name)
        if prog
        else re.sub(r"https?://", "", name).split("/")[0]
    )
    if not prog:
        # Treat name as domain/URL directly
        _warn(f"Program '{name}' not in cache — hunting {target} directly")

    scope_gate = ProgramScopeGate(prog, target_fallback=target)
    return recon(
        target, scope_gate=scope_gate, controlled=getattr(args, "controlled", True)
    )


def _resolve_analyze_workspace(d: Path) -> Tuple[Path, str, Dict]:
    """Resolve an analyze/seams/verify input to (recon_dir, target_name, prog).

    Accepts all three real shapes:
      - hunt workspace root  targets/<Plat>/<slug>/       (recon/ inside)
      - its recon subdir     targets/<Plat>/<slug>/recon/
      - legacy flat recon    recon/<slug>/                 (files directly)
    Program scope comes from the workspace's own hunt_scope.json /
    program.json when present — never from the literal folder name
    "recon" (which matches no program and empties the scope gate).
    """
    d = Path(d)
    if d.name.lower() == "recon":
        workspace = d.parent
        if str(workspace) in ("", "."):
            workspace = Path.cwd()
        recon_dir = d
    elif (d / "recon").is_dir():
        workspace, recon_dir = d, d / "recon"
    else:
        workspace, recon_dir = d, d

    def _norm_id(v: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(v or "").lower())

    def _identity_matches(candidate: Dict, wanted: Any) -> bool:
        wanted_norm = {_norm_id(v) for v in wanted if _norm_id(v)}
        vals = {
            _norm_id(candidate.get("name")),
            _norm_id(candidate.get("handle")),
        }
        url = str(candidate.get("url", "") or "")
        if url:
            vals.add(_norm_id(url.rstrip("/").rsplit("/", 1)[-1]))
        vals.discard("")
        return bool(wanted_norm & vals)

    file_prog: Dict = {}
    scoped_prog: Dict = {}
    for fname in ("hunt_scope.json", "program.json"):
        f = workspace / fname
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text())
        except Exception:
            data = {}
        if not isinstance(data, dict):
            continue
        if not file_prog:
            file_prog = data
        scopes = _normalized_structured_scopes(data.get("structured_scopes"))
        if scopes:
            scoped_prog = dict(data)
            scoped_prog["structured_scopes"] = scopes
            break
    if scoped_prog:
        target_name = (
            scoped_prog.get("name") or scoped_prog.get("handle") or workspace.name
        )
        return recon_dir, str(target_name), scoped_prog

    identity_source = file_prog or {}
    target_name = (
        identity_source.get("name")
        or identity_source.get("handle")
        or workspace.name
    )
    wanted = [
        identity_source.get("handle"),
        identity_source.get("name"),
        workspace.name,
        target_name,
    ]
    seen_keys = set()
    for key in wanted:
        key_s = str(key or "").strip()
        if not key_s or key_s.lower() == "recon" or key_s in seen_keys:
            continue
        seen_keys.add(key_s)
        candidate = _scope_from_programs(key_s) or {}
        if candidate and _identity_matches(candidate, wanted):
            target_name = candidate.get("name") or candidate.get("handle") or target_name
            return recon_dir, str(target_name), candidate
    return recon_dir, str(target_name), file_prog


def cmd_analyze(recon_dir: str, args):
    d = Path(recon_dir)
    if not d.exists():
        _die(f"Recon dir not found: {recon_dir}")
    no_cloud = _apply_no_cloud(args)
    model = _pin_local_model(args)  # --model must reach the router
    rdir, target_name, prog = _resolve_analyze_workspace(d)
    _banner(f"Oracle Analysis: {target_name}")
    cloud = getattr(args, "cloud", False)
    scope_gate = ProgramScopeGate(
        prog, target_fallback=_derive_target(prog, target_name)
    )
    _kh = ((prog or {}).get("_hunt_filter") or {}).get("kept_hosts")
    raw = run_reflexes(
        rdir,
        model=model,
        target=target_name,
        cloud=cloud,
        scope_gate=scope_gate,
        no_cloud=no_cloud,
        kept_hosts=set(_kh) if _kh else None,
    )
    print(raw)
    seams = _parse_seams(raw, recon_dir=rdir)
    # #18: the standalone path runs the SAME mindset/synthesis contract as
    # cmd_hunt — no parallel legacy ranking. The single reflex pass is the
    # MITRE-grounded lens output; it flows through lens outcomes → the
    # deterministic red-team challenger → Mindset-3 synthesis. A pass that
    # produced no output object at all (no recon data) dies here instead
    # of writing an empty-analysis report.
    from oracle_mindset_context import TYPE_1, TYPE_2, OracleMindsetContext
    from oracle_mindsets import (
        apply_mindset3_gates,
        build_seam_sets,
        synthesize_seams,
    )

    _outcome = lens_outcome(raw, seams)
    if _outcome == "error":
        _raw_s = str(raw or "").strip()
        if _raw_s.startswith("[no backend"):
            _die(f"standalone analysis failed: {_raw_s}")
        _die(
            "standalone analysis produced no output object "
            f"(no in-scope recon data under {rdir}) — nothing to analyze"
        )
    if _outcome == "empty":
        _die(
            "standalone analysis failed: model returned off-format prose "
            "(no seam cards, no TARGET CLEAN verdict) — failed pass, "
            "nothing synthesized"
        )
    for s in seams:
        s.setdefault("origin", "standalone-reflex")
        s["mindset"] = "mitre"
        _bt = re.search(r"Bug Type[:\s]+([A-Z_1-9]+)", s.get("raw", ""))
        if _bt and _bt.group(1) in (TYPE_1, TYPE_2):
            s["bug_type"] = _bt.group(1)
        else:
            s["bug_type"] = OracleMindsetContext.classify_seam(s)
    seams, _verdicts, _ = apply_mindset3_gates(
        seams, in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0])
    )
    _sets = build_seam_sets(["mitre"], seams, {"standalone-mitre": _outcome})
    seams = synthesize_seams(_sets, redteam_verdicts=_verdicts)
    _ok(f"{len(seams)} seams found (synthesized, mitre lens)")
    report = _write_report(target_name, rdir, raw, seams)
    _ok(f"Report → {report}")
    return seams, raw


def cmd_traffic(har_file: str, program: str):
    """Import redacted, in-scope HAR traffic into an existing recon directory."""
    har_path = Path(har_file)
    if not har_path.is_file():
        _die(f"HAR file not found: {har_path}")
    prog = _scope_from_programs(program)
    if not prog:
        _die(
            f"Program '{program}' is not in the local cache; scope is required for HAR import"
        )
    target = _derive_target(prog, program)
    gate = ProgramScopeGate(prog, target_fallback=target)
    recon_dir = RECON_DIR / re.sub(r"[^a-zA-Z0-9_.-]+", "_", program).strip("_")
    from oracle_traffic import import_har

    result = import_har(har_path, recon_dir, scope_gate=gate)
    _ok(
        f"HAR evidence: {result['accepted']} in scope, "
        f"{result['rejected_out_of_scope']} rejected, {result['malformed']} malformed → {recon_dir}"
    )


def _format_chain_report(chain: Dict, target: str) -> str:
    """Format a chain finding into a submission-ready Markdown report."""
    links = chain.get("links", [])
    sev = chain.get("combined_severity", "High")
    seams = chain.get("seams", [])

    steps = []
    for i, (seq_cmd, s) in enumerate(zip(chain.get("check_sequence", []), seams), 1):
        inner = s.get("seam", s)
        steps.append(
            f"{i}. Run: `{seq_cmd}`  \n" f"   Proves: {inner.get('assertion_b', '')}"
        )

    return "\n".join(
        [
            f"# Chained Finding: Seams {links} → {sev}",
            "",
            f"## Composite Severity: {sev}",
            "",
            "## Chain Narrative",
            chain.get("chain_impact", ""),
            "",
            "## Assertion A (combined claim)",
            chain.get("chain_assertion_a", ""),
            "",
            "## Assertion B (combined wire reality)",
            chain.get("chain_assertion_b", ""),
            "",
            "## Steps to Reproduce (ordered)",
            "\n".join(steps),
            "",
            "## Impact",
            chain.get("chain_impact", ""),
            "",
            "## Remediation",
            "Address each linked finding independently; the compound severity collapses "
            "when either link in the chain is closed.",
        ]
    )


def _web_scope_assets(prog: Optional[Dict]) -> List[Dict]:
    """In-scope assets that are live web targets (recon candidates).

    Mirrors ProgramScopeGate eligibility semantics exactly: an asset is
    eligible unless explicitly marked otherwise, and WEB-typed adapter
    output counts (adapters emit WEB/URL/WILDCARD/DOMAIN). Non-web
    pointers (wp.org pages, github orgs, svn) are excluded — crawling
    them is wasted time; their signal is in source.
    """
    out = []
    for s in (prog or {}).get("structured_scopes", []):
        if not s.get("eligible_for_bounty", True):
            continue
        if not s.get("eligible_for_submission", True):
            continue
        if s.get("asset_type") not in ("URL", "WILDCARD", "DOMAIN", "WEB"):
            continue
        if any(
            x in (s.get("asset_identifier") or "")
            for x in (
                "wordpress.org",
                "github.com",
                "downloads.wordpress",
                "plugins.svn.wordpress",
            )
        ):
            continue
        out.append(s)
    return out


def _code_only_decision(args, src, web_scope) -> bool:
    """Decide whether the hunt skips live recon for the code lens only.

    Forced (--code-only): local source is mandatory and web scope does
    not re-admit live probing — some programs (e.g. Matomo) forbid
    automated tools against live servers while welcoming local-instance
    research, so a mixed-scope program must still be huntable offline.
    Dying loud here beats silently falling through to live recon.
    Unforced: legacy rule — source on disk and zero web assets.
    """
    if getattr(args, "code_only", False):
        if src is None:
            _die(
                "--code-only requires target source on disk "
                "(--code PATH or a repo cloned into the workspace)"
            )
        return True
    return bool(src and not web_scope)


def _seed_hosts(scope_gate: "ProgramScopeGate") -> List[str]:
    """Concrete in-scope hosts to seed recon with.

    Wildcards strip to apex; mobile app IDs are rejected (not DNS
    targets). Loopback lab targets keep their port — default-port
    probing would miss them entirely.
    """
    seeds: List[str] = []
    for raw in scope_gate.raw_in_scope:
        h = ProgramScopeGate.extract_host(raw)
        if not h or " " in h:
            continue
        if h in ("localhost", "127.0.0.1", "0.0.0.0"):
            try:
                _port = urllib.parse.urlsplit(
                    raw if "://" in raw else f"http://{raw}"
                ).port
            except ValueError:
                _port = None
            _seed = f"{h}:{_port}" if _port else h
            if _seed not in seeds:
                seeds.append(_seed)
            continue
        if "." not in h:
            continue
        if h.startswith("*."):
            h = h[2:]
        if any(
            x in h
            for x in (
                "wordpress.org",
                "github.com",
                "gitlab.com",
                "downloads.wordpress",
                "plugins.svn.wordpress",
            )
        ):
            continue
        if not _is_dns_target(h):
            continue
        # A seed the gate explicitly denies (ident in both lists, typed
        # source vs URL) must never be handed to recon. UNRECOGNIZED
        # verdicts survive: a wildcard apex is an enumeration base, not
        # a probe target.
        _ok, _reason = scope_gate.is_host_in_scope(h)
        if not _ok and _reason.startswith(
            ("EXPLICIT_OUT_OF_SCOPE", "GLOBAL_3RD_PARTY_BLOCKED")
        ):
            continue
        if h and h not in seeds:
            seeds.append(h)
    return seeds


# NOTE (#17): _collaborate_bounded lived here until its only production
# caller (the unread model_reviews pass) was cut. Resurrect from git
# history if a real consumer appears — never as blind per-seam spend.


def _scope_sha256(scopes) -> str:
    raw = json.dumps(
        scopes or [], sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _chain_scope_prog(chain, resolved):
    """Pin a chain hunt to the scan-verified deep-dive scope.

    The schedule/handoff pick carries the exact assets Oracle verified
    at scan time. A queued hunt hunts those assets: whatever
    ``_scope_from_programs`` resolved (workspace file, Scan4Me DB, or
    cache) may supply program metadata, but its scope fields are always
    replaced by the chain's. Missing chain assets fail closed — a chain
    hunt never falls back to DB scope. The hunt-time platform refresh
    still runs afterwards and may authoritatively replace this set; the
    stamp records both sides. Never mutates ``resolved``.
    """
    deep = chain.get("deep_dive") if isinstance(chain, dict) else None
    deep = deep if isinstance(deep, dict) else {}
    assets = deep.get("assets")
    if not isinstance(assets, list) or not assets:
        raise ValueError(
            "chain scope missing: pick carries no deep-dive assets; "
            "refusing to re-resolve scope from the Scan4Me DB"
        )
    scopes = []
    for item in assets:
        if isinstance(item, dict):
            scopes.append(dict(item))
        elif isinstance(item, str) and item.strip():
            scopes.append({"asset_identifier": item.strip()})
        else:
            raise ValueError(
                "chain scope malformed: deep-dive assets must be objects "
                "or strings"
            )
    prog = dict(resolved) if isinstance(resolved, dict) else {}
    prog.setdefault("name", chain.get("name", ""))
    prog.setdefault("handle", chain.get("handle", ""))
    prog.setdefault("platform", chain.get("site", ""))
    prog.setdefault("url", chain.get("program_url", ""))
    prog.setdefault("website", deep.get("website", "") or "")
    prog.setdefault("score", chain.get("score", 0) or 0)
    prog["structured_scopes"] = scopes
    prog["out_of_scope"] = list(deep.get("out_of_scope") or [])
    prog["_chain_scope"] = {
        "source": "scan-deep-dive",
        "origin": chain.get("origin", ""),
        "asset_count": len(scopes),
        "out_of_scope_count": len(prog["out_of_scope"]),
        "sha256": _scope_sha256(scopes),
    }
    return prog


def _hunt_scope_stamp(chain_prog, final_prog):
    """Provenance stamp binding chain scope to the hunted scope."""
    chain = {}
    if isinstance(chain_prog, dict):
        raw = chain_prog.get("_chain_scope")
        chain = raw if isinstance(raw, dict) else {}
    final = final_prog if isinstance(final_prog, dict) else {}
    final_scopes = final.get("structured_scopes") or []
    return {
        "source": chain.get("source", "scan-deep-dive"),
        "origin": chain.get("origin", ""),
        "chain_sha256": chain.get("sha256", ""),
        "chain_asset_count": chain.get("asset_count", 0),
        "intake_status": final.get("scope_intake_status"),
        "intake_at": final.get("scope_intake_at"),
        "intake_fresh": final.get("scope_intake_fresh"),
        "final_asset_count": len(final_scopes)
        if isinstance(final_scopes, list)
        else 0,
        "final_sha256": _scope_sha256(final_scopes),
    }


def _hunt_target_from_chain(name, args):
    """Resolve the hunt target from an internal handoff/schedule chain (#19).

    Returns the pick_hunt_target() dict, or None when no chain flags were
    given / an explicit program name wins. Chain errors die loudly via
    _die — never a silent fallthrough to auto-pick.
    """
    handoff_src = getattr(args, "handoff", None)
    schedule_src = getattr(args, "schedule", None)
    if not handoff_src and not schedule_src:
        return None
    if name and name != "__auto__":
        return None
    from oracle_queue import QueueConfigError, pick_hunt_target

    try:
        target = pick_hunt_target(
            handoff_src, schedule_src, getattr(args, "pick", 1) or 1
        )
    except QueueConfigError as e:
        _die(f"chain target unresolvable: {e}")
    if not target["name"] and not target["handle"]:
        _die(f"chain entry #{target['position']} has no name or handle")
    return target


def _resolve_max_cards_per_family(prog, mindset_cfg, args):
    """Resolve the mint family cap (E1.1-C): prog > CLI > shipped config.

    ``None`` or ``0`` means no cap. The cap is armed by configuration,
    never by an implicit library default — a default cap starves the tail
    of same-family sources (and broke the crawled-coverage contract).
    """
    hunt_cfg = (prog or {}).get("hunt_config") or {}
    value = hunt_cfg.get("max_cards_per_family")
    if value is not None:
        return value
    value = getattr(args, "max_cards_per_family", None)
    if value is not None:
        return value
    return ((mindset_cfg or {}).get("hunt") or {}).get(
        "max_cards_per_family"
    )


def cmd_hunt(name: str, args):
    """Full pipeline: mindset context → workspace → assets → recon → reflexes → verify → chain → report."""
    from oracle_mindset_context import (
        OracleMindsetContext,
        ProgramWorkspace,
        TYPE_1,
        TYPE_2,
    )

    _config_hunt_cloud(args)  # config hunt.cloud=false pins local-only
    no_cloud = _apply_no_cloud(
        args
    )  # enforce --no-cloud end to end (router + Firecrawl)
    cloud = getattr(args, "cloud", False)
    model = _pin_local_model(args)
    from oracle_foundation import GearTurn, validate_card_shape

    _gear = GearTurn()

    # ── P11/P12 chain resolve (#19: intake→queue→hunt is connected) ──────────────
    # Internal handoff/schedule chains fill in the program identity when no explicit name
    # was given; an explicit name always wins. Failures die loudly here —
    # a hunt over an empty/missing chain never silently auto-picks.
    _chain = _hunt_target_from_chain(name, args)
    _chain_feed_trust = None
    _chain_rescan = None
    _chain_prog = None
    _hunt_scope_stamp_value = None
    if _chain is not None:
        # A chain hunt is a product hunt: the pick itself must be a whole
        # strict-verified record, not merely carry one green flag.
        import oracle_intake as _chain_intake

        if not _chain_intake.is_independently_verified_entry(
            {
                "name": _chain.get("name", ""),
                "handle": _chain.get("handle", ""),
                "verdict": _chain.get("verdict"),
                "failed_checks": _chain.get("failed_checks", []),
                "oracle_rescan": _chain.get("oracle_rescan"),
            }
        ):
            _die(
                "chain entry is not independently verified by Oracle "
                f"(verdict={_chain.get('verdict')!r}, "
                f"failed_checks={_chain.get('failed_checks')!r}, "
                f"oracle_rescan={_chain.get('oracle_rescan')!r}); "
                "refusing to hunt it"
            )
        name = _chain["name"] or _chain["handle"]
        _chain_feed_trust = _chain.get("feed_trust")
        _chain_rescan = _chain.get("oracle_rescan")
        _banner(
            f"Hunt target from chain: {_chain['name']} "
            f"(#{_chain['position']}/{_chain['count']} via {_chain['origin']})"
        )
        _runlog_event(
            "hunt.provenance",
            feed_trust_ok=bool(
                isinstance(_chain_feed_trust, dict)
                and _chain_feed_trust.get("ok") is True
            ),
            rescan_mode=(_chain_rescan or {}).get("mode")
            if isinstance(_chain_rescan, dict)
            else None,
            scope_independent=_chain_intake.is_independent_rescan_meta(
                _chain_rescan, _chain
            ),
        )

    name = (name or "").strip()
    if not name or name == "__auto__":
        _die(
            "hunt requires an explicit program; pipeline runs use "
            "prescan → scan → queue --execute"
        )

    _banner(f"Oracle Hunt: {name}")

    # ── 1. Resolve program (FULL scope) ────────────────────────────────────────
    prog = _scope_from_programs(name)
    if _chain is not None:
        # Pin the hunt to the exact scan-verified deep-dive scope carried
        # by the pick. Resolution above may supply metadata only; its
        # scope (possibly a Scan4Me DB copy) is never hunt truth here.
        try:
            prog = _chain_scope_prog(_chain, prog)
        except ValueError as _scope_exc:
            _die(str(_scope_exc))
        _chain_prog = prog
    _full_prog = prog
    if prog:
        _ok(
            f"Program: {prog['name']} ({prog['platform']}) — "
            f"max=${prog.get('max_payout_usd', prog.get('max_payout', 0))}"
        )
        _runlog_event(
            "program.resolved",
            program=prog.get("name"),
            handle=prog.get("handle"),
            platform=prog.get("platform"),
            max_payout=prog.get("max_payout_usd", prog.get("max_payout", 0)),
            scopes=len(prog.get("structured_scopes") or []),
        )

    # ── 1a. Scope intake (Work-4 / G11) ──────────────────────────────────────
    # Oracle re-scans scope at the platform source on EVERY hunt (owner
    # design: Scan4Me handoff scopes come from the local DB and may be
    # stale), exactly like the download path. A successful intake is
    # authoritative (revoked assets leave current scope; an authoritative
    # vanish clears it). Only an empty/failed intake keeps the last known
    # set, freshness unverified. Rejected credentials fail loud below:
    # they are permanent until fixed, unlike a transient transport error.
    # Skipped for 'direct' targets (e.g. 127.0.0.1) which have no adapter.
    if _full_prog and (_full_prog.get("platform") or "").lower() not in (
        "",
        "direct",
    ):
        _had_scopes = bool(_full_prog.get("structured_scopes") or [])
        try:
            import oracle_bulk_download as _obd

            _full_prog = _obd.refresh_program_scopes(_full_prog)
            prog = _full_prog
            _status = _full_prog.get("scope_intake_status", "?")
            if _full_prog.get("structured_scopes"):
                _runlog_event(
                    "scope.intake",
                    assets=len(_full_prog["structured_scopes"]),
                    status=_status,
                    new=_full_prog.get("scope_intake_new"),
                    missing=_full_prog.get("scope_intake_missing"),
                    fresh="scope_intake_fresh" in _full_prog,
                )
                _ok(
                    f"Scope intake: {len(_full_prog['structured_scopes'])} "
                    f"in-scope asset(s) ({_status}"
                    + (
                        f", +{_full_prog.get('scope_intake_new', 0)} new, "
                        f"{_full_prog.get('scope_intake_missing', 0)} no longer listed"
                        if "scope_intake_fresh" in _full_prog
                        else ", freshness unverified"
                        if _had_scopes
                        else ""
                    )
                    + ")"
                )
            else:
                _warn(
                    f"Scope intake: no assets (status={_status}) — gate will fall "
                    f"back to target name; run scope download or check the session"
                )
        except Exception as _e:
            _warn(f"Scope intake failed ({_e}) — continuing with available scope")

        if _full_prog.get("scope_intake_status") == "auth-error":
            prog_name = _full_prog.get("handle") or _full_prog.get("name") or name
            raise RuntimeError(
                f"SCOPE INTAKE AUTH FAILED — cannot hunt {prog_name}: the "
                "platform rejected Oracle's credentials, so scope truth "
                "cannot be refreshed. Refusing to hunt on stale scope.\n"
                "Fix HACKERONE_USERNAME / HACKERONE_API_TOKEN and retry."
            )

        if not (_full_prog.get("structured_scopes") or []):
            prog_name = _full_prog.get("handle") or _full_prog.get("name") or name
            raise RuntimeError(
                f"SCOPE EMPTY — cannot hunt {prog_name}: no in-scope assets.\n"
                f"Run: oracle-hunter download {prog_name}\n"
                f"Or pass a direct target: oracle-hunter hunt https://example.com"
            )

    if _chain is not None:
        # Bind what was actually hunted (post-refresh scope) back to the
        # scan-verified chain scope in the runlog and the hunt snapshot.
        _hunt_scope_stamp_value = _hunt_scope_stamp(
            _chain_prog, _full_prog if isinstance(_full_prog, dict) else prog
        )
        _runlog_event("hunt.scope", **_hunt_scope_stamp_value)

    # ── 1b. Hunt filter: program gates + phase-1 asset scoping ────────────────
    # Downloads, repo clones, and the workspace program.json use the FULL
    # program scope. Everything else (mindset, scope gate, recon, phase-1
    # target) only ever sees the filtered hunt scope — the model cannot
    # cite assets it was never shown.
    from oracle_hunt_filter import (
        HuntFilterEmpty,
        apply_hunt_filter,
        load_hunt_filter_config,
        program_qualifies,
        variant_sweep_plan,
    )

    _hf = load_hunt_filter_config()
    if prog:
        _gates_ok, _gate_reasons = program_qualifies(prog, _hf)
        if not _gates_ok:
            _die("Program fails hunt_filter gates: " + "; ".join(_gate_reasons))
        try:
            prog = apply_hunt_filter(prog, _hf)
        except HuntFilterEmpty as e:
            _die(str(e))
        _fi = prog.get("_hunt_filter", {})
        _ok(
            f"Hunt scope: {_fi.get('kept')} of "
            f"{_fi.get('kept', 0) + _fi.get('dropped', 0)} assets "
            f"(mode={_fi.get('mode')})"
        )

    # Phase-1 target is derived AFTER filtering, from the hunt scope (m1).
    # Deriving it from the full program could seed recon on a filtered-out asset.
    # _derive_target: structured_scopes first, mobile IDs excluded, never the
    # platform URL (2026-10-01: the old inline logic derived hackerone.com).
    if prog:
        target = _derive_target(prog, name)
    else:
        target = re.sub(r"https?://", "", name).rstrip("/").split("/")[0]
        _warn(f"Program not in cache — hunting {target} directly")

    # Build the unified Oracle mindset — philosophy + TTPs + program scope in one prompt
    # ttp_mode="full" on cloud (128k context → all 344 TTPs)
    # ttp_mode="auto" on local (16k model context — the fused prompt still
    # runs ~106KB, so reporting legs use reporting_prompt(), not this).
    # Per-tactic passes are run separately in the tactic sweep below.
    _ttp_mode = "full" if not no_cloud else "auto"
    # paradox context: philosophy corpus + compact TTP ref — for Engine A paradox lens
    # and as the shared downstream context (verify, PoC, correlation).
    ctx = OracleMindsetContext(program=prog, voice=True, ttp_mode=_ttp_mode)
    # mitre context: full TTP library, no philosophy corpus — for Engine B local tactic sweep.
    # BUG FIX: Engine B was using ctx (paradox) and labeling seams "mitre" — label and
    # content now agree. mitre profile = technique-indexed sweep, paradox profile = corpus lens.
    _mitre_ctx = OracleMindsetContext(
        program=prog, voice=True, ttp_mode="auto", mindset="mitre"
    )
    _ok(
        f"Mindset contexts loaded — paradox (philosophy+corpus, ttp={_ttp_mode}) + mitre (technique-indexed)"
    )

    # Resolve which mindset generators run this hunt (mitre/paradox LLM lenses +
    # the Mindset-3 synthesis profile). The operator CLI always requests all
    # three; internal callers/tests may pass an explicit subset;
    # else "all". oracle.config.json is loaded explicitly (the module global
    # _BACKEND_CONFIG is the routing config, not this settings file).
    from oracle_mindsets import (
        apply_mindset3_gates,
        resolve_mindsets,
        seam_candidate_key,
        second_seam_pass,
        synthesize_seams,
        mindset_of_origin,
        build_seam_sets,
        redteam_challenge,
        redteam_challenge_by_lens,
    )

    try:
        _mindset_cfg = json.loads(
            (Path(__file__).resolve().parent / "oracle.config.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, ValueError):
        _mindset_cfg = {}
    # Operator config cannot narrow the product: M1+M2→M3 always run.
    # Embedded callers/tests may pass an explicit args.mindset subset.
    _profiles = resolve_mindsets(getattr(args, "mindset", None), {})
    _ok(f"Requested mindsets: {', '.join(_profiles)}")
    _runlog_event(
        "mindset.requested",
        profiles=list(_profiles),
        cloud=bool(cloud),
        no_cloud=bool(no_cloud),
        model=model,
    )
    # FIX 2026-10-01: mindset_sys was referenced at the variant-sweep (3444)
    # and finalize (3464) call sites but never assigned — NameError crashed
    # every hunt after analysis. The fused system prompt string is what both
    # call sites expect (mindset_system: Optional[str]).
    mindset_sys = ctx.system_prompt()
    mindset_compact_sys = ctx.reporting_prompt()
    # Per-lens downstream prompts: PoC/escalation/sweep reasoning runs in
    # the lens that produced each seam (mitre cards in the technique
    # prompt), not paradox-for-everything. Seam/unknown fall back to the
    # shared paradox context (see _lens_prompt_for).
    mindset_sys_by_lens = {
        "paradox": mindset_sys,
        "mitre": _mitre_ctx.system_prompt(),
    }

    # ── 2. Program workspace ───────────────────────────────────────────────────
    # Built from the FULL program (M5): downloads, repo clones, and the saved
    # program.json must see every asset. The filtered hunt scope is saved
    # separately as hunt_scope.json — the model's world, never the disk's.
    ws = ProgramWorkspace(
        _full_prog or {"name": name, "platform": "direct", "url": target},
        base=TARGETS_DIR,
    )
    ws.save_program_json()
    if prog and prog.get("_hunt_filter"):
        ws.save_hunt_scope(prog)
    ws.save_program_brief(ctx)
    _ok(f"Workspace: {ws.base}")

    # ── 3. Asset download ──────────────────────────────────────────────────────
    if getattr(args, "code_only", False):
        _info("--code-only: skipping live asset download (no requests to target hosts)")
        saved_assets = []
    else:
        _info("Downloading program assets (scope pages, JS, API docs)…")
        saved_assets = ws.download_assets(cdp_port=_cdp_port(args), timeout=12)
    if saved_assets:
        _ok(f"Assets downloaded: {len(saved_assets)} file(s) → {ws.assets_dir}")
    else:
        _info(
            "Asset download returned no files — recon will proceed without pre-fetched assets"
        )

    # Downloaded program pages are where the actual bounty rules live.
    # Patch that policy/company context into the hunt program BEFORE the
    # lens futures are built, and rebuild any already-cached mindset
    # prompts so Mindset 1 and Mindset 2 both reason with the downloaded
    # rules instead of listing-only metadata.
    if prog:
        try:
            from oracle_bulk_download import _extract_policy_from_assets

            _policy_text = _extract_policy_from_assets(
                ws.assets_dir, str(prog.get("platform") or "")
            )
        except Exception as _policy_exc:
            _warn(f"policy extraction from downloaded assets failed: {_policy_exc}")
            _policy_text = ""
        if _policy_text:
            prog["policy_text"] = _policy_text
            if isinstance(_full_prog, dict):
                _full_prog["policy_text"] = _policy_text
            ctx.update_program(prog)
            _mitre_ctx.update_program(prog)
            mindset_sys = ctx.system_prompt()
            mindset_compact_sys = ctx.reporting_prompt()
            mindset_sys_by_lens = {
                "paradox": mindset_sys,
                "mitre": _mitre_ctx.system_prompt(),
            }
            ws.save_program_brief(ctx)
            _ok("Program policy/rules extracted from assets → both mindsets rebuilt")

    # ── 3b. Repo auto-clone (additive — repo-less live-asset targets unaffected)
    # NOTE: clone gating uses the FULL program scope (downloads are unfiltered;
    # only the hunt's mindset/gate/recon see the filtered scope).
    try:
        repo_urls = _extract_repo_urls(_full_prog or {}, ws.assets_dir)
        if repo_urls:
            _clone_program_repos(repo_urls, ws.base / "repos", prog=_full_prog or {})
        else:
            _info("no repo URLs found in program data/assets — live-asset path only")
    except Exception as e:
        _warn(f"repo auto-clone failed: {e} — continuing without cloned source")

    # ── 4. Scope gate & recon ─────────────────────────────────────────────────
    # FIDUCIARY DIODE: The scope gate is a structural one-way barrier.
    # Truth data (scope, rules, assets) flows IN to the hunt engine.
    # Revenue data (payouts, commissions, platform incentives) NEVER flows
    # into the ranking/verification path. The scope gate validates every
    # probe against in-scope patterns BEFORE execution — no exceptions.
    # This is not a policy. It is code. The ranking/verification engine
    # literally cannot see out-of-scope targets because the gate runs at
    # the wire level (validate_check) and at the recon seeding level.
    # Proof Packet verification (teardown) re-validates the gate post-hoc.
    scope_gate = ProgramScopeGate(prog, target_fallback=target)
    is_testnet = getattr(args, "testnet", False)
    recon_dir = ws.recon_dir  # recon output lands in the workspace

    # ── Detect code-only targets: skip live recon, go straight to code lens ──
    # A program is code-only when ALL its in-scope assets are non-web
    # (zips, svn, github orgs, wp.org pages) AND local source is on disk.
    # Spending time crawling wordpress.org or github.com is wasted — the
    # signal is entirely in the PHP/JS source.
    # M3: when a hunt filter is active, auto-selection is restricted to
    # repos attributed to kept assets; --code still bypasses (deliberate).
    _kept_repo_dirs: Optional[Set[str]] = None
    if (prog or {}).get("_hunt_filter"):
        from oracle_mindset_context import _kept_repos_of

        _kept_repo_dirs = _kept_repos_of(prog) or set()
    _src_early = _locate_target_source(
        name, getattr(args, "code", None), kept_repo_dirs=_kept_repo_dirs
    )
    _web_scope = _web_scope_assets(prog)
    _code_only = _code_only_decision(args, _src_early, _web_scope)

    _recon_started = time.monotonic()
    _runlog_event(
        "recon.start",
        target=target,
        code_only=bool(_code_only),
        web_scope=len(_web_scope or []),
    )
    if _code_only and _src_early is not None:
        _forced = " (forced by --code-only)" if getattr(args, "code_only", False) else ""
        _ok(
            f"Code-only target{_forced} — skipping live recon, running code lens directly on {_src_early.name}/"
        )
    else:
        # Seed recon with every concrete in-scope hostname from the program's
        # scope list (loopback keeps its port; app IDs rejected as non-DNS).
        seed_hosts = _seed_hosts(scope_gate)
        if seed_hosts:
            _ok(f"Recon seeds: {len(seed_hosts)} in-scope hosts from scope list")
        recon(
            target,
            out_dir=recon_dir,
            scope_gate=scope_gate,
            seed_hosts=seed_hosts,
            controlled=getattr(args, "controlled", True),
            auth=_effective_recon_auth(args),
            cookie=getattr(args, "cookie", None),
        )
    _runlog_event(
        "recon.complete",
        code_only=bool(_code_only),
        duration_s=round(time.monotonic() - _recon_started, 3),
    )

    # ── Session-gate detection: block the hunt if the target is behind auth ──
    # Read back live_hosts.txt status codes. If >= 60% are 502/401/403 AND
    # no auth material was provided, the lenses will see nothing real and
    # declare TARGET CLEAN — burning 40 minutes of recon for zero output.
    # Block loud here instead, naming what's needed.
    _lh_file = recon_dir / "live_hosts.txt"
    if _lh_file.exists() and _lh_file.stat().st_size > 0:
        _lh_lines = [l.strip() for l in _lh_file.read_text().splitlines() if l.strip()]
        _wall_codes = {"[502]", "[401]", "[403]", "[530]", "[000]"}
        _wall_count = sum(
            1 for l in _lh_lines
            if any(c in l for c in _wall_codes)
        )
        _total_hosts = len(_lh_lines)
        _has_auth = bool(
            getattr(args, "auth", None)
            or getattr(args, "cookie", None)
            or getattr(args, "account_a", None)
            or getattr(args, "account_b", None)
            or getattr(args, "prompt_login", False)
        )
        # Also check if traffic_evidence.jsonl already exists (pre-imported HAR)
        _has_traffic = (recon_dir / "traffic_evidence.jsonl").exists()
        if (
            _total_hosts >= 3
            and _wall_count / _total_hosts >= 0.6
            and not _has_auth
            and not _has_traffic
        ):
            _die(
                f"SESSION-GATED TARGET: {_wall_count}/{_total_hosts} live hosts "
                f"return auth-wall status codes (502/401/403/530). "
                f"The mindsets will see nothing real and declare TARGET CLEAN.\n"
                f"Provide credentials to continue:\n"
                f"  --auth 'Bearer <token>'      (Authorization header)\n"
                f"  --cookie '<name>=<value>'    (Cookie header)\n"
                f"  --prompt-login               (interactive credential entry)\n"
                f"  --account-a env:TOKEN_A_VAR  (IDOR dual-account regime)\n"
                f"Or import authenticated HAR traffic first:\n"
                f"  oracle-hunter traffic <file.har> {name}"
            )

    # GAP 5: inject live recon context into mindset for target-specific TTP seeds
    # Read the live hosts and any discovered paths from recon output
    # M4: gate-filter endpoints/hosts through the hunt-scope gate before they
    # reach the model — wayback/gau output can name filtered-out assets.
    _recon_ctx_cfg = (
        (prog or {}).get("hunt_config", {}).get("recon_context")
        or _mindset_cfg.get("hunt", {}).get("recon_context", {})
    )
    _max_hosts = (
        (prog or {}).get("hunt_config", {}).get("max_hosts")
        or _recon_ctx_cfg.get("max_hosts", 20)
    )
    _max_endpoints = (
        (prog or {}).get("hunt_config", {}).get("max_endpoints")
        or _recon_ctx_cfg.get("max_endpoints", 30)
    )
    _live_hosts: List[str] = []
    _live_endpoints: List[str] = []
    _served_200_hosts = 0
    for fname in ("clean_live_hosts.txt", "live_hosts.txt"):
        lf = recon_dir / fname
        if lf.exists() and lf.stat().st_size > 0:
            _host_lines = [
                host_line
                for host_line in lf.read_text().splitlines()
                if host_line.strip()
            ]
            _live_hosts = [
                host_line.split()[0] for host_line in _host_lines
            ][:_max_hosts]
            break
    # Observed-200 evidence comes from the TAGGED live_hosts.txt —
    # clean_live_hosts.txt is written tag-stripped for tooling, so
    # counting there would always read zero. Counted below, after the
    # scope filter, against the hosts actually injected.
    # Discovered endpoints land in several recon files depending on source:
    #   crawl.txt / known_urls.txt      — full URLs (katana crawl, archives)
    #   js_endpoints.txt / listed_paths.txt — paths (JS mining, content listing)
    # Aggregate across ALL of them, deduped. The previous names
    # (waybackurls/gau_urls/endpoints.txt) are never written by recon, so
    # _live_endpoints always arrived empty — the lenses then hypothesised
    # ungrounded seams against the bare host and the verifier rejected them all.
    _ep_base = (
        _live_hosts[0].rstrip("/")
        if _live_hosts
        else "http://" + ProgramScopeGate.extract_host(name)
    )
    _ep_seen: set = set()
    for fname in (
        "crawl.txt",
        "known_urls.txt",
        "waybackurls.txt",
        "gau_urls.txt",
        "js_endpoints.txt",
        "listed_paths.txt",
        "endpoints.txt",
    ):
        ef = recon_dir / fname
        if not (ef.exists() and ef.stat().st_size > 0):
            continue
        for endpoint_line in ef.read_text().splitlines():
            tok = endpoint_line.strip().split()[0] if endpoint_line.strip() else ""
            if not tok:
                continue
            if "://" not in tok:  # path-only — absolutize against the live host
                tok = _ep_base + "/" + tok.lstrip("/")
            if tok not in _ep_seen:
                _ep_seen.add(tok)
                _live_endpoints.append(tok)
    _live_endpoints = _live_endpoints[:_max_endpoints]
    _live_hosts = [h for h in _live_hosts if scope_gate.is_in_scope(h)[0]]
    _tagged_live = recon_dir / "live_hosts.txt"
    if _tagged_live.exists() and _tagged_live.stat().st_size > 0:
        _served_200_hosts = count_served_200_lines(
            _tagged_live.read_text(errors="ignore").splitlines(),
            hosts=_live_hosts,
        )
    _kept_eps = [e for e in _live_endpoints if scope_gate.is_in_scope(e)[0]]
    if len(_kept_eps) != len(_live_endpoints):
        _info(
            f"Recon context: dropped {len(_live_endpoints) - len(_kept_eps)} "
            f"out-of-hunt-scope endpoint(s) before mindset injection"
        )
    _live_endpoints = _kept_eps
    if _live_hosts or _live_endpoints:
        ctx.inject_recon_context(_live_hosts, _live_endpoints)
        _ok(
            f"Recon context injected: {len(_live_hosts)} hosts, {len(_live_endpoints)} endpoints → personalized TTP seeds"  # noqa: E501
        )

    # ── 5 / 6 / 6b. Dual-engine parallel analysis ────────────────────────────
    # Architecture:
    #   Engine A — OpenRouter (full mode, 344 TTPs in one shot, cloud model)
    #   Engine B — Local Ollama (tactic sweep, 14 focused passes, one per MITRE tactic)
    #
    # Both fire simultaneously via ThreadPoolExecutor.
    # Engine A is skipped when --no-cloud is set.
    # Engine B is skipped when ollama is not reachable.
    # Results from both engines are merged — the union of all unique seams.
    # If only one engine is available, that one runs alone (graceful degradation).
    _banner("Oracle Dual-Engine Analysis (OpenRouter + Local parallel)")
    import oracle_llm
    import textwrap as _tw
    from concurrent.futures import (
        ThreadPoolExecutor,
        as_completed as _as_completed,
        TimeoutError as _FuturesTimeout,
    )

    recon_text = _collect_recon(recon_dir, max_chars=20000, scope_gate=scope_gate)
    ttp_context = _map_ttps_to_recon(
        recon_dir, max_ttps=12, kind=(prog or {}).get("kind")
    )
    _kh = ((prog or {}).get("_hunt_filter") or {}).get("kept_hosts")
    asset_text = _collect_asset_context(
        ws.assets_dir, kept_hosts=set(_kh) if _kh else None
    )
    asset_block = asset_text if asset_text else "(no program assets downloaded)"

    target_base = f"https://{target}" if not target.startswith("http") else target
    live_f = recon_dir / "clean_live_hosts.txt"
    if not live_f.exists() or live_f.stat().st_size == 0:
        live_f = recon_dir / "live_hosts.txt"
    if live_f.exists() and live_f.stat().st_size > 0:
        # FIX 2026-10-01: blank lines (e.g. a 1-byte file holding only "\n")
        # made lines_live truthy while lines_live[0].split() was [] → IndexError.
        # Strip empties; fall back to the program target when nothing usable.
        lines_live = [
            ln.strip() for ln in live_f.read_text().splitlines() if ln.strip()
        ]
        if lines_live:
            target_base = lines_live[0].split()[0]

    # ── Shared task template ──────────────────────────────────────────────────
    def _reflex_task(tactic_focus: str = "") -> str:
        from oracle_foundation import INSTRUCTION_HIERARCHY_REMINDER as _IER
        from oracle_foundation import sanitize_prompt_text as _san_task
        from oracle_foundation import untrusted_block as _untrusted_task

        header = (
            f"TACTIC FOCUS: {tactic_focus}\n"
            f"Apply ONLY the {tactic_focus} techniques from your system prompt to this target.\n"
            if tactic_focus
            else "Run ALL 11 Oracle reflexes and ALL techniques in your system prompt.\n"
        )
        _regime = _lens_regime_block(args)
        _task_target = _san_task(target, 300, oneline=True)
        _task_recon = _untrusted_task(recon_text, "recon-data")
        _task_assets = _untrusted_task(asset_block, "program-assets")
        return _tw.dedent(
            f"""
            {header}
            {_regime}
            Target: {_task_target}
            Live Target Host: {target_base}

            A SEAM is a BINARY CONFLICT: two irreconcilable assertions where one must be false.
            A 401/403 response is NOT a seam — it confirms the boundary works.
            Only emit a card when wire behavior CONTRADICTS the claim.

            For each genuine seam output EXACTLY:

            **SEAM [N]**
            - Assertion A: [what docs/policy/UI explicitly claims]
            - Assertion A source: [exact in-scope URL or program asset containing Assertion A]
            - Assertion B: [what wire actually does — cite exact URL from RECON DATA]
            - Bug Type: [TYPE_1_CODE or TYPE_2_LOGIC]
            - Reflex: [Reflex N — NAME]
            - MITRE: [TTP code or N/A]
            - Frame: [paradox | impossible | iphone — required for the paradox/philosophy lens; omit for the technique lens]
            - Reproducible check: `curl -i -s [REAL URL from RECON DATA]`
            - Expected: status <NNN>[, body contains "<marker>"] — the wire result that PROVES Assertion B; MUST include a status code  # noqa: E501
            - Chain output: [optional exact value expected in this check's observed output]
            - Chain precondition: [optional exact value required from a prior confirmed finding]
            - Impact: [one sentence, real harm to a real user]

            HARD RULES:
            1. Every Assertion A MUST cite an exact source from RECON DATA or PROGRAM ASSETS below.
            2. Every check URL MUST appear verbatim in RECON DATA or PROGRAM ASSETS below.
            3. Do NOT emit a card for any surface returning 401/403/530.
            4. All surfaces genuinely clean → output exactly: TARGET CLEAN
            5. SCOPE LOCK: URL not on IN SCOPE domain → AUTOMATICALLY INVALID.
            6. Platform domain (bugcrowd.com, patchstack.com etc.) is NEVER a target.
            7. SCOPE NOT LOADED in system prompt → output TARGET CLEAN immediately.
            8. Expected field is MANDATORY and MUST include a status code (e.g. "status 200"). No status code = the card is INVALID and will be rejected by the verifier.  # noqa: E501
            9. DISCRIMINATE: the check MUST fail if Assertion A is true. BAD: check `curl -i -s <login page>`, expected `status 200, body contains "<page title>"` — the title renders whether auth works or not, so it proves NOTHING. GOOD: log in with observed creds, request ANOTHER user's object ID, and pin THEIR data in the marker. Vary identity (drop/swap tokens, cookies, IDs) and reuse observed credentials, IDs, and tokens from RECON DATA and wire output; fuzz every ID-like value.  # noqa: E501
            10. {_IER}

            Rank by harm: account takeover > data exposure > logic flaw > info leak.

            --- RECON DATA ---
            {_task_recon}

            --- DOWNLOADED PROGRAM ASSETS ---
            {_task_assets}

            {ttp_context}
        """
        ).strip()

    # ── Check which engines are available ────────────────────────────────────
    _llm_cfg = oracle_llm.load_backend_config()
    _ollama_up = oracle_llm.OllamaBackend(
        _llm_cfg.get("local_model", "devstral:24b")
    ).available()
    # All-sites launch: scoping is per-program, never a global bypass. `all`
    # iterates every registered platform source; each program still gets its
    # own scope intake, scope gate, and recon seeds. A program with no usable
    # scope is skipped loudly, never hunted against a bare-name fallback.
    _env = _load_env()
    # Honest cloud gate: any configured non-local lane counts (same route
    # complete() walks), not a hardcoded OpenRouter/NVIDIA key pair.
    _cloud_up = not no_cloud and oracle_llm.cloud_lane_available(_llm_cfg, _env)

    _info(
        f"Engines — Cloud lanes: {'✓ active' if _cloud_up else '✗ skipped (--no-cloud)' if no_cloud else '✗ no lane available'} | "  # noqa: E501
        f"Local ({_llm_cfg.get('local_model', 'devstral:24b')}): "
        f"{'✓ active' if _ollama_up else '✗ not reachable'}"
    )

    # Disclose-fix (P0): report the lenses that will actually execute, not
    # just the requested ones. P1: a --no-cloud hunt must RUN every requested
    # lens (paradox has a local Engine B pass) — a lens with no local engine
    # is a hard error here, never a silent drop.
    from oracle_mindsets import require_mindsets as _require_ms

    _effective = _require_ms(_profiles, _cloud_up, _ollama_up, local_only=no_cloud)
    if _effective != _profiles:
        # #25: a dropped lens is a hard error in EVERY mode — --no-cloud
        # already raises inside require_mindsets, and cloud mode dies
        # here. Proceeding short a lens on a mere warning violated the
        # equal-citizens doctrine: the hunt you get must be the hunt you
        # asked for, or no hunt at all.
        _dropped = [p for p in _profiles if p not in _effective]
        _seam_hint = (
            " — the deterministic seam feed alone is not the complete"
            " three-mindset product"
            if _effective == ["seam"]
            else ""
        )
        _die(
            f"Requested mindset(s) {', '.join(_dropped)} cannot run: no "
            f"engine is up for them (cloud={'up' if _cloud_up else 'down'}, "
            f"ollama={'up' if _ollama_up else 'down'}){_seam_hint}"
        )
    _ok(f"Effective mindsets: {', '.join(_effective)}")
    _runlog_event(
        "mindset.effective",
        requested=list(_profiles),
        effective=list(_effective),
        dropped=[p for p in _profiles if p not in _effective],
    )

    # Lane preflight (E0-3): refuses to spend budget on a hunt that would
    # starve mid-analysis when the reflex route is below the living-lane
    # floor. --no-cloud hunts declare a local-only regime up front, so the
    # gate bypasses them (their floor is the local lane, not the fleet).
    _living, _dead, _floor = oracle_llm.enforce_lane_preflight(
        "reflex", cfg=_llm_cfg, env=_env, no_cloud=no_cloud
    )
    _info(
        f"Preflight — reflex lanes living: {len(_living)} "
        f"(floor {_floor}); dead: {len(_dead)}"
    )

    # ── Build the futures ─────────────────────────────────────────────────────
    futures_meta: List[Dict] = []  # {future, label, origin}
    # Passes that cannot even be submitted (local fit failures) are
    # recorded here and merged into outcome accounting at collection —
    # never silently absent from the yield ledger.
    _presubmit_failed: List[Dict] = []
    executor = ThreadPoolExecutor(max_workers=16)

    # Deterministic engine observations are generated once and appended to
    # every dual-engine task — the same grounding run_reflexes() provides.
    # Without this, the cloud path analyzes recon text the deterministic
    # engine never re-observed.
    _det_block = _deterministic_block(recon_dir, scope_gate=scope_gate)
    _info("Deterministic findings block generated for dual-engine tasks")

    # ── Invisible Seam, generated BEFORE the lenses so BOTH reason WITH it ────
    # The code lens + template engine are deterministic. Running them first and
    # injecting their candidates into every lens context means the paradox lens
    # reasons with (philosophy + invisible seam) and the mitre lens with
    # (MITRE + invisible seam) — not blind, with the candidates bolted on after.
    # Mindset 3 synthesis then unifies both lenses ("one that runs from both").
    # #9: this is the ONLY run. The scans are pure functions of files on
    # disk, so §7/§7b below reuse these cached lists instead of re-running
    # the same scans (the old double-scan is gone; same inputs → same cards).
    _det_code_seams: List[Dict] = []
    _det_template_seams: List[Dict] = []
    _det_template_errors: List[Dict] = []  # #15: broken-template ledger
    _det_src = None
    _inv_seams: List[Dict] = []
    _seam_feed_ran = False
    # Owner spec: Mindset 1 and Mindset 2 both work WITH Invisible Seam.
    # The deterministic feed therefore runs for either LLM lens as well
    # as for Mindset 3; selecting one mindset never makes it seam-blind.
    if any(p in _profiles for p in ("mitre", "paradox", "seam")):
        _det_src = _src_early or _locate_target_source(
            name, getattr(args, "code", None), kept_repo_dirs=_kept_repo_dirs
        )
        _inv_src = _det_src
        # Source was expected when the operator gave --code or an early
        # source tree was located; then an unavailable pre-pass means the
        # requested seam lens cannot see — die BEFORE prompt assembly.
        # With no source expected (pure web target), an unavailable
        # pre-pass degrades loudly to an empty feed instead.
        _source_expected = bool(getattr(args, "code", None) or _src_early)
        _auth_param = (
            getattr(args, "auth", None)
            or getattr(args, "cookie", None)
        )
        _max_family = _resolve_max_cards_per_family(
            prog, _mindset_cfg, args
        )
        try:
            _raw_code, _raw_tpl, _raw_w3 = seam_prepass(
                repo_path=_inv_src if _inv_src else None,
                recon_dir=recon_dir,
                program=prog,
                scope_gate=scope_gate,
                errors=_det_template_errors,
                auth=_auth_param,
                max_per_family=_max_family,
            )
            _seam_feed_ran = True
        except SeamPrepassUnavailableError as _exc:
            if _source_expected:
                _die(
                    f"seam pre-pass unavailable for requested mindset(s) "
                    f"{', '.join(_profiles)} on {name}: {_exc}. Mindset 1 "
                    f"and Mindset 2 both require the Invisible Seam feed; "
                    f"provide --code or fix the seam engine."
                )
            _warn(
                f"seam pre-pass unavailable (no source expected): {_exc} "
                f"— continuing with empty seam feed (recorded)"
            )
            _raw_code, _raw_tpl, _raw_w3 = [], [], []
        for _cs in _raw_code:
            _cs["bug_type"] = TYPE_1
            _cs["mindset"] = "seam"
            _det_code_seams.append(_cs)
        for _ts in [*_raw_tpl, *_raw_w3]:
            _ts["bug_type"] = ctx.classify_seam(_ts)
            _ts["mindset"] = "seam"
            _det_template_seams.append(_ts)
        if _det_template_errors:
            _warn(
                "template hunt: "
                f"{len(_det_template_errors)} template(s) errored "
                f"({', '.join(e['tid'] for e in _det_template_errors)}) — "
                "coverage gap recorded in report"
            )
        _inv_seams = _det_code_seams + _det_template_seams
        if _seam_feed_ran:
            for _c in (ctx, _mitre_ctx):
                _c.inject_recon_context(_live_hosts, _live_endpoints)
                _c.inject_pending_seams(_inv_seams)
            _ok(
                f"invisible seam → injected into BOTH lenses (paradox + mitre): "
                f"{len(_inv_seams)} candidate(s)"
            )

    # Engine A — OpenRouter pass, once per selected LLM profile.
    #   mitre   → full 344-TTP technique lens
    #   paradox → full un-flattened corpus lens (compact TTP ref)
    # Each pass is tagged by origin so its seams carry the right mindset.
    if _cloud_up:
        for _profile in [p for p in _profiles if p in ("mitre", "paradox")]:
            # Per stated design above: mitre carries the full TTP library;
            # paradox carries the full corpus with a compact TTP reference.
            # Requesting "full" for paradox stacks both libraries (~285k
            # chars) and free lanes reject/timeout the pass into a
            # deadline drop — corpus ALL is unchanged either way.
            _pctx = OracleMindsetContext(
                program=prog,
                voice=True,
                ttp_mode="full" if _profile == "mitre" else "auto",
                mindset=_profile,
            )
            _pctx.inject_recon_context(_live_hosts, _live_endpoints)
            if _seam_feed_ran:
                _pctx.inject_pending_seams(_inv_seams)
            _prompt = _reflex_task() + "\n\n" + _det_block
            # Lens prompt packing: the full mitre/paradox systems run
            # 72-92k tokens and answering lanes returned empty/
            # unparseable cards at that size (Matomo 2026-10-27, both
            # lenses minted 0). Slice the library across passes under
            # the lens pass budget; every TTP/corpus document still
            # reaches the lens exactly once across its passes.
            _systems = _lens_systems_for(
                _pctx, _prompt, cfg=_llm_cfg, env=_env, no_cloud=False
            )
            for _slice_no, _psys in enumerate(_systems, 1):
                _suffix = "" if len(_systems) == 1 else f"-{_slice_no}"
                f_cloud = executor.submit(
                    oracle_llm.complete,
                    _prompt,
                    _psys,
                    "reflex",
                    360,  # total router budget per pass (< 420s collect deadline)
                    None,
                    None,
                    False,  # positional: prompt,system,task_type,timeout,cfg,env,no_cloud
                    return_model=True,
                )
                futures_meta.append(
                    {
                        "future": f_cloud,
                        "label": f"openrouter-{_profile}{_suffix}",
                        "origin": f"cloud-{_profile}{_suffix}",
                        "prompt": _prompt,
                        "system": _psys,
                        "no_cloud": False,
                    }
                )
            _info(
                f"Engine A (OpenRouter, {_profile} lens): "
                f"{len(_systems)} pass(es) submitted"
            )

    # Engine B — Local GENERATION passes, local-only hunts only (S5/S6):
    # multiple APIs are the primary engines and local is an additional
    # verification tool, so when cloud lanes are up local does not
    # co-generate — it second-votes after synthesis. Under --no-cloud
    # local is the only engine and keeps the all-mindsets bench
    # contract: tactic sweep (mitre lens, _mitre_ctx — pure
    # technique-indexed, no philosophy corpus) plus the paradox
    # corpus-lens pass, never silently dropping a requested lens.
    #
    # Phase 2.2 — per-tactic token budget: each local pass gets a 90s wall
    # clock timeout. A stalled 30b model (no tokens in 90s) raises a
    # BackendError or TimeoutError, which is caught by the outer _as_completed
    # loop and logged as a failed pass. The outer _COLLECT_BUDGET_S is the
    # global backstop; this inner budget prevents one silent stall from
    # blocking all 14 passes for 600s each.
    _ENGINE_B_TACTIC_TIMEOUT_S = 90  # per-tactic pass budget (seconds)
    _local_generates = _ollama_up and no_cloud
    if _ollama_up and not no_cloud:
        _info(
            "Engine B local generation demoted: cloud APIs primary — "
            "local second-votes after synthesis (S6)"
        )
    if _local_generates and "paradox" in _profiles:
        _par_local = OracleMindsetContext(
            program=prog, voice=True, ttp_mode="compact", mindset="paradox"
        )
        _par_local.inject_recon_context(_live_hosts, _live_endpoints)
        if _seam_feed_ran:
            _par_local.inject_pending_seams(_inv_seams)
        _par_task = _reflex_task() + "\n\n" + _det_block
        _local_ctx_tok = int(_llm_cfg.get("local_context_tokens", 16000))
        try:
            # Slice the ALL-corpus paradox prompt to the local window
            # (every corpus doc exactly once) instead of not submitting:
            # an unsubmitted lens with no outcome object starved yield
            # accounting while looking like a clean skip.
            _par_systems = _local_lens_systems(
                _par_local, _par_task, _local_ctx_tok
            )
        except RuntimeError as _fit_exc:
            _warn(
                f"Engine B (Local, paradox lens): NOT submitted — {_fit_exc}"
            )
            _presubmit_failed.append(
                {
                    "label": "local-paradox",
                    "origin": "local-paradox",
                    "reason": f"local fit: {_fit_exc}",
                    "prompt": _par_task,
                    "system": "",
                    "no_cloud": True,
                }
            )
            _par_systems = []
        for _pi, _par_sys in enumerate(_par_systems):
            _origin = (
                "local-paradox"
                if len(_par_systems) == 1
                else f"local-paradox-{_pi + 1}"
            )
            f_paradox = executor.submit(
                oracle_llm.complete,
                _par_task,
                _par_sys,
                "reflex",
                _ENGINE_B_TACTIC_TIMEOUT_S,
                None,
                None,
                True,  # no_cloud=True (local only)
                return_model=True,
            )
            futures_meta.append(
                {
                    "future": f_paradox,
                    "label": _origin,
                    "origin": _origin,
                    "prompt": _par_task,
                    "system": _par_sys,
                    "no_cloud": True,
                }
            )
        if _par_systems:
            _info(
                f"Engine B (Local, paradox lens): submitted "
                f"({len(_par_systems)} slice pass(es))"
            )
    if _local_generates and "mitre" in _profiles:
        all_tactics = _mitre_ctx.all_tactics()
        _local_ctx_tok = int(_llm_cfg.get("local_context_tokens", 16000))
        _submitted_tactics = 0
        for tactic in all_tactics:
            tactic_task = _reflex_task(tactic) + "\n\n" + _det_block
            try:
                # Fit-check every tactic pass and slice oversized tactics
                # (records exactly once) — an oversized prompt is never
                # submitted to be silently server-truncated.
                _budget = _local_ctx_tok - 1024
                _task_tok = estimate_tokens("", tactic_task)
                _max_chars = max(0, (_budget - _task_tok) * 4 - 8)
                if _max_chars <= 0:
                    raise RuntimeError(
                        f"task alone needs ~{_task_tok}tok of the "
                        f"{_budget}tok local budget"
                    )
                tactic_systems = _mitre_ctx.tactic_prompt_slices(
                    tactic, _max_chars
                )
                for _sys in tactic_systems:
                    _need = estimate_tokens(_sys, tactic_task)
                    if _need > _budget:
                        raise RuntimeError(
                            f"tactic slice need~{_need}tok exceeds local "
                            f"budget {_budget}tok"
                        )
            except RuntimeError as _fit_exc:
                _warn(
                    f"Engine B (Local, tactic {tactic}): NOT submitted "
                    f"— {_fit_exc}"
                )
                _presubmit_failed.append(
                    {
                        "label": f"local-{tactic}",
                        "origin": f"local-tactic:{tactic}",
                        "reason": f"local fit: {_fit_exc}",
                        "prompt": tactic_task,
                        "system": "",
                        "no_cloud": True,
                    }
                )
                continue
            for _ti, tactic_sys in enumerate(tactic_systems):
                _origin = (
                    f"local-tactic:{tactic}"
                    if len(tactic_systems) == 1
                    else f"local-tactic:{tactic}#{_ti + 1}"
                )
                f_tactic = executor.submit(
                    oracle_llm.complete,
                    tactic_task,
                    tactic_sys,
                    "reflex",
                    _ENGINE_B_TACTIC_TIMEOUT_S,
                    None,
                    None,
                    True,  # no_cloud=True (local only)
                    return_model=True,
                )
                futures_meta.append(
                    {
                        "future": f_tactic,
                        "label": f"local-{tactic}",
                        "origin": _origin,
                        "prompt": tactic_task,
                        "system": tactic_sys,
                        "no_cloud": True,
                    }
                )
            _submitted_tactics += 1
        _info(
            f"Engine B (Local, {_submitted_tactics}/{len(all_tactics)} "
            f"tactics submitted)"
        )

    if not futures_meta:
        _warn(
            "No analysis engines available — no cloud, no local. Skipping reflex pass."
        )
        raw = "[no backend produced output] no engines available"
        seams: List[Dict[str, Any]] = []
        _engine_models: List[str] = []
        _lens_outcomes: Dict[str, str] = {}
        _failed_passes: List[Dict] = []
        for _pf in _presubmit_failed:
            _lens_outcomes[_pf["origin"]] = "error"
            _failed_passes.append(_pf)
        _tactic_coverage = {"attempted": [], "returned": [], "dropped": []}
        _cage_rejected: List[Dict] = []
    else:
        # ── Collect results as they complete ─────────────────────────────────
        all_raw_results: List[tuple] = []  # (origin, raw_text)
        _engine_models = []  # "label:backend:model" per engine pass
        # Per-pass outcome (clean/empty/error/seams) + retry ledger for the
        # escalation ladder. Keys are engine origins (cloud-mitre,
        # local-tactic:*, local-paradox); failed passes keep their prompt
        # so L1 can resubmit the exact same pass.
        _lens_outcomes: Dict[str, str] = {}
        _failed_passes: List[Dict] = []  # {label, origin, reason, prompt, system, no_cloud}
        for _pf in _presubmit_failed:
            _lens_outcomes[_pf["origin"]] = "error"
            _failed_passes.append(_pf)
        # Overall deadline so slow engines (e.g. the 14 local tactic passes on a
        # 30B model) cannot block the whole hunt — proceed with whatever returned.
        _COLLECT_BUDGET_S = 420
        try:
            for fm in _as_completed(
                [m["future"] for m in futures_meta], timeout=_COLLECT_BUDGET_S
            ):
                meta = next(m for m in futures_meta if m["future"] is fm)
                try:
                    raw_out, model_id = fm.result()
                    all_raw_results.append((meta["origin"], raw_out))
                    _engine_models.append(f"{meta['label']}:{model_id}")
                    _ok(f"  {meta['label']}: response received (model: {model_id})")
                except Exception as e:
                    _lens_outcomes[meta["origin"]] = "error"
                    _failed_passes.append(
                        {
                            "label": meta["label"],
                            "origin": meta["origin"],
                            "reason": f"exception: {e}",
                            "prompt": meta.get("prompt", ""),
                            "system": meta.get("system", ""),
                            "no_cloud": meta.get("no_cloud", True),
                        }
                    )
                    _warn(f"  {meta['label']}: failed — {e}")
        except _FuturesTimeout:
            _dropped = [
                m
                for m in futures_meta
                if m["origin"]
                not in {o for o, _ in all_raw_results} | set(_lens_outcomes)
            ]
            for m in _dropped:
                _lens_outcomes[m["origin"]] = "error"
                _failed_passes.append(
                    {
                        "label": m["label"],
                        "origin": m["origin"],
                        "reason": f"collection deadline ({_COLLECT_BUDGET_S}s) hit",
                        "prompt": m.get("prompt", ""),
                        "system": m.get("system", ""),
                        "no_cloud": m.get("no_cloud", True),
                    }
                )
                try:
                    m["future"].cancel()
                except Exception:
                    pass
            _warn(
                f"  engine collection deadline ({_COLLECT_BUDGET_S}s) hit — "
                f"proceeding with {len(all_raw_results)} engine response(s); "
                f"dropped passes: {', '.join(m['label'] for m in _dropped) or 'none'}"
            )

        executor.shutdown(wait=False)

        # ── Parse and merge all results ───────────────────────────────────────
        seams = []
        _cage_rejected: List[Dict] = []
        for origin, raw_out in all_raw_results:
            _persist_raw_response(recon_dir, origin, raw_out)
            parsed = _parse_seams(raw_out, recon_dir=recon_dir)
            parsed, _cage_rej = _cage_admit_parsed(
                parsed, origin, scope_gate
            )
            _cage_rejected.extend(_cage_rej)
            if _cage_rej:
                _first = ""
                if _cage_rej[0]["reasons"]:
                    _first = _cage_rej[0]["reasons"][0]
                _warn(
                    f"  {origin}: cage rejected {len(_cage_rej)} card(s) — "
                    f"first reason: {_first}"
                )
            for s in parsed:
                s.setdefault("origin", origin)
            _outcome = _lens_outcome_after_cage(
                raw_out, parsed, _cage_rej
            )
            if pass_failed(_outcome):
                # Unparseable/off-format prose is a failed pass: keep it
                # OUT of _lens_outcomes so build_seam_sets sees the lens
                # as missing and the ladder rescues it (L1 verbatim
                # retry, then L2 widen) instead of crediting a lens
                # that produced nothing usable.
                _meta = next(
                    (m for m in futures_meta if m["origin"] == origin), {}
                )
                _all_rejected = bool(_cage_rej) and not parsed
                _fail_reason = (
                    f"cage rejected all {len(_cage_rej)} card(s)"
                    if _all_rejected
                    else f"unparseable response (outcome={_outcome})"
                )
                _failed_passes.append(
                    {
                        "label": _meta.get("label", origin),
                        "origin": origin,
                        "outcome": _outcome,
                        "reason": _fail_reason,
                        "prompt": _meta.get("prompt", ""),
                        "system": _meta.get("system", ""),
                        "no_cloud": _meta.get("no_cloud", True),
                    }
                )
                _warn(
                    f"  {origin}: {_fail_reason} "
                    f"({len(str(raw_out or ''))} chars) — failed pass, "
                    f"ladder will retry"
                )
            else:
                _lens_outcomes[origin] = _outcome
            seams = _merge_seams(seams, parsed)
        _outcome_line = ", ".join(
            f"{o}={_lens_outcomes.get(o, 'failed')}" for o, _ in all_raw_results
        )
        _info(f"Lens outcomes: {_outcome_line or 'no engine responses'}")
        # Attempted-vs-returned tactic account (recorded in the report).
        # The --no-cloud fatal check runs AFTER the ladder (below), so L1
        # retries get a chance to rescue drops before the hunt refuses.
        _tactic_coverage = tactic_coverage(futures_meta, _lens_outcomes)
        if _tactic_coverage["attempted"]:
            _ok(
                f"Tactic sweep: {len(_tactic_coverage['returned'])}/"
                f"{len(_tactic_coverage['attempted'])} tactics returned"
            )
            if _tactic_coverage["dropped"]:
                _warn(
                    "Tactic sweep dropped: "
                    + ", ".join(_tactic_coverage["dropped"])
                )

        # keep raw for the report (use cloud result if present, else first local)
        cloud_results_raw = [r for o, r in all_raw_results if "cloud" in o]
        raw = (
            cloud_results_raw[0]
            if cloud_results_raw
            else (all_raw_results[0][1] if all_raw_results else "[no output]")
        )
        _ok(
            f"{len(seams)} total seams from {len(all_raw_results)} engine passes "
            f"(cloud: {sum(1 for o, _ in all_raw_results if 'cloud' in o)} | "
            f"local: {sum(1 for o, _ in all_raw_results if 'local' in o)})"
        )
        _gear.mark("delayed")
        try:
            _write_lens_funnel(
                ws.reports_dir,
                outcomes=_lens_outcomes,
                raw_results=all_raw_results,
                recon_chars=len(recon_text),
                asset_chars=len(asset_text),
                effective=_effective,
                minted=len(seams),
            )
        except Exception as _lf_exc:  # diagnostics never kill the hunt
            _warn(f"lens funnel not written: {_lf_exc}")

    # Tag each seam with its bug type
    for s in seams:
        s.setdefault("origin", "recon-reflex")
        # Try to pull bug type from model output first, fall back to classifier
        bt_m = re.search(r"Bug Type[:\s]+([A-Z_1-9]+)", s.get("raw", ""))
        if bt_m and bt_m.group(1) in (TYPE_1, TYPE_2):
            s["bug_type"] = bt_m.group(1)
        else:
            s["bug_type"] = ctx.classify_seam(s)

    # ── 7. Code lens (Invisible Seam) — Type 1 engine ─────────────────────────
    # #9: reuse the single pre-pass run — no re-scan. Shallow copies keep
    # the merge's renumbering (n/attribution) off the injected copies, so
    # lens prompts render exactly what the pre-pass produced.
    # The seam feed already ran for Mindset 1/2 prompt grounding. Its
    # deterministic cards enter the unified candidate list only when
    # Mindset 3 is selected to synthesize them; in a single-lens hunt
    # they remain prompt feed, not a silently separate result lane.
    code_seams: List[Dict] = (
        [dict(c) for c in _det_code_seams] if "seam" in _profiles else []
    )
    src = _det_src
    if "seam" not in _profiles:
        _info(
            "seam mindset not selected — Invisible Seam feed stayed "
            "prompt-only for the selected lens(es); no Mindset 3 synthesis"
        )
    elif src:
        _banner(f"Code Lens / Type-1 Engine (Invisible Seam): {src.name}")
        # Bake seams into the mindset context so verify/PoC/chain passes
        # see them within the philosophy+scope wall, not after it
        ctx.inject_pending_seams(code_seams)
        _ok(
            f"code lens: {len(code_seams)} Type-1 seam(s) — single scan reused, injected into mindset context"
        )
    else:
        _info("no source on disk — Type-1 code lens skipped")

    # ── 7b. Template seam hunt — paradox/TTP-derived conflict shapes ─────────
    # Inverts the code lens: each impossible-problem/paradox move and each
    # MITRE tactic predicts a binary-conflict SHAPE, hunted deterministically
    # against recon material (web2) and repo source (code). No LLM, no
    # network — pure functions of material on disk. Candidates carry check
    # commands; the deterministic verifier promotes them.
    # #9: reuse the single pre-pass run (web3 already folded in) — no re-scan.
    template_seams: List[Dict] = (
        [dict(t) for t in _det_template_seams] if "seam" in _profiles else []
    )
    if "seam" in _profiles and template_seams:
        # inject_pending_seams overwrites: single call with the full set so
        # the model meets code-lens + template seams inside the box
        ctx.inject_pending_seams(code_seams + template_seams)
        _ok(
            f"template seams: {len(template_seams)} paradox/TTP-derived candidate(s) — single scan reused, in the box"
        )

    seams = _merge_seams(seams, code_seams + template_seams)

    # Apply mutation triggers from program_changes (Product.ai Kinetic Axiom)
    try:
        from oracle_scan4me import scan4me_db_path as _s4m_db_path

        _mutation_triggers = load_mutation_triggers(str(_s4m_db_path()), prog)
        if _mutation_triggers:
            apply_mutation_triggers(seams, _mutation_triggers)
            _ok(f"Mutation triggers active: {sorted(_mutation_triggers)} — "
                f"{sum(1 for s in seams if s.get('mutation_triggered'))} seam(s) marked for re-verification")
    except Exception as _mt_e:
        # Mutation triggers are best-effort; don't break the hunt
        _warn(f"Mutation trigger load failed (non-fatal): {_mt_e}")

    _ok(
        f"{len(seams)} total seam(s) from Wave 1 (Type-1: {sum(1 for s in seams if s.get('bug_type') == TYPE_1)} / "
        f"Type-2: {sum(1 for s in seams if s.get('bug_type') == TYPE_2)})"
    )
    _gear.mark("instant")
    _snapshot_seams(
        ws,
        seams,
        "wave1",
        target=name,
        requested_mindsets=list(_profiles),
        effective_mindsets=list(_effective),
        lens_outcomes=dict(_lens_outcomes),
        code_seams=len(code_seams),
        template_seams=len(template_seams),
    )

    # ── 7d. Escalation ladder: L1 retry failed passes, L2 widen engines ────
    # Fires only on a zero-seam Wave 1 with at least one engine up. Every
    # attempt is recorded (round/label/origin/outcome/seams_added) into
    # the report snapshot — a ladder with no ledger is a rumor.
    _escalation_record: Dict[str, Any] = {
        "triggered": False,
        "reason": "",
        "attempts": [],
    }
    # A dropped/errored LLM lens must be ladder-rescued even when the
    # deterministic template feed produced seams: template candidates do
    # not rescue a missing lens output object. If the ladder also fails,
    # synthesis proceeds short a lens and the hunt fails loud as
    # LENS-STARVED only after the report is preserved.
    _probe_sets = build_seam_sets(_effective, seams, _lens_outcomes)
    _missing_llm = [lens for lens, val in _probe_sets.items() if val is None]
    if seams and not _missing_llm:
        _escalation_record["reason"] = (
            f"{len(seams)} seam(s) already — ladder not needed"
        )
    elif not (_cloud_up or _ollama_up):
        _escalation_record["reason"] = "no engines available — cannot escalate"
    else:
        _escalation_record["triggered"] = True
        _escalation_record["reason"] = (
            f"missing LLM lens output: {', '.join(_missing_llm)}"
            if _missing_llm
            else "zero seams"
        )
        _banner(
            "Escalation Ladder — "
            + (
                f"missing lens ({', '.join(_missing_llm)}), rescuing the hunt"
                if _missing_llm
                else "zero seams, widening the hunt"
            )
        )

        def _ladder_complete(prompt, system, nc):
            # 170s total router budget fits the 180s ladder round budget;
            # lanes that already failed this run are skipped by the
            # router's circuit breaker instead of being re-walked.
            return oracle_llm.complete(
                prompt, system, "reflex", 170, None, None, nc, return_model=True
            )

        def _ladder_absorb(round_tag, level, spec, raw_out, model):
            _parsed = (
                _parse_seams(raw_out, recon_dir=recon_dir)
                if raw_out is not None
                else []
            )
            _parsed, _cage_rej = _cage_admit_parsed(
                _parsed, spec["origin"], scope_gate
            )
            _cage_rejected.extend(_cage_rej)
            if _cage_rej:
                _first_r = _cage_rej[0]["reasons"]
                _warn(
                    f"  {spec['origin']}: cage rejected "
                    f"{len(_cage_rej)} card(s) — first reason: "
                    f"{_first_r[0] if _first_r else 'unknown'}"
                )
            for _s in _parsed:
                _s.setdefault("origin", spec["origin"])
                if "bug_type" not in _s:
                    _bt = re.search(
                        r"Bug Type[:\s]+([A-Z_1-9]+)", _s.get("raw", "")
                    )
                    if _bt and _bt.group(1) in (TYPE_1, TYPE_2):
                        _s["bug_type"] = _bt.group(1)
                    else:
                        _s["bug_type"] = ctx.classify_seam(_s)
            if raw_out is not None:
                _lout = _lens_outcome_after_cage(
                    raw_out, _parsed, _cage_rej
                )
                if _cage_rej and not _parsed:
                    # Never leave "empty" in the ledger: build_seam_sets
                    # would count the lens as ran-clean. Missing = unserved.
                    _lens_outcomes.pop(spec["origin"], None)
                else:
                    _lens_outcomes[spec["origin"]] = _lout
            else:
                _lout = "error"
                _lens_outcomes[spec["origin"]] = "error"
            _before = len(seams)
            _merged = _merge_seams(seams, _parsed)
            _escalation_record["attempts"].append(
                {
                    "round": round_tag,
                    "level": level,
                    "label": spec["label"],
                    "origin": spec["origin"],
                    "outcome": _lout,
                    "model": model,
                    "seams_added": len(_merged) - _before,
                }
            )
            _ok(
                f"  {spec['label']}: {_lout} "
                f"(+{len(_merged) - _before} seams, model: {model})"
            )
            return _merged

        # L1: retry failed/dropped passes verbatim (same prompt, same engine).
        _l1_specs = [
            {
                "label": f"L1-retry-{p['label']}",
                "origin": p["origin"],
                "prompt": p["prompt"],
                "system": p.get("system", ""),
                "no_cloud": p.get("no_cloud", True),
            }
            for p in _failed_passes
            if p.get("prompt")
        ]
        if _l1_specs:
            _info(f"L1 retry: resubmitting {len(_l1_specs)} failed/dropped pass(es)")
            for _spec, _raw, _model in run_ladder_passes(_l1_specs, _ladder_complete):
                seams = _ladder_absorb("L1", "retry", _spec, _raw, _model)
                _engine_models.append(f"{_spec['label']}:{_model}")
        else:
            _info("L1 retry: no failed passes to retry (all passes returned)")
        # L2: widen — one full-lens pass per effective LLM lens, preferring
        # the engine that did NOT serve it in the main round.
        if not seams:
            _l2_specs = []
            _l2_prompt = _reflex_task() + "\n\n" + _det_block
            for _plan in plan_ladder_l2(
                _effective, futures_meta, _cloud_up, _ollama_up
            ):
                _lens, _eng = _plan["lens"], _plan["engine"]
                if _eng == "local" and not no_cloud:
                    # S6: with cloud lanes up, local never generates —
                    # not even as zero-seam widening. It second-votes.
                    _info(
                        f"L2 widen: skipping local {_lens} pass "
                        f"(cloud primary, local verify-only)"
                    )
                    continue
                _lctx = OracleMindsetContext(
                    program=prog,
                    voice=True,
                    ttp_mode="full" if (_eng == "cloud" and _lens == "mitre") else "auto",
                    mindset=_lens,
                )
                _lctx.inject_recon_context(_live_hosts, _live_endpoints)
                if _seam_feed_ran:
                    _lctx.inject_pending_seams(_inv_seams)
                # Same lens packing as Engine A: never resubmit the
                # unsliced 72-92k-token system on the widen path.
                try:
                    _l2_systems = _lens_systems_for(
                        _lctx,
                        _l2_prompt,
                        cfg=_llm_cfg,
                        env=_env,
                        no_cloud=_eng != "cloud",
                    )
                except RuntimeError as _l2_err:
                    _warn(
                        f"L2 widen: skipping {_eng} {_lens} pass — {_l2_err}"
                    )
                    continue
                for _l2_no, _l2_system in enumerate(_l2_systems, 1):
                    _l2_suffix = "" if len(_l2_systems) == 1 else f"-{_l2_no}"
                    _l2_specs.append(
                        {
                            "label": f"L2-widen-{_eng}-{_lens}{_l2_suffix}",
                            "origin": f"ladder-L2-{_eng}-{_lens}{_l2_suffix}",
                            "prompt": _l2_prompt,
                            "system": _l2_system,
                            "no_cloud": _eng != "cloud",
                        }
                    )
            if _l2_specs:
                _info(
                    f"L2 widen: {len(_l2_specs)} full-lens pass(es) "
                    f"({', '.join(s['label'] for s in _l2_specs)})"
                )
                for _spec, _raw, _model in run_ladder_passes(
                    _l2_specs, _ladder_complete
                ):
                    seams = _ladder_absorb("L2", "widen", _spec, _raw, _model)
                    _engine_models.append(f"{_spec['label']}:{_model}")
            else:
                _info("L2 widen: no effective LLM lens to widen")

    # Final tactic account after any ladder retries. Drops are fatal: a
    # partial sweep must never report as full.
    _tactic_coverage = tactic_coverage(futures_meta, _lens_outcomes)
    _raise_on_tactic_drops(_tactic_coverage, allow_incomplete=False)

    # ── 7b2. Per-lens red-team gates (S3): Mindset 1 and Mindset 2 (plus
    # pre-pass seam cards) are challenged separately BEFORE their results
    # go to Mindset 3. Rank-only: verdicts annotate candidates (Mindset 3
    # sees them in its seam block); nothing is dropped — the 5-gate
    # verifier stays the sole arbiter.
    for s in seams:
        if "mindset" not in s:
            s["mindset"] = mindset_of_origin(s.get("origin"))
    _pre_m3_verdicts, _pre_m3_counts = redteam_challenge_by_lens(
        seams,
        in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0]),
    )
    for s in seams:
        _pre_v = _pre_m3_verdicts.get(seam_candidate_key(s))
        if _pre_v:
            s["redteam_verdict"] = _pre_v
            s["pre_m3_redteam_verdict"] = _pre_v
    for _lens in ("mitre", "paradox", "seam"):
        _c = _pre_m3_counts.get(_lens)
        if _c:
            _ok(
                f"Red-team gate ({_lens}): {_c.get('confirmed', 0)} confirmed / "
                f"{_c.get('unreviewed', 0)} unreviewed / "
                f"{_c.get('rejected', 0)} rejected"
            )
    _snapshot_seams(
        ws,
        seams,
        "pre_synthesis",
        target=name,
        requested_mindsets=list(_profiles),
        effective_mindsets=list(_effective),
        lens_outcomes=dict(_lens_outcomes),
        pre_m3_redteam={k: dict(v) for k, v in _pre_m3_counts.items()},
        escalation=_escalation_record,
    )

    # ── 7c. Mindset 3: Invisible Seam & Adversarial Red-Team Synthesis ─────
    # Corroborates/ranks candidate seams from code lens, templates, and
    # MITRE/Paradox passes. Attacks candidates to bypass defensive
    # controls, discards noise, and formulates multi-step compound
    # exploit chains. M3 never mints brand-new seams: that is doctrine,
    # not an operator toggle.
    _m3_record: Dict[str, Any] = {
        "ran": False,
        "new_seams_allowed": False,
        "candidates_in": 0,
        "synth_out": 0,
        "kept": 0,
        "dropped_new": 0,
        "second_seam_pass": {"ran": False, "candidates": 0},
        "mindset3_gates": {"ran": False, "candidates": 0},
        "redteam_by_lens": {},
    }
    if "seam" in _profiles and (_cloud_up or _ollama_up):
        _banner("Mindset 3: Invisible Seam & Adversarial Red-Team Synthesis")
        try:
            seam_ctx = OracleMindsetContext(
                program=prog,
                voice=True,
                # M3 corroborates and chains M1/M2 cards — it does not re-enumerate
                # TTPs from scratch. Compact TTP reference is sufficient and keeps the
                # synthesis prompt well under 128k tokens even on large targets.
                ttp_mode="compact",
                mindset="seam",
            )
            seam_ctx.inject_recon_context(_live_hosts, _live_endpoints)
            # Mindset 3 is another Invisible Seam pass, this time over
            # Mindset 1/2's own cards: same-subject cards are marked
            # corroborated, conflicted, or single-lens before synthesis.
            # This annotated set feeds the synthesis prompt below
            # (inject_pending_seams); apply_mindset3_gates later re-runs
            # second_seam_pass over the POST-merge set (recorded separately
            # under "mindset3_gates"), so this call is not redundant with it.
            seams = second_seam_pass(seams)
            _m3_record["second_seam_pass"] = {
                "ran": True,
                "candidates": len(seams),
                "corroborated": sum(
                    1 for s in seams if s.get("m3_seam_state") == "corroborated"
                ),
                "conflicted": sum(
                    1 for s in seams if s.get("m3_seam_state") == "conflicted"
                ),
                "single_lens": sum(
                    1 for s in seams if s.get("m3_seam_state") == "single-lens"
                ),
            }
            # Mindset 3 sees EVERY candidate seam (S4) — no top-N cap and
            # no silent slice. When the full set cannot fit the smallest
            # viable lane, partition it into sequential batches: every
            # candidate is submitted exactly once with the full Mindset 3
            # system context, and batch outputs are corroborated below
            # against the complete candidate set.
            _corroboration_rule = (
                "5. NO-INVENTION RULE: emit cards ONLY for the pending "
                "candidate seams above (same subject/check-URL) — attack, "
                "corroborate, rank, and chain them, but do NOT mint "
                "brand-new seams on subjects no lens produced. A card on "
                "a new subject is dropped automatically.\n\n"
            )

            def _seam_task(batch_no: int = 999, batch_total: int = 999) -> str:
                return (
                    "INVISIBLE SEAM & ADVERSARIAL SYNTHESIS TASK:\n"
                    f"BATCH {batch_no}/{batch_total}: the pending seams above are this batch; candidates in other batches are preserved and merged after synthesis.\n"  # noqa: E501
                    "Review the pending candidate seams (from code, templates, and MITRE/Paradox passes) and live recon surface.\n"  # noqa: E501
                    "Act as the Lead Adversarial Synthesizer:\n"
                    "1. Actively discover bypasses for any defensive controls (tampered headers, verb tunneling, role confusion).\n"  # noqa: E501
                    "2. Find chained exploitation paths: how does output from one seam satisfy the precondition for another?\n"  # noqa: E501
                    "3. Discard theoretical or low-impact candidates.\n"
                    "4. Produce verified candidate seams with exact reproduction curl checks, expected status/body, and chain links.\n"  # noqa: E501
                    + _corroboration_rule
                    + _det_block
                )

            def _render_synthesis_call(batch):
                seam_ctx.inject_pending_seams(batch)
                return seam_ctx.system_prompt(), _seam_task()

            _base_system, _base_task = _render_synthesis_call([])
            _minimum_synth_need = estimate_tokens(_base_system, _base_task)
            _lane_limit = oracle_llm.smallest_viable_lane_limit(
                "reflex",
                cfg=_llm_cfg,
                env=_env,
                no_cloud=no_cloud,
                minimum_tokens=_minimum_synth_need,
            )
            _input_budget = _synthesis_input_budget(
                _lane_limit, _minimum_synth_need
            )
            if _lane_limit is None or _input_budget is None:
                raise RuntimeError(
                    "no viable synthesis lane fits the mandatory Mindset 3 "
                    f"base prompt (~{_minimum_synth_need}tok before candidates)"
                )
            _synthesis_batches = _plan_synthesis_batches(
                seams, _render_synthesis_call, budget_tokens=_input_budget
            )
            _m3_record["batching"] = {
                "smallest_viable_lane_limit": _lane_limit,
                "input_budget": _input_budget,
                "base_tokens": _minimum_synth_need,
                "response_reserve": _lane_limit - _input_budget,
                "batches": [len(batch) for batch in _synthesis_batches],
            }
            _info(
                "Mindset 3 synthesis packing: "
                f"{len(seams)} candidate(s) in {len(_synthesis_batches)} batch(es); "
                f"smallest viable lane {_lane_limit}tok, "
                f"input budget {_input_budget}tok"
            )
            rt_seams = []
            _rt_raw_parts = []
            _rt_models = []
            for _batch_no, _batch in enumerate(_synthesis_batches, 1):
                seam_ctx.inject_pending_seams(_batch)
                seam_sys = seam_ctx.system_prompt()
                seam_task = _seam_task(_batch_no, len(_synthesis_batches))
                _actual_need = estimate_tokens(seam_sys, seam_task)
                if _actual_need > _input_budget:
                    raise RuntimeError(
                        f"synthesis batch {_batch_no}/{len(_synthesis_batches)} "
                        f"need~{_actual_need}tok exceeds planned budget "
                        f"{_input_budget}tok"
                    )
                _info(
                    "Engine (Mindset 3 Adversarial Seam Synthesis) "
                    f"batch {_batch_no}/{len(_synthesis_batches)}: submitted"
                )
                _batch_raw, _batch_model = oracle_llm.complete(
                    seam_task,
                    seam_sys,
                    "reflex",
                    360,  # per-batch total router budget, as Engine A passes
                    None,
                    None,
                    no_cloud,
                    return_model=True,
                )
                _rt_raw_parts.append(_batch_raw or "")
                _rt_models.append(str(_batch_model))
                _batch_seams = _parse_seams(_batch_raw, recon_dir=recon_dir)
                for rts in _batch_seams:
                    rts["origin"] = (
                        "cloud-seam-synth" if not no_cloud else "local-seam-synth"
                    )
                    rts["mindset"] = "seam"
                    bt_m = re.search(
                        r"Bug Type[:\s]+([A-Z_1-9]+)", rts.get("raw", "")
                    )
                    if bt_m and bt_m.group(1) in (TYPE_1, TYPE_2):
                        rts["bug_type"] = bt_m.group(1)
                    else:
                        rts["bug_type"] = ctx.classify_seam(rts)
                rt_seams.extend(_batch_seams)
            rt_raw = "\n\n".join(_rt_raw_parts)
            rt_model = ", ".join(dict.fromkeys(_rt_models)) or "unknown"
            _ok(f"Mindset 3 Adversarial Seam Synthesis completed (model: {rt_model})")
            _m3_record["ran"] = True
            _m3_record["candidates_in"] = len(seams)
            _m3_record["synth_out"] = len(rt_seams)
            # No-invention gate: keep only seams on known subjects unless
            # invention was explicitly permitted for this run.
            _kept, _dropped = corroborate_synth_seams(
                rt_seams, seams, allow_new=False
            )
            _m3_record["kept"] = len(_kept)
            _m3_record["dropped_new"] = len(_dropped)
            if _kept:
                _ok(
                    f"Mindset 3 corroborated {len(_kept)}/{len(rt_seams)} "
                    f"synth seam(s)"
                    + (
                        f" — dropped {len(_dropped)} brand-new "
                        f"(M3 never invents)"
                        if _dropped
                        else ""
                    )
                )
                seams = _merge_seams(seams, _kept)
            elif _dropped:
                _warn(
                    f"Mindset 3 dropped {len(_dropped)} brand-new synth seam(s) "
                    f"— no lens produced those subjects; M3 never invents"
                )
            else:
                _info("Mindset 3 synthesis produced no new cards")
        except Exception as e:
            # Same law as a dead lens (2026-10-25): a failed synthesis
            # pass must not incinerate wire-verifiable candidates before
            # verify/report exist. Record the failure, mark the seam
            # lens unserved at yield accounting, and let the hunt fail
            # loud AFTER the report is preserved.
            _m3_record["synthesis_failed"] = f"{type(e).__name__}: {e}"
            _lens_outcomes[
                "local-seam-synth" if no_cloud else "cloud-seam-synth"
            ] = "error"
            _warn(
                f"Mindset 3 Adversarial Synthesis failed — continuing to "
                f"wire verification short the synth pass; this hunt will "
                f"fail as LENS-STARVED after the report: {e}"
            )

    # Mindset tagging + Mindset 3 synthesis (triangulation). LLM seams take
    # their mindset from the engine origin; deterministic seams already carry
    # mindset="seam". synthesize_seams unifies both lenses' outputs + the seam
    # feed into one ranked list (corroborated_by + agreement + red-team
    # verdict are ranking/confidence metadata ONLY — the 5-gate verifier stays
    # the sole arbiter and runs on every candidate; nothing is dropped here).
    for s in seams:
        if "mindset" not in s:
            s["mindset"] = mindset_of_origin(s.get("origin"))
    # Mindset 3 gates: run the second Invisible Seam pass over the
    # merged Mindset 1/2 + synth/feed cards, then run MORE red teaming
    # as a fresh per-lens challenge over every card. Mindset 1/2 cards
    # keep their pre-M3 verdict in pre_m3_redteam_verdict, but synthesis
    # ranks on this final verdict because only the second seam pass can
    # see cross-lens contradictions.
    # apply_mindset3_gates re-runs second_seam_pass internally over the
    # post-merge card set (synth seams were merged in above), so this is a
    # SEPARATE pass from the conditional one at the M3 synthesis block — its
    # stats go under their own key and must NOT clobber the conditional
    # "second_seam_pass" record (which honestly reports whether that gated
    # block ran). Overwriting it would misreport "ran": True even when the
    # seam profile was unselected or engines were down.
    seams, _redteam_verdicts, _m3_rt_counts = apply_mindset3_gates(
        seams,
        in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0]),
    )
    _m3_record["mindset3_gates"] = {
        "ran": True,
        "candidates": len(seams),
        "corroborated": sum(
            1 for s in seams if s.get("m3_seam_state") == "corroborated"
        ),
        "conflicted": sum(
            1 for s in seams if s.get("m3_seam_state") == "conflicted"
        ),
        "single_lens": sum(
            1 for s in seams if s.get("m3_seam_state") == "single-lens"
        ),
    }
    _m3_record["redteam_by_lens"] = _m3_rt_counts
    # Structural: build the synthesis input from SELECTED lenses (_effective),
    # not from observed keys — a lens that ran clean contributes [] and a
    # lens that produced no output object contributes None, which
    # synthesize_seams refuses loudly instead of unifying short a lens.
    _seam_sets = build_seam_sets(_effective, seams, _lens_outcomes)
    _missing_lenses = [lens for lens, val in _seam_sets.items() if val is None]
    if _missing_lenses:
        # A dead/refused lens must not incinerate the surviving lenses'
        # wire-verifiable candidates before verify/report exist. The hunt
        # still fails loud — at _die_on_unserved_mindsets AFTER
        # _finalize_verify preserves the report (owner law 2026-10-25:
        # fail loud, report preserved; bundle gate also refuses readiness
        # while unserved_mindsets is non-empty).
        _warn(
            f"synthesize input: lens(es) {', '.join(_missing_lenses)} produced "
            f"no output object — unifying short a lens; this hunt will "
            f"fail as LENS-STARVED after the report is preserved"
        )
        _seam_sets = {
            lens: (val if val is not None else [])
            for lens, val in _seam_sets.items()
        }
    _rt_counts = {"confirmed": 0, "rejected": 0, "unreviewed": 0}
    for _v in _redteam_verdicts.values():
        _rt_counts[_v] = _rt_counts.get(_v, 0) + 1
    _ok(
        f"Red-team challenge: {len(_redteam_verdicts)} candidate(s) reviewed "
        f"({_rt_counts.get('confirmed', 0)} confirmed / "
        f"{_rt_counts.get('unreviewed', 0)} unreviewed / "
        f"{_rt_counts.get('rejected', 0)} rejected)"
    )
    seams = synthesize_seams(_seam_sets, redteam_verdicts=_redteam_verdicts)
    _agree = sum(1 for s in seams if int(s.get("agreement", 1)) >= 2)
    _ok(
        f"Cross-compare: {len(seams)} candidate(s), {_agree} corroborated by ≥2 mindsets"
    )

    # Local second vote (S6): local is an additional verification tool,
    # not a co-primary generator. One bounded collaborate() packet over
    # the top-ranked synthesized seams; the local private_reviewer vote
    # is recorded per packet seam and in hunt meta (readers below), and
    # never confirms/rejects/drops a candidate — the wire verifier
    # still decides. This replaces the cut #17 pass, whose per-seam
    # model_reviews output had zero readers.
    _sv_record: Dict[str, Any] = {"ran": False, "status": "not-run", "seams": 0}
    # Availability is rechecked AT VOTE TIME: the hunt-start probe goes
    # stale over a long hunt (hunt5 recorded local-unavailable with no
    # log line while ollama was in fact up). Every branch logs one
    # outcome line and persists the record — never silent.
    _sv_local_up = (
        oracle_llm.OllamaBackend(
            _llm_cfg.get("local_model", "devstral:24b"),
            context_tokens=int(_llm_cfg.get("local_context_tokens", 16000)),
        ).available()
        if seams
        else False
    )
    # The packet review is multi-role (Databricks scout, OmniCLI
    # adversary, local private): a down local lane must not silence
    # the cloud roles. Run when any role lane can answer; each role's
    # own status is recorded in the record below.
    if seams and (_sv_local_up or _cloud_up):
        _sv_system = OracleMindsetContext(
            program=prog, mindset="seam"
        ).reporting_prompt()
        # Half-budget packet: collaborate's private prompt re-embeds the
        # packet plus scout/adversary outputs, so a full-window packet
        # overflows the local reviewer's own vote (hunt2 second-vote
        # FAILED this way). Reserve the other half for those outputs.
        _sv_packet, _sv_included = oracle_llm.build_second_vote_packet(
            seams,
            _sv_system,
            int(_llm_cfg.get("local_context_tokens", 16000)) // 2,
        )
        if _sv_packet:
            try:
                _sv = oracle_llm.collaborate(
                    _sv_packet,
                    _sv_system,
                    cfg=_llm_cfg,
                    env=_env,
                    no_cloud=no_cloud,
                )
                _sv_local = _sv.get("private_reviewer", {})
            except Exception as e:
                _sv_local = {
                    "status": "failed",
                    "error": f"{type(e).__name__}: {e}",
                }
            _sv_status = str(_sv_local.get("status", "unavailable"))
            _sv_record = {
                "ran": True,
                "status": _sv_status,
                "seams": len(_sv_included),
                "model": _sv_local.get("model"),
                "error": _sv_local.get("error"),
                "roles": {
                    _role: {
                        "status": _r.get("status"),
                        "backend": _r.get("backend"),
                        "model": _r.get("model"),
                    }
                    for _role, _r in (locals().get("_sv") or {}).items()
                },
            }
            for _idx in _sv_included:
                seams[_idx]["local_second_vote"] = _sv_status
                if _sv_local.get("output"):
                    seams[_idx]["local_second_vote_output"] = _sv_local["output"]
            _sv_adv = (_sv_record.get("roles") or {}).get("adversary", {})
            _ok(
                f"Local second vote: {_sv_status} over top "
                f"{len(_sv_included)}/{len(seams)} seam(s) "
                f"[scout=databricks adversary=omnicli:{_sv_adv.get('status')} "
                f"private=local:{_sv_status}] "
                f"(packet-level; wire verifier still decides)"
            )
        else:
            _sv_record = {"ran": False, "status": "packet-overflow", "seams": 0}
            _warn(
                "Local second vote: no seam card fits the local context "
                "window — vote skipped (recorded, never truncated silently)"
            )
    elif seams:
        _sv_record = {"ran": False, "status": "no-role-lane-available", "seams": 0}
        _warn(
            "Local second vote: no role lane available at vote time "
            "(local down, cloud down) — skipped "
            "(recorded in hunt meta, never silent)"
        )
    if RICH and seams:
        tbl = Table(show_header=True, title="Seams — ranked by harm")
        tbl.add_column("#")
        tbl.add_column("Rank")
        tbl.add_column("Type")
        tbl.add_column("Reflex")
        tbl.add_column("Assertion A")
        tbl.add_column("Assertion B")
        tbl.add_column("Check")
        for s in seams:
            bt_label = "T1" if s.get("bug_type") == TYPE_1 else "T2"
            tbl.add_row(
                str(s["n"]),
                str(s.get("synthesis_rank", "")),
                bt_label,
                s["reflex"][:18],
                s["assertion_a"][:36],
                s["assertion_b"][:36],
                f"`{s['check'][:45]}`",
            )
        console.print(tbl)
    elif seams:
        for s in seams:
            bt = "T1-Code" if s.get("bug_type") == TYPE_1 else "T2-Logic"
            _rk = s.get("synthesis_rank")
            _rk_txt = f" [rank {_rk}]" if _rk else ""
            print(f"\n[{s['n']}]{_rk_txt} [{bt}] {s['reflex']}")
            print(f"  A: {s['assertion_a']}")
            print(f"  B: {s['assertion_b']}")
            print(f"  Check: {s['check']}")
            print(f"  Impact: {s['impact']}")

    # ── 8. Dual-account harness — wire --account-a / --account-b ─────────────
    _auth = getattr(args, "auth", None)
    _cookie = getattr(args, "cookie", None)
    _acct_a = getattr(args, "account_a", None)
    _acct_b = getattr(args, "account_b", None)

    _auto_prov = getattr(args, "auto_provision", None)
    if _acct_a or _acct_b or getattr(args, "prompt_login", False) or _auto_prov:
        try:
            from oracle_auth_session import DualAccountHarness

            _researcher = getattr(args, "researcher", None) or prog.get(
                "researcher_handle", ""
            )
            harness = DualAccountHarness(
                target_domain=target,
                platform=prog.get("platform", "generic") if prog else "generic",
                researcher_username=_researcher or None,
            )
            if _acct_a:
                harness.account_a.token = (
                    _acct_a
                    if _acct_a.lower().startswith("bearer ")
                    else f"Bearer {_acct_a}"
                )
            if _acct_b:
                harness.account_b.token = (
                    _acct_b
                    if _acct_b.lower().startswith("bearer ")
                    else f"Bearer {_acct_b}"
                )
            if getattr(args, "prompt_login", False):
                harness.prompt_credentials()
            # Wall gap 4.2: auto-register both accounts when no manual
            # tokens were given — provisioned JWTs flow into _auth,
            # build_idor_probes, and the saved session below.
            if _auto_prov and not (_acct_a or _acct_b):
                from oracle_auth_session import auto_provision_accounts

                _minted = auto_provision_accounts(harness, _auto_prov)
                _ok(
                    "Auto-provisioned 2 IDOR accounts at"
                    f" {_auto_prov} (tokens: {len(_minted)}/2)"
                )
            # Inject Account A token as the primary auth for verify probes
            if harness.account_a.token and not _auth:
                _auth = harness.account_a.token
            # Add IDOR probe seams from cross-account surface — C1: scope-gated
            # against the hunt scope gate with recon-verified hosts only.
            _recon_hosts_for_idor: list = []
            try:
                for _rf in ("clean_live_hosts.txt", "live_hosts.txt"):
                    _rp = recon_dir / _rf
                    if _rp.exists() and _rp.stat().st_size > 0:
                        _recon_hosts_for_idor = [
                            host_line.split()[0]
                            for host_line in _rp.read_text().splitlines()
                            if host_line.strip()
                        ][:20]
                        break
            except Exception:
                _recon_hosts_for_idor = []
            idor_probes = (
                harness.build_idor_probes(
                    seams, scope_gate=scope_gate, recon_hosts=_recon_hosts_for_idor
                )
                if hasattr(harness, "build_idor_probes")
                else []
            )
            if idor_probes:
                _ok(f"DualAccountHarness: {len(idor_probes)} IDOR probe(s) generated")
                # IDOR probes are minted after synthesis (the dual-account
                # session exists only here) — they still pass the final
                # red-team challenger before verify, ranked after the
                # synthesized set. Nothing reaches the wire unreviewed.
                for _p in idor_probes:
                    _p.setdefault("mindset", mindset_of_origin(_p.get("origin")))
                _idor_verdicts = redteam_challenge(
                    idor_probes,
                    in_scope=lambda u: bool(scope_gate.is_in_scope(u)[0]),
                )
                _redteam_verdicts.update(_idor_verdicts)
                _rank_base = max(
                    (int(s.get("synthesis_rank", 0) or 0) for s in seams),
                    default=0,
                )
                for _i, _p in enumerate(idor_probes, 1):
                    _p["redteam_verdict"] = _idor_verdicts.get(
                        seam_candidate_key(_p), "unreviewed"
                    )
                    _p.setdefault("agreement", 1)
                    _p["synthesis_rank"] = _rank_base + _i
                seams = seams + idor_probes
            # Persist session so tokens survive across runs — no re-entry needed
            harness.save_session(ws.recon_dir)
            _ok(f"Session saved → {ws.recon_dir / 'sessions.json'}")
        except Exception as e:
            _warn(f"DualAccountHarness setup failed: {e} — continuing single-account")

    _snapshot_seams(
        ws,
        seams,
        "pre_verify",
        target=name,
        requested_mindsets=list(_profiles),
        effective_mindsets=list(_effective),
        lens_outcomes=dict(_lens_outcomes),
        tactic_coverage=_tactic_coverage,
        mindset3=_m3_record,
        second_vote=_sv_record,
    )

    # ── 9. Interactive verify ─────────────────────────────────────────────────
    verify = getattr(args, "verify", True)
    auto = getattr(args, "auto", False)
    confirmed_seams: Dict[int, Dict] = {}

    def _is_static_code_card(s: Dict) -> bool:
        # Static repo-evidence cards confirm on localized extractor
        # evidence, never on the wire: invisible-seam cards and
        # grep-check template cards. Sending grep through the wire
        # scope gate (URL required) killed this class unconditionally.
        return s.get("origin") == "invisible-seam" or str(
            s.get("check", "")
        ).lstrip().startswith("grep ")

    recon_only = [s for s in seams if not _is_static_code_card(s)]
    code_only = [s for s in seams if _is_static_code_card(s)]

    _verify_started = time.monotonic()
    _runlog_event(
        "verify.start",
        candidates=len(recon_only) + len(code_only),
        wire_candidates=len(recon_only),
        code_candidates=len(code_only),
        verify=bool(verify),
        auto=bool(auto),
    )
    if recon_only and verify:
        _banner("Interactive Verify (recon lens)")
        _funnel_mined = len(recon_only)
        confirmed_seams = verify_seams(
            recon_only,
            name,
            recon_dir,
            model=model,
            auto=auto,
            scope_gate=scope_gate,
            is_testnet=is_testnet,
            auth=_auth,
            cookie=_cookie,
            no_cloud=no_cloud,
        )
        _write_funnel_artifact(
            ws, confirmed_seams, _funnel_mined, len(recon_only) - _funnel_mined
        )
    if any(s.get("reframed") for s in recon_only):
        _gear.mark("breakthrough")
    for s in code_only:
        confirmed_seams[s["n"]] = {
            "seam": s,
            "check": s.get("check", ""),
            "output": s.get("check_output", ""),
            "verdict": s.get("verdict", ""),
            # Static code-lens verdicts are never promoted to confirmed on the
            # label alone — confirmation requires executed wire evidence AND
            # a valid binary card (A vs B must actually conflict).
            "confirmed": s.get("verdict") in ("RESOLVED", "CERTAIN")
            and bool((s.get("check_output") or "").strip())
            and validate_card_shape(s) is None,
        }
    _runlog_event(
        "verify.complete",
        candidates=len(recon_only) + len(code_only),
        confirmed=sum(1 for v in confirmed_seams.values() if v.get("confirmed")),
        duration_s=round(time.monotonic() - _verify_started, 3),
    )

    # Rebuild downstream prompts AFTER recon/seam injections and BEFORE
    # variant sweep / finalize: the strings captured at hunt start predate
    # inject_recon_context / inject_pending_seams (both reset the ctx
    # prompt cache), so sweep, PoC, and report legs must reason from the
    # current prompt for both paradox and mitre.
    mindset_sys = ctx.system_prompt()
    mindset_compact_sys = ctx.reporting_prompt()
    mindset_sys_by_lens["paradox"] = mindset_sys
    mindset_sys_by_lens["mitre"] = _mitre_ctx.system_prompt()

    # ── 9b. Variant sweep (phase 2): confirmed bug → same issue class on the
    # remaining in-scope assets. Runs through the FULL-program scope gate
    # (those assets are in program scope, just outside the phase-1 filter).
    # Sweep hits merge into confirmed_seams so _finalize_verify reports them.
    if _hf.get("variant_sweep") and _full_prog and (prog or {}).get("_hunt_filter"):
        _sweep_plan = variant_sweep_plan(confirmed_seams, _full_prog, prog or {}, _hf)
        if _sweep_plan:
            _sweep_gate = ProgramScopeGate(_full_prog, target_fallback=target)
            _sweep_hits = _run_variant_sweep(
                _sweep_plan,
                _sweep_gate,
                name,
                recon_dir,
                model=model,
                auto=auto,
                auth=_auth,
                cookie=getattr(args, "cookie", None),
                is_testnet=is_testnet,
                no_cloud=no_cloud,
                mindset_system=mindset_sys,
                mindset_system_by_lens=mindset_sys_by_lens,
            )
            for _k, _v in _sweep_hits.items():
                confirmed_seams[_k] = _v
            _ok(f"Variant sweep: {len(_sweep_hits)} confirmed on remaining assets")
            _gear.mark("recalled")
        else:
            # LOW: say exactly why there is nothing to sweep — these are
            # different situations, not one ambiguous "no probes".
            _d = getattr(_sweep_plan, "diagnosis", {}) or {}
            if not _d.get("confirmed_parents"):
                _info("Variant sweep: no confirmed phase-1 findings to sweep from")
            elif not _d.get("remaining_assets"):
                _info(
                    "Variant sweep: no remaining in-scope assets outside the phase-1 filter"
                )
            elif not _d.get("retargetable_checks"):
                _info(
                    f"Variant sweep: confirmed findings have no retargetable host "
                    f"({_d.get('skipped_static', 0)} static/code finding(s) skipped)"
                )
            else:
                _info("Variant sweep: no retargetable probes for remaining assets")

    # ── 9-12. Shared post-verify pipeline (persist, PoC, chains, correlation, report)
    # Compute yield before finalize so the verify-results snapshot carries the
    # unserved-mindset truth. The product bundle reads this snapshot and must
    # never call a lens-starved hunt ready.
    _yield_ledger: List[Dict[str, Any]] = []
    _yield_lines = None
    _yield_unserved: List[str] = []
    # Accounting boundary: every submitted pass origin must carry an
    # outcome. Failed passes were withheld from _lens_outcomes during
    # collection (ladder semantics); completing the map here keeps a
    # withheld slice from vanishing out of the yield aggregation.
    _submitted_passes = (
        list(futures_meta or [])
        + [f for f in (_failed_passes or []) if isinstance(f, dict)]
        + [
            a
            for a in ((_escalation_record or {}).get("attempts") or [])
            if isinstance(a, dict)
        ]
    )
    _completed_outcomes = complete_lens_outcomes(
        dict(_lens_outcomes or {}), _submitted_passes
    )
    try:
        from oracle_mindsets import (
            mindset_yield_ledger as _mindset_yield_ledger,
            sut_format_lines as _yield_lines,
            yield_unserved as _yield_unserved_f,
        )

        # Regime receipts from observed evidence only: the count is
        # recon live-host lines explicitly tagged [200] (responses this
        # hunt's recon actually served — recon ran with the hunt's
        # configured auth), and session_regime requires both configured
        # auth materials and at least one such observed 200. A bare
        # credential string, discovered-URL line counts, and host
        # counts prove nothing and receipt nothing.
        from oracle_mindsets import build_regime_receipts as _build_receipts

        _regime_receipts = _build_receipts(
            _effective,
            auth_configured=bool(
                _effective_recon_auth(args) or getattr(args, "cookie", None)
            ),
            served_200=_served_200_hosts,
        )
        _yield_ledger = _mindset_yield_ledger(
            _effective,
            list(seams or []),
            dict(_completed_outcomes or {}),
            regime_receipts=_regime_receipts,
        )
        _yield_unserved = _yield_unserved_f(_yield_ledger)
        if _m3_record.get("synthesis_failed") and "seam" in (_effective or []):
            # The M3 LLM synthesis pass itself failed: deterministic feed
            # cards minting under "seam" do not retroactively serve it.
            if "seam" not in _yield_unserved:
                _yield_unserved = list(_yield_unserved) + ["seam"]
    except Exception as _yle:  # noqa: BLE001
        # Fail closed: accounting failure proves no lens served. (This
        # once left _yield_unserved=[] and minted readiness downstream.)
        _yield_unserved = list(_effective or [])
        _warn(f"Mindset yield accounting failed (all lenses unserved): {_yle}")
    # Per-code / per-slice coverage ledgers: the denominators behind the
    # yield verdicts, persisted for audit and summarized into hunt meta.
    _lens_coverage: Dict[str, Any] = {"status": "unknown"}
    try:
        _all_passes = list(_submitted_passes or [])
        _mitre_ledger = mitre_coverage_ledger(
            _mitre_ctx._load_ttps(),
            _all_passes,
            dict(_completed_outcomes or {}),
            list(seams or []),
        )
        _paradox_ledger = slice_coverage_ledger(
            _all_passes, dict(_completed_outcomes or {}), "paradox"
        )
        _coverage_doc = {
            "schema": "oracle.lens-coverage/v1",
            "mitre": _mitre_ledger,
            "paradox": _paradox_ledger,
            "tactic_coverage": _tactic_coverage,
        }
        (ws.base / "reports" / "lens_coverage_ledger.json").write_text(
            json.dumps(_coverage_doc, indent=1), encoding="utf-8"
        )
        # Feed manifest: which owner-required feeds actually reach each
        # mindset this hunt (present/source/size/known loss), persisted
        # beside the coverage ledger it explains.
        _seam_manifest_ctx = OracleMindsetContext(
            program=dict(_full_prog) if isinstance(_full_prog, dict) else {},
            ttp_mode="compact",
            mindset="seam",
        )
        _seam_manifest_ctx.inject_pending_seams(list(seams or []))
        _feed_doc = {
            "schema": "oracle.hunt-feed-manifests/v1",
            "mitre": _mitre_ctx.feed_manifest(),
            "paradox": ctx.feed_manifest(),
            "seam": _seam_manifest_ctx.feed_manifest(),
        }
        (ws.base / "reports" / "feed_manifests.json").write_text(
            json.dumps(_feed_doc, indent=1), encoding="utf-8"
        )
        _lens_coverage["feed_manifests"] = {
            k: bool(v.get("complete")) for k, v in _feed_doc.items() if k != "schema"
        }
        _lens_coverage = {
            "status": "recorded",
            "mitre_total": _mitre_ledger["total"],
            "mitre_complete": _mitre_ledger["complete"],
            "paradox_complete": _paradox_ledger["complete"],
            "report": "reports/lens_coverage_ledger.json",
        }
        _runlog_event("lens.coverage", **_lens_coverage)
    except Exception as _cle:  # noqa: BLE001
        _warn(f"Lens coverage ledger failed: {_cle}")
    _hunt_meta: Dict[str, Any] = {
        "requested_mindsets": list(_profiles),
        "effective_mindsets": list(_effective),
        "unserved_mindsets": list(_yield_unserved),
        "yield_ledger": list(_yield_ledger),
        "lens_coverage": _lens_coverage,
        "feed_trust": _chain_feed_trust,
        "oracle_rescan": _chain_rescan,
        "hunt_scope": _hunt_scope_stamp_value,
        "lens_outcomes": dict(_completed_outcomes),
        "tactic_coverage": _tactic_coverage,
        "template_errors": list(_det_template_errors),
        "cage_rejected": list(_cage_rejected),
        "escalation": _escalation_record,
        "m3": _m3_record,
        "local_second_vote": _sv_record,
        "redteam": {
            "subjects_reviewed": len(_redteam_verdicts),
            "confirmed": sum(1 for v in _redteam_verdicts.values() if v == "confirmed"),
            "unreviewed": sum(1 for v in _redteam_verdicts.values() if v == "unreviewed"),
            "rejected": sum(1 for v in _redteam_verdicts.values() if v == "rejected"),
        },
    }
    _finalize_started = time.monotonic()
    _runlog_event(
        "finalize.start",
        candidates=len(seams or []),
        confirmed=sum(1 for v in confirmed_seams.values() if v.get("confirmed")),
    )
    finalized = _finalize_verify(
        confirmed_seams,
        seams,
        name,
        ws,
        recon_dir=recon_dir,
        raw_analysis=raw,
        no_cloud=no_cloud,
        mindset_system=mindset_sys,
        mindset_compact=mindset_compact_sys,
        mindset_system_by_lens=mindset_sys_by_lens,
        chain_seams_fn=ctx.chain_seams,
        model_info="; ".join(_engine_models) if _engine_models else None,
        is_testnet=is_testnet,
        hunt_meta=_hunt_meta,
    )
    cloud_results = finalized["cloud_results"]
    _runlog_event(
        "finalize.complete",
        report=str(finalized.get("report") or ""),
        cloud_results=len(cloud_results or {}),
        correlation=bool(
            isinstance(finalized.get("correlation"), dict)
            and finalized["correlation"].get("summary")
        ),
        duration_s=round(time.monotonic() - _finalize_started, 3),
    )

    if cloud and seams and not cloud_results:
        _banner("Cloud Escalation (no verify pass — top 3 seams)")
        for s in seams[:3]:
            result = _cloud_escalate(
                s["raw"],
                name,
                no_cloud=no_cloud,
                mindset_system=_lens_prompt_for(
                    s, mindset_sys, mindset_sys_by_lens
                ),
                mindset_compact=mindset_compact_sys,
            )
            cloud_results[s["n"]] = result
            if RICH:
                console.print(Panel(result[:2000], title=f"Seam {s['n']} — Cloud PoC"))
            else:
                print(f"\n=== Seam {s['n']} Cloud PoC ===\n{result[:2000]}")

    # Final report, findings, PoC, chains and correlation are all handled by
    # _finalize_verify above; cloud_results here only gains cloud-escalation
    # entries when nothing confirmed.
    _n_confirmed = sum(
        1 for v in confirmed_seams.values() if v.get("confirmed")
    )
    # Full-service law (user, 2026-10-21): every effective mindset owes the
    # run cards. Yield lines print ALWAYS; unserved mindsets get named in
    # the failure banner, so a context-only lens can never hide again.
    if _yield_lines is not None:
        for _yl in _yield_lines(_yield_ledger):
            _info(_yl)
    _gear_line = _gear.summary(_n_confirmed)
    # The law is causal, not cosmetic: unserved mindsets FORCE the failure
    # verdict even when confirmations alone would read green.
    if _yield_unserved and "SYSTEM FAILURE" not in _gear_line:
        _gear_line = (
            "SYSTEM FAILURE: " + _gear_line
            + f" — mindsets unserved: {', '.join(_yield_unserved)}"
        )
        _warn(_gear_line)
    elif "SYSTEM FAILURE" in _gear_line:
        if _yield_unserved:
            _gear_line += f" — mindsets unserved: {', '.join(_yield_unserved)}"
        _warn(_gear_line)
    else:
        _ok(_gear_line)
    _report_path = finalized.get("report")
    _runlog_event(
        "hunt.complete",
        program=name,
        candidates=len(seams or []),
        confirmed=_n_confirmed,
        requested_mindsets=list(_profiles),
        effective_mindsets=list(_effective),
        unserved_mindsets=list(_yield_unserved),
        report=str(_report_path) if _report_path else None,
        gear=_gear_line,
        lens_outcomes=dict(_lens_outcomes or {}),
        tactic_coverage=_tactic_coverage,
        redteam=dict((_hunt_meta or {}).get("redteam") or {}),
        m3=_m3_record,
        local_second_vote=_sv_record,
    )
    if _report_path:
        _runlog_artifact(
            _report_path,
            "verify_results",
            program=name,
            candidates=len(seams or []),
            confirmed=_n_confirmed,
        )
    for _p in (
        ws.base / "program.json",
        ws.base / "program_brief.md",
        ws.base / "hunt_scope.json",
    ):
        if _p.is_file():
            _runlog_artifact(_p, _p.name, program=name)

    # Owner law escalated (2026-10-25): unserved mindsets fail the hunt
    # process itself, after _finalize_verify has preserved the report.
    _die_on_unserved_mindsets(_yield_unserved)
    return {
        "workspace": str(ws.base),
        "confirmed": _n_confirmed,
        "report": str(_report_path) if _report_path else None,
    }


def _audit_executed_seams(seams: List[Dict]) -> List[Dict]:
    """Seams eligible for compound modeling on the audit path.

    Mirrors the hunt path's confirmation rule: a static Invisible Seam
    verdict (RESOLVED/CERTAIN/...) is never enough on its own — the seam
    must also carry non-empty executed check_output. Everything else is a
    candidate, never "confirmed".
    """
    return [
        s
        for s in seams
        if s.get("verdict") in ("RESOLVED", "CERTAIN")
        and (s.get("check_output") or "").strip()
    ]


def cmd_audit(repo_dir: str, args) -> None:
    """Audit a codebase or repository for contract seams and security contradictions."""
    repo = Path(repo_dir).resolve()
    if not repo.exists() or not repo.is_dir():
        _die(f"Repository not found or is not a directory: {repo_dir}")

    _banner(f"Oracle Code Seam Audit — {repo.name}")
    from oracle_code_seam import (
        scan_repository_seams,
        print_seam_cards,
        generate_code_audit_report,
    )

    _info(
        f"Extracting specification contracts and analyzing AST implementations in {repo}…"
    )
    seams = list(scan_repository_seams(repo))
    from oracle_seam_templates import scan_template_seams

    tpl_seams = scan_template_seams(
        repo_path=repo,
        scope_gate=ProgramScopeGate({}, target_fallback="http://127.0.0.1"),
    )
    for ts in tpl_seams:
        seams.append({**ts, "n": len(seams) + 1})
    _ok(f"{len(seams)} code seam(s) identified")
    print_seam_cards(seams)

    correlation_report = None
    # Compound modeling only over seams whose deterministic check actually
    # executed (check_output present) — static labels alone are candidates.
    confirmed_seams = _audit_executed_seams(seams)

    no_cloud = _apply_no_cloud(args)
    cloud = getattr(args, "cloud", None)
    if cloud is None:
        import oracle_llm

        cfg = oracle_llm.load_backend_config()
        env = _load_env()
        cloud = bool(env.get("OPENROUTER_API_KEY")) or cfg.get("local_enabled", True)

    # --no-cloud still runs compound modeling, but local-only (fail-closed
    # when no local backend answers); it never silently calls cloud.
    if (cloud or no_cloud) and len(confirmed_seams) >= 2:
        _banner(f"Compound Threat Modeling ({len(confirmed_seams)} confirmed seams)")
        from oracle_mindset_context import OracleMindsetContext

        _audit_mindset = OracleMindsetContext(program=None, voice=False).system_prompt()
        correlation_report = _correlate_seams(
            confirmed_seams, repo.name, no_cloud=no_cloud, mindset_system=_audit_mindset
        )
        if correlation_report and correlation_report.get("summary"):
            if RICH:
                console.print(
                    Panel(
                        correlation_report["summary"],
                        title="Compound Architectural Threat",
                    )
                )
            else:
                print(
                    f"\n=== Compound Architectural Threat ===\n{correlation_report['summary']}"
                )

    report_text = generate_code_audit_report(
        repo.name, seams, compound_report=correlation_report
    )
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = REPORTS_DIR / f"audit_{repo.name}.md"
    report_file.write_text(report_text, encoding="utf-8")
    _ok(f"Audit report saved to: {report_file}")


# Whole files or no grounding: truncating a source block silently shifts
# every line number after the cut, so citations would ground against a
# truncation artifact instead of the real file. Sources over this cap are
# refused loudly (same 200k budget as `omni swarm --source-file`).
ORACLE_AUDIT_SOURCE_CAP = 200_000


def _read_whole_source_file(path: Path) -> str:
    content = path.read_text(encoding="utf-8", errors="replace")
    if len(content) > ORACLE_AUDIT_SOURCE_CAP:
        raise ValueError(
            f"Refusing to ground against a truncated {path.name} "
            f"({len(content):,} chars exceeds the {ORACLE_AUDIT_SOURCE_CAP:,} "
            "cap): line numbers would not match the real file. Scope a "
            "smaller target instead."
        )
    return content


_AUDIT_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".php",
    ".rb", ".c", ".cpp", ".h", ".hpp", ".java", ".sh", ".bash",
    ".sql", ".json", ".yaml", ".yml", ".toml", ".html", ".css", ".md",
    ".sol", ".move", ".cairo",
}
_AUDIT_IGNORED_DIRS = {
    ".git", "__pycache__", "venv", ".venv", "env", "node_modules",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "dist", "build",
    ".egg-info", ".idea", ".vscode", "artifacts", "cache",
}
_AUDIT_SENSITIVE_RE = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|\.netrc|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|"
    r"credentials?(?:\..*)?|secrets?(?:\..*)?|passwords?(?:\..*)?)$"
    r"|\.(?:pem|key|p12|pfx|jks|keystore|kdbx)$",
    re.IGNORECASE,
)
# `token(s)` as a bare stem is a credential container only for data files
# (token.json, token.txt). In source extensions it is the audit subject
# itself (Token.sol, token.py), and the operator explicitly targeted this
# directory — silently skipping the main contract would gut the audit.
_AUDIT_TOKEN_DATA_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".txt", ".md", ""}


def _is_audit_sensitive(rel: str) -> bool:
    if _AUDIT_SENSITIVE_RE.search(rel):
        return True
    name = rel.rsplit("/", 1)[-1]
    stem, dot, suffix = name.partition(".")
    return (
        stem.lower() in ("token", "tokens")
        and (f".{suffix.lower()}" if dot else "") in _AUDIT_TOKEN_DATA_SUFFIXES
    )


def _embed_directory_sources(target_dir: Path) -> str:
    """Embed a directory target's sources WHOLE as labeled source blocks.

    A bare ``Directory: <path>`` line gives the red-team swarm nothing to
    ground on (it refuses to run without source blocks), so a local
    directory target must ship its files. Whole files only, deterministic
    order, credential-like names excluded, symlink escapes skipped, and
    the combined size refuses loudly over the same 200k cap instead of
    truncating (truncation forges line numbers).
    """
    base = target_dir.resolve()
    blocks = []
    total = 0
    for current_root, dirs, files in os.walk(base):
        dirs[:] = sorted(
            d for d in dirs
            if not d.startswith(".") and d not in _AUDIT_IGNORED_DIRS
        )
        for name in sorted(files):
            if name.startswith("."):
                continue
            fpath = Path(current_root) / name
            if fpath.suffix.lower() not in _AUDIT_SOURCE_EXTENSIONS:
                continue
            rel = str(fpath.relative_to(base)).replace("\\", "/")
            if _is_audit_sensitive(rel):
                continue
            if fpath.is_symlink():
                try:
                    if not fpath.resolve().is_relative_to(base):
                        continue
                except OSError:
                    continue
            content = _read_whole_source_file(fpath)
            if not content.strip():
                continue
            total += len(content)
            if total > ORACLE_AUDIT_SOURCE_CAP:
                raise ValueError(
                    f"Refusing to ground a red-team audit against a "
                    f"truncated directory: {base} sources exceed the "
                    f"{ORACLE_AUDIT_SOURCE_CAP:,}-char cap (>{total:,} with "
                    f"{rel}). Scope a smaller target instead."
                )
            blocks.append(f"\n### Source file: {rel}\n```\n{content}\n```\n")
    return "".join(blocks)


def build_redteam_audit_prompt(target: str, finding: Optional[str] = None) -> str:
    """Build the red-team audit prompt for a target, finding, or code file.

    File and seams content is embedded WHOLE as ``### Source file: <path>``
    fenced blocks — the exact shape OmniCLI's evidence gate requires (see
    ``omnicli.evidence._SOURCE_BLOCK``). Without at least one such block,
    ``swarm_redteam`` refuses to run (no-sources early-FAIL). Oversized
    sources raise instead of truncating: grounding against a truncation
    artifact forges line numbers.
    """
    target_path = Path(target)
    prompt_context = f"Target: {target}\n"

    # If target is a directory or file, inspect it
    if target_path.exists():
        if target_path.is_file():
            content = _read_whole_source_file(target_path)
            prompt_context += (
                f"\n### Source file: {target_path.name}\n"
                f"```\n{content}\n```\n"
            )
        elif target_path.is_dir():
            seams_file = target_path / "seams.json"
            if seams_file.exists():
                prompt_context += f"\n### Source file: {seams_file.name}\n```json\n{_read_whole_source_file(seams_file)}\n```\n"  # noqa: E501
            else:
                # Ground on the directory's actual local sources; a bare
                # path line alone leaves the swarm nothing to review.
                embedded = _embed_directory_sources(target_path)
                if embedded:
                    prompt_context += embedded
                else:
                    prompt_context += f"\nDirectory: {target_path.resolve()}\n"

    if finding:
        prompt_context += f"\nSpecific Finding / Assertion:\n{finding}\n"

    return (
        f"Perform an adversarial red-team security assessment and triage critique of the following Oracle bug bounty target:\n"  # noqa: E501
        f"{prompt_context}\n"
        f"Rigorously evaluate:\n"
        f"1. Is this vulnerability grounded and reproducible, or a false positive / LLM hallucination?\n"
        f"2. Does it infer server-side flaws solely from client-side UI behavior?\n"
        f"3. Scope check: Could this exploit affect out-of-scope assets or violate program rules?\n"
        f"4. Submission readiness: Would a professional bug bounty triage team (HackerOne/Bugcrowd) accept, duplicate, or reject this finding?\n"  # noqa: E501
        f"Separate all findings into PROVEN vs PLAUSIBLE, and provide clear triage remediations."
    )


def format_council_verdict(gate) -> "tuple[str, str]":
    """Render OmniCLI's assessed council conclusion for a red-team run.

    Pure (no I/O, no imports): takes the run's ``evidence_gate`` mapping and
    returns ``(text, severity)`` with severity one of ``findings`` (upheld
    findings need verification), ``clear`` (assessed negative over judged
    candidates only), or ``blocked`` (no assessable verdict — the run must
    not be treated as submission-ready).
    """
    gate = gate if isinstance(gate, dict) else {}
    conclusion = gate.get("security_conclusion", "NOT_ASSESSED")
    counts = gate.get("verdict_counts")
    lines = [
        f"Security conclusion: {conclusion}",
        f"Evidence gate: {gate.get('status', 'FAIL')}",
    ]
    if isinstance(counts, dict):
        lines.append(
            f"Verdicts: upheld {counts.get('uphold', 0)} / "
            f"killed {counts.get('kill', 0)} / "
            f"contested {counts.get('contested', 0)} / "
            f"unjudged {counts.get('unjudged', 0)}"
        )
    else:
        lines.append("Verdicts: none recorded")
    for item in gate.get("security_evidence") or []:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- {item.get('verdict')}: {item.get('category')} "
            f"(`{item.get('file')}:{item.get('line')}`) "
            f"`{item.get('quote')}`"
        )
    if conclusion == "UPHELD_FINDINGS":
        severity = "findings"
    elif conclusion == "NO_UPHELD_FINDINGS":
        severity = "clear"
        lines.append(
            "Assessed negative over the judged candidates only — "
            "not proof of safety."
        )
    else:
        severity = "blocked"
        lines.append(
            "WARNING: no assessable council verdict — do NOT treat this run "
            "as submission-ready."
        )
    return "\n".join(lines), severity


def _print_council_verdict(gate) -> None:
    """Display the assessed council conclusion; fail loud, never silent."""
    text, severity = format_council_verdict(gate)
    if RICH:
        console.print(
            Panel(
                text,
                title="[bold]Council Security Verdict[/bold]",
                border_style=("yellow" if severity == "clear" else "red"),
            )
        )
    else:
        print("\n=== Council Security Verdict ===\n")
        print(text)
    _flush()


def cmd_redteam(target: str, args) -> None:
    """Execute OmniCLI's multi-model adversarial red-team audit on a target, finding, or code."""
    _banner(f"Oracle Adversarial Red-Team Swarm — Target: {target}")

    try:
        from oracle_llm import ensure_omnicli_importable

        if not ensure_omnicli_importable():
            raise ImportError("no OmniCLI checkout found (see omnicli_home())")
        from omnicli.config import ConfigManager
        from omnicli.client import OmniClient
        from omnicli.orchestrate import build_swarm, run_orchestration
        from omnicli.scanner import classify_family
        try:
            from omnicli.router import ProviderRouter
        except ImportError:  # older OmniCLI checkout
            ProviderRouter = None
    except ImportError as e:
        _die(f"OmniCLI engine not found or failed to load: {e}")

    finding = getattr(args, "finding", None)
    try:
        audit_prompt = build_redteam_audit_prompt(target, finding)
    except (OSError, ValueError) as e:
        _die(str(e))

    cfg = ConfigManager()
    client = OmniClient(cfg)
    if ProviderRouter is not None:
        # Health-ranked, capped, family-diverse panel: do not fan a red-team
        # audit out to every configured key, including balance-gated ones.
        swarm = ProviderRouter(cfg).build_panel()
    else:
        swarm = build_swarm(cfg)
    if not swarm:
        _die("No swarm members are configured (run 'omni scan' first).")
    families = sorted({classify_family(model) for _, model in swarm})
    _info(
        f"Deploying {len(swarm)}-model adversarial swarm "
        f"across {', '.join(families)}…"
    )

    res = run_orchestration(
        "redteam",
        cfg,
        client,
        audit_prompt,
        max_tokens=1024,
        swarm=swarm,
        report_path=REPORTS_DIR,
    )

    if RICH:
        console.print(
            Panel(
                res.get("final", "No consensus generated"),
                title="[bold red]Consolidated Adversarial Red-Team Findings[/bold red]",
                border_style="red",
            )
        )
    else:
        print("\n=== Consolidated Adversarial Red-Team Findings ===\n")
        print(res.get("final", "No consensus generated"))

    _print_council_verdict(res.get("evidence_gate"))

    if res.get("report_path"):
        _ok(f"Red-team audit report saved to: {res['report_path']}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def main():
    global _ACTIVE_RUNLOG, _JSON_STDOUT

    parser = argparse.ArgumentParser(
        description="Oracle Hunter — Bug Bounty Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--prescan",
        action="store_true",
        help="P11: fast Scan4Me sweep → prescan report (raw, untrusted). "
        "For --limit/--no-cloud use: oracle-hunter prescan --help",
    )
    sub = parser.add_subparsers(dest="cmd")

    # prescan (P11 step 1)
    p_prescan = sub.add_parser(
        "prescan", help="P11: fast Scan4Me sweep → prescan report (raw, untrusted)"
    )
    p_prescan.add_argument("--limit", type=int, default=50)
    p_prescan.add_argument(
        "--sync",
        action="store_true",
        help="Refresh Scan4Me DB from platforms first (network; refused under --no-cloud)",
    )
    p_prescan.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Allow network I/O for the sweep (default)",
    )
    p_prescan.add_argument(
        "--no-cloud", dest="cloud", action="store_false", help="Offline: local DB only"
    )
    p_prescan.add_argument("--out-dir", default=None, help="Report directory")

    # scan (P11 steps 2+3: verify pass, then -N/--sites deep-dive + P12 handoff)
    p_scan = sub.add_parser(
        "scan", help="P11: verify a prescan → scan report + P12 handoff"
    )
    p_scan.add_argument(
        "--prescan-file", default=None, help="Prescan report (default: latest)"
    )
    p_scan.add_argument(
        "-N",
        "--top-n",
        type=int,
        default=None,
        dest="top_n",
        help="Deep-dive the top N VERIFIED programs (named --sites override this)",
    )
    p_scan.add_argument(
        "--sites",
        default=None,
        help="Comma-separated program names/handles to deep-dive (overrides -N; must be verified)",
    )
    p_scan.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Allow network probes for the scope-live check (default)",
    )
    p_scan.add_argument(
        "--no-cloud",
        dest="cloud",
        action="store_false",
        help="Offline: skip liveness probes (scope-live fails closed)",
    )
    p_scan.add_argument(
        "--probe-timeout", type=float, default=8.0, help="Seconds per liveness probe"
    )
    p_scan.add_argument(
        "--download",
        action="store_true",
        help="Download one workspace per selected VERIFIED program "
        "(targets/<platform>/<slug>/) before writing the handoff",
    )
    p_scan.add_argument(
        "--cdp-port",
        type=int,
        default=None,
        dest="cdp_port",
        help="Signed-in Chrome CDP port for --download "
        "(default: ORACLE_CDP_PORT or 9227)",
    )
    p_scan.add_argument("--out-dir", default=None, help="Report directory")
    p_scan.add_argument(
        "--config", default=None, help="Config file (default: oracle.config.json)"
    )

    # bundle (product gate: report + findings + PoCs + SHA-256 manifest)
    p_bundle = sub.add_parser(
        "bundle", help="Package a hunt workspace into a verifiable product bundle"
    )
    p_bundle.add_argument("workspace", help="Path to targets/<platform>/<slug>")
    p_bundle.add_argument(
        "--out-dir",
        default=None,
        help="Where to write product_<stamp>/ and .zip (default: <workspace>/reports)",
    )

    # verify-download (offline integrity + submission-readiness gate)
    p_vd = sub.add_parser(
        "verify-download",
        help="Verify a product bundle's SHA-256 manifest and readiness gate",
    )
    p_vd.add_argument("bundle", help="Path to product_<stamp>.zip or its directory")
    p_vd.add_argument(
        "--json", action="store_true", help="Print the verification result as JSON"
    )

    # queue (P12: order a P11 handoff into a deterministic work list)
    p_queue = sub.add_parser(
        "queue", help="P12: schedule a P11 handoff → ordered work list"
    )
    p_queue.add_argument(
        "--handoff", default=None, help="Handoff report (default: latest)"
    )
    p_queue.add_argument(
        "--order",
        default=None,
        choices=["finish-site", "round-robin"],
        help="Site order (default: queue.order from config, else finish-site)",
    )
    p_queue.add_argument(
        "--concurrent",
        dest="concurrent",
        action="store_true",
        default=None,
        help="Cross-site parallelism on (default: queue.concurrent from config)",
    )
    p_queue.add_argument(
        "--sequential",
        dest="concurrent",
        action="store_false",
        help="Cross-site parallelism off (sequential within a site, always)",
    )
    p_queue.add_argument(
        "--cross-site-cap",
        type=int,
        default=None,
        dest="cross_site_cap",
        help="Max parallel sites when concurrent (default: config, else 3)",
    )
    p_queue.add_argument(
        "--execute",
        action="store_true",
        help="Execute the schedule after building it: ensure each item's "
        "workspace, then hunt it (wave order, cap, resumable state file)",
    )
    p_queue.add_argument(
        "--max-items",
        type=int,
        default=None,
        dest="max_items",
        help="With --execute: attempt at most N items this run",
    )
    p_queue.add_argument(
        "--no-resume",
        dest="resume",
        action="store_false",
        help="With --execute: ignore prior state and re-hunt done items",
    )
    p_queue.add_argument(
        "--skip-download",
        dest="skip_download",
        action="store_true",
        help="With --execute: do not ensure workspaces before hunting",
    )
    p_queue.add_argument(
        "--controlled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Controlled (low-rate) recon for executed hunts (default: on)",
    )
    p_queue.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Allow cloud backends for executed hunts (default: auto)",
    )
    p_queue.add_argument(
        "--no-cloud",
        dest="cloud",
        action="store_false",
        help="Force local model only for executed hunts",
    )
    p_queue.add_argument("--model", default=LOCAL_MODEL)
    p_queue.add_argument("--researcher", default=None)
    p_queue.add_argument(
        "--testnet",
        action="store_true",
        help="With --execute: testnet safe-mode for executed hunts",
    )
    p_queue.add_argument(
        "--code",
        default=None,
        help="With --execute: on-disk source tree passed to executed hunts",
    )
    p_queue.add_argument(
        "--code-only",
        dest="code_only",
        action="store_true",
        default=None,
        help="With --execute: hunts skip live recon/download (code lens only)",
    )
    # M4: executed hunts inherit this auth material (secret sources only,
    # resolved by main(); queued hunts stay unattended — no prompt-login).
    p_queue.add_argument(
        "--auth",
        help="Auth secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_queue.add_argument(
        "--cookie",
        help="Cookie secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_queue.add_argument(
        "--account-a",
        help="Account A (Victim) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_queue.add_argument(
        "--account-b",
        help="Account B (Attacker / IDOR) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_queue.add_argument(
        "--cdp-port",
        type=int,
        default=None,
        dest="cdp_port",
        help="Signed-in Chrome CDP port for workspace downloads "
        "(default: ORACLE_CDP_PORT or 9227)",
    )
    p_queue.add_argument("--out-dir", default=None, help="Report directory")
    p_queue.add_argument(
        "--config", default=None, help="Config file (default: oracle.config.json)"
    )

    # list
    p_list = sub.add_parser("list", help="List programs from cache")
    p_list.add_argument("--refresh", action="store_true")
    p_list.add_argument("--min-payout", type=int, default=0, dest="min_payout")
    p_list.add_argument("--platform")
    p_list.add_argument("--fast-triage", action="store_true", dest="fast_triage")
    p_list.add_argument("--web2", action="store_true")
    p_list.add_argument("--web3", action="store_true")
    p_list.add_argument("--top", type=int, default=50)

    # hunt
    p_hunt = sub.add_parser("hunt", help="Full pipeline: recon → Oracle → verify → PoC")
    p_hunt.add_argument(
        "program",
        help="Program name or URL. Pipeline runs use prescan → scan → queue.",
    )
    p_hunt.add_argument(
        "--controlled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Low-rate recon: cap crawl pressure, skip content fuzzing, and "
        "health-check the target (default: on; use --no-controlled to disable)",
    )
    p_hunt.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Use OpenRouter / cloud model (default: auto if OPENROUTER_API_KEY set)",
    )
    p_hunt.add_argument(
        "--no-cloud", dest="cloud", action="store_false", help="Force local model only"
    )
    p_hunt.add_argument("--model", default=LOCAL_MODEL)
    p_hunt.add_argument(
        "--auto", action="store_true", help="Auto-confirm seams without prompting"
    )
    p_hunt.add_argument(
        "--testnet",
        action="store_true",
        help="Permit state mutations on testnet/staging targets",
    )
    p_hunt.add_argument(
        "--auth",
        help="Auth secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_hunt.add_argument(
        "--cookie",
        help="Cookie secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_hunt.add_argument(
        "--code",
        help="Path to the target's on-disk source tree (enables the Invisible Seam code lens)",
    )
    p_hunt.add_argument(
        "--code-only",
        dest="code_only",
        action="store_true",
        help="Skip live recon and live asset download entirely; code lens on "
        "local source only. For programs forbidding automated live testing. "
        "Requires --code or a workspace-cloned repo",
    )
    p_hunt.add_argument(
        "--account-a",
        help="Account A (Victim) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_hunt.add_argument(
        "--account-b",
        help="Account B (Attacker / IDOR) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_hunt.add_argument(
        "--prompt-login",
        action="store_true",
        help="Prompt for live website login/session tokens for Account A & B",
    )
    p_hunt.add_argument(
        "--auto-provision",
        default=None,
        metavar="REGISTER_URL",
        help="Auto-register the 2 IDOR test accounts at this registration endpoint (JWTs extracted automatically)",
    )
    p_hunt.add_argument(
        "--researcher",
        default=None,
        help="Researcher handle for compliance headers (e.g. H1/Bugcrowd username)",
    )

    # verify
    p_verify = sub.add_parser(
        "verify", help="Interactively verify seams from a recon dir"
    )
    p_verify.add_argument("recon_dir", help="Path to recon dir with existing analysis")
    p_verify.add_argument("--model", default=LOCAL_MODEL)
    p_verify.add_argument(
        "--auto", action="store_true", help="Auto-run all checks without prompting"
    )
    p_verify.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Use OpenRouter / cloud model for verify & PoC",
    )
    p_verify.add_argument(
        "--no-cloud", dest="cloud", action="store_false", help="Force local model only"
    )
    p_verify.add_argument(
        "--testnet",
        action="store_true",
        help="Permit state mutations on testnet/staging targets",
    )
    p_verify.add_argument(
        "--auth",
        help="Auth secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_verify.add_argument(
        "--cookie",
        help="Cookie secret source, never a literal secret: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_verify.add_argument(
        "--account-a",
        help="Account A (Victim) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_verify.add_argument(
        "--account-b",
        help="Account B (Attacker / IDOR) secret source: env:VAR_NAME, @FILE, or 'prompt'",
    )
    p_verify.add_argument(
        "--prompt-login",
        action="store_true",
        help="Prompt for live website login/session tokens for Account A & B",
    )
    p_verify.add_argument(
        "--researcher",
        default=None,
        help="Researcher handle for compliance headers (e.g. H1/Bugcrowd username)",
    )

    # recon
    p_recon = sub.add_parser("recon", help="Recon only, no analysis")
    p_recon.add_argument("program")
    p_recon.add_argument(
        "--controlled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Low-rate recon: cap crawl pressure, skip content fuzzing, and "
        "health-check the target (default: on; use --no-controlled to disable)",
    )

    p_traffic = sub.add_parser(
        "traffic", help="Import redacted, scoped HAR traffic evidence"
    )
    p_traffic.add_argument("har_file", help="Path to an exported HAR file")
    p_traffic.add_argument(
        "--program",
        required=True,
        help="Cached program name used for scope enforcement",
    )

    # analyze
    p_analyze = sub.add_parser(
        "analyze", help="Run Oracle reflexes on existing recon dir"
    )
    p_analyze.add_argument("recon_dir")
    p_analyze.add_argument("--model", default=LOCAL_MODEL)
    p_analyze.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Use OpenRouter / cloud model for reflex analysis",
    )
    p_analyze.add_argument(
        "--no-cloud", dest="cloud", action="store_false", help="Force local model only"
    )

    # seams
    p_seams = sub.add_parser(
        "seams", help="Run analysis on existing recon dir and print seam cards"
    )
    p_seams.add_argument("recon_dir")
    p_seams.add_argument("--model", default=LOCAL_MODEL)
    p_seams.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Use OpenRouter / cloud model for reflex analysis",
    )
    p_seams.add_argument(
        "--no-cloud", dest="cloud", action="store_false", help="Force local model only"
    )

    # scope
    p_scope = sub.add_parser("scope", help="Show scope assets for a program")
    p_scope.add_argument("program")

    # audit
    p_audit = sub.add_parser(
        "audit",
        help="Audit code repository / spec for contract seams & vulnerabilities",
    )
    p_audit.add_argument(
        "repo_dir", help="Path to repository or code directory to audit"
    )
    p_audit.add_argument(
        "--cloud",
        dest="cloud",
        action="store_true",
        default=None,
        help="Use OpenRouter / cloud model for compound threat modeling",
    )
    p_audit.add_argument(
        "--no-cloud",
        dest="cloud",
        action="store_false",
        help="Force local analysis only",
    )

    # redteam
    p_redteam = sub.add_parser(
        "redteam",
        help="Run multi-model adversarial red-team audit on a target, finding, or code",
    )
    p_redteam.add_argument(
        "target", help="Target program name, URL, code directory, or finding card file"
    )
    p_redteam.add_argument(
        "--finding",
        default=None,
        help="Specific finding assertion, hypothesis, or curl check command",
    )

    # status
    sub.add_parser("status", help="Check tools, models, and API keys")

    # backends
    p_bk = sub.add_parser("backends", help="Backend router utilities")
    bk_sub = p_bk.add_subparsers(dest="bk_cmd")
    p_bk_test = bk_sub.add_parser(
        "test", help="Run one sample across each backend for a task"
    )
    p_bk_test.add_argument("--task", default="reflex")

    args = parser.parse_args()
    _resolve_secret_args(args)

    _command = args.cmd or ("prescan" if getattr(args, "prescan", False) else "help")
    _runlog_root = (
        Path(os.environ["ORACLE_RUNLOG_DIR"])
        if os.environ.get("ORACLE_RUNLOG_DIR")
        else REPORTS_DIR / "runs"
    )
    _ACTIVE_RUNLOG = RunLog(
        _command,
        argv=sys.argv[1:],
        root=_runlog_root,
    )
    _JSON_STDOUT = bool(
        args.cmd == "verify-download" and getattr(args, "json", False)
    )
    _runlog_event("run.command", command=_command)
    _info(f"Run log: {_ACTIVE_RUNLOG.summary_path}")

    if getattr(args, "prescan", False) and not args.cmd:
        cmd_prescan(args)
        _ACTIVE_RUNLOG.finish("ok", exit_code=0)
        return

    if args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "prescan":
        cmd_prescan(args)
    elif args.cmd == "scan":
        cmd_scan(args)
    elif args.cmd == "bundle":
        cmd_bundle(args)
    elif args.cmd == "verify-download":
        cmd_verify_download(args)
    elif args.cmd == "queue":
        cmd_queue(args)
    elif args.cmd == "hunt":
        cmd_hunt(args.program, args)
    elif args.cmd == "recon":
        cmd_recon(args.program, args)
    elif args.cmd == "traffic":
        cmd_traffic(args.har_file, args.program)
    elif args.cmd == "analyze":
        cmd_analyze(args.recon_dir, args)
    elif args.cmd == "seams":
        seams, _ = cmd_analyze(args.recon_dir, args)
        for s in seams:
            print(
                f"\n[{s.get('n', '?')}] {s.get('assertion_a', '')}"
                f" → {s.get('assertion_b', '')}"
            )
            print(f"  check: {s.get('check', '')}")
    elif args.cmd == "verify":
        d = Path(args.recon_dir)
        if not d.exists():
            _die(f"Recon dir not found: {args.recon_dir}")
        _reject_verify_account_flags(args)
        no_cloud = _apply_no_cloud(args)
        _pin_local_model(args)
        _rdir, _tname, _vprog = _resolve_analyze_workspace(d)
        # Load existing report if available, else re-run analysis
        _report_needles = {_tname, d.name}
        if _rdir.parent != d:
            _report_needles.add(_rdir.parent.name)
        _report_needles = {n for n in _report_needles if n}
        report_files = sorted(
            (
                f
                for f in (REPORTS_DIR.glob("*.md") if REPORTS_DIR.exists() else [])
                if any(n in f.name for n in _report_needles)
            ),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if report_files:
            raw_text = report_files[0].read_text()
            # A report renders cards and embeds the original model output.
            # Parse only the raw output so each candidate is verified once.
            raw_analysis = raw_text.split("## Raw Oracle Analysis", 1)
            seams = _parse_seams(raw_analysis[-1], recon_dir=_rdir)
            _ok(
                f"Loaded {len(seams)} seams from existing report: {report_files[0].name}"
            )
        else:
            seams, raw_analysis = cmd_analyze(str(d), args)
            raw_text = raw_analysis
        if seams:
            prog = _vprog or _scope_from_programs(_tname)
            gate = ProgramScopeGate(
                prog, target_fallback=_derive_target(prog, _tname)
            )
            # Fused mindset context (philosophy + TTP + scope wall) so verify,
            # PoC, and correlation reason from the same grounding as the
            # reflex pass — even on the standalone path.
            from oracle_mindset_context import OracleMindsetContext, ProgramWorkspace

            _verify_mindset = OracleMindsetContext(
                program=prog or {}, voice=False
            ).system_prompt()
            ws = ProgramWorkspace(
                prog or {"name": _tname, "platform": "direct", "url": _tname},
                base=TARGETS_DIR,
            )
            is_testnet = getattr(args, "testnet", False)
            _funnel_mined = len(seams)
            confirmed = verify_seams(
                seams,
                _tname,
                _rdir,
                model=args.model,
                auto=args.auto,
                scope_gate=gate,
                is_testnet=is_testnet,
                auth=getattr(args, "auth", None),
                cookie=getattr(args, "cookie", None),
                no_cloud=no_cloud,
            )
            _write_funnel_artifact(
                ws, confirmed, _funnel_mined, len(seams) - _funnel_mined
            )
            # Same post-verify pipeline as cmd_hunt: persist every result
            # (INCONCLUSIVE preserved, never dropped), PoC for confirmed,
            # compound correlation, and the final verdict report.
            _finalize_verify(
                confirmed,
                seams,
                _tname,
                ws,
                recon_dir=_rdir,
                raw_analysis=raw_text,
                no_cloud=no_cloud,
                mindset_system=_verify_mindset,
                is_testnet=is_testnet,
            )
        else:
            _info("No seams found in analysis")
    elif args.cmd == "scope":
        cmd_scope(args.program)
    elif args.cmd == "audit":
        cmd_audit(args.repo_dir, args)
    elif args.cmd == "redteam":
        cmd_redteam(args.target, args)
    elif args.cmd == "status":
        cmd_status()
    elif args.cmd == "backends":
        if getattr(args, "bk_cmd", None) == "test":
            cmd_backends_test(args)
        else:
            parser.print_help()
    else:
        parser.print_help()

    if _ACTIVE_RUNLOG is not None:
        _ACTIVE_RUNLOG.finish("ok", exit_code=0)


if __name__ == "__main__":
    main()
