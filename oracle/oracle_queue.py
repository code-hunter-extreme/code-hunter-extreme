#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: QueueConfigError, QueueSpec, resolve_queue, load_queue_config, build_schedule, order_programs, load_schedule, pick_hunt_target
# TOPICS: none
"""oracle_queue.py — P12 queue config + deterministic scheduler (Oracle-side).

Doctrine ORACLE_DOCTRINE.md §4, implemented against the P11 handoff::

    config ``queue`` block (``oracle.config.json``)::

        "queue": {
          "order": "finish-site",
          "concurrent": false,
          "cross_site_cap": 3,
          "default_count": 5
        }

  - ``order``: ``finish-site`` (exhaust every company on one site, then move
    on) or ``round-robin`` (first company per site in rotation).
    A "site" is a bounty platform (the handoff's ``platform`` field,
    lowercased): companies group under the platform that lists them.
  - ``concurrent``: cross-site parallelism on/off. Sequential within a site,
    ALWAYS (one rate-limit bucket per site).
  - ``cross_site_cap``: max parallel sites when concurrent.
  - ``default_count``: programs to deep-dive when ``-N`` is not given
    (applied by ``oracle-hunter scan``; explicit ``--sites`` still overrides
    the count per doctrine §3).

Precedence everywhere: CLI flag > config file > built-in default.
An explicit ``null`` (or missing key) at any layer means "unspecified" and
falls through to the next layer. Any *specified* value with the wrong type
or range fails closed with :class:`QueueConfigError` — never a silent
fallback, even when another layer would have overridden it.

Determinism: the same handoff + resolved spec always yields the same queue.
Programs sort by handoff rank (ties broken by handle, then name); sites
order by their best rank (ties broken by site name); waves are greedy
earliest-fit in queue order. No timestamps, dict order, or input order leak
into the schedule.

The scheduler emits the ordered work list; ``oracle-hunter queue --execute``
executes it item by item (see :func:`pick_hunt_target`). Each item carries
its site, company, and deep-dive refs so the executor can resolve the full
record from the handoff file.
"""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

# P11 handoff format — imported, NEVER redefined here (P11 owns it).
from oracle_intake import (
    HANDOFF_SCHEMA,
    is_independently_verified_entry,
    latest_report,
)

HERE = Path(__file__).resolve().parent
REPORTS_DIR = HERE / "reports"
CONFIG_PATH = HERE / "oracle.config.json"

SCHEDULE_SCHEMA = "oracle.p12.schedule/v1"

ORDER_FINISH_SITE = "finish-site"
ORDER_ROUND_ROBIN = "round-robin"
ORDERS = (ORDER_FINISH_SITE, ORDER_ROUND_ROBIN)

DEFAULT_ORDER = ORDER_FINISH_SITE
DEFAULT_CONCURRENT = False
DEFAULT_CROSS_SITE_CAP = 3
DEFAULT_DEFAULT_COUNT = 5

QUEUE_KEYS = ("order", "concurrent", "cross_site_cap", "default_count")

_MISSING_RANK = 10**9


class QueueConfigError(ValueError):
    """A specified queue value has a bad type, range, or shape (fail-closed)."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(now: Optional[datetime] = None) -> str:
    return (now or _utc_now()).strftime("%Y%m%d_%H%M%S")


# ── validation (fail-closed) ──────────────────────────────────────────────────


def _validate_value(key: str, value: Any) -> Any:
    if key == "order":
        if not isinstance(value, str) or value not in ORDERS:
            raise QueueConfigError(
                f"queue.order must be one of {list(ORDERS)}, got {value!r}"
            )
        return value
    if key == "concurrent":
        if type(value) is not bool:
            raise QueueConfigError(f"queue.concurrent must be a boolean, got {value!r}")
        return value
    if key == "cross_site_cap":
        if type(value) is not int or value < 1:
            raise QueueConfigError(
                f"queue.cross_site_cap must be an int >= 1, got {value!r}"
            )
        return value
    if key == "default_count":
        if type(value) is not int or value < 0:
            raise QueueConfigError(
                f"queue.default_count must be an int >= 0, got {value!r}"
            )
        return value
    raise QueueConfigError(
        f"unknown queue key {key!r} (valid keys: {list(QUEUE_KEYS)})"
    )


def _clean_layer(layer: Mapping[str, Any], origin: str) -> Dict[str, Any]:
    """Validate one precedence layer; drop ``_comment``/``None`` entries."""
    if not isinstance(layer, Mapping):
        raise QueueConfigError(f"queue {origin} must be an object, got {layer!r}")
    clean: Dict[str, Any] = {}
    for key, value in layer.items():
        if isinstance(key, str) and key.startswith("_"):
            continue  # _comment keys, same convention as oracle_scan.load_config
        if key not in QUEUE_KEYS:
            raise QueueConfigError(
                f"unknown queue key {key!r} in {origin} "
                f"(valid keys: {list(QUEUE_KEYS)})"
            )
        if value is None:
            continue  # null = unspecified → falls through to the next layer
        clean[key] = _validate_value(key, value)
    return clean


def validate_queue_block(block: Any) -> Dict[str, Any]:
    """Validate a raw ``queue`` config block → clean dict of specified values.

    ``None`` (or a missing block) means "all unspecified". Anything specified
    with a bad type/range, or any unknown key, raises :class:`QueueConfigError`.
    """
    if block is None:
        return {}
    return _clean_layer(block, "config")


# ── config loading + precedence ───────────────────────────────────────────────


def load_queue_config(path: Optional[Path | str] = None) -> Dict[str, Any]:
    """Load + validate the ``queue`` block from ``oracle.config.json``.

    A missing file means "all unspecified" (built-ins apply). A malformed
    file or block fails closed with :class:`QueueConfigError`.
    """
    cfg_path = Path(path) if path is not None else CONFIG_PATH
    if not cfg_path.exists():
        return {}
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise QueueConfigError(f"bad JSON in {cfg_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise QueueConfigError(f"config {cfg_path} must hold a JSON object")
    return validate_queue_block(raw.get("queue"))


@dataclass(frozen=True)
class QueueSpec:
    """Fully resolved queue behavior (no layer left unspecified)."""

    order: str = DEFAULT_ORDER
    concurrent: bool = DEFAULT_CONCURRENT
    cross_site_cap: int = DEFAULT_CROSS_SITE_CAP
    default_count: int = DEFAULT_DEFAULT_COUNT

    @property
    def effective_cap(self) -> int:
        """Max items per wave: 1 when sequential, else the cross-site cap."""
        return self.cross_site_cap if self.concurrent else 1


def resolve_queue(
    cli: Optional[Mapping[str, Any]] = None,
    config: Optional[Mapping[str, Any]] = None,
) -> QueueSpec:
    """Merge CLI > config > built-in into a :class:`QueueSpec`.

    Every *specified* value at every layer is validated — a bad config value
    raises even when a CLI flag would have overridden it (scream, don't hide).
    """
    # Validate every specified value at each layer BEFORE merging —
    # a bad value raises here, never falls through silently.
    if cli is not None:
        _clean_layer(cli, "CLI")
    if config is not None:
        _clean_layer(config, "config")

    merged: Dict[str, Any] = {
        "order": DEFAULT_ORDER,
        "concurrent": DEFAULT_CONCURRENT,
        "cross_site_cap": DEFAULT_CROSS_SITE_CAP,
        "default_count": DEFAULT_DEFAULT_COUNT,
    }
    if config is not None:
        merged.update(_clean_layer(config, "config"))
    if cli is not None:
        merged.update(_clean_layer(cli, "CLI"))
    return QueueSpec(**merged)


# ── deterministic ordering ────────────────────────────────────────────────────


def site_of(prog: Mapping[str, Any]) -> str:
    """Site key for a handoff program: its bounty platform, lowercased."""
    platform = prog.get("platform", "")
    text = platform.strip().lower() if isinstance(platform, str) else ""
    return text or "unknown"


def _rank_key(prog: Mapping[str, Any]) -> Tuple[int, str, str]:
    rank = prog.get("rank", _MISSING_RANK)
    if type(rank) is not int:
        rank = _MISSING_RANK
    handle = prog.get("handle", "")
    name = prog.get("name", "")
    return (
        rank,
        handle.strip().lower() if isinstance(handle, str) else "",
        name.strip().lower() if isinstance(name, str) else "",
    )


def order_programs(
    programs: List[Dict[str, Any]], order: str = DEFAULT_ORDER
) -> List[Dict[str, Any]]:
    """Deterministically order handoff programs for ``order`` mode.

    Sites (platforms) run in order of their best handoff rank; within a site,
    rank order. ``finish-site`` exhausts each site before moving on;
    ``round-robin`` takes the first remaining company per site in rotation.
    Same input → same queue, regardless of input order.
    """
    if order not in ORDERS:
        raise QueueConfigError(
            f"queue.order must be one of {list(ORDERS)}, got {order!r}"
        )
    by_site: Dict[str, List[Dict[str, Any]]] = {}
    for prog in programs:
        by_site.setdefault(site_of(prog), []).append(prog)
    for members in by_site.values():
        members.sort(key=_rank_key)
    site_order = sorted(by_site, key=lambda s: (_rank_key(by_site[s][0]), s))
    if order == ORDER_FINISH_SITE:
        return [prog for site in site_order for prog in by_site[site]]
    rounds: List[Dict[str, Any]] = []
    depth = 0
    while True:
        progressed = False
        for site in site_order:
            members = by_site[site]
            if depth < len(members):
                rounds.append(members[depth])
                progressed = True
        if not progressed:
            return rounds
        depth += 1


def assign_waves(ordered: List[Dict[str, Any]], spec: QueueSpec) -> List[int]:
    """Wave index per item: greedy earliest-fit honoring the spec.

    Sequential within a site ALWAYS (a site's items land on strictly
    increasing waves); each wave holds at most ``effective_cap`` items.
    """
    cap = spec.effective_cap
    wave_sizes: List[int] = []
    site_last_wave: Dict[str, int] = {}
    waves: List[int] = []
    for prog in ordered:
        site = site_of(prog)
        wave = site_last_wave.get(site, -1) + 1
        while wave < len(wave_sizes) and wave_sizes[wave] >= cap:
            wave += 1
        if wave == len(wave_sizes):
            wave_sizes.append(0)
        wave_sizes[wave] += 1
        site_last_wave[site] = wave
        waves.append(wave)
    return waves


# ── handoff loading (P11 format, consumed as-is) ──────────────────────────────


def load_handoff(source: Any = None, out_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load a P11 handoff from a path, dict, or the latest on disk.

    ``None`` resolves the newest ``intake_ranked_verified_*.json`` report.
    Schema or shape mismatch fails closed with :class:`QueueConfigError`.
    The returned dict carries its origin under ``_handoff_path`` ("" when the
    caller passed a bare dict with no ``_report_path``).
    """
    if source is None:
        found = latest_report(out_dir or REPORTS_DIR, "intake_ranked_verified")
        if found is None:
            raise QueueConfigError(
                "no P11 handoff found — run: oracle-hunter scan "
                "(-N/--sites Deep-dive writes the handoff)"
            )
        source = found
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise QueueConfigError(f"handoff file not found: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise QueueConfigError(f"bad JSON in handoff {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise QueueConfigError(f"handoff {path} must hold a JSON object")
        payload.setdefault("_handoff_path", str(path))
        handoff = payload
    elif isinstance(source, dict):
        handoff = dict(source)
        handoff.setdefault("_handoff_path", str(handoff.get("_report_path", "")))
    else:
        raise QueueConfigError(
            f"handoff source must be a path or dict, got {type(source).__name__}"
        )
    if handoff.get("_schema") != HANDOFF_SCHEMA:
        raise QueueConfigError(
            f"handoff _schema must be {HANDOFF_SCHEMA!r}, "
            f"got {handoff.get('_schema')!r}"
        )
    ranked = handoff.get("ranked_verified")
    if not isinstance(ranked, list) or any(not isinstance(r, dict) for r in ranked):
        raise QueueConfigError("handoff 'ranked_verified' must be a list of objects")
    return handoff


# ── scheduler ─────────────────────────────────────────────────────────────────


def _schedule_item(prog: Dict[str, Any], position: int, wave: int) -> Dict[str, Any]:
    deep = prog.get("deep_dive", {})
    if not isinstance(deep, dict):
        deep = {}
    assets = deep.get("assets", [])
    company = deep.get("company", {})
    if not isinstance(company, dict):
        company = {}
    sources = deep.get("sources", [])
    oos = deep.get("out_of_scope", [])
    ws = prog.get("workspace", {})
    if not isinstance(ws, dict):
        ws = {}
    rank = prog.get("rank")
    raw_failed = prog.get("failed_checks", [])
    failed_checks = (
        list(raw_failed) if isinstance(raw_failed, list) else raw_failed
    )
    return {
        "position": position,
        "wave": wave,
        "site": site_of(prog),
        "company": {
            "name": prog.get("name", ""),
            "handle": prog.get("handle", ""),
        },
        "program_url": prog.get("url", ""),
        "score": prog.get("score", 0) or 0,
        "max_payout_usd": prog.get("max_payout_usd"),
        "handoff_rank": rank if type(rank) is int else None,
        "verdict": prog.get("verdict", ""),
        "failed_checks": failed_checks,
        "oracle_rescan": prog.get("oracle_rescan", {}),
        "workspace": {
            "path": ws.get("path", "") or "",
            "status": ws.get("status", "") or "",
        },
        "deep_dive": {
            "asset_count": len(assets) if isinstance(assets, list) else 0,
            "assets": list(assets) if isinstance(assets, list) else [],
            "out_of_scope": list(oos) if isinstance(oos, list) else [],
            "website": company.get("website", "") or "",
            "sources": list(sources) if isinstance(sources, list) else [],
        },
    }


def _item_identity(item: Mapping[str, Any]) -> Dict[str, Any]:
    """Stable target identity for one schedule item (resume safety)."""
    company = item.get("company") or {}
    if not isinstance(company, Mapping):
        company = {}
    return {
        "site": str(item.get("site", "") or "").strip().lower(),
        "handle": str(company.get("handle", "") or "").strip().lower(),
        "name": str(company.get("name", "") or "").strip().lower(),
        "program_url": str(item.get("program_url", "") or "").strip(),
        "handoff_rank": item.get("handoff_rank")
        if type(item.get("handoff_rank")) is int
        else None,
    }


def _item_identity_key(item: Mapping[str, Any]) -> str:
    ident = _item_identity(item)
    return json.dumps(ident, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _schedule_fingerprint(
    items: List[Dict[str, Any]], queue_block: Optional[Mapping[str, Any]] = None
) -> str:
    """Content identity for a schedule, independent of its timestamped path."""
    canonical = {
        "queue": dict(queue_block or {}),
        "items": [
            {
                "position": it.get("position"),
                "wave": it.get("wave", 0),
                "identity": _item_identity(it),
            }
            for it in sorted(
                items, key=lambda x: (x.get("position") or 0, x.get("wave") or 0)
            )
        ],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _entry_independently_verified(entry: Any) -> bool:
    """Shared strict P11 entry check (verdict + failures + re-scan meta)."""
    return is_independently_verified_entry(entry)


def build_schedule(
    handoff: Any = None,
    *,
    order: Optional[str] = None,
    concurrent: Optional[bool] = None,
    cross_site_cap: Optional[int] = None,
    config: Optional[Mapping[str, Any]] = None,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
    require_trusted_handoff: bool = False,
) -> Dict[str, Any]:
    """Resolve the spec, order the handoff, assign waves, write the schedule.

    CLI kwargs (``None`` = unspecified) beat ``config`` (a raw ``queue``
    block), which beats the built-ins. Returns the schedule payload, which
    carries its file path under ``_report_path``. An empty handoff still
    writes a file (fail-closed empty), never nothing.

    ``require_trusted_handoff=True`` is the product path (historical
    name): every ranked entry must carry an independent Oracle re-scan.
    Public Scan4Me discovery provenance is raw candidate material and is
    neither sufficient nor, by itself, a blocker once Oracle verified
    the entry; a bridge-only entry can never become a schedule.
    """
    spec = resolve_queue(
        cli={
            "order": order,
            "concurrent": concurrent,
            "cross_site_cap": cross_site_cap,
        },
        config=config,
    )
    directory = out_dir or REPORTS_DIR
    loaded = load_handoff(handoff, out_dir=directory)
    if require_trusted_handoff:
        unverified = [
            str(entry.get("name") or entry.get("handle") or "<unnamed>")
            for entry in loaded["ranked_verified"]
            if not _entry_independently_verified(entry)
        ]
        if unverified:
            raise QueueConfigError(
                "handoff entries are not independently verified by Oracle: "
                + ", ".join(unverified)
                + f" ({loaded.get('_handoff_path', '')})"
            )
    ranked = list(loaded["ranked_verified"])
    ordered = order_programs(ranked, spec.order)
    wave_of = assign_waves(ordered, spec)
    items = [
        _schedule_item(prog, position=i + 1, wave=w)
        for i, (prog, w) in enumerate(zip(ordered, wave_of))
    ]
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"queue_schedule_{tag}.json"
    queue_block = {
        "order": spec.order,
        "concurrent": spec.concurrent,
        "cross_site_cap": spec.cross_site_cap,
        "effective_cap": spec.effective_cap,
    }
    payload: Dict[str, Any] = {
        "_schema": SCHEDULE_SCHEMA,
        "schedule_id": _schedule_fingerprint(items, queue_block),
        "created_utc": _utc_now().isoformat(),
        "handoff_report": str(loaded.get("_handoff_path", "")),
        "no_cloud": bool(loaded.get("no_cloud", False)),
        "queue": queue_block,
        "count": len(items),
        "waves": (max(wave_of) + 1) if wave_of else 0,
        "items": items,
        "feed_provenance": loaded.get("feed_provenance", {"unavailable": "handoff unstamped"}),
        "feed_trust": loaded.get(
            "feed_trust", {"ok": None, "issues": ["handoff unstamped"]}
        ),
        "oracle_rescan": loaded.get("oracle_rescan", {}),
        "note": (
            "sequential within a site always (one rate-limit bucket); "
            "cross-site parallelism capped; execute the whole queue via "
            "`oracle-hunter queue --execute` (resumable, per-item state)"
        ),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["_report_path"] = str(path)
    return payload


# ── hunt-chain reader (#19: intake→queue→hunt is connected) ──────────────────


def load_schedule(
    source: Any = None, out_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Load a P12 schedule from a path, dict, or the latest on disk.

    ``None`` resolves the newest ``queue_schedule_*.json`` report. Schema
    or shape mismatch fails closed with :class:`QueueConfigError`.
    """
    if source is None:
        found = latest_report(out_dir or REPORTS_DIR, "queue_schedule")
        if found is None:
            raise QueueConfigError(
                "no P12 schedule found — run: oracle-hunter queue"
            )
        source = found
    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.exists():
            raise QueueConfigError(f"schedule file not found: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise QueueConfigError(f"bad JSON in schedule {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise QueueConfigError(f"schedule {path} must hold a JSON object")
        payload.setdefault("_schedule_path", str(path))
        sched = payload
    elif isinstance(source, dict):
        sched = dict(source)
        sched.setdefault("_schedule_path", str(sched.get("_report_path", "")))
    else:
        raise QueueConfigError(
            f"schedule source must be a path or dict, got {type(source).__name__}"
        )
    if sched.get("_schema") != SCHEDULE_SCHEMA:
        raise QueueConfigError(
            f"schedule _schema must be {SCHEDULE_SCHEMA!r}, "
            f"got {sched.get('_schema')!r}"
        )
    items = sched.get("items")
    if not isinstance(items, list) or any(not isinstance(r, dict) for r in items):
        raise QueueConfigError("schedule 'items' must be a list of objects")
    return sched


def pick_hunt_target(
    handoff: Any = None,
    schedule: Any = None,
    pick: int = 1,
    out_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Resolve the hunt target at 1-based position ``pick``.

    Schedule wins over handoff when both are given (the schedule is the
    ordered, wave-assigned view of the handoff). Empty queues and
    out-of-range picks fail closed with :class:`QueueConfigError` — a
    hunt over an empty chain must die loudly, never auto-pick silently.
    Returns ``{name, handle, site, program_url, score, position, count,
    wave, origin, verdict, failed_checks, oracle_rescan, deep_dive}``
    where origin is the artifact path (or "handoff:…"). The deep-dive
    scope travels with the pick so a chain hunt can pin the exact
    scan-verified assets instead of re-resolving scope from a DB.
    """
    if pick is None:
        pick = 1
    if type(pick) is not int or pick < 1:
        raise QueueConfigError(f"--pick must be a positive integer, got {pick!r}")
    if schedule is not None:
        sched = load_schedule(schedule, out_dir=out_dir)
        items = sched["items"]
        origin = str(sched.get("_schedule_path", "")) or "schedule"
        if not items:
            raise QueueConfigError(
                f"schedule {origin} is EMPTY — nothing to hunt"
            )
        if pick > len(items):
            raise QueueConfigError(
                f"--pick {pick} out of range: schedule holds {len(items)} items"
            )
        item = items[pick - 1]
        company = item.get("company", {})
        if not isinstance(company, dict):
            company = {}
        deep = item.get("deep_dive", {})
        if not isinstance(deep, dict):
            deep = {}
        return {
            "name": company.get("name", ""),
            "handle": company.get("handle", ""),
            "site": item.get("site", ""),
            "program_url": item.get("program_url", ""),
            "score": item.get("score", 0) or 0,
            "position": item.get("position", pick),
            "count": len(items),
            "wave": item.get("wave", 0),
            "origin": origin,
            "verdict": item.get("verdict", ""),
            "failed_checks": item.get("failed_checks", []),
            "feed_trust": sched.get("feed_trust", {}),
            "oracle_rescan": item.get("oracle_rescan", {}),
            "deep_dive": {
                "assets": list(deep.get("assets") or []),
                "out_of_scope": list(deep.get("out_of_scope") or []),
                "website": deep.get("website", "") or "",
                "sources": list(deep.get("sources") or []),
            },
        }
    loaded = load_handoff(handoff, out_dir=out_dir)
    ranked = loaded["ranked_verified"]
    origin = str(loaded.get("_handoff_path", "")) or "handoff"
    if not ranked:
        raise QueueConfigError(f"handoff {origin} is EMPTY — nothing to hunt")
    if pick > len(ranked):
        raise QueueConfigError(
            f"--pick {pick} out of range: handoff holds {len(ranked)} programs"
        )
    prog = ranked[pick - 1]
    deep = prog.get("deep_dive", {})
    if not isinstance(deep, dict):
        deep = {}
    deep_company = deep.get("company", {})
    if not isinstance(deep_company, dict):
        deep_company = {}
    return {
        "name": prog.get("name", ""),
        "handle": prog.get("handle", ""),
        "site": site_of(prog),
        "program_url": prog.get("url", ""),
        "score": prog.get("score", 0) or 0,
        "position": pick,
        "count": len(ranked),
        "wave": 0,
        "origin": origin,
        "verdict": prog.get("verdict", ""),
        "failed_checks": prog.get("failed_checks", []),
        "feed_trust": loaded.get("feed_trust", {}),
        "oracle_rescan": prog.get("oracle_rescan", {}),
        "deep_dive": {
            "assets": list(deep.get("assets") or []),
            "out_of_scope": list(deep.get("out_of_scope") or []),
            "website": deep_company.get("website", "") or "",
            "sources": list(deep.get("sources") or []),
        },
    }


# ── executor ──────────────────────────────────────────────────────────────────

STATE_SCHEMA = "oracle.p12.queue-state/v1"
HuntFn = Callable[[Dict[str, Any]], Any]
EnsureFn = Callable[[Dict[str, Any]], Any]


def _default_state_path(
    sched: Mapping[str, Any],
    out_dir: Optional[Path],
    fingerprint: Optional[str] = None,
) -> Path:
    directory = out_dir or REPORTS_DIR
    fid = fingerprint or str(sched.get("schedule_id") or "")
    if not fid:
        items = sched.get("items") if isinstance(sched.get("items"), list) else []
        queue_block = sched.get("queue") if isinstance(sched.get("queue"), Mapping) else {}
        fid = _schedule_fingerprint(items, queue_block)
    return directory / f"queue_state_{fid[:16]}.json"


def _load_state(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def execute_schedule(
    schedule: Any = None,
    *,
    hunt_fn: HuntFn,
    ensure_workspace_fn: Optional[EnsureFn] = None,
    out_dir: Optional[Path] = None,
    state_path: Optional[Path] = None,
    max_items: Optional[int] = None,
    resume: bool = True,
) -> Dict[str, Any]:
    """Execute a P12 schedule wave by wave and persist per-item state.

    Invariants (all inherited from the schedule, enforced here):
      - waves run in ascending order; a wave never starts before the
        previous wave finishes (so same-site items — strictly increasing
        waves by construction — are always sequential);
      - at most ``queue.effective_cap`` items run concurrently, and only
        within one wave (cap is 1 unless the schedule is concurrent);
      - a failing item (exception or SystemExit from the hunt) is
        recorded ``failed`` and never aborts the rest of the queue;
      - state is rewritten atomically after every item, keyed by stable
        target identity (not timestamp or position alone); with
        ``resume`` (default) targets already ``done`` for the same
        schedule content are skipped, never re-hunted.

    ``ensure_workspace_fn(item)`` (optional) runs before each hunt to
    download/repair the item's workspace; its failure is recorded but
    does not block the hunt (the hunt can still resolve the program).
    ``max_items`` caps how many items are ATTEMPTED this run (skips of
    already-done items do not count).
    """
    if max_items is not None and (
        isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0
    ):
        raise QueueConfigError(f"max_items must be an int >= 0, got {max_items!r}")
    sched = load_schedule(schedule, out_dir=out_dir)
    items = sorted(
        sched["items"],
        key=lambda it: (it.get("wave", 0), it.get("position", 0)),
    )
    queue_block = sched.get("queue") or {}
    cap = queue_block.get("effective_cap") or 1
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        cap = 1
    fingerprint = str(
        sched.get("schedule_id") or _schedule_fingerprint(items, queue_block)
    )
    item_keys: Dict[int, str] = {}
    _occurrences: Dict[str, int] = {}
    for it in items:
        base_key = _item_identity_key(it)
        occ = _occurrences.get(base_key, 0)
        _occurrences[base_key] = occ + 1
        item_keys[id(it)] = base_key if occ == 0 else f"{base_key}#{occ + 1}"
    current_keys = set(item_keys.values())
    sp = (
        Path(state_path)
        if state_path
        else _default_state_path(sched, out_dir, fingerprint=fingerprint)
    )
    state: Dict[str, Any] = _load_state(sp) if (resume and sp.exists()) else {}
    records: Dict[str, Dict[str, Any]] = {}
    if state.get("_schema") == STATE_SCHEMA and isinstance(state.get("items"), dict):
        records = {
            k: v
            for k, v in state["items"].items()
            if k in current_keys and isinstance(v, dict)
        }
    lock = threading.Lock()
    attempted = 0

    def _persist() -> None:
        payload = {
            "_schema": STATE_SCHEMA,
            "updated_utc": _utc_now().isoformat(),
            "schedule": str(sched.get("_schedule_path", "")),
            "schedule_id": fingerprint,
            "schedule_fingerprint": fingerprint,
            "handoff_report": str(sched.get("handoff_report", "")),
            "items": records,
        }
        sp.parent.mkdir(parents=True, exist_ok=True)
        tmp = sp.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(sp)

    def _run_one(item: Dict[str, Any]) -> None:
        pos = item_keys[id(item)]
        company = item.get("company") or {}
        rec: Dict[str, Any] = {
            "position": item.get("position"),
            "wave": item.get("wave", 0),
            "site": item.get("site", ""),
            "name": company.get("name", "") if isinstance(company, dict) else "",
            "identity": _item_identity(item),
            "started_utc": _utc_now().isoformat(),
        }
        if ensure_workspace_fn is not None:
            try:
                ws_res = ensure_workspace_fn(item)
                if isinstance(ws_res, dict):
                    rec["workspace"] = ws_res
            except SystemExit as exc:  # recorded; hunt still attempted
                rec["workspace"] = {
                    "status": "error",
                    "detail": f"SystemExit({exc.code})",
                }
            except Exception as exc:  # recorded; hunt still attempted
                rec["workspace"] = {
                    "status": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
        try:
            hunt_result = hunt_fn(item)
            if isinstance(hunt_result, dict):
                rec["result"] = hunt_result
            rec["status"] = "done"
        except SystemExit as exc:  # cmd_hunt dies via SystemExit on _die()
            rec["status"] = "failed"
            rec["detail"] = f"SystemExit({exc.code})"
        except Exception as exc:
            rec["status"] = "failed"
            rec["detail"] = f"{type(exc).__name__}: {exc}"
        rec["finished_utc"] = _utc_now().isoformat()
        with lock:
            records[pos] = rec
            _persist()

    waves: Dict[int, List[Dict[str, Any]]] = {}
    for it in items:
        waves.setdefault(int(it.get("wave", 0) or 0), []).append(it)
    skipped = 0
    for wave in sorted(waves):
        todo: List[Dict[str, Any]] = []
        for it in waves[wave]:
            prev = records.get(item_keys[id(it)]) or {}
            if resume and prev.get("status") == "done":
                skipped += 1
                continue
            if max_items is not None and attempted >= max_items:
                continue
            attempted += 1
            todo.append(it)
        if not todo:
            continue
        # Enforce same-site sequential execution inside the executor too:
        # a hand-crafted schedule cannot parallelise one rate-limit bucket
        # merely by putting same-site items in one wave.
        chains_by_site: Dict[str, List[Dict[str, Any]]] = {}
        for it in todo:
            chains_by_site.setdefault(str(it.get("site", "") or ""), []).append(it)
        chains = list(chains_by_site.values())

        def _run_chain(chain: List[Dict[str, Any]]) -> None:
            for chain_item in chain:
                _run_one(chain_item)

        if len(chains) == 1 or cap == 1:
            for chain in chains:
                _run_chain(chain)
        else:
            with ThreadPoolExecutor(max_workers=min(cap, len(chains))) as pool:
                list(pool.map(_run_chain, chains))
    done = sum(1 for r in records.values() if r.get("status") == "done")
    failed = sum(1 for r in records.values() if r.get("status") == "failed")
    summary = {
        "state_path": str(sp),
        "schedule": str(sched.get("_schedule_path", "")),
        "schedule_id": fingerprint,
        "attempted_this_run": attempted,
        "skipped_done": skipped,
        "done_total": done,
        "failed_total": failed,
        "items_total": len(items),
        "records": records,
    }
    return summary
