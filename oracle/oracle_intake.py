#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: run_prescan, run_scan, select_deep_dive, write_handoff, latest_report
# TOPICS: none
"""oracle_intake.py — P11 prescan / scan / -N intake sweep (Oracle-side).

Doctrine ORACLE_DOCTRINE.md §3 pipeline, implemented against Scan4Me intel:

  1. ``prescan`` — fast no-login Scan4Me sweep (local ranked DB via the
     ``oracle_scan4me`` bridge; ``--sync`` refreshes first with
     ``use_auth=False``). Produces a **prescan report**. Raw output;
     ``trusted: false`` — nothing downstream trusts it. Public provenance
     is candidate material for Oracle's verify pass, never product truth.
     The product path still refuses an unavailable, stale, or
     failed-refresh feed. The rejected report is written first so the
     evidence and runlog survive the failure.
  2. ``scan`` — Oracle's verification pass over the prescan. Produces a
     **scan report** with a per-program verdict. A program is verified iff
     no leg blocks (doctrine §3 verify-pass definition):
       - scope URLs resolve / are live (direct local probes, scope-gated);
       - payouts match the fresh platform listing (re-resolved via bridge),
         tri-state: match / mismatch / unknown — only mismatch blocks;
       - bounty rules text is unchanged since prescan (sha256 comparison),
         ADVISORY skip-when-unavailable: unknown never blocks, only a
         proven change does (no feed carries rules text; it is never faked).
     Only verified programs proceed. Unverified programs NEVER proceed.
  3. ``-N`` / ``--sites`` — deep-dive the top N **verified** programs (full
     assets, company info, resources). Naming sites explicitly overrides the
     count. The result is the **ranked-verified list** handed to P12.
     Deep-dive assets are re-resolved fresh at dive time (``resolve_fn``); a
     stale prescan snapshot can never feed deep-dive.

Scan4Me is intel-only (no scanner/prober of its own), so the whole sweep
lives here, Oracle-side, consuming the bridge (``oracle_scan4me``).

Apex exclusion (P7) holds throughout: wildcard scope rules (``*.base``) are
never expanded, so an apex host is probed only when it is itself an
explicitly listed in-scope asset. All matching goes through
``bridge.verify_in_scope``, which rejects apex-under-wildcard fail-closed.

Offline (``--no-cloud``): prescan reads the local DB only (``--sync`` is
refused); scan skips all network probing, so the scope-live leg fails
closed with an explicit ``offline`` reason. Reports are still written.

P12 handoff format (``oracle.p12.handoff/v1``) — ``reports/`` JSON file::

    {
      "_schema": "oracle.p12.handoff/v1",
      "created_utc": "2026-10-12T00:00:00+00:00",
      "prescan_report": "reports/prescan_<stamp>.json",
      "scan_report": "reports/scan_<stamp>.json",
      "no_cloud": false,
      "selector": {"top_n": 5, "sites": null},
      "ranked_verified": [
        {
          "rank": 1,
          "name": "...", "handle": "...", "platform": "...", "url": "...",
          "score": 87.5, "max_payout_usd": 25000, "currency": "USD",
          "verdict": "verified",
          "checks": {"scope_live": {...}, "payouts_match": {...},
                      "rules_unchanged": {...}},
          "deep_dive": {
            "assets": [...], "company": {...}, "resources": {...},
            "sources": ["scan4me:programs+assets"]
          }
        }
      ],
      "excluded_named": [],
      "note": "unverified programs never appear here; see the scan report"
    }

No ``queue`` config is read here (zero queue refs exist; P12 owns
scheduling, order, concurrency, and ``default_count``). Without ``-N`` or
``--sites``, ALL verified programs are handed off, ranked by score.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import socket
import ssl
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPORTS_DIR = HERE / "reports"

PRESCAN_SCHEMA = "oracle.intake.prescan/v1"
SCAN_SCHEMA = "oracle.intake.scan/v1"
HANDOFF_SCHEMA = "oracle.p12.handoff/v1"

# Scan4Me's own freshness bound (scan4me.STALE_AFTER_HOURS). The raw gate
# re-checks the numeric age instead of trusting a stale flag alone.
RAW_FEED_MAX_AGE_HOURS = 48.0

ProbeFn = Callable[[str, float], Dict[str, Any]]
FetchFn = Callable[[], List[Dict[str, Any]]]
ResolveFn = Callable[[str], Optional[Dict[str, Any]]]
RescanFn = Callable[[Dict[str, Any]], Tuple[Optional[Dict[str, Any]], Dict[str, Any]]]

# Scope asset types that can never yield a DNS probe target.
_NON_DNS_ASSET_TYPES = {
    "cidr",
    "ios_app",
    "android_app",
    "executable",
    "smart_contract",
    "source_code",
    "other",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(now: Optional[datetime] = None) -> str:
    return (now or _utc_now()).strftime("%Y%m%d_%H%M%S")


# ── rules text ──────────────────────────────────────────────────────────────


def rules_text_of(prog: Dict[str, Any]) -> str:
    """Best-available bounty rules text for a program ("" when none)."""
    for key in ("rules_text", "policy"):
        val = prog.get(key)
        if isinstance(val, str) and val.strip():
            return val
    return ""


def rules_hash_of(prog: Dict[str, Any]) -> Optional[str]:
    """sha256 of the rules text, or None when no rules text is available."""
    text = rules_text_of(prog)
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── probe-host derivation (apex-excluded, scope-gated) ──────────────────────


def _is_dns_target(host: str) -> bool:
    """The one shared DNS predicate: hunter._is_dns_target (lazy import).

    No local fallback — a divergent copy once accepted the very app IDs
    the predicate exists to reject. Import failure fails closed.
    """
    try:
        import oracle_hunter as _h  # lazy: hunter is heavy, intake stays light

        return bool(_h._is_dns_target(host))
    except Exception:
        return False


def _strip_to_host(ident: str) -> str:
    text = (ident or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("@")[-1]
    if text.startswith("[") and "]" in text:  # IPv6 literal
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:  # host:port
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def derive_probe_hosts(prog: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Explicit in-scope DNS hosts to probe + skip reasons.

    Wildcard rules are never expanded: an apex host is probed only when it
    is itself explicitly listed. Every candidate must pass
    ``bridge.verify_in_scope`` (P7 fail-closed: apex-under-wildcard fails).
    """
    import oracle_scan4me as bridge

    hosts: List[str] = []
    skipped: List[str] = []
    for scope in prog.get("structured_scopes", []) or []:
        if not isinstance(scope, dict):
            continue
        ident = (scope.get("asset_identifier") or "").strip()
        if not ident:
            continue
        atype = (scope.get("asset_type") or "").strip().lower()
        lowered = ident.lower().rstrip(".")
        if atype in _NON_DNS_ASSET_TYPES:
            skipped.append(f"{ident}: non-DNS asset type ({atype or 'unknown'})")
            continue
        if lowered.startswith("*") or scope.get("is_wildcard"):
            base = lowered[2:] if lowered.startswith("*.") else lowered.lstrip("*")
            skipped.append(
                f"{ident}: wildcard not expanded"
                + (f" (apex {base} excluded per P7)" if base else "")
            )
            continue
        host = _strip_to_host(ident)
        if not host or not _is_dns_target(host):
            skipped.append(f"{ident}: not a DNS target")
            continue
        ok, _rule = bridge.verify_in_scope(host, prog)
        if not ok:
            skipped.append(f"{ident}: out of scope (fail-closed)")
            continue
        if host not in hosts:
            hosts.append(host)
    return hosts, skipped


# ── liveness probing (direct sockets only — never cloud/LLM) ────────────────


def default_probe_host(host: str, timeout: float = 8.0) -> Dict[str, Any]:
    """DNS-resolve + HTTPS/HTTP HEAD a host. No redirects followed."""
    result: Dict[str, Any] = {
        "host": host,
        "resolves": False,
        "live": False,
        "status": None,
        "error": "",
    }
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        result["resolves"] = True
    except Exception as e:
        result["error"] = f"dns: {e}"
        return result

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            req: object,
            fp: object,
            code: int,
            msg: str,
            headers: object,
            newurl: str,
        ) -> None:
            return None

    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx)
    )
    last_err = ""
    for url in (f"https://{host}", f"http://{host}"):
        try:
            req = urllib.request.Request(
                url, method="HEAD", headers={"User-Agent": "oracle-intake/1.0"}
            )
            with opener.open(req, timeout=timeout) as resp:
                result["live"] = True
                result["status"] = int(resp.status)
                result["error"] = ""
                return result
        except Exception as e:
            last_err = f"{url}: {e}"
    result["error"] = last_err
    return result


# ── the three verify checks (doctrine §3) ───────────────────────────────────


# ── non-DNS liveness leg (#8): web3 scope-live proof ──────────────────────────
# DNS probing can never verify contract-only scope, so web3 programs need an
# alternate proof or the verify pass blocks them by design. Two target kinds:
#   evm-address  0x + 40 hex → eth_getCode via JSON-RPC; live iff code != 0x
#   repo-url     scheme URL (the shape real SMART_CONTRACT rows carry, e.g.
#                github repo links) → live iff the artifact URL serves HTTP
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def derive_contract_targets(
    prog: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """SMART_CONTRACT scope entries → probe targets + skip reasons."""
    targets: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for scope in prog.get("structured_scopes", []) or []:
        if not isinstance(scope, dict):
            continue
        atype = (scope.get("asset_type") or "").strip().lower()
        if atype not in ("smart_contract", "smartcontract"):
            continue
        ident = (scope.get("asset_identifier") or "").strip()
        if not ident:
            continue
        if _EVM_ADDR_RE.match(ident):
            targets.append({"kind": "evm-address", "address": ident})
        elif ident.lower().startswith(("http://", "https://")):
            targets.append({"kind": "repo-url", "url": ident})
        else:
            skipped.append(f"{ident}: contract target is neither 0x-address nor URL")
    return targets, skipped


def default_contract_probe(
    target: Dict[str, Any], rpc_url: Optional[str] = None, timeout: float = 8.0
) -> Dict[str, Any]:
    """Probe one contract target. Direct sockets/HTTP only — never cloud/LLM."""
    kind = target.get("kind")
    if kind == "evm-address":
        result: Dict[str, Any] = {
            "target": target.get("address"),
            "kind": kind,
            "live": False,
            "error": "",
        }
        if not rpc_url:
            result["error"] = "no RPC configured (ORACLE_RPC_URL or rpc_url=)"
            return result
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getCode",
                "params": [target.get("address"), "latest"],
            }
        ).encode()
        try:
            req = urllib.request.Request(
                rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                req, timeout=timeout, context=ctx
            ) as resp:  # nosec B310
                body = json.loads(resp.read().decode("utf-8", "replace"))
            code = body.get("result") or ""
            result["live"] = isinstance(code, str) and code not in ("", "0x", "0X")
            if not result["live"]:
                result["error"] = f"no code at address (got {code!r})"
            return result
        except Exception as e:
            result["error"] = f"rpc: {e}"
            return result
    if kind == "repo-url":
        result = {"target": target.get("url"), "kind": kind, "live": False, "error": ""}
        try:
            req = urllib.request.Request(
                target.get("url", ""),
                method="HEAD",
                headers={"User-Agent": "oracle-intake/1.0"},
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                req, timeout=timeout, context=ctx
            ) as resp:  # nosec B310
                result["live"] = 200 <= int(resp.status) < 400
                if not result["live"]:
                    result["error"] = f"http {resp.status}"
                return result
        except Exception as e:
            result["error"] = f"http: {e}"
            return result
    return {"target": None, "kind": kind, "live": False, "error": "unknown kind"}


def _is_wildcard_scope(scope: Dict[str, Any]) -> bool:
    """True when a structured-scope entry is a wildcard rule (never expanded)."""
    if not isinstance(scope, dict):
        return False
    ident = (scope.get("asset_identifier") or "").strip()
    if not ident:
        return False
    return ident.lower().rstrip(".").startswith("*") or bool(scope.get("is_wildcard"))


def check_scope_live(
    prog: Dict[str, Any],
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
    contract_probe_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    rpc_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Check 1: scope URLs resolve / are live. Pass iff ≥1 host is LIVE
    (serves HTTP/S) — resolves ≠ live: a parked DNS record that answers
    no HTTP is stale scope, not a verified target.

    Non-DNS leg (#8): SMART_CONTRACT scope is probed as an alternate
    proof — eth_getCode liveness for 0x addresses (needs ORACLE_RPC_URL),
    HTTP existence for repo-URL scope. Contract-only programs verify
    through this leg; it never rescues stale DNS scope.
    """
    hosts, skipped = derive_probe_hosts(prog)
    contracts, contract_skipped = derive_contract_targets(prog)
    skipped = skipped + contract_skipped
    if no_cloud:
        return {
            "pass": False,
            "reason": "offline (--no-cloud): liveness not probed",
            "hosts": hosts,
            "probed": [],
            "skipped": skipped,
            "contracts": contracts,
            "contracts_probed": [],
        }
    if not hosts and not contracts:
        # #14 POLICY (declared, not fixed — expansion is out of scope for
        # intake by design): a program whose scope is ONLY wildcard rules
        # can never verify here. Wildcards are never expanded (probing
        # hosts the program never named is out-of-scope scanning), and
        # the apex is excluded per P7 (fail-closed: apex-under-wildcard
        # is not in scope). Such programs need explicit hosts added to
        # scope (or an operator-supplied host list) before intake can
        # verify them. The distinct status keeps policy-unverifiable
        # apart from stale/empty scope in the report. Doctrine §3 should
        # state this (flagged for the doctrine owner — not edited here).
        _named = [
            s
            for s in (prog.get("structured_scopes") or [])
            if isinstance(s, dict) and (s.get("asset_identifier") or "").strip()
        ]
        _wild_only = bool(_named) and all(_is_wildcard_scope(s) for s in _named)
        if _wild_only:
            return {
                "pass": False,
                "status": "wildcard_only_unverifiable",
                "reason": (
                    "policy: wildcard-only scope cannot verify at intake "
                    "(wildcards never expanded; apex excluded per P7) — "
                    "add explicit in-scope hosts"
                ),
                "hosts": [],
                "probed": [],
                "skipped": skipped,
                "contracts": [],
                "contracts_probed": [],
            }
        return {
            "pass": False,
            "status": "no_probe_hosts",
            "reason": (
                "no probed scope hosts (empty or app-ID scope;" " apex excluded per P7)"
            ),
            "hosts": [],
            "probed": [],
            "skipped": skipped,
            "contracts": [],
            "contracts_probed": [],
        }
    fn = probe_fn or default_probe_host
    probed = [fn(h, timeout) for h in hosts]
    resolved = [p for p in probed if p.get("resolves")]
    live = [p for p in probed if p.get("live")]
    # Non-DNS leg: probe contract targets alongside (or instead of) DNS.
    cfn = contract_probe_fn or default_contract_probe
    rpc = rpc_url or os.environ.get("ORACLE_RPC_URL")
    contracts_probed = [cfn(t, rpc, timeout) for t in contracts]
    contracts_live = [p for p in contracts_probed if p.get("live")]
    ok = len(live) > 0 or len(contracts_live) > 0
    if ok:
        parts = []
        if live:
            parts.append(
                f"{len(live)}/{len(probed)} hosts live ({len(resolved)} resolve)"
            )
        if contracts_live:
            parts.append(
                f"{len(contracts_live)}/{len(contracts_probed)} contracts live"
            )
        reason = "; ".join(parts)
    elif resolved:
        reason = (
            f"0/{len(probed)} hosts live "
            f"({len(resolved)} resolve but no HTTP(S) response — stale scope)"
        )
    elif contracts_probed:
        reason = (
            f"0/{len(contracts_probed)} contracts live"
            + (f"; 0/{len(probed)} hosts resolve" if probed else "")
            + " (stale scope)"
        )
    else:
        reason = f"0/{len(probed)} hosts resolve (stale scope)"
    return {
        "pass": ok,
        "reason": reason,
        "hosts": hosts,
        "probed": probed,
        "skipped": skipped,
        "resolved_count": len(resolved),
        "live_count": len(live),
        "contracts": contracts,
        "contracts_probed": contracts_probed,
        "contracts_live_count": len(contracts_live),
    }


def check_payouts_match(
    prescan_prog: Dict[str, Any], fresh_prog: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Check 2: payouts match the fresh platform listing (tri-state).

    status is match / mismatch / unknown / missing. Only mismatch and
    missing block verification: unknown (a feed with no payout field, e.g.
    HackerOne's bool-only offers_bounties) is explicit and non-blocking.
    """
    if fresh_prog is None:
        return {
            "pass": False,
            "status": "missing",
            "reason": "program missing from fresh listing",
            "prescan": prescan_prog.get("max_payout_usd"),
            "fresh": None,
        }
    pre = prescan_prog.get("max_payout_usd")
    fr = fresh_prog.get("max_payout_usd")
    if pre is None or fr is None:
        return {
            "pass": True,
            "status": "unknown",
            "reason": (
                "payout unknown (prescan or fresh listing has none);"
                " tri-state unknown does not block verification"
            ),
            "prescan": pre,
            "fresh": fr,
        }
    try:
        _pre_f, _fr_f = float(pre), float(fr)
    except (TypeError, ValueError):
        match = pre == fr
        _delta = None
    else:
        # #24 POLICY: exact float equality blocked verification on any
        # payout wobble (currency-conversion dust, str/float round-trips).
        # Tolerance covers float dust + sub-dollar rounding ONLY — a real
        # payout change still mismatches and blocks.
        match = math.isclose(_pre_f, _fr_f, rel_tol=1e-6, abs_tol=1.0)
        _delta = abs(_fr_f - _pre_f)
    pre_cur = prescan_prog.get("currency") or fresh_prog.get("currency")
    fr_cur = fresh_prog.get("currency") or pre_cur
    if match and pre_cur and fr_cur and pre_cur != fr_cur:
        match = False
    if match:
        _amt = f"${float(fr):,.0f}" if _delta is not None else str(fr)
        reason = f"payout {_amt} {fr_cur or 'USD'} matches prescan"
    elif _delta is None:
        reason = f"payout mismatch: prescan {pre} {pre_cur} vs fresh {fr} {fr_cur}"
    else:
        reason = (
            f"payout mismatch: prescan {pre} {pre_cur} vs fresh {fr} {fr_cur} "
            f"(Δ ${_delta:,.2f})"
        )
    return {
        "pass": match,
        "status": "match" if match else "mismatch",
        "reason": reason,
        "prescan": pre,
        "fresh": fr,
    }


def check_rules_unchanged(
    prescan_prog: Dict[str, Any], fresh_prog: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Check 3: bounty rules text unchanged since prescan (sha256). ADVISORY.

    No feed carries rules/policy text, so this leg is skip-when-unavailable:
    status unknown (either side hashless) is explicit and non-blocking. Only
    a proven change (both hashes present and different) or a vanished program
    fails the leg. Rules text is NEVER faked — unknown stays unknown.
    """
    pre_hash = prescan_prog.get("rules_hash") or rules_hash_of(prescan_prog)
    if fresh_prog is None:
        return {
            "pass": False,
            "status": "missing",
            "advisory": True,
            "reason": "program missing from fresh listing",
            "prescan_hash": pre_hash,
            "fresh_hash": None,
        }
    fr_hash = rules_hash_of(fresh_prog)
    if not pre_hash or not fr_hash:
        return {
            "pass": True,
            "status": "unknown",
            "advisory": True,
            "reason": (
                "rules text unavailable (prescan or fresh has none);"
                " advisory leg skipped, unknown does not block verification"
            ),
            "prescan_hash": pre_hash,
            "fresh_hash": fr_hash,
        }
    match = pre_hash == fr_hash
    return {
        "pass": match,
        "status": "match" if match else "mismatch",
        "advisory": True,
        "reason": (
            "rules text unchanged since prescan"
            if match
            else "rules text changed since prescan"
        ),
        "prescan_hash": pre_hash,
        "fresh_hash": fr_hash,
    }


def verify_program(
    prescan_prog: Dict[str, Any],
    fresh_prog: Optional[Dict[str, Any]],
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
) -> Dict[str, Any]:
    """Run all three checks; verdict is verified iff NO leg blocks.

    scope_live is fail-closed (must pass). payouts_match is tri-state: only
    mismatch/missing block — unknown is explicit and non-blocking. rules is
    advisory skip-when-unavailable: only a proven change or a vanished
    program fails it. A program the feeds can actually describe (live scope,
    unknown payouts, unknown rules) therefore verifies.
    """
    if fresh_prog is None:
        # The program vanished from the fresh listing: a stale snapshot's
        # scope is never probed — fail all three legs explicitly.
        scope: Dict[str, Any] = {
            "pass": False,
            "reason": "program missing from fresh listing",
            "hosts": [],
            "probed": [],
            "skipped": [],
        }
    else:
        scope = check_scope_live(
            fresh_prog, probe_fn=probe_fn, timeout=timeout, no_cloud=no_cloud
        )
    payout = check_payouts_match(prescan_prog, fresh_prog)
    rules = check_rules_unchanged(prescan_prog, fresh_prog)
    verified = bool(scope["pass"] and payout["pass"] and rules["pass"])
    failed = [
        name
        for name, chk in (
            ("scope_live", scope),
            ("payouts_match", payout),
            ("rules_unchanged", rules),
        )
        if not chk["pass"]
    ]
    return {
        "name": prescan_prog.get("name", ""),
        "handle": prescan_prog.get("handle", ""),
        "platform": prescan_prog.get("platform", ""),
        "url": prescan_prog.get("url", ""),
        "score": prescan_prog.get("score", 0) or 0,
        "max_payout_usd": prescan_prog.get("max_payout_usd"),
        "currency": prescan_prog.get("currency", "USD"),
        "verdict": "verified" if verified else "unverified",
        "failed_checks": failed,
        "checks": {
            "scope_live": scope,
            "payouts_match": payout,
            "rules_unchanged": rules,
        },
    }


# ── prescan ─────────────────────────────────────────────────────────────────


def _snapshot_program(prog: Dict[str, Any]) -> Dict[str, Any]:
    scopes = prog.get("structured_scopes", []) or []
    rules_hash = rules_hash_of(prog)
    return {
        "name": prog.get("name", ""),
        "handle": prog.get("handle", ""),
        "platform": prog.get("platform", ""),
        "url": prog.get("url", ""),
        "website": prog.get("website", "") or "",
        "score": prog.get("score", 0) or 0,
        "max_payout_usd": prog.get("max_payout_usd"),
        "currency": prog.get("currency", "USD"),
        "safe_harbor": prog.get("safe_harbor", ""),
        "managed_triage": bool(prog.get("managed_triage", False)),
        "program_kind": prog.get("program_kind", "web2"),
        "first_response_hours": prog.get("first_response_hours"),
        "response_efficiency": prog.get("response_efficiency"),
        "scope_count": len(scopes),
        "structured_scopes": scopes,
        "out_of_scope": list(prog.get("out_of_scope") or []),
        "rules_hash": rules_hash,
        "rules_source": "program.rules_text/policy" if rules_hash else None,
        "trusted": False,
    }


def run_prescan(
    fetch_fn: Optional[FetchFn] = None,
    limit: int = 50,
    sync: bool = False,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
    allow_public_feed: bool = False,
) -> Dict[str, Any]:
    """Fast no-login Scan4Me sweep → prescan report (raw, untrusted).

    Product callers (``fetch_fn is None``) need a fresh, successfully
    refreshed feed. Public provenance is accepted only as raw candidate
    material (``feed_trust.raw_candidate_ok``); it never sets the
    authenticated ``feed_trust.ok`` verdict. When the raw gate fails the
    report is still written with its ``feed_trust`` verdict, then
    :class:`FeedTrustError` is raised so the runlog and the artifact both
    tell the truth. ``allow_public_feed`` is a deprecated compatibility
    argument: accepted, recorded, and never able to mint authenticated
    truth.

    The returned dict carries its file path under ``_report_path``.
    Empty fetch is a valid fail-closed outcome for synthetic callers.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"prescan limit must be an int >= 0, got {limit!r}")
    if sync and no_cloud:
        raise ValueError("--sync refused under --no-cloud (offline: local DB only)")
    if sync:
        import oracle_scan4me as bridge

        home = str(bridge.scan4me_home())
        import sys

        if home not in sys.path:
            sys.path.insert(0, home)
        import scan4me as s4m

        try:
            # Owner design: Scan4Me discovery is no-login. Oracle creates
            # trust later, in its own independent verify pass.
            s4m.sync_data(refresh=True, use_auth=False)
        except Exception as e:
            raise RuntimeError(f"Scan4Me sync failed: {e}") from e

    if fetch_fn is not None:
        programs = list(fetch_fn())[:limit]
    else:
        import oracle_scan4me as bridge

        programs = bridge.fetch_programs(limit=limit)

    provenance = feed_provenance_block()
    trust = feed_trust_block(provenance, allow_public_feed=allow_public_feed)
    trust["enforced"] = fetch_fn is None

    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"prescan_{tag}.json"
    report = {
        "_schema": PRESCAN_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "trusted": False,
        "source": "scan4me-ranked-db",
        "synced": bool(sync),
        "no_cloud": bool(no_cloud),
        "limit": limit,
        "count": len(programs),
        "programs": [_snapshot_program(p) for p in programs],
        "feed_provenance": provenance,
        "feed_trust": trust,
        "note": "raw prescan output — untrusted until the scan verify pass",
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["_report_path"] = str(path)
    if fetch_fn is None and not trust["raw_candidate_ok"]:
        issues = trust.get("raw_candidate_issues") or [
            "unknown raw feed failure"
        ]
        raise FeedTrustError(
            "Scan4Me feed is not fresh enough for raw candidates: "
            + "; ".join(issues)
            + f". Prescan report preserved: {path}",
            report=report,
        )
    return report


# ── feed provenance stamping (#5/#9) ──────────────────────────────────────────


def feed_provenance_block() -> Dict[str, Any]:
    """Scan4Me feed provenance for prescan/scan/handoff stamps.

    Upstream SHA + per-platform status + row counts + age + coverage gaps,
    read live from scan4me.db. Unreadable DB → explicit unavailable marker,
    never a silent omission or a zero-filled guess.
    """
    try:
        import oracle_scan4me as bridge

        home = str(bridge.scan4me_home())
        import sys

        if home not in sys.path:
            sys.path.insert(0, home)
        import scan4me as s4m

        return s4m.feed_provenance()
    except Exception as e:
        return {"unavailable": f"scan4me.db unreadable: {e}"}


class FeedTrustError(RuntimeError):
    """The Scan4Me feed is not fresh enough to supply raw candidates.

    Carries the rejected prescan report so the caller can preserve/name the
    artifact instead of losing the evidence when the process exits.
    """

    def __init__(self, message: str, report: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.report = report or {}
        self.report_path = str(self.report.get("_report_path") or "")


def feed_trust_block(
    provenance: Optional[Dict[str, Any]] = None,
    *,
    allow_public_feed: bool = False,
) -> Dict[str, Any]:
    """Pure trust verdicts for a Scan4Me provenance stamp.

    Two verdicts stay separate. ``ok`` is the authenticated-feed verdict:
    only rows whose source is exactly ``authenticated`` count, and every
    other counted source (``public-file``, live boards/listings, public
    mirrors, unlabeled, or a label invented tomorrow) fails it.
    ``raw_candidate_ok`` is the no-login discovery verdict: public rows
    may pass as raw candidates for Oracle's independent verify pass, but
    an unavailable feed, failed refresh, missing sync timestamp, stale
    flag, age over Scan4Me's 48h bound, or platform refresh error fails.
    Public provenance therefore reaches ``scan`` without ever becoming
    product truth. ``allow_public_feed`` is deprecated compatibility
    only: it is recorded and never changes either verdict.

    Malformed provenance fails closed on both verdicts: a missing or
    non-boolean ``refresh_ok``/``stale``, a non-numeric, NaN, boolean, or
    negative ``age_hours``, a non-object ``platforms`` map, or a platform
    entry/count that cannot be read as a non-negative number is never
    coerced into freshness.
    """
    prov = provenance if isinstance(provenance, dict) else {}
    issues: List[str] = []
    raw_issues: List[str] = []
    warnings: List[str] = []

    def _both(message: str) -> None:
        issues.append(message)
        raw_issues.append(message)

    if not isinstance(provenance, dict):
        _both("feed provenance is malformed (not an object)")
    if prov.get("unavailable"):
        _both(str(prov["unavailable"]))
    if prov.get("refresh_ok") is not True:
        _both(
            "last Scan4Me refresh did not succeed "
            f"(refresh_ok={prov.get('refresh_ok')!r})"
        )
    age = prov.get("age_hours")
    stale = prov.get("stale")
    if stale is True:
        _both(f"feed is stale ({age}h old)")
    elif stale is not False:
        _both(f"feed stale flag is malformed (stale={stale!r})")
    if age is None:
        _both("feed has no successful sync timestamp")
    elif (
        isinstance(age, bool)
        or not isinstance(age, (int, float))
        or not math.isfinite(age)
        or age < 0
    ):
        _both(f"feed age_hours is malformed ({age!r})")
    elif age > RAW_FEED_MAX_AGE_HOURS:
        _both(
            f"feed is stale ({age}h old; raw limit {RAW_FEED_MAX_AGE_HOURS:g}h)"
        )
    raw_platforms = prov.get("platforms")
    if isinstance(raw_platforms, dict):
        platforms = raw_platforms
    else:
        platforms = {}
        _both(
            "feed platforms provenance is malformed "
            f"(platforms={raw_platforms!r})"
        )

    def _count(entry: Dict[str, Any]) -> Optional[float]:
        value = entry.get("count", 0)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            return None
        return float(value)

    malformed_platforms = sorted(
        str(name)
        for name, entry in platforms.items()
        if not isinstance(entry, dict) or _count(entry) is None
    )
    if malformed_platforms:
        _both(
            "platform provenance entries are malformed: "
            + ", ".join(malformed_platforms)
        )

    def _counted(entry: Any) -> bool:
        return isinstance(entry, dict) and (_count(entry) or 0) > 0

    public_rows = sorted(
        str(name)
        for name, entry in platforms.items()
        if _counted(entry) and entry.get("source") != "authenticated"
    )
    public_labels = {
        str(name): str(entry.get("source"))
        for name, entry in platforms.items()
        if str(name) in public_rows and isinstance(entry, dict)
    }
    authenticated = sorted(
        str(name)
        for name, entry in platforms.items()
        if _counted(entry) and entry.get("source") == "authenticated"
    )
    errored = sorted(
        str(name)
        for name, entry in platforms.items()
        if isinstance(entry, dict) and entry.get("status") == "error"
    )
    labeled_public = ", ".join(
        f"{name} ({public_labels.get(name)})" for name in public_rows
    )
    if public_rows:
        issues.append("unauthenticated feed rows: " + labeled_public)
        if allow_public_feed:
            warnings.append(
                "allow_public_feed is deprecated and has no effect; "
                "unauthenticated rows remain raw candidates only: "
                + labeled_public
            )
    if not authenticated:
        issues.append("no authenticated platform rows in the feed")
    if errored:
        issues.append("platform refresh errors: " + ", ".join(errored))
        raw_issues.append("platform refresh errors: " + ", ".join(errored))
    return {
        "ok": not issues,
        "issues": issues,
        "raw_candidate_ok": not raw_issues,
        "raw_candidate_issues": raw_issues,
        "warnings": warnings,
        "stale": prov.get("stale"),
        "age_hours": age,
        "public_platforms": public_rows,
        "public_sources": public_labels,
        "authenticated_platforms": authenticated,
        "errored_platforms": errored,
        "malformed_platforms": malformed_platforms,
        "allow_public_feed": bool(allow_public_feed),
        "overridden": False,
    }


def _prescan_trust(prescan: Dict[str, Any]) -> Dict[str, Any]:
    """Trust block for an existing prescan, re-derived from provenance.

    A stored ``feed_trust`` block is a claim, not evidence: whenever the
    prescan carries provenance, both verdicts are recomputed from that
    provenance and the stored block is ignored. A prescan with no usable
    provenance object cannot establish even raw-candidate freshness —
    however green its stored trust block claims to be — and is rejected.
    """
    prov = prescan.get("feed_provenance")
    if isinstance(prov, dict) and prov:
        return feed_trust_block(prov)
    return {
        "ok": False,
        "issues": ["prescan carries no feed_provenance stamp to re-derive trust"],
        "raw_candidate_ok": False,
        "raw_candidate_issues": [
            "prescan carries no feed_provenance stamp to re-derive trust"
        ],
        "warnings": [],
        "stale": None,
        "age_hours": None,
        "public_platforms": [],
        "public_sources": {},
        "authenticated_platforms": [],
        "errored_platforms": [],
        "malformed_platforms": [],
        "allow_public_feed": False,
        "overridden": False,
    }


def _raw_candidate_ok(trust: Any) -> bool:
    """Fresh raw-candidate verdict, with an authenticated-ok fallback."""
    if not isinstance(trust, dict):
        return False
    if "raw_candidate_ok" in trust:
        return trust.get("raw_candidate_ok") is True
    return trust.get("ok") is True


def _raw_candidate_issues(trust: Any) -> List[str]:
    if not isinstance(trust, dict):
        return ["missing feed_trust stamp"]
    raw = trust.get("raw_candidate_issues")
    if isinstance(raw, list) and raw:
        return [str(x) for x in raw]
    issues = trust.get("issues")
    if isinstance(issues, list) and issues:
        return [str(x) for x in issues]
    return ["unknown raw feed failure"]


def require_trusted_prescan(prescan: Dict[str, Any]) -> Dict[str, Any]:
    """Return the prescan trust block or raise FeedTrustError.

    Historical name kept for API compatibility. Product scan now requires
    fresh raw candidates, not an authenticated Scan4Me feed: trust is
    created per program by Oracle's independent re-scan. Synthetic
    callers/tests can call run_scan directly for pure verdict tests.
    """
    trust = _prescan_trust(prescan)
    if not _raw_candidate_ok(trust):
        raise FeedTrustError(
            "prescan feed is not fresh enough for raw candidates: "
            + "; ".join(_raw_candidate_issues(trust))
        )
    return trust


# ── scan (verify pass) ──────────────────────────────────────────────────────


def load_prescan(source: Any) -> Dict[str, Any]:
    """Load a prescan report from a path or pass through a dict."""
    if isinstance(source, dict):
        return source
    return json.loads(Path(source).read_text(encoding="utf-8"))


def latest_report(out_dir: Optional[Path], prefix: str) -> Optional[Path]:
    """Newest ``<prefix>_*.json`` in a reports dir, or None when absent."""
    directory = out_dir or REPORTS_DIR
    if not directory.is_dir():
        return None
    cands = sorted(directory.glob(f"{prefix}_*.json"))
    return cands[-1] if cands else None


def _default_resolve(name_or_handle: str) -> Optional[Dict[str, Any]]:
    import oracle_scan4me as bridge

    return bridge.resolve(name_or_handle)


def oracle_rescan(
    prog: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Oracle-owned re-scan for the verify pass.

    HackerOne programs are fetched from HackerOne's own authenticated Hacker
    API with Oracle's credentials, never from Scan4Me's DB copy. When API
    credentials are missing or rejected, the fallback is the operator's
    signed-in CDP browser session (``_cdp_rescan_program``) — the browser IS
    the credential. If neither path can produce a fresh program, the result
    is a clean miss: the program stays unverified, and the scan continues.

    Other platforms have no Oracle-side API/browser adapter yet: they return
    no fresh program, explicitly marked ``independent: false`` with source
    ``no-oracle-adapter``, and therefore cannot verify. The Scan4Me bridge
    is never read here — a DB copy cannot corroborate itself.
    """
    platform = str(prog.get("platform") or "").strip()
    handle = str(prog.get("handle") or prog.get("name") or "").strip()
    if platform.lower() != "hackerone":
        return None, {
            "source": "no-oracle-adapter",
            "independent": False,
            "platform": platform,
            "handle": handle,
            "found": False,
        }

    import oracle_h1_api as h1

    fresh: Optional[Dict[str, Any]] = None
    via_cdp = False
    try:
        fresh = h1.fetch_program(handle)
    except h1.H1AuthError:
        # No API credentials — fall back to the signed-in browser session.
        fresh = _cdp_rescan_program(handle)
        via_cdp = fresh is not None

    if fresh is None:
        return None, {
            "source": "hackerone-api-authenticated",
            "independent": True,
            "platform": platform,
            "handle": handle,
            "found": False,
            **({"via_cdp": True} if via_cdp else {}),
        }

    meta = fresh.pop("_oracle_rescan", {})
    meta.setdefault("source", "hackerone-api-authenticated")
    meta["independent"] = True
    # OOS is safety-critical: union the platform's explicit fresh OOS with
    # known snapshot OOS. Never union in-scope assets (that would revive
    # revoked scope).
    known_oos = {
        str(x).strip() for x in (prog.get("out_of_scope") or []) if str(x).strip()
    }
    fresh_oos = {
        str(x).strip() for x in (fresh.get("out_of_scope") or []) if str(x).strip()
    }
    if known_oos - fresh_oos:
        fresh["out_of_scope"] = sorted(known_oos | fresh_oos)
        meta["out_of_scope_union"] = sorted(known_oos - fresh_oos)
    return fresh, meta


# Persistent signed-in profile for the CDP re-scan browser. The operator
# signs in to HackerOne once; the session survives across runs. NEVER a
# throwaway temp dir — a fresh profile is a signed-out profile.
_CDP_PROFILE_DIR = Path.home() / ".oracle-chromium-cdp"
_CDP_DEFAULT_PORT = 9227


def _cdp_tabs(port: int) -> Optional[List[Dict[str, Any]]]:
    """Return the CDP tab list, or None when no browser answers the port."""
    try:
        raw = urllib.request.urlopen(
            f"http://localhost:{port}/json", timeout=3
        ).read()
        tabs = json.loads(raw)
        return tabs if isinstance(tabs, list) else None
    except Exception:
        return None


def _cdp_ensure_browser(port: int = _CDP_DEFAULT_PORT) -> Optional[List[Dict[str, Any]]]:
    """Return CDP tabs, starting the operator's persistent-profile browser if needed.

    The browser runs with the PERSISTENT profile at ``~/.oracle-chromium-cdp``
    so a one-time HackerOne sign-in is enough. A profile that already holds a
    session starts headless; a fresh profile starts headed so the operator can
    sign in. A temp/throwaway profile is never used: a signed-out browser
    cannot verify scope from the platform.
    """
    import subprocess as _sp
    import time as _time

    tabs = _cdp_tabs(port)
    if tabs is not None:
        return tabs

    _CDP_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        profile_has_state = any(_CDP_PROFILE_DIR.iterdir())
    except OSError:
        profile_has_state = True  # unreadable ≠ safe to assume fresh; stay headless
    headless_flags = ["--headless=new"] if profile_has_state else []

    base_flags = [
        f"--remote-debugging-port={port}",
        f"--user-data-dir={_CDP_PROFILE_DIR}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-gpu",
    ]
    for binary in (
        "chromium-browser",
        "chromium",
        "google-chrome-stable",
        "google-chrome",
    ):
        try:
            proc = _sp.Popen(
                [binary, *base_flags, *headless_flags, "about:blank"],
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
            )
        except (FileNotFoundError, OSError):
            continue
        deadline = _time.monotonic() + 30.0
        while _time.monotonic() < deadline:
            tabs = _cdp_tabs(port)
            if tabs is not None:
                return tabs
            if proc.poll() is not None:
                break  # this binary died; try the next
            _time.sleep(1.0)
        try:
            proc.terminate()
        except Exception:
            pass
    return None


def _cdp_call(
    ws: Any,
    msg_id: int,
    method: str,
    params: Dict[str, Any],
    deadline_s: float = 15.0,
) -> Optional[Dict[str, Any]]:
    """Send one CDP command; read replies until the response with msg_id arrives.

    CDP streams interleave protocol events with command responses, so a
    single recv() is NOT guaranteed to return the reply for the command just
    sent. This loops with a deadline and returns the matching response, or
    None on timeout / transport failure.
    """
    import time as _time

    try:
        ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
    except Exception:
        return None
    deadline = _time.monotonic() + deadline_s
    while _time.monotonic() < deadline:
        try:
            ws.settimeout(max(0.1, deadline - _time.monotonic()))
            raw = ws.recv()
        except Exception:
            return None
        try:
            reply = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(reply, dict) and reply.get("id") == msg_id:
            return reply
    return None


def _extract_embedded_scope_records(raw_json: Optional[str]) -> List[Dict[str, Any]]:
    """Scope records from HackerOne's own embedded page JSON, or [].

    Only records carrying HackerOne's structured scope schema
    (``asset_identifier`` + ``asset_type`` — the same field names its API
    returns) are accepted. Raw page text is NEVER scraped into scope: a URL
    that merely appears on the page is not proof it is in scope, and treating
    it as scope would test assets nobody authorized.
    """
    if not raw_json:
        return []
    try:
        data = json.loads(raw_json)
    except (TypeError, ValueError):
        return []

    found: List[Dict[str, Any]] = []
    seen: set = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            ident = node.get("asset_identifier")
            atype = node.get("asset_type")
            if (
                isinstance(ident, str)
                and ident.strip()
                and isinstance(atype, str)
                and atype.strip()
            ):
                key = (ident.strip().lower(), atype.strip().lower())
                if key not in seen:
                    seen.add(key)
                    found.append(
                        {
                            "asset_identifier": ident.strip(),
                            "asset_type": atype.strip(),
                        }
                    )
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return found


def _cdp_rescan_program(handle: str) -> Optional[Dict[str, Any]]:
    """Fetch a HackerOne program through the operator's signed-in browser.

    Uses the persistent CDP profile (``~/.oracle-chromium-cdp``) so a
    one-time HackerOne sign-in survives across re-scans. Only scope records
    embedded by HackerOne itself (structured JSON on the page, the platform's
    own ``asset_identifier`` / ``asset_type`` schema) are accepted; raw page
    text is never scraped into scope. Returns a Scan4Me-shaped program dict,
    or None when the browser is unavailable, the page cannot load, or no
    structured scope can be read (fail closed — the program stays unverified).
    """
    import time as _time

    try:
        import websocket
    except ImportError:
        return None  # websocket-client not installed; CDP path unavailable

    port = _CDP_DEFAULT_PORT
    tabs = _cdp_ensure_browser(port)
    if not tabs:
        return None

    # Prefer an existing HackerOne tab (already signed in); else any page.
    page_tab = next(
        (
            t
            for t in tabs
            if t.get("type") == "page"
            and "hackerone.com" in str(t.get("url") or "")
        ),
        None,
    )
    if page_tab is None:
        page_tab = next((t for t in tabs if t.get("type") == "page"), None)
    if page_tab is None or not page_tab.get("webSocketDebuggerUrl"):
        return None

    try:
        ws = websocket.create_connection(
            page_tab["webSocketDebuggerUrl"], timeout=10
        )
    except Exception:
        return None

    try:
        nav = _cdp_call(
            ws,
            1,
            "Page.navigate",
            {"url": f"https://hackerone.com/programs/{handle}"},
            deadline_s=10.0,
        )
        if nav is None:
            return None
        # Let the SPA hydrate before reading embedded payloads.
        _time.sleep(4)

        eval_reply = _cdp_call(
            ws,
            2,
            "Runtime.evaluate",
            {
                "expression": (
                    "(function(){"
                    "var out={url:location.href,title:document.title,"
                    "next:null,apollo:null};"
                    "try{var n=document.getElementById('__NEXT_DATA__');"
                    "if(n){out.next=n.textContent.slice(0,300000);}}catch(e){}"
                    "try{if(window.__APOLLO_STATE__){"
                    "out.apollo=JSON.stringify(window.__APOLLO_STATE__)"
                    ".slice(0,300000);}}catch(e){}"
                    "return JSON.stringify(out);"
                    "})()"
                ),
                "returnByValue": True,
            },
            deadline_s=15.0,
        )
    finally:
        try:
            ws.close()
        except Exception:
            pass

    if eval_reply is None:
        return None
    raw_value = eval_reply.get("result", {}).get("result", {}).get("value") or ""
    try:
        page_state = json.loads(raw_value)
    except (TypeError, ValueError):
        return None

    title = str(page_state.get("title") or "").lower()
    url = str(page_state.get("url") or "").lower()
    if "not found" in title or "/users/sign_in" in url or "/login" in url:
        # The program page did not load for this session (missing program or
        # not signed in). Fail closed.
        return None

    scopes = _extract_embedded_scope_records(page_state.get("next"))
    if not scopes:
        scopes = _extract_embedded_scope_records(page_state.get("apollo"))
    if not scopes:
        # No structured scope on the page — never guess from raw text.
        return None

    return {
        "name": handle,
        "handle": handle,
        "platform": "hackerone",
        "structured_scopes": scopes,
        "_oracle_rescan": {
            "source": "hackerone-cdp-browser",
            "independent": True,
            "platform": "hackerone",
            "handle": handle,
            "via_cdp": True,
            "scope_records": len(scopes),
        },
    }


def run_scan(
    prescan: Any,
    resolve_fn: Optional[ResolveFn] = None,
    probe_fn: Optional[ProbeFn] = None,
    timeout: float = 8.0,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
    require_trusted_prescan: bool = False,
    rescan_fn: Optional[RescanFn] = None,
) -> Dict[str, Any]:
    """Oracle verification pass over a prescan → scan report with verdicts.

    Product scan passes ``require_trusted_prescan=True`` (historical name;
    now the fresh raw-candidate gate) and ``rescan_fn=oracle_rescan``.
    A fresh public prescan may enter, but trust is created here per
    program: a verdict is ``verified`` only when the three verify legs
    pass **and** the re-scan metadata says ``independent is True``.
    Bridge/DB copies, missing adapters, and absent re-scans therefore
    never verify and never contribute ``_fresh`` scope downstream.
    HackerOne scope must come from Oracle's own authenticated API rather
    than Scan4Me's DB copy.

    Synthetic callers may inject ``rescan_fn`` or, only outside product
    mode, ``resolve_fn`` as an independent-fetch seam. In product mode
    (``require_trusted_prescan=True``) a ``resolve_fn`` is never called
    and can never verify — only ``rescan_fn`` can. The Scan4Me bridge
    resolver (``_default_resolve``) is never independent under any mode,
    and contradictory metadata (bridge source, ``found`` not true, or a
    handle bound to a different program) can never verify.
    """
    report_in = load_prescan(prescan)
    if not isinstance(report_in.get("programs"), list):
        raise ValueError("prescan report has no 'programs' list")
    if require_trusted_prescan:
        prescan_trust = _prescan_trust(report_in)
        if not _raw_candidate_ok(prescan_trust):
            raise FeedTrustError(
                "prescan feed is not fresh enough for raw candidates: "
                + "; ".join(_raw_candidate_issues(prescan_trust))
                + f". Prescan: {report_in.get('_report_path', '')}"
            )
    provenance = feed_provenance_block()
    feed_trust = feed_trust_block(provenance)
    feed_trust["enforced"] = bool(require_trusted_prescan)
    if require_trusted_prescan and not _raw_candidate_ok(feed_trust):
        raise FeedTrustError(
            "current Scan4Me feed is not fresh enough for raw candidates: "
            + "; ".join(_raw_candidate_issues(feed_trust))
        )
    verdicts: List[Dict[str, Any]] = []
    for snap in report_in["programs"]:
        key = snap.get("handle") or snap.get("name") or ""
        if rescan_fn is not None:
            # Product path: an auth/transport failure is a failed scan, not a
            # vanished program. Never convert it into a silent fresh=None.
            try:
                fresh, rescan_meta = rescan_fn(snap)
            except Exception as exc:
                raise RuntimeError(
                    f"Oracle re-scan failed for {key or '<unknown>'}: {exc}"
                ) from exc
        elif require_trusted_prescan:
            # Product mode has exactly one verification seam: rescan_fn.
            # A resolve_fn is not called here at all.
            fresh = None
            rescan_meta = {
                "source": "no-oracle-adapter",
                "independent": False,
                "found": False,
            }
        elif resolve_fn is _default_resolve:
            # The bridge resolver reads Scan4Me's own DB copy. It is never
            # an independent fetch, however the caller labels the seam.
            fresh = None
            rescan_meta = {
                "source": "scan4me-db",
                "independent": False,
                "found": False,
            }
        elif resolve_fn is not None:
            # Explicit synthetic injection is the caller's independent
            # fetch seam (never reached in product mode, handled above).
            try:
                fresh = resolve_fn(key) if key else None
            except Exception:
                fresh = None
            rescan_meta = {
                "source": "injected-resolver",
                "independent": True,
                "found": isinstance(fresh, dict),
                "handle": key,
            }
        else:
            fresh = None
            rescan_meta = {
                "source": "no-oracle-adapter",
                "independent": False,
                "found": False,
            }
        if not isinstance(rescan_meta, dict):
            rescan_meta = {
                "source": "invalid-rescan-metadata",
                "independent": False,
                "found": False,
            }
        verdict = verify_program(
            snap, fresh, probe_fn=probe_fn, timeout=timeout, no_cloud=no_cloud
        )
        verdict["oracle_rescan"] = rescan_meta
        independent_attempt = _rescan_source_is_independent(rescan_meta)
        verified_allowed = isinstance(fresh, dict) and (
            is_independent_rescan_meta(rescan_meta, snap)
        )
        if not verified_allowed:
            verdict["verdict"] = "unverified"
            # A genuinely independent "program vanished" answer already
            # fails the three legs on its own; every other non-allowed
            # shape (bridge, missing adapter, contradictory found/source,
            # wrong handle) names the independent-rescan gate explicitly.
            vanished = (
                independent_attempt
                and fresh is None
                and rescan_meta.get("found") is False
            )
            if not vanished and (
                "oracle_independent_rescan" not in verdict["failed_checks"]
            ):
                verdict["failed_checks"].append("oracle_independent_rescan")
            verdict["_fresh"] = None
        else:
            # Keep the exact scope snapshot the verify pass used. Deep-dive
            # must consume this, not re-resolve the Scan4Me DB after an
            # independent re-scan.
            verdict["_fresh"] = fresh
        verdicts.append(verdict)
    verified = [v for v in verdicts if v["verdict"] == "verified"]
    rescan_metas = [v.get("oracle_rescan") or {} for v in verdicts]
    independent_count = sum(
        1 for meta in rescan_metas if _rescan_source_is_independent(meta)
    )
    rescan_sources = sorted(
        {str(meta.get("source")) for meta in rescan_metas if meta.get("source")}
    )
    if not rescan_metas:
        rescan_mode = "none"
    elif independent_count == len(rescan_metas):
        rescan_mode = "independent"
    elif independent_count:
        rescan_mode = "mixed"
    elif rescan_sources == ["no-oracle-adapter"]:
        rescan_mode = "no-oracle-adapter"
    else:
        rescan_mode = "scan4me-db"
    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"scan_{tag}.json"
    report = {
        "_schema": SCAN_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "prescan_report": str(report_in.get("_report_path", "")),
        "no_cloud": bool(no_cloud),
        "count": len(verdicts),
        "verified_count": len(verified),
        "verdicts": verdicts,
        "feed_provenance": provenance,
        "feed_trust": feed_trust,
        "oracle_rescan": {
            "mode": rescan_mode,
            "independent": bool(rescan_metas)
            and independent_count == len(rescan_metas),
            "programs": len(rescan_metas),
            "independent_programs": independent_count,
            "sources": rescan_sources,
        },
        "note": "only verdict=verified programs may proceed to deep-dive/handoff",
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["_report_path"] = str(path)
    return report


# ── -N deep-dive (verified only) + P12 handoff ───────────────────────────────


def _deep_dive_for(
    prog: Dict[str, Any],
    verdict: Dict[str, Any],
    fresh: bool = False,
    fresh_source: str = "",
) -> Dict[str, Any]:
    scopes = prog.get("structured_scopes", []) or []
    sources = ["scan4me:programs+assets"]
    if fresh:
        sources.append(fresh_source or "deep-dive:fresh-resolve")
    return {
        "assets": scopes,
        "out_of_scope": list(prog.get("out_of_scope") or []),
        "company": {
            "name": prog.get("name", ""),
            "handle": prog.get("handle", ""),
            "platform": prog.get("platform", ""),
            "program_url": prog.get("url", ""),
            "website": prog.get("website", "") or "",
            "safe_harbor": prog.get("safe_harbor", ""),
            "managed_triage": bool(prog.get("managed_triage", False)),
            "program_kind": prog.get("program_kind", "web2"),
            "first_response_hours": prog.get("first_response_hours"),
            "response_efficiency": prog.get("response_efficiency"),
        },
        "resources": {
            "program_url": prog.get("url", ""),
            "platform": prog.get("platform", ""),
            "max_payout_usd": prog.get("max_payout_usd"),
            "currency": prog.get("currency", "USD"),
            "scope_count": len(scopes),
        },
        "sources": sources,
        "checks": verdict.get("checks", {}),
    }


def _matches_site(prog: Dict[str, Any], site: str) -> bool:
    """Precise --sites matching: exact on name/handle, domain-boundary on URLs.

    Pure substring matching ("acm" hits "Acme", "evil-acme.com" hits
    "acme.com") caused false-positive deep-dives, so:
      - ``name`` / ``handle`` must equal the site (case-insensitive);
      - ``url`` / ``website`` compare by host: equal, or one a
        domain-boundary parent of the other (``app.acme.com`` matches a
        program on ``acme.com``, but ``notacme.com`` never matches).
    """
    needle = (site or "").strip().lower().rstrip(".")
    if not needle:
        return False
    for key in ("name", "handle"):
        val = prog.get(key)
        if isinstance(val, str) and val.strip().lower() == needle:
            return True
    needle_host = _strip_to_host(needle)
    if not needle_host:
        return False
    for key in ("url", "website"):
        val = prog.get(key)
        if not isinstance(val, str) or not val.strip():
            continue
        host = _strip_to_host(val)
        if not host:
            continue
        if needle_host == host:
            return True
        if host.endswith("." + needle_host) or needle_host.endswith("." + host):
            return True
    return False


_NON_INDEPENDENT_RESCAN_SOURCES = {
    "scan4me-db",
    "no-oracle-adapter",
    "missing",
    "invalid-rescan-metadata",
}


def _rescan_source_is_independent(meta: Any) -> bool:
    """Source/mode half of the strict re-scan check (found may be False)."""
    if not isinstance(meta, dict) or meta.get("independent") is not True:
        return False
    source = meta.get("source")
    if (
        not isinstance(source, str)
        or not source.strip()
        or source.strip().lower() in _NON_INDEPENDENT_RESCAN_SOURCES
    ):
        return False
    mode = meta.get("mode")
    if (
        isinstance(mode, str)
        and mode.strip().lower() in _NON_INDEPENDENT_RESCAN_SOURCES
    ):
        return False
    return True


def is_independent_rescan_meta(
    meta: Any, entry: Optional[Dict[str, Any]] = None
) -> bool:
    """Strict independent-found re-scan metadata check.

    This is the single downstream trust anchor shared by scan, deep-dive,
    download, queue, queue execution, and bundle readiness. It requires
    ``independent is True``, ``found is True``, and a non-empty source
    that is not a known bridge/missing/adapter-absent label. When the
    metadata carries a ``handle`` and an entry is supplied, the handle
    must bind to that entry's handle or name — a strict stamp minted for
    one program cannot be replayed onto another.
    """
    if not _rescan_source_is_independent(meta):
        return False
    if not isinstance(meta, dict) or meta.get("found") is not True:
        return False
    handle = meta.get("handle")
    if entry is not None and isinstance(handle, str) and handle.strip():
        wanted = handle.strip().lower()
        candidates = {
            str(entry.get(key) or "").strip().lower()
            for key in ("handle", "name")
        }
        if wanted not in candidates:
            return False
    return True


def is_independently_verified_entry(entry: Any) -> bool:
    """True only for a whole scan-shaped independently verified entry.

    Requires ``verdict == "verified"``, no failed checks, and strict
    independent-found re-scan metadata bound to the entry. One green
    flag on an otherwise contradictory record is never enough.
    """
    if not isinstance(entry, dict) or entry.get("verdict") != "verified":
        return False
    failed = entry.get("failed_checks", [])
    if not isinstance(failed, list) or failed:
        return False
    return is_independent_rescan_meta(entry.get("oracle_rescan"), entry)


def _is_independently_verified(entry: Dict[str, Any]) -> bool:
    """Backward-compatible private alias for the strict entry check."""
    return is_independently_verified_entry(entry)


def select_deep_dive(
    scan_report: Dict[str, Any],
    prescan_programs: Optional[List[Dict[str, Any]]] = None,
    top_n: Optional[int] = None,
    sites: Optional[List[str]] = None,
    resolve_fn: Optional[ResolveFn] = None,
) -> Dict[str, Any]:
    """Pick independently verified programs for deep-dive.

    Named sites override the count. Only entries with
    ``verdict == verified`` **and** ``oracle_rescan.independent is True``
    are ever selected — unverified or bridge-only programs (including
    named ones) land in ``excluded`` and never proceed. Without ``top_n``
    or ``sites``, ALL such programs are selected, ranked by score (P12
    owns ``default_count`` scheduling, not P11).

    Assets/company/resources come from the scan verdict's embedded
    ``_fresh`` program — the exact independent listing the verify pass
    used. For scan reports without embedded fresh data, an explicitly
    injected ``resolve_fn`` may supply it at dive time. A program missing
    from (or erroring on) that listing, or with neither fresh source, is
    excluded fail-closed with a ``deep-dive-stale`` reason. The prescan
    snapshot is never a scope fallback.
    """
    if top_n is not None and (
        isinstance(top_n, bool) or not isinstance(top_n, int) or top_n < 0
    ):
        raise ValueError(f"-N/--top-n must be an int >= 0, got {top_n!r}")
    by_key: Dict[str, Dict[str, Any]] = {}
    for prog in prescan_programs or []:
        for key in (prog.get("handle") or "", prog.get("name") or ""):
            if key and key not in by_key:
                by_key[key] = prog

    verified = [
        v
        for v in scan_report.get("verdicts", [])
        if _is_independently_verified(v)
    ]
    verified.sort(key=lambda v: (v.get("score", 0) or 0), reverse=True)

    site_list = [s.strip() for s in (sites or []) if s and s.strip()]
    excluded: List[Dict[str, Any]] = []
    if site_list:
        picked: List[Dict[str, Any]] = []

        def _site_hit(verdict: Dict[str, Any], site: str) -> bool:
            if _matches_site(verdict, site):
                return True
            snap = by_key.get(verdict.get("handle") or verdict.get("name") or "", {})
            return _matches_site(snap, site)

        for site in site_list:
            match = next((v for v in verified if _site_hit(v, site)), None)
            if match is not None:
                if match not in picked:
                    picked.append(match)
                continue
            # No verified hit: name the reason — unverified match, or nothing.
            unverified_hit = next(
                (
                    v
                    for v in scan_report.get("verdicts", [])
                    if not _is_independently_verified(v) and _site_hit(v, site)
                ),
                None,
            )
            if unverified_hit is not None:
                failed = list(unverified_hit.get("failed_checks", []) or [])
                if not is_independent_rescan_meta(
                    unverified_hit.get("oracle_rescan"), unverified_hit
                ) and "oracle_independent_rescan" not in failed:
                    failed.append("oracle_independent_rescan")
                excluded.append(
                    {
                        "site": site,
                        "program": unverified_hit.get("name", ""),
                        "reason": (
                            "program is unverified "
                            f"(failed: {','.join(failed)});"
                            " unverified programs never proceed"
                        ),
                    }
                )
            else:
                excluded.append({"site": site, "reason": "no verified program matches"})
        selected = picked
    elif top_n is not None:
        selected = verified[:top_n]
    else:
        selected = verified

    ranked: List[Dict[str, Any]] = []
    rank = 0
    for verdict in selected:
        snap = by_key.get(verdict.get("handle") or verdict.get("name") or "", {})
        merged = {**snap, **verdict}
        fresh_used = False
        fresh_source = ""
        embedded_fresh = verdict.get("_fresh")
        embedded_scopes = (
            embedded_fresh.get("structured_scopes")
            if isinstance(embedded_fresh, dict)
            else None
        )
        if isinstance(embedded_fresh, dict) and isinstance(
            embedded_scopes, list
        ):
            # The verify pass already fetched this scope independently.
            # Reuse it byte-for-byte; never re-resolve through a stale DB
            # after an independent re-scan. Scope fields are pinned to the
            # fresh listing after the merge so a snapshot or verdict key
            # can never supply them by fall-through.
            merged = {**snap, **embedded_fresh, **verdict}
            merged["structured_scopes"] = embedded_scopes
            merged["out_of_scope"] = list(
                embedded_fresh.get("out_of_scope") or []
            )
            fresh_used = True
            fresh_source = str(
                (verdict.get("oracle_rescan") or {}).get("source") or "scan-rescan"
            )
            fresh_source = f"scan-rescan:{fresh_source}"
        elif resolve_fn is not None:
            key = verdict.get("handle") or verdict.get("name") or ""
            try:
                fresh_prog = resolve_fn(key) if key else None
            except Exception:
                fresh_prog = None
            fresh_scopes = (
                fresh_prog.get("structured_scopes")
                if isinstance(fresh_prog, dict)
                else None
            )
            if not isinstance(fresh_prog, dict) or not isinstance(
                fresh_scopes, list
            ):
                excluded.append(
                    {
                        "site": verdict.get("name", ""),
                        "program": verdict.get("name", ""),
                        "reason": (
                            "deep-dive-stale: program missing from the fresh"
                            " listing (or its structured_scopes) at"
                            " deep-dive time; prescan snapshot not used"
                            " (fail-closed)"
                        ),
                    }
                )
                continue
            merged = {**snap, **fresh_prog, **verdict}
            merged["structured_scopes"] = fresh_scopes
            merged["out_of_scope"] = list(fresh_prog.get("out_of_scope") or [])
            fresh_used = True
            fresh_source = "deep-dive:fresh-resolve"
        else:
            excluded.append(
                {
                    "site": verdict.get("name", ""),
                    "program": verdict.get("name", ""),
                    "reason": (
                        "deep-dive-stale: no Oracle-verified fresh scope "
                        "embedded in the scan verdict and no resolver "
                        "injected; prescan snapshot not used (fail-closed)"
                    ),
                }
            )
            continue
        rank += 1
        ranked.append(
            {
                "rank": rank,
                "name": verdict.get("name", ""),
                "handle": verdict.get("handle", ""),
                "platform": verdict.get("platform", ""),
                "url": verdict.get("url", ""),
                "score": verdict.get("score", 0) or 0,
                "max_payout_usd": verdict.get("max_payout_usd"),
                "currency": verdict.get("currency", "USD"),
                "verdict": "verified",
                "failed_checks": list(verdict.get("failed_checks") or []),
                "checks": verdict.get("checks", {}),
                "oracle_rescan": verdict.get("oracle_rescan", {}),
                "deep_dive": _deep_dive_for(
                    merged,
                    verdict,
                    fresh=fresh_used,
                    fresh_source=fresh_source,
                ),
            }
        )
    selection: Dict[str, Any] = {
        "ranked_verified": ranked,
        "excluded_named": excluded,
        "oracle_rescan": scan_report.get("oracle_rescan", {}),
    }
    # Carry the scan's own discovery stamps forward verbatim. The handoff
    # must describe the feed this scan consumed, never a later live feed.
    if isinstance(scan_report.get("feed_provenance"), dict):
        selection["feed_provenance"] = dict(scan_report["feed_provenance"])
    if isinstance(scan_report.get("feed_trust"), dict):
        selection["feed_trust"] = dict(scan_report["feed_trust"])
    return selection


def write_handoff(
    selection: Dict[str, Any],
    scan_report_path: str = "",
    prescan_report_path: str = "",
    top_n: Optional[int] = None,
    sites: Optional[List[str]] = None,
    no_cloud: bool = False,
    out_dir: Optional[Path] = None,
    stamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Write the P12 handoff file (ranked-verified list). Returns the payload.

    The payload carries its file path under ``_report_path``. An empty
    verified set still writes a file (fail-closed empty), never nothing.
    Discovery provenance is copied from the selection (which copies it
    from the scan report) when present: a later live Scan4Me sync must
    never relabel what this scan actually consumed. The trust verdicts
    are then re-derived from that copied provenance — a stored trust
    block paired with it is a claim and is never copied through.
    Selections without provenance (synthetic callers) fall back to a
    live stamp.
    """
    directory = out_dir or REPORTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    tag = stamp or _stamp()
    path = directory / f"intake_ranked_verified_{tag}.json"
    sel_provenance = selection.get("feed_provenance")
    if isinstance(sel_provenance, dict) and sel_provenance:
        provenance = dict(sel_provenance)
    else:
        provenance = feed_provenance_block()
    feed_trust = feed_trust_block(provenance)
    feed_trust["enforced"] = True
    payload = {
        "_schema": HANDOFF_SCHEMA,
        "created_utc": _utc_now().isoformat(),
        "prescan_report": prescan_report_path,
        "scan_report": scan_report_path,
        "no_cloud": bool(no_cloud),
        "selector": {"top_n": top_n, "sites": sites or None},
        "ranked_verified": selection.get("ranked_verified", []),
        "excluded_named": selection.get("excluded_named", []),
        "oracle_rescan": selection.get("oracle_rescan", {}),
        "feed_provenance": provenance,
        "feed_trust": feed_trust,
        "note": "unverified programs never appear here; see the scan report",
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    payload["_report_path"] = str(path)
    return payload


# ── workspace downloads for the verified selection ───────────────────────────


def _download_assets_list(raw: Any, *, field: str) -> List[Dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list):
        raise ValueError(f"{field} must be a list or string, got {type(raw).__name__}")
    out: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(dict(item))
        elif isinstance(item, str) and item.strip():
            out.append({"asset_identifier": item.strip()})
        else:
            raise ValueError(f"{field} entries must be objects or strings")
    return out


def _download_oos_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [line.strip() for line in raw.splitlines() if line.strip()]
    if not isinstance(raw, list):
        raise ValueError(
            f"out_of_scope must be a list or string, got {type(raw).__name__}"
        )
    out: List[str] = []
    for item in raw:
        if isinstance(item, dict):
            ident = item.get("asset_identifier") or item.get("identifier") or ""
            if str(ident).strip():
                out.append(str(ident).strip())
        elif isinstance(item, str) and item.strip():
            out.append(item.strip())
        else:
            raise ValueError("out_of_scope entries must be objects or strings")
    return out


def _prog_for_download(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map a ranked-verified handoff entry to the cache-shaped ``prog``
    dict the bulk downloader consumes (scopes at ``structured_scopes``,
    company fields flat). Passing the raw entry would silently degrade
    to scope-reintake plus a program-page-only download."""
    if not isinstance(entry, dict):
        raise TypeError(
            f"ranked_verified entry must be an object, got {type(entry).__name__}"
        )
    deep = entry.get("deep_dive")
    if deep is None:
        deep = {}
    if not isinstance(deep, dict):
        raise ValueError("deep_dive must be an object")
    company = deep.get("company") or {}
    if not isinstance(company, dict):
        raise ValueError("deep_dive.company must be an object")
    if "assets" in deep:
        assets_raw = deep.get("assets")
    elif "structured_scopes" in entry:
        assets_raw = entry.get("structured_scopes")
    else:
        raise ValueError("entry has no deep_dive.assets or structured_scopes")
    assets = _download_assets_list(assets_raw, field="deep_dive.assets")
    oos_raw = (
        deep.get("out_of_scope")
        if "out_of_scope" in deep
        else entry.get("out_of_scope")
    )
    oos = _download_oos_list(oos_raw)
    name = str(entry.get("name") or company.get("name", "") or "").strip()
    platform = str(entry.get("platform") or company.get("platform", "") or "").strip()
    if not name or not platform:
        raise ValueError("entry requires non-empty name and platform for a workspace")
    return {
        "name": name,
        "handle": entry.get("handle") or company.get("handle", ""),
        "platform": platform,
        "url": entry.get("url") or company.get("program_url", ""),
        "website": company.get("website", "") or entry.get("website", "") or "",
        "safe_harbor": company.get("safe_harbor", ""),
        "managed_triage": bool(company.get("managed_triage", False)),
        "program_kind": company.get("program_kind", "web2"),
        "first_response_hours": company.get("first_response_hours"),
        "response_efficiency": company.get("response_efficiency"),
        "max_payout_usd": entry.get("max_payout_usd"),
        "currency": entry.get("currency", "USD"),
        "structured_scopes": assets,
        "out_of_scope": oos,
    }


DownloadFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def download_selected_workspaces(
    selection: Dict[str, Any],
    download_fn: Optional[DownloadFn] = None,
    cdp_port: int = 9227,
    take_screenshot: bool = False,
) -> Dict[str, Any]:
    """Download one workspace per ranked-verified entry in ``selection``.

    Each entry gains ``workspace: {path, status, detail}`` where status is
    ``present`` (manifest already on disk — skipped), the downloader's own
    status (``downloaded``/``empty``), ``skipped``, or ``error``. A
    failure on one program never aborts the rest. An entry is touched
    only when it is ``verified`` with an independent Oracle re-scan;
    bridge-only or unstamped entries are skipped even if a caller placed
    them in ``ranked_verified`` by hand.
    """
    from oracle_bulk_download import (
        already_downloaded,
        download_one,
        workspace_base_for,
    )

    fn: DownloadFn = download_fn or (
        lambda prog: download_one(
            prog, cdp_port=cdp_port, take_screenshot=take_screenshot
        )
    )
    if not isinstance(selection, dict):
        raise ValueError(f"selection must be an object, got {type(selection).__name__}")
    ranked = selection.get("ranked_verified", [])
    if ranked is None:
        ranked = []
    if not isinstance(ranked, list):
        raise ValueError("selection.ranked_verified must be a list")
    for entry in ranked:
        base = ""
        try:
            if not isinstance(entry, dict):
                raise TypeError(
                    f"ranked_verified entry must be an object, got {type(entry).__name__}"
                )
            if not is_independently_verified_entry(entry):
                entry["workspace"] = {
                    "path": "",
                    "status": "skipped",
                    "detail": (
                        "not independently Oracle-verified "
                        f"(verdict={entry.get('verdict')!r}, "
                        f"failed_checks={entry.get('failed_checks')!r}, "
                        f"oracle_rescan={entry.get('oracle_rescan')!r})"
                    ),
                }
                continue
            prog = _prog_for_download(entry)
            base = str(workspace_base_for(prog))
            if already_downloaded(prog):
                entry["workspace"] = {
                    "path": base,
                    "status": "present",
                    "detail": "complete download report already on disk",
                }
                continue
            res = fn(prog) or {}
            entry["workspace"] = {
                "path": base,
                "status": str(res.get("status", "unknown")),
                "detail": str(res.get("detail", "")),
            }
        except Exception as exc:  # per-program isolation; status recorded
            if isinstance(entry, dict):
                entry["workspace"] = {
                    "path": base,
                    "status": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            else:
                selection.setdefault("download_errors", []).append(
                    f"{type(exc).__name__}: {exc}"
                )
    return selection
