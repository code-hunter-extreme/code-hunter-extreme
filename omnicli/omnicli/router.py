"""Health-aware provider routing for swarms and red-team panels.

A red-team panel is only as good as its live members. With dozens of
configured gateways, some are balance-gated (402), account-gated (401/403),
throttled (429) or simply unreachable. Fanning out to all of them wastes
calls, burns wall-clock time and can fail a family-diversity gate because
"configured" members never actually answered.

This module ranks providers by locally known health and remembers recent
failures so the next panel starts from the healthy set. It performs NO
network I/O: health comes from the heartbeat status file (``omni
heartbeat``) and a small failure cache written by swarm runs. Probing is
explicit and belongs to ``omni heartbeat``.

Failure memory is best-effort: a corrupt or unwritable cache must never
break a run, so all persistence errors are swallowed.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_PANEL_CAP = 8
FAILURE_TTL_S = 30 * 60
ACCOUNT_FAILURE_TTL_S = 24 * 60 * 60

_HEALTHY_STATUSES = {"healthy", "ok", "up"}
_UNHEALTHY_STATUSES = {
    "unhealthy",
    "unreachable",
    "error",
    "auth_error",
    "down",
    "offline",
    "invalid",
    "config_needed",
}

_TIER = {"healthy": 0, "degraded": 1, "unknown": 2, "unhealthy": 3}


def classify_failure(message: Any) -> str:
    """Classify a member/provider error into a routing category.

    Categories drive how long a provider is deprioritized: account-level
    failures (balance/auth) are sticky for a day, transient ones for 30 min.
    """
    text = str(message or "").lower()
    if any(
        key in text
        for key in (
            "402",
            "insufficient balance",
            "out of credits",
            "credit limit",
            "budget_exceeded",
            "free_quota_exhausted",
            "balance is too low",
            "quota exhausted",
        )
    ):
        return "balance"
    if any(
        key in text
        for key in (
            "401",
            "403",
            "unauthorized",
            "invalid api key",
            "authentication",
            "forbidden",
            "error code: 1010",
        )
    ):
        return "auth"
    if any(key in text for key in ("429", "rate limit", "too many requests", "throttl")):
        return "throttle"
    if any(
        key in text
        for key in ("timeout", "timed out", "connection", "unreachable", "dns", "network")
    ):
        return "unreachable"
    if any(key in text for key in ("500", "502", "503", "504", "server error", "upstream")):
        return "server"
    return "unknown"


def _failure_ttl(kind: str) -> int:
    return ACCOUNT_FAILURE_TTL_S if kind in ("balance", "auth") else FAILURE_TTL_S


class ProviderRouter:
    """Rank providers for a swarm panel using local health signals."""

    def __init__(self, cfg: Any, now: Optional[float] = None) -> None:
        self.cfg = cfg
        self._now = now

    # ------------------------------------------------------------------ paths
    def _status_file(self) -> Optional[Path]:
        try:
            status = self.cfg.get_heartbeat_config().get("status_file")
        except (AttributeError, KeyError, TypeError):
            return None
        if not status:
            return None
        return Path(str(status)).expanduser()

    def _failure_file(self) -> Path:
        return Path(self.cfg.config_dir) / "provider_failures.json"

    def _now_ts(self) -> float:
        return time.time() if self._now is None else float(self._now)

    # ----------------------------------------------------------------- health
    def _heartbeat_health(self) -> Dict[str, str]:
        path = self._status_file()
        if path is None or not path.is_file():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        records = payload.get("providers") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return {}
        out: Dict[str, str] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            pid = str(record.get("provider") or "").strip().lower()
            status = str(record.get("status") or "").strip().lower()
            if not pid or not status:
                continue
            canary = record.get("canary")
            if isinstance(canary, dict) and canary.get("ok") is False:
                # /models answered but the canary chat call did not: the
                # endpoint is reachable, the provider is not usable.
                out[pid] = "unhealthy"
            else:
                out[pid] = status
        return out

    def failures(self) -> Dict[str, Dict[str, Any]]:
        """Active (unexpired) failure records: pid -> {until, reason, ...}."""
        path = self._failure_file()
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        now = self._now_ts()
        out: Dict[str, Dict[str, Any]] = {}
        for pid, record in data.items():
            if not isinstance(record, dict):
                continue
            until = record.get("until")
            if isinstance(until, (int, float)) and until > now:
                out[str(pid).lower()] = record
        return out

    def _write_failures(self, data: Dict[str, Dict[str, Any]]) -> None:
        path = self._failure_file()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            tmp.replace(path)
        except OSError:
            # Routing memory is an optimization; never fail a run for it.
            pass

    def health(self) -> Dict[str, str]:
        """pid -> healthy | degraded | unknown | unhealthy.

        Heartbeat status is the base signal; an active failure record
        overrides it to ``unhealthy`` until the TTL expires.
        """
        heartbeat = self._heartbeat_health()
        out: Dict[str, str] = {}
        for pid, status in heartbeat.items():
            if status in _HEALTHY_STATUSES:
                out[pid] = "healthy"
            elif status in _UNHEALTHY_STATUSES or status in {
                "http_401",
                "http_402",
                "http_403",
                "http_404",
            }:
                out[pid] = "unhealthy"
            else:
                # Throttles (http_429) and upstream 5xx are transient;
                # auth/balance/not-found codes above are sticky.
                out[pid] = "degraded"
        for pid in self.failures():
            out[pid] = "unhealthy"
        return out

    def tier(self, provider: str, health: Optional[Dict[str, str]] = None) -> int:
        status = (health if health is not None else self.health()).get(
            provider.lower(), "unknown"
        )
        return _TIER.get(status, 2)

    # -------------------------------------------------------------- selection
    def usable_providers(self, provider: Optional[str] = None) -> List[str]:
        """Providers that could actually be called with current credentials."""
        all_providers = list(self.cfg.data.get("providers", {}).keys())
        if provider:
            # An explicit provider is an operator instruction: keep it even
            # if the local config does not know it yet (a patched/extension
            # config may resolve it). Unknown ids simply yield no models.
            return [provider.lower()]
        usable = [
            pid
            for pid in all_providers
            if self.cfg.has_credential(pid)
            or not self.cfg.provider_requires_key(pid)
        ]
        return usable or all_providers

    def _primary_family(self, provider: str) -> str:
        """Family of the provider's default model (fallback: first roster model)."""
        from omnicli.scanner import classify_family

        try:
            model = self.cfg.get_default_model(provider)
        except (AttributeError, KeyError, TypeError):
            model = ""
        if not model:
            try:
                fallbacks = list(self.cfg.get_fallback_models(provider))
            except (AttributeError, KeyError, TypeError):
                fallbacks = []
            model = fallbacks[0] if fallbacks else ""
        return classify_family(model) if model else "other"

    def ranked_providers(self, provider: Optional[str] = None) -> List[str]:
        """Tier order, but one provider per family first.

        A red-team panel gains more from a distinct family than from a
        second instance of a family already present. Known-dead providers
        stay at the end so diversity never resurrects them.
        """
        providers = self.usable_providers(provider)
        health = self.health()
        order = {pid: index for index, pid in enumerate(providers)}
        tiered = sorted(
            providers,
            key=lambda pid: (self.tier(pid, health), order[pid]),
        )
        usable = [pid for pid in tiered if self.tier(pid, health) < 3]
        dead = [pid for pid in tiered if self.tier(pid, health) >= 3]
        seen: set = set()
        head: List[str] = []
        for pid in usable:
            family = self._primary_family(pid)
            if family not in seen:
                seen.add(family)
                head.append(pid)
        chosen = set(head)
        return head + [pid for pid in usable if pid not in chosen] + dead

    def build_panel(
        self,
        size: Optional[int] = None,
        provider: Optional[str] = None,
        cap: int = DEFAULT_PANEL_CAP,
    ) -> List[Tuple[str, str]]:
        """Health-ranked, family-diverse (provider, model) panel.

        ``size=None`` means "up to ``cap``" rather than "every configured
        provider": a red-team panel should be deliberate, not a fan-out to
        every key in the config. Providers with an active failure record are
        only used to fill a panel that the healthy set cannot complete.
        """
        from omnicli.orchestrate import build_swarm

        ranked = self.ranked_providers(provider)
        if not ranked:
            return []
        failures = self.failures()
        preferred = [pid for pid in ranked if pid not in failures]
        fallback = [pid for pid in ranked if pid in failures]
        if size is None or size <= 0:
            size = min(cap, len(ranked))
        size = max(1, int(size))
        panel = build_swarm(
            self.cfg, size=size, providers=preferred or ranked
        )
        if len(panel) < size and fallback:
            for pair in build_swarm(self.cfg, size=size, providers=fallback):
                if pair not in panel:
                    panel.append(pair)
                if len(panel) >= size:
                    break
        return panel[:size]

    # ------------------------------------------------------------- feedback
    def record_failure(self, provider: str, message: Any) -> None:
        pid = str(provider or "").strip().lower()
        if not pid:
            return
        data = self.failures()
        now = self._now_ts()
        record = data.get(pid, {})
        kind = classify_failure(message)
        data[pid] = {
            "until": now + _failure_ttl(kind),
            "reason": kind,
            "message": str(message or "")[:200],
            "count": int(record.get("count", 0)) + 1,
            "recorded_at": now,
        }
        data = {
            key: value
            for key, value in data.items()
            if isinstance(value, dict) and value.get("until", 0) > now
        }
        self._write_failures(data)

    def record_success(self, provider: str) -> None:
        pid = str(provider or "").strip().lower()
        if not pid:
            return
        data = self.failures()
        if pid in data:
            data.pop(pid)
            self._write_failures(data)

    def record_results(self, members: Optional[List[Dict[str, Any]]]) -> None:
        """Update failure memory from swarm member records (best-effort)."""
        data = self.failures()
        now = self._now_ts()
        changed = False
        for member in members or []:
            if not isinstance(member, dict):
                continue
            pid = str(member.get("provider") or "").strip().lower()
            if not pid:
                continue
            if member.get("error"):
                kind = classify_failure(member.get("error"))
                previous = data.get(pid, {})
                data[pid] = {
                    "until": now + _failure_ttl(kind),
                    "reason": kind,
                    "message": str(member.get("error") or "")[:200],
                    "count": int(previous.get("count", 0)) + 1,
                    "recorded_at": now,
                }
                changed = True
            elif str(member.get("answer") or "").strip():
                if pid in data:
                    data.pop(pid)
                    changed = True
        if changed:
            data = {
                key: value
                for key, value in data.items()
                if isinstance(value, dict) and value.get("until", 0) > now
            }
            self._write_failures(data)
