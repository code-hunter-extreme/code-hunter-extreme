#!/usr/bin/env python3
"""
Scan4Me: Precision Bug Bounty Intelligence & Scope Targeter
Filters tens of thousands of assets across HackerOne, Bugcrowd, Intigriti,
YesWeHack, Immunefi, Sherlock, PDPrograms, and listing-only discovery feeds
(Bugbase, HackenProof, Cantina, Patchstack, Huntr, CodeHawks) for paid
program discovery, scope size, available response-time measurements, and
first-observed changes in the imported feeds. Standalone ranking uses this
repo's config.json; under Oracle, triage.yaml overlays it (see README).
"""

import argparse
import base64
import ipaddress
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess  # nosec B404
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Any

from scan4me_pkg.fx_rates import to_usd as _fx_to_usd
from scan4me_pkg.fx_rates import FX_TO_USD as _STATIC_FX_TO_USD

REPO_ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SCAN4ME_DB_PATH") or REPO_ROOT / "scan4me.db")
CONFIG_PATH = REPO_ROOT / "config.json"
CONFIG_EXAMPLE_PATH = REPO_ROOT / "config.example.json"
CACHE_DATA_DIR = REPO_ROOT / "data_cache"

# ── SQL fragment validation (defense-in-depth) ──────────────────────────────
# Dynamic SQL fragments built internally (never from user input) are validated
# to contain only safe characters before concatenation into SQL queries.
_SQL_FRAGMENT_RE = re.compile(r"^[A-Za-z0-9_().,<>=!+\-*/% ]+$")
# SQL keywords that could be used for injection — none appear in our
# internally-built fragments (COALESCE(...)=0, 1=1, deleted_timestamp=0, etc.)
_SQL_KEYWORD_RE = re.compile(
    r"\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|"
    r"TRUNCATE|ALTER|CREATE|GRANT|REVOKE|FROM|WHERE|HAVING|GROUP|ORDER|"
    r"BY|LIMIT|OFFSET)\b", re.IGNORECASE,
)


def _validate_sql_fragment(fragment: str, origin: str) -> str:
    """Validate that a SQL fragment contains only safe characters.

    Fragments are built internally from column-existence checks, never from
    user input. This is defense-in-depth: if a future change introduces user
    input into a fragment, this raises loud instead of enabling injection.
    """
    if not _SQL_FRAGMENT_RE.match(fragment):
        raise ValueError(f"unsafe SQL fragment in {origin}: {fragment!r}")
    if _SQL_KEYWORD_RE.search(fragment):
        raise ValueError(
            f"SQL keyword found in fragment in {origin}: {fragment!r}"
        )
    return fragment

UPSTREAM_REPO = "https://github.com/arkadiyt/bounty-targets-data.git"
# Secondary feed: projectdiscovery/public-bugbounty-programs (machine-readable scope JSON)
PD_PROGRAMS_REPO = "https://github.com/projectdiscovery/public-bugbounty-programs.git"
# Immunefi: no public JSON API — but the bug-bounty board page embeds the full
# bounty list as escaped JSON (verified 2026-10-12: 169 bounties). No auth needed.
IMMUNEFI_BOUNTIES_URL = "https://immunefi.com/bug-bounty/"
# Sherlock audit contest API (Web3 smart contract audit contests — confirmed public, paginated)
SHERLOCK_API_URL = "https://audits.sherlock.xyz/api/contests"
# Public listing pages for platforms without a usable researcher listing API.
# Server-rendered cards are parsed directly; no browser or account needed.
BUGBASE_PROGRAMS_URL = "https://bugbase.ai/programs"
HACKENPROOF_PROGRAMS_URL = "https://hackenproof.com/programs"
CANTINA_OPPORTUNITIES_URL = "https://cantina.xyz/opportunities"
CODEHAWKS_CONTESTS_URL = "https://codehawks.cyfrin.io/contests"
PATCHSTACK_VDP_URL = "https://patchstack.com/database/vdp"
HUNTR_CHALLENGES_URL = "https://huntr.com/challenges"
SHERLOCK_BOUNTIES_URL = "https://audits.sherlock.xyz/bug-bounties"
# Listing-only platforms: public cards carry no scope assets. They are
# indexed for discovery/newness; Oracle deep-dive fetches real scope.
LISTING_ONLY_PLATFORMS = {"Bugbase", "HackenProof", "Cantina", "Patchstack", "Huntr"}

# ── Authenticated API endpoints ───────────────────────────────────────────────
# Used when an api_key is configured for the platform; falls back to public feed.
H1_API_BASE = "https://api.hackerone.com/v1"
BUGCROWD_API_BASE = "https://api.bugcrowd.com"
INTIGRITI_API_BASE = "https://api.intigriti.com/core"
YESWEHACK_API_BASE = "https://api.yeswehack.com"


# ─────────────────────────────────────────────────────────────────────────────
# Credential loader
# Priority: environment variable > config.json api_keys > trio central > None
# Never store real keys in config.json when using git — use env vars instead.
# New shared keys go in the trio central store, never in this repo.
# ─────────────────────────────────────────────────────────────────────────────
TRIO_KEYS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "trio", "keys.env"
)


def _read_trio_keys():
    """Read the trio central key store. Missing/unreadable → {}."""
    out = {}
    try:
        with open(TRIO_KEYS_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    if k and k not in out:
                        out[k] = v.strip().strip("\"'")
    except OSError:
        pass
    return out


def load_credentials(config=None):
    """Return a dict of per-platform credential dicts.

    For each platform the returned dict has whatever keys that platform needs
    (e.g. {'username': '...', 'api_token': '...'} for HackerOne).
    A key is absent or None when not configured — callers must check before use.

    Env var names follow the pattern documented in config.json api_keys._env.
    Env vars always override config.json values so real secrets stay out of files.
    """
    cfg_keys = (config or {}).get("api_keys", {})
    trio_keys = _read_trio_keys()

    def _get(platform, field, env_var):
        """env var > config.json > trio central > None"""
        env_val = os.environ.get(env_var, "").strip()
        if env_val:
            return env_val
        cfg_val = (cfg_keys.get(platform) or {}).get(field)
        if cfg_val:
            import warnings
            warnings.warn(
                f"API key for {platform}.{field} loaded from config.json — "
                "never commit config.json with real keys (git-tracked secret risk).",
                stacklevel=3,
            )
            return cfg_val
        return trio_keys.get(env_var) or None

    return {
        "hackerone": {
            "username": _get("hackerone", "username", "HACKERONE_USERNAME"),
            "api_token": _get("hackerone", "api_token", "HACKERONE_API_TOKEN"),
        },
        "bugcrowd": {
            "api_token": _get("bugcrowd", "api_token", "BUGCROWD_API_TOKEN"),
        },
        "intigriti": {
            "api_token": _get("intigriti", "api_token", "INTIGRITI_API_TOKEN"),
        },
        "yeswehack": {
            "api_token": _get("yeswehack", "api_token", "YESWEHACK_API_TOKEN"),
        },
        # Slots for platforms that don't have APIs yet — ready when they do
        "federacy": {"api_token": _get("federacy", "api_token", "FEDERACY_API_TOKEN")},
        "immunefi": {"api_token": _get("immunefi", "api_token", "IMMUNEFI_API_TOKEN")},
        "sherlock": {"api_token": _get("sherlock", "api_token", "SHERLOCK_API_TOKEN")},
        "hackenproof": {
            "api_token": _get("hackenproof", "api_token", "HACKENPROOF_API_TOKEN")
        },
        "bugbase": {"api_token": _get("bugbase", "api_token", "BUGBASE_API_TOKEN")},
        "pd_programs": {
            "api_token": _get("pd_programs", "api_token", "PD_PROGRAMS_API_TOKEN")
        },
    }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: urllib would otherwise re-send the
    Authorization header to the redirect target, any host or scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _api_request(
    url, *, auth_basic=None, bearer=None, token_header=None, method="GET", timeout=30
):
    """Make an authenticated HTTP request, return parsed JSON or raise.

    auth_basic   : (username, password/token) tuple → HTTP Basic Authorization
    bearer       : string → Authorization: Bearer <token>
    token_header : string → Authorization: Token <token>

    Redirects are refused (a 3xx raises HTTPError): platform credentials
    must never be forwarded to a host the platform did not name (S5).
    """
    req = urllib.request.Request(url, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "Scan4Me authenticated sync/1.0")
    if auth_basic:
        creds = base64.b64encode(f"{auth_basic[0]}:{auth_basic[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
    elif bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    elif token_header:
        req.add_header("Authorization", f"Token {token_header}")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    with opener.open(req, timeout=timeout) as resp:  # nosec B310
        # Defense-in-depth: _NoRedirectHandler refuses 3xx responses by
        # returning None from redirect_request, which makes urllib raise
        # HTTPError. Verify no redirect was silently followed.
        resp_url = getattr(resp, "geturl", lambda: url)()
        if resp_url != url:
            raise urllib.error.HTTPError(
                url, resp.status, f"redirect refused: {url} -> {resp_url}",
                resp.headers, None,
            )
        return json.load(resp)


# ─────────────────────────────────────────────────────────────────────────────
# Authenticated program fetchers
# Each returns a list of normalized program dicts identical to the public feed
# schema so sync_data can use them as a drop-in replacement.
# ─────────────────────────────────────────────────────────────────────────────


def _h1_in_scope(structured_scopes):
    """Submission-eligible HackerOne scopes, preserving the eligibility and
    restriction fields (#15). Dropping eligible_for_bounty/instruction/
    max_severity here makes _eligibility_of default them to eligible, so a
    submit-but-no-bounty asset would wrongly enter the paid target list and
    its restrictions would vanish. Keep them alongside identifier + type.
    """
    out = []
    for s in structured_scopes or []:
        if not s.get("eligible_for_submission"):
            continue
        out.append(
            {
                "asset_identifier": s.get("asset_identifier", ""),
                "asset_type": s.get("asset_type", "URL"),
                "eligible_for_bounty": s.get("eligible_for_bounty", True),
                "eligible_for_submission": s.get("eligible_for_submission", True),
                "instruction": s.get("instruction") or "",
                "max_severity": s.get("max_severity") or "",
            }
        )
    return out


def _fetch_h1_authenticated(username, api_token, delay=1.0):
    """Fetch your full HackerOne program list via the authenticated API.

    Returns private + public programs you have access to.
    Endpoint: GET /v1/hackers/programs (paginated, 100/page).
    Auth: HTTP Basic username:api_token.
    """
    programs = []
    page = 1
    while True:
        if page > 1 and delay and delay > 0:
            time.sleep(delay)
        try:
            data = _api_request(
                f"{H1_API_BASE}/hackers/programs"
                f"?page%5Bnumber%5D={page}&page%5Bsize%5D=100"
                f"&sort=name&filter%5Bsubmission_state%5D%5B%5D=open",
                auth_basic=(username, api_token),
            )
        except Exception as e:
            if page == 1:
                print(f"[!] HackerOne authenticated fetch failed: {e}")
            break

        items = data.get("data", [])
        for item in items:
            attrs = item.get("attributes", {})
            handle = attrs.get("handle", "")
            raw_max = (
                attrs.get("top_bounty_upper_amount")
                or attrs.get("top_bounty_lower_amount")
                or attrs.get("max_payout")
                or 0.0
            )
            max_payout = _safe_non_negative_float(raw_max)
            programs.append(
                {
                    "handle": handle,
                    "name": attrs.get("name") or handle,
                    "url": f"https://hackerone.com/{handle}",
                    "website": attrs.get("profile", {}).get("website") or "",
                    "offers_bounties": bool(attrs.get("offers_bounties")),
                    "managed_program": bool(attrs.get("managed_program")),
                    "max_payout": max_payout,
                    "average_time_to_first_program_response": attrs.get(
                        "average_time_to_first_program_response"
                    ),
                    "average_time_to_bounty_awarded": attrs.get(
                        "average_time_to_bounty_awarded"
                    ),
                    "average_time_to_report_resolved": attrs.get(
                        "average_time_to_report_resolved"
                    ),
                    "response_efficiency_percentage": attrs.get(
                        "response_efficiency_percentage"
                    ),
                    "targets": {
                        "in_scope": _h1_in_scope(attrs.get("structured_scopes", []))
                    },
                }
            )

        links = data.get("links", {})
        if not links.get("next"):
            break
        page += 1

    print(
        f"[+] HackerOne authenticated: {len(programs)} programs (including private invites)."
    )
    return programs


def _fetch_bugcrowd_authenticated(api_token, delay=1.0):
    """Fetch your Bugcrowd program list via the authenticated API.

    Endpoint: GET /engagements (paginated).
    Auth: Authorization: Token <api_token>.
    """
    programs = []
    page = 1
    while True:
        if page > 1 and delay and delay > 0:
            time.sleep(delay)
        try:
            data = _api_request(
                f"{BUGCROWD_API_BASE}/engagements?page={page}&sort=name",
                token_header=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] Bugcrowd authenticated fetch failed: {e}")
            break

        items = data.get("data", data if isinstance(data, list) else [])
        if not items:
            break
        for item in items:
            attrs = item.get("attributes", item)
            name = attrs.get("name", "Unknown")
            handle = attrs.get("code", name.lower().replace(" ", "-"))
            url = attrs.get("url", "") or f"https://bugcrowd.com/{handle}"
            if url.startswith("/"):
                url = f"https://bugcrowd.com{url}"
            max_p = _safe_non_negative_float(attrs.get("max_payout", 0))
            programs.append(
                {
                    "name": name,
                    "url": url,
                    "max_payout": max_p,
                    "managed_by_bugcrowd": bool(attrs.get("managed_by_bugcrowd")),
                    "safe_harbor": attrs.get("safe_harbor", "Standard"),
                    "targets": {
                        "in_scope": [
                            {
                                "target": s.get("target", ""),
                                "type": s.get("type", "website"),
                            }
                            for s in attrs.get("targets", {}).get("in_scope", [])
                        ]
                    },
                }
            )

        if len(items) < 25:
            break
        page += 1

    print(f"[+] Bugcrowd authenticated: {len(programs)} programs (including private).")
    return programs


def _fetch_intigriti_authenticated(api_token, delay=1.0):
    """Fetch your Intigriti program list via the authenticated API.

    Endpoint: GET /core/researcher/programs (paginated).
    Auth: Authorization: Bearer <api_token>.
    """
    programs = []
    page = 1
    while True:
        if page > 1 and delay and delay > 0:
            time.sleep(delay)
        try:
            data = _api_request(
                f"{INTIGRITI_API_BASE}/researcher/programs"
                f"?offset={(page-1)*20}&limit=20&status=open",
                bearer=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] Intigriti authenticated fetch failed: {e}")
            break

        records = data.get("records", data if isinstance(data, list) else [])
        if not records:
            break
        for item in records:
            handle = item.get("handle") or str(item.get("id", ""))
            max_b = item.get("maxBounty") or item.get("max_bounty") or {}
            max_val = _safe_non_negative_float(max_b.get("value") if isinstance(max_b, dict) else 0)
            curr = max_b.get("currency", "EUR") if isinstance(max_b, dict) else "EUR"
            programs.append(
                {
                    "handle": handle,
                    "name": item.get("name", handle),
                    "url": item.get(
                        "url", f"https://app.intigriti.com/programs/{handle}"
                    ),
                    "max_bounty": {"value": max_val, "currency": curr},
                    "targets": {
                        "in_scope": [
                            {
                                "endpoint": s.get("endpoint", ""),
                                "type": s.get("type", "url"),
                            }
                            for s in item.get(
                                "domains", item.get("targets", {}).get("in_scope", [])
                            )
                        ]
                    },
                }
            )

        total = data.get("total", data.get("maxCount", 0))
        if page * 20 >= total or len(records) < 20:
            break
        page += 1

    print(f"[+] Intigriti authenticated: {len(programs)} programs (including private).")
    return programs


def _fetch_yeswehack_authenticated(api_token, delay=1.0):
    """Fetch your YesWeHack program list via the authenticated API.

    Endpoint: GET /programs (paginated, includes private programs).
    Auth: Authorization: Bearer <api_token>.
    """
    programs = []
    page = 1
    while True:
        if page > 1 and delay and delay > 0:
            time.sleep(delay)
        try:
            data = _api_request(
                f"{YESWEHACK_API_BASE}/programs?page={page}&perPage=50",
                bearer=api_token,
            )
        except Exception as e:
            if page == 1:
                print(f"[!] YesWeHack authenticated fetch failed: {e}")
            break

        items = data.get("items", data if isinstance(data, list) else [])
        if not items:
            break
        for item in items:
            programs.append(
                {
                    "id": item.get("id", item.get("slug", "")),
                    "name": item.get("title", item.get("name", "")),
                    "max_bounty": _safe_non_negative_float(item.get("maxBounty", item.get("max_bounty", 0))),
                    "managed": bool(item.get("managed")),
                    "targets": {
                        "in_scope": [
                            {
                                "target": s.get("target", s.get("scope", "")),
                                "type": s.get("type", "web"),
                            }
                            for s in item.get(
                                "scope", item.get("targets", {}).get("in_scope", [])
                            )
                        ]
                    },
                }
            )

        pagination = data.get("pagination", {})
        if page >= pagination.get("nb_pages", 1):
            break
        page += 1

    print(f"[+] YesWeHack authenticated: {len(programs)} programs (including private).")
    return programs


DEFAULT_CONFIG = {
    "filters": {
        "paid_bounties_only": True,
        "fast_triage": {
            "enabled": True,
            "max_first_response_hours": 24.0,
            "min_response_efficiency_pct": 90.0,
            "prefer_managed_triage": True,
            "max_time_to_bounty_awarded_hours": 336.0,
            "require_measured_response_time": False,
            "max_validation_days": 14,
            "strict_validation_days": False,
        },
        "attack_surface_and_scope": {
            "prefer_large_attack_surface": True,
            "min_in_scope_assets": 1,
            "prioritize_wildcards": True,
            "wildcard_multiplier": 2.5,
        },
        "freshness_and_competition": {
            "prefer_fresh_programs": True,
            "low_report_saturation": True,
            "prefer_new_companies": True,
            "new_company_days": 90,
            "strict_new_companies": False,
            "prefer_new_assets": True,
            "new_asset_days": 30,
            "strict_new_assets": False,
            "max_rewarded_vulnerabilities": 150,
        },
        "payouts": {"min_max_payout_usd": 1000.0, "prioritize_fast_cash": True},
        "program_kind": {"web2": True, "web3": True},
    },
    "platforms": {
        "hackerone": True,
        "bugcrowd": True,
        "intigriti": True,
        "yeswehack": True,
        "federacy": False,  # operator has no account — ignored
        "immunefi": True,
        "sherlock": True,
        "pd_programs": True,
        "bugbase": True,
        "hackenproof": True,
        "cantina": True,
        "codehawks": True,
        "patchstack": True,
        "huntr": True,
    },
    "ranking_weights": {
        "payout_size": 0.35,
        "attack_surface_size": 0.30,
        "freshness_and_low_saturation": 0.20,
        "triage_speed": 0.15,
    },
    "display": {"limit": 25, "show_company_profile": True, "show_assets_sample": True},
}


def _to_usd(amount, currency) -> float:
    """Convert amount to USD using live/cached FX rates."""
    return _fx_to_usd(amount, currency)


def _coerce_bool(value, default=False):
    """Strict config boolean: quoted false/0/no/off never enable."""
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    if isinstance(value, (int, float)):
        return math.isfinite(float(value)) and value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("", "0", "false", "no", "off"):
            return False
        return bool(default)
    return bool(default)


def _safe_non_negative_float(value) -> float:
    """Feed numeric guard: bad/non-finite/negative payouts become 0."""
    try:
        out = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    return out if math.isfinite(out) and out > 0 else 0.0


def _deep_merge(base, override):
    """Recursively merge override onto a copy of base (dicts merge, other
    values replace)."""
    import copy as _copy

    merged = _copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = _copy.deepcopy(val)
    return merged


def _normalize_weights(cfg):
    weights = cfg.get("ranking_weights")
    if isinstance(weights, dict) and weights:
        total = sum(_safe_non_negative_float(v) for v in weights.values())
        if total > 0:
            cfg["ranking_weights"] = {
                k: _safe_non_negative_float(v) / total for k, v in weights.items()
            }
    return cfg


def load_config():
    # Priority: config.json (local, git-ignored) → config.example.json → DEFAULT_CONFIG.
    # File configs are DEEP-MERGED over DEFAULT_CONFIG so a partial file
    # (one weight, one filter) cannot silently drop every other default,
    # and ranking weights are normalized to sum to 1.
    for path in (CONFIG_PATH, CONFIG_EXAMPLE_PATH):
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    cfg = json.load(f)
                if path == CONFIG_EXAMPLE_PATH:
                    print(
                        f"[*] config.json not found — using {path.name} (template). "
                        "Copy it to config.json and set your API keys."
                    )
                return _normalize_weights(_deep_merge(DEFAULT_CONFIG, cfg))
            except Exception as e:
                print(f"[!] Warning: Failed to load {path.name} ({e}), trying next.")
    return _normalize_weights(_deep_merge(DEFAULT_CONFIG, {}))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    """Initialize database schema if tables don't exist."""
    cur = conn.cursor()

    # Check if programs table exists
    result = cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='programs'"
    ).fetchone()
    if result is None:
        with conn:
            conn.executescript(
                """
            CREATE TABLE programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                name TEXT NOT NULL,
                handle TEXT,
                url TEXT,
                website TEXT,
                offers_bounties BOOLEAN DEFAULT 0,
                managed_triage BOOLEAN DEFAULT 0,
                first_response_hours REAL,
                bounty_awarded_hours REAL,
                report_resolved_hours REAL,
                response_efficiency REAL,
                max_payout REAL DEFAULT 0,
                min_payout REAL DEFAULT 0,
                currency TEXT DEFAULT 'USD',
                safe_harbor TEXT,
                submission_state TEXT DEFAULT 'open',
                offers_swag BOOLEAN DEFAULT 0,
                allows_disclosure BOOLEAN DEFAULT 0,
                company_handle TEXT DEFAULT '',
                rules_text TEXT DEFAULT '',
                first_seen_timestamp INTEGER DEFAULT 0,
                last_updated_timestamp INTEGER DEFAULT 0,
                deleted_timestamp INTEGER DEFAULT 0,
                official_start_timestamp INTEGER,
                official_scope_updated_timestamp INTEGER,
                rewarded_vulnerabilities INTEGER,
                validation_days REAL,
                average_payout REAL,
                official_metadata_checked_timestamp INTEGER,
                program_kind TEXT DEFAULT 'web2',
                UNIQUE(platform, handle)
            );

            CREATE TABLE assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                asset_identifier TEXT NOT NULL,
                asset_type TEXT,
                is_wildcard BOOLEAN DEFAULT 0,
                eligible_for_bounty INTEGER DEFAULT 1,
                eligible_for_submission INTEGER DEFAULT 1,
                instruction TEXT DEFAULT '',
                max_severity TEXT DEFAULT '',
                first_seen_timestamp INTEGER DEFAULT 0,
                deleted_timestamp INTEGER DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(id)
            );

            CREATE TABLE oos_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                asset_identifier TEXT NOT NULL,
                asset_type TEXT,
                is_wildcard BOOLEAN DEFAULT 0,
                first_seen_timestamp INTEGER DEFAULT 0,
                deleted_timestamp INTEGER DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(id)
            );

            CREATE TABLE contests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                name TEXT NOT NULL,
                handle TEXT,
                url TEXT,
                offers_bounties BOOLEAN DEFAULT 0,
                max_payout REAL DEFAULT 0,
                currency TEXT DEFAULT 'USD',
                status TEXT,
                starts_at TEXT,
                ends_at TEXT,
                description TEXT,
                first_seen_timestamp INTEGER DEFAULT 0,
                last_updated_timestamp INTEGER DEFAULT 0,
                UNIQUE(platform, handle)
            );

            CREATE TABLE site_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL UNIQUE,
                final_url TEXT,
                status_code INTEGER,
                headers_json TEXT,
                security_headers_json TEXT,
                cookies_json TEXT,
                title TEXT,
                body_sha256 TEXT,
                body_length INTEGER,
                auth_surfaces_json TEXT,
                public_endpoints_json TEXT,
                security_txt TEXT,
                robots_txt TEXT,
                scanned_at INTEGER DEFAULT 0
            );

            CREATE INDEX idx_asset_identifier ON assets(asset_identifier);
            CREATE INDEX idx_asset_program_live ON assets(program_id, deleted_timestamp);
            CREATE INDEX idx_oos_program_live ON oos_assets(program_id, deleted_timestamp);
            CREATE INDEX idx_contest_platform ON contests(platform);
            CREATE INDEX idx_contest_first_seen ON contests(first_seen_timestamp);
            CREATE INDEX idx_program_platform ON programs(platform);
            CREATE INDEX idx_program_bounty ON programs(offers_bounties);
            CREATE INDEX idx_program_first_seen ON programs(first_seen_timestamp);
            CREATE INDEX idx_asset_first_seen ON assets(first_seen_timestamp);
            CREATE TABLE sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
            )
    else:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sync_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """
        )
        conn.commit()


def migrate_db(conn):
    """Add timestamp columns if they don't exist (for backward compatibility)."""
    cur = conn.cursor()

    # Check if programs table has first_seen_timestamp column
    prog_cols = [row[1] for row in cur.execute("PRAGMA table_info(programs)")]
    if "first_seen_timestamp" not in prog_cols:
        print(
            "[*] Migrating programs table: adding first_seen_timestamp, last_updated_timestamp..."
        )
        cur.execute(
            "ALTER TABLE programs ADD COLUMN first_seen_timestamp INTEGER DEFAULT 0"
        )
    if "last_updated_timestamp" not in prog_cols:
        cur.execute(
            "ALTER TABLE programs ADD COLUMN last_updated_timestamp INTEGER DEFAULT 0"
        )
    for column, definition in (
        ("official_start_timestamp", "INTEGER"),
        ("official_scope_updated_timestamp", "INTEGER"),
        ("rewarded_vulnerabilities", "INTEGER"),
        ("validation_days", "REAL"),
        ("average_payout", "REAL"),
        ("official_metadata_checked_timestamp", "INTEGER"),
        ("program_kind", "TEXT DEFAULT 'web2'"),
        ("deleted_timestamp", "INTEGER DEFAULT 0"),
        ("min_payout", "REAL DEFAULT 0"),
        ("submission_state", "TEXT DEFAULT 'open'"),
        ("offers_swag", "BOOLEAN DEFAULT 0"),
        ("allows_disclosure", "BOOLEAN DEFAULT 0"),
        ("company_handle", "TEXT DEFAULT ''"),
        ("rules_text", "TEXT DEFAULT ''"),
    ):
        if column not in prog_cols:
            cur.execute(f"ALTER TABLE programs ADD COLUMN {column} {definition}")

    # Check if assets table has first_seen_timestamp column
    asset_cols = [row[1] for row in cur.execute("PRAGMA table_info(assets)")]
    if "first_seen_timestamp" not in asset_cols:
        print("[*] Migrating assets table: adding first_seen_timestamp...")
        cur.execute(
            "ALTER TABLE assets ADD COLUMN first_seen_timestamp INTEGER DEFAULT 0"
        )
    if "official_first_seen_timestamp" not in asset_cols:
        cur.execute(
            "ALTER TABLE assets ADD COLUMN official_first_seen_timestamp INTEGER"
        )
    for column, definition in (
        ("eligible_for_bounty", "INTEGER DEFAULT 1"),
        ("eligible_for_submission", "INTEGER DEFAULT 1"),
        ("instruction", "TEXT DEFAULT ''"),
        ("max_severity", "TEXT DEFAULT ''"),
        ("deleted_timestamp", "INTEGER DEFAULT 0"),
    ):
        if column not in asset_cols:
            cur.execute(f"ALTER TABLE assets ADD COLUMN {column} {definition}")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS oos_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id INTEGER,
            asset_identifier TEXT NOT NULL,
            asset_type TEXT,
            is_wildcard BOOLEAN DEFAULT 0,
            first_seen_timestamp INTEGER DEFAULT 0,
            deleted_timestamp INTEGER DEFAULT 0,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_asset_program_live "
        "ON assets(program_id, deleted_timestamp)"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_oos_program_live "
        "ON oos_assets(program_id, deleted_timestamp)"
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS contests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            name TEXT NOT NULL,
            handle TEXT,
            url TEXT,
            offers_bounties BOOLEAN DEFAULT 0,
            max_payout REAL DEFAULT 0,
            currency TEXT DEFAULT 'USD',
            status TEXT,
            starts_at TEXT,
            ends_at TEXT,
            description TEXT,
            first_seen_timestamp INTEGER DEFAULT 0,
            last_updated_timestamp INTEGER DEFAULT 0,
            UNIQUE(platform, handle)
        )
        """
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_contest_platform ON contests(platform)")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_contest_first_seen "
        "ON contests(first_seen_timestamp)"
    )

    # Program change detection table (Phase 3)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS program_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            program_id INTEGER,
            change_type TEXT,  -- 'scope_added', 'scope_removed', 'payout_changed', 'rules_changed', 'new_asset', 'tombstone_resurrected'
            old_value TEXT,
            new_value TEXT,
            detected_at INTEGER,
            FOREIGN KEY (program_id) REFERENCES programs(id)
        )
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_program_changes_program "
        "ON program_changes(program_id, detected_at)"
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS site_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            final_url TEXT,
            status_code INTEGER,
            headers_json TEXT,
            security_headers_json TEXT,
            cookies_json TEXT,
            title TEXT,
            body_sha256 TEXT,
            body_length INTEGER,
            auth_surfaces_json TEXT,
            public_endpoints_json TEXT,
            security_txt TEXT,
            robots_txt TEXT,
            scanned_at INTEGER DEFAULT 0
        )
        """
    )

    # P6: Sherlock audit contests are not bug-bounty programs. Move legacy
    # contest rows (handle 'sherlock-<id>') out of programs into contests.
    # Bug-bounty rows use handle 'sherlock-bb-<id>' and stay in programs.
    for row in cur.execute(
        """SELECT name, handle, url, offers_bounties, max_payout, currency,
           first_seen_timestamp, last_updated_timestamp
           FROM programs WHERE platform='Sherlock'
           AND handle NOT LIKE 'sherlock-bb-%'"""
    ).fetchall():
        cur.execute(
            """
            INSERT INTO contests (
                platform, name, handle, url, offers_bounties, max_payout,
                currency, first_seen_timestamp, last_updated_timestamp
            ) VALUES ('Sherlock', ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(platform, handle) DO UPDATE SET
                name=excluded.name, url=excluded.url,
                offers_bounties=MAX(COALESCE(contests.offers_bounties, 0), excluded.offers_bounties),
                max_payout=excluded.max_payout,
                currency=excluded.currency,
                last_updated_timestamp=excluded.last_updated_timestamp
            """,
            tuple(row),
        )
    cur.execute(
        "DELETE FROM programs WHERE platform='Sherlock' AND handle NOT LIKE 'sherlock-bb-%'"
    )

    conn.commit()


def ensure_schema(conn):
    """Idempotent: create + migrate schema so read paths see new columns.

    Write paths (sync) already init+migrate; read paths (radar/check/export)
    call this so tombstone/eligibility filters never hit a stale schema.
    """
    init_db(conn)
    migrate_db(conn)


def _eligibility_of(target):
    """(bounty, submission, instruction, severity) for an asset dict.

    Feeds without eligibility keys (Bugcrowd/Intigriti/YWH/...) default to
    eligible — unknown means "no signal", never "forbidden".
    Extracts public per-asset descriptions/impacts (Intigriti) alongside
    HackerOne instruction/max_severity keys.
    """
    bounty = target.get("eligible_for_bounty", True)
    submission = target.get("eligible_for_submission", True)
    instruction = target.get("instruction") or target.get("description") or ""
    severity = target.get("max_severity") or target.get("impact") or ""
    return (
        0 if bounty is False or bounty == 0 else 1,
        0 if submission is False or submission == 0 else 1,
        str(instruction),
        str(severity),
    )


# ── Asset normalizer (#4): canonical types + identifiers at ingest ──────────────
# Raw feeds use 15+ case/source-variant type strings and verbatim identifiers
# (scheme-prefixed wildcards, free-text sentences, bare words like "all").
# Everything is canonicalized here, once, before storage; match-time code
# (scope_match, clean_asset_identifier, the Oracle bridge) applies the same
# host-stripping so old verbatim rows still match until the next sync.
CANON_ASSET_TYPES = frozenset(
    {
        "url",
        "wildcard",
        "cidr",
        "api",
        "ios_app",
        "android_app",
        "smart_contract",
        "source_code",
        "executable",
        "other",
    }
)

_CANON_TYPE_ALIASES = {
    # url-ish
    "url": "url",
    "website": "url",
    "web": "url",
    "web_application": "url",
    "webapplication": "url",
    "web_app": "url",
    "webapp": "url",
    "domain": "url",
    "subdomain": "url",
    "host": "url",
    # wildcard
    "wildcard": "wildcard",
    # ip-ish (single literals and ranges both ride as cidr: non-DNS scope)
    "cidr": "cidr",
    "ip": "cidr",
    "ip_address": "cidr",
    "ipaddress": "cidr",
    "iprange": "cidr",
    "ip_range": "cidr",
    "network": "cidr",
    # api
    "api": "api",
    # mobile
    "android": "android_app",
    "android_app": "android_app",
    "google_play": "android_app",
    "google_play_app_id": "android_app",
    "googleplay_app_id": "android_app",
    "ios": "ios_app",
    "ios_app": "ios_app",
    "apple": "ios_app",
    "apple_store_app_id": "ios_app",
    "applestore_app_id": "ios_app",
    "mobile": "other",
    # web3
    "smartcontract": "smart_contract",
    "smart_contract": "smart_contract",
    "contract": "smart_contract",
    "blockchain": "smart_contract",
    # source
    "source_code": "source_code",
    "sourcecode": "source_code",
    "github": "source_code",
    "repository": "source_code",
    "repo": "source_code",
    "git": "source_code",
    # binaries
    "executable": "executable",
    "downloadable_executables": "executable",
    "downloadable": "executable",
    "binary": "executable",
    "download": "executable",
    # fallback
    "other": "other",
    "unknown": "other",
    "": "other",
}


def canonicalize_asset_type(raw_type):
    """Map any raw feed type string to the canonical enum (default: other)."""
    key = str(raw_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _CANON_TYPE_ALIASES.get(key, "other")


def _strip_host(value):
    """Lowercased bare host from a URL-ish identifier (no scheme/path/port)."""
    text = (value or "").strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/")[0].split("@")[-1].strip().rstrip(".")
    if text.startswith("[") and "]" in text:  # IPv6 literal
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1 and "*" not in text:  # host:port
        text = text.split(":")[0]
    return text.strip().rstrip(".")


def _strip_to_host(ident: str) -> str:
    """Alias for _strip_host — consistent with Oracle intake naming."""
    return _strip_host(ident)


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


# Common multi-label public suffixes. A wildcard anchored at one of these
# (or at a bare TLD) would authorize an entire registry downstream, so
# ingest rejects it. Heuristic subset, not the full PSL: when in doubt the
# label-count rule below still blocks every single-label base.
_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset({
    "ac.uk", "co.uk", "gov.uk", "org.uk",
    "com.au", "net.au", "org.au", "co.nz", "org.nz",
    "com.br", "com.cn", "com.tw", "com.hk", "com.sg",
    "co.jp", "co.kr", "co.in", "com.mx", "com.ar",
    "co.za", "com.tr", "com.pl", "com.ru", "co.il",
})


def _wildcard_base_is_registrable(rest):
    """True when post-star text anchors at a registrable domain.

    ``*.acme.com`` and ``*.example.co.uk`` pass; ``*.com``, ``*.co.uk``
    and ``*com`` fail. Glued forms (``*-vpn.8x8.com``) pass on their
    dotted remainder, which endswith-matching keeps narrow.
    """
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


def canonicalize_asset(identifier, raw_type):
    """Canonicalize one scope identifier + type.

    Returns ``(identifier, asset_type, is_wildcard, ok)``. ``ok`` is False
    for non-host junk (free-text sentences, bare words like Intigriti's
    ``"all"`` endpoint) which callers must reject, never store as scope.
    CIDRs, IPs and app IDs are kept verbatim (lowercased) with their enum
    type — they are scope, just not DNS scope.
    """
    raw = (identifier or "").strip()
    if not raw:
        return "", "other", 0, False
    # No legitimate scope identifier contains whitespace or control
    # characters; accepting them lets one row export as several lines.
    if any(ord(ch) < 32 or ord(ch) == 127 or ch.isspace() for ch in raw):
        return "", "other", 0, False
    atype = canonicalize_asset_type(raw_type)
    lowered = raw.lower().rstrip(".")

    # IP literals / ranges: scope, not DNS — keep verbatim, never host-strip.
    # A "/" alone is not a CIDR (URLs have paths): require ipaddress to agree.
    token = raw.split()[0] if raw.split() else ""
    if " " in raw:
        return "", "other", 0, False
    if "/" in token or atype == "cidr":
        try:
            return str(ipaddress.ip_address(token)), "cidr", 0, True
        except ValueError:
            pass
        try:
            return str(ipaddress.ip_network(token, strict=False)), "cidr", 0, True
        except ValueError:
            pass
        if "/" in token:
            pass  # URL path, not a range — fall through to host stripping.
        elif atype == "cidr":
            return "", "other", 0, False  # feed claims CIDR, value unparseable.
    # App IDs / package names / store numerics: keep verbatim.
    if atype in ("ios_app", "android_app"):
        if " " in raw:
            return "", "other", 0, False
        return lowered, atype, 0, True

    # Source repositories (github.com/owner/repo, gitlab.com/owner/repo):
    # preserve <host>/<owner>[/<repo>] instead of stripping path to bare
    # "github.com", so Oracle's repo auto-cloner and code lens receive the
    # real repository path.
    _repo_m = re.match(
        r"^(?:https?://)?(github\.com|gitlab\.com)/([\w.\-]+(?:/[\w.\-*]+)?)",
        lowered,
    )
    if _repo_m:
        repo_path = _repo_m.group(2).rstrip("/")
        if repo_path.endswith(".git"):
            repo_path = repo_path[:-4]
        out_type = atype if atype in ("source_code", "smart_contract") else "source_code"
        is_wild = 1 if "*" in repo_path else 0
        return f"{_repo_m.group(1)}/{repo_path}", out_type, is_wild, True

    host = _strip_host(raw)
    if not host or " " in host:
        return "", "other", 0, False
    is_wildcard = 0
    if "*" in host:
        star, _, rest = host.partition("*")
        # Only leading-star forms are matchable scope (*.base, *-glued).
        if star not in ("",):
            return "", "other", 0, False
        rest = rest.lstrip(".")
        if not rest or "*" in rest or " " in rest:
            return "", "other", 0, False
        if not _wildcard_base_is_registrable(rest):
            return "", "other", 0, False
        # Glued form (*-prefix.host) keeps its literal post-star shape.
        host = "*." + rest if not rest.startswith("-") else "*" + rest
        is_wildcard = 1
        atype = "wildcard"
    else:
        # DNS-ish scope needs a dot (rejects "all" and other bare words);
        # localhost is the one legitimate single-label host.
        if "." not in host and host != "localhost":
            return "", "other", 0, False
    if atype == "wildcard" and not is_wildcard:
        # Feed claims wildcard but the identifier has no star: typeless host.
        atype = "url"
    return host, atype, is_wildcard, True


def sync_assets(cur, program_id, targets, identifier_key, type_key, now_ts, stats=None):
    """Reconcile a program's current scope while retaining first-observed times.

    Vanished assets are TOMBSTONED (deleted_timestamp set), never hard-DELETEd:
    a truncated feed or upstream schema change degrades to stale scope instead
    of destroying first-seen evidence, and reappearing assets resurrect with
    their original first_seen_timestamp intact. Live-scope queries must filter
    ``deleted_timestamp=0``. Per-asset eligibility flags are stored verbatim.
    Identifiers + types are canonicalized at ingest (#4); rejected junk is
    counted into ``stats["rejected"]`` when a stats dict is passed.
    """
    current_assets = {}
    for target in targets:
        if not isinstance(target, dict):
            continue
        raw_identifier = str(target.get(identifier_key) or "").strip()
        target_name = str(target.get("name") or "").strip().lower()
        if (
            "temporarily out of scope" in raw_identifier.lower()
            or "temporarily out of scope" in target_name
        ):
            continue
        identifier, asset_type, is_wildcard, ok = canonicalize_asset(
            raw_identifier, target.get(type_key, "URL")
        )
        if not ok or not identifier:
            if stats is not None:
                stats["rejected"] = stats.get("rejected", 0) + 1
            continue
        current_assets[identifier] = (
            asset_type,
            is_wildcard,
            *_eligibility_of(target),
        )

    # Case-insensitive lookup: the canonicalizer lowercases, so verbatim
    # legacy rows still match and keep their original first_seen evidence.
    existing_assets = {}
    for row in cur.execute(
        "SELECT id, asset_identifier, first_seen_timestamp, deleted_timestamp"
        " FROM assets WHERE program_id=?",
        (program_id,),
    ).fetchall():
        existing_assets.setdefault(
            (row["asset_identifier"] or "").strip().lower(), row
        )
    
    # Track changes for program_changes table
    new_assets = []
    resurrected_assets = []
    updated_assets = []
    removed_assets = []

    for identifier, spec in current_assets.items():
        asset_type, is_wildcard, bounty, submission, instruction, severity = spec
        existing = existing_assets.get(identifier.strip().lower())
        if existing:
            if existing["deleted_timestamp"]:
                # Resurrected
                resurrected_assets.append(identifier)
            else:
                # Check for updates
                cur.execute(
                    "SELECT asset_type, is_wildcard, eligible_for_bounty, eligible_for_submission, instruction, max_severity FROM assets WHERE id=?",
                    (existing["id"],),
                )
                old = cur.fetchone()
                if old and (
                    old["asset_type"] != asset_type
                    or old["is_wildcard"] != is_wildcard
                    or old["eligible_for_bounty"] != bounty
                    or old["eligible_for_submission"] != submission
                    or (old["instruction"] or "") != (instruction or "")
                    or (old["max_severity"] or "") != (severity or "")
                ):
                    updated_assets.append(identifier)
            cur.execute(
                """UPDATE assets SET asset_identifier=?, asset_type=?, is_wildcard=?,
                   eligible_for_bounty=?, eligible_for_submission=?,
                   instruction=?, max_severity=?, deleted_timestamp=0 WHERE id=?""",
                (
                    identifier,
                    asset_type,
                    is_wildcard,
                    bounty,
                    submission,
                    instruction,
                    severity,
                    existing["id"],
                ),
            )
        else:
            new_assets.append(identifier)
            cur.execute(
                """INSERT INTO assets
                   (program_id, asset_identifier, asset_type, is_wildcard,
                    eligible_for_bounty, eligible_for_submission,
                    instruction, max_severity,
                    first_seen_timestamp, deleted_timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                (
                    program_id,
                    identifier,
                    asset_type,
                    is_wildcard,
                    bounty,
                    submission,
                    instruction,
                    severity,
                    now_ts,
                ),
            )

    current_lower = {identifier.strip().lower() for identifier in current_assets}
    stale_ids = [
        row["id"]
        for lowered, row in existing_assets.items()
        if lowered not in current_lower and not (row["deleted_timestamp"] or 0)
    ]
    if stale_ids:
        # Record removed assets before tombstoning
        for asset_id in stale_ids:
            cur.execute("SELECT asset_identifier FROM assets WHERE id=?", (asset_id,))
            row = cur.fetchone()
            if row:
                removed_assets.append(row["asset_identifier"])
        cur.executemany(
            "UPDATE assets SET deleted_timestamp=? WHERE id=?",
            ((now_ts, asset_id) for asset_id in stale_ids),
        )

    # Record program changes
    if new_assets:
        for ident in new_assets:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'scope_added', '', ?, ?)",
                (program_id, ident, now_ts),
            )
    if resurrected_assets:
        for ident in resurrected_assets:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'tombstone_resurrected', '', ?, ?)",
                (program_id, ident, now_ts),
            )
    if updated_assets:
        for ident in updated_assets:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'scope_updated', '', ?, ?)",
                (program_id, ident, now_ts),
            )
    if removed_assets:
        for ident in removed_assets:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'scope_removed', ?, '', ?)",
                (program_id, ident, now_ts),
            )


def sync_oos_assets(cur, program_id, targets, identifier_key, type_key, now_ts, stats=None):
    """Reconcile a program's OUT-OF-SCOPE identifiers (tombstoned, like scope).

    Only call when the feed entry actually carries out-of-scope data — feeds
    without the key must leave previously synced OOS rows untouched.
    Canonicalized at ingest like scope (#4); rejects counted into stats.
    """
    current_oos = {}
    for target in targets:
        if not isinstance(target, dict):
            continue
        raw_identifier = str(target.get(identifier_key) or "").strip()
        identifier, asset_type, is_wildcard, ok = canonicalize_asset(
            raw_identifier, target.get(type_key, "URL")
        )
        if not ok or not identifier:
            if stats is not None:
                stats["rejected"] = stats.get("rejected", 0) + 1
            continue
        current_oos[identifier] = (asset_type, is_wildcard)

    existing_oos = {}
    for row in cur.execute(
        "SELECT id, asset_identifier, first_seen_timestamp, deleted_timestamp"
        " FROM oos_assets WHERE program_id=?",
        (program_id,),
    ).fetchall():
        existing_oos.setdefault((row["asset_identifier"] or "").strip().lower(), row)

    new_oos = []
    removed_oos = []

    for identifier, (asset_type, is_wildcard) in current_oos.items():
        existing = existing_oos.get(identifier.strip().lower())
        if existing:
            if existing["deleted_timestamp"]:
                # Resurrected OOS
                cur.execute(
                    "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'oos_resurrected', '', ?, ?)",
                    (program_id, identifier, now_ts),
                )
            cur.execute(
                """UPDATE oos_assets SET asset_identifier=?, asset_type=?, is_wildcard=?,
                   deleted_timestamp=0 WHERE id=?""",
                (identifier, asset_type, is_wildcard, existing["id"]),
            )
        else:
            new_oos.append(identifier)
            cur.execute(
                """INSERT INTO oos_assets
                   (program_id, asset_identifier, asset_type, is_wildcard,
                    first_seen_timestamp, deleted_timestamp)
                   VALUES (?, ?, ?, ?, ?, 0)""",
                (program_id, identifier, asset_type, is_wildcard, now_ts),
            )

    current_lower = {identifier.strip().lower() for identifier in current_oos}
    stale_ids = [
        row["id"]
        for lowered, row in existing_oos.items()
        if lowered not in current_lower and not (row["deleted_timestamp"] or 0)
    ]
    if stale_ids:
        for asset_id in stale_ids:
            cur.execute("SELECT asset_identifier FROM oos_assets WHERE id=?", (asset_id,))
            row = cur.fetchone()
            if row:
                removed_oos.append(row["asset_identifier"])
        cur.executemany(
            "UPDATE oos_assets SET deleted_timestamp=? WHERE id=?",
            ((now_ts, asset_id) for asset_id in stale_ids),
        )
        for ident in removed_oos:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'oos_removed', ?, '', ?)",
                (program_id, ident, now_ts),
            )

    if new_oos:
        for ident in new_oos:
            cur.execute(
                "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, 'oos_added', '', ?, ?)",
                (program_id, ident, now_ts),
            )


def _sync_program_scope(
    cur, prog_id, entry, identifier_key, type_key, now_ts, stats=None
):
    """Sync in-scope + out-of-scope targets for one feed entry.

    Each side syncs only when its key is present: feeds that structurally
    omit out-of-scope (e.g. authenticated fetchers) must not wipe previously
    synced OOS rows, and a malformed entry missing scope must not wipe scope.
    Absent sides are left untouched; present-but-empty sides tombstone.
    Normalizer rejects accumulate into ``stats`` when passed.
    """
    targets = entry.get("targets") if isinstance(entry, dict) else None
    if not isinstance(targets, dict):
        return
    if "in_scope" in targets:
        sync_assets(
            cur,
            prog_id,
            targets.get("in_scope") or [],
            identifier_key,
            type_key,
            now_ts,
            stats=stats,
        )
    if "out_of_scope" in targets:
        sync_oos_assets(
            cur,
            prog_id,
            targets.get("out_of_scope") or [],
            identifier_key,
            type_key,
            now_ts,
            stats=stats,
        )


def fetch_public_json(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "Scan4Me public bug-bounty metadata sync"}
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
        return json.load(response)


def parse_public_timestamp(value):
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except (AttributeError, TypeError, ValueError):
        return None


def bugcrowd_scope_aliases(scope):
    aliases = set()
    for group in scope or []:
        if not group.get("inScope", True):
            continue
        for target in group.get("targets", []):
            if "temporarily out of scope" in str(target.get("name") or "").lower():
                continue
            for field in ("uri", "name"):
                value = target.get(field)
                if value:
                    aliases.add(str(value).strip().rstrip("/").lower())
    return aliases


def enrich_bugcrowd_program(conn, program_id, handle, now_ts=None):
    """Store public Bugcrowd program dates, scope history, and aggregate statistics."""
    now_ts = now_ts or int(time.time())
    base_url = f"https://bugcrowd.com/engagements/{urllib.parse.quote(handle, safe='')}"
    changelog_index = fetch_public_json(f"{base_url}/changelog.json")
    entries = changelog_index.get("changelogs", [])

    program_start = None
    scope_history = []
    latest_rules_text = ""
    latest_rules_ts = -1
    for entry in entries:
        version_timestamp = parse_public_timestamp(entry.get("publishedAt"))
        if not version_timestamp:
            continue
        if "targets" in (entry.get("tags") or "").split(","):
            detail_url = entry.get("changelogShowUrl")
            if not detail_url or not detail_url.startswith("/"):
                continue
            detail = fetch_public_json(f"https://bugcrowd.com{detail_url}.json")
            data = detail.get("data", {})
            start = parse_public_timestamp(data.get("engagement", {}).get("startsAt"))
            if start:
                program_start = start
            brief = data.get("brief") if isinstance(data.get("brief"), dict) else {}
            eng = (
                data.get("engagement")
                if isinstance(data.get("engagement"), dict)
                else {}
            )
            candidate_rules = (
                brief.get("description")
                or brief.get("targetsOverview")
                or eng.get("description")
                or data.get("targetsOverview")
                or ""
            )
            if candidate_rules and version_timestamp >= latest_rules_ts:
                latest_rules_text = str(candidate_rules).strip()
                latest_rules_ts = version_timestamp
            scope_history.append(
                (version_timestamp, bugcrowd_scope_aliases(data.get("scope")))
            )

    stats = fetch_public_json(f"{base_url}/statistics")
    rewarded = stats.get("rewardedVulnerabilities")
    validation_text = stats.get("validationWithin")
    validation_days = None
    if isinstance(validation_text, str):
        match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s+days?\s*", validation_text)
        if match:
            validation_days = float(match.group(1))
    average_payout = None
    average_text = stats.get("averagePayout")
    if isinstance(average_text, str):
        match = re.fullmatch(r"\s*\$([\d,]+(?:\.\d{1,2})?)\s*", average_text)
        if match:
            average_payout = float(match.group(1).replace(",", ""))

    cur = conn.cursor()
    asset_rows = cur.execute(
        "SELECT id, asset_identifier FROM assets"
        " WHERE program_id=? AND deleted_timestamp=0",
        (program_id,),
    ).fetchall()
    first_added = {}
    for version_timestamp, aliases in sorted(scope_history):
        for asset in asset_rows:
            key = asset["asset_identifier"].strip().rstrip("/").lower()
            if key in aliases and asset["id"] not in first_added:
                first_added[asset["id"]] = version_timestamp

    with conn:
        cur.execute(
            """UPDATE programs
               SET official_start_timestamp=?,
                   official_scope_updated_timestamp=?,
                   rewarded_vulnerabilities=?,
                   validation_days=?,
                   average_payout=?,
                   official_metadata_checked_timestamp=?,
                   rules_text=CASE WHEN ? != '' THEN ? ELSE rules_text END
               WHERE id=?""",
            (
                program_start,
                max((timestamp for timestamp, _ in scope_history), default=None),
                rewarded if isinstance(rewarded, int) else None,
                validation_days,
                average_payout,
                now_ts,
                latest_rules_text,
                latest_rules_text,
                program_id,
            ),
        )
        for asset_id, timestamp in first_added.items():
            cur.execute(
                "UPDATE assets SET official_first_seen_timestamp=? WHERE id=?",
                (timestamp, asset_id),
            )
        if asset_rows:
            reset_holders = ",".join("?" for _ in first_added) or "NULL"
            reset_sql = (
                "UPDATE assets SET official_first_seen_timestamp=NULL "  # nosec B608
                "WHERE program_id=? AND id NOT IN (" + reset_holders + ")"
            )
            cur.execute(reset_sql, (program_id, *first_added.keys()))
    return {
        "program_start": program_start,
        "scope_versions": len(scope_history),
        "assets_with_official_dates": len(first_added),
        "rewarded_vulnerabilities": rewarded if isinstance(rewarded, int) else None,
        "validation_days": validation_days,
        "average_payout": average_payout,
        "rules_text_length": len(latest_rules_text),
    }


def _js_unescape_once(text):
    """Decode one layer of JS string escapes (\\", \\\\, \\n, \\/, \\uXXXX)."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "n":
                out.append("\n")
                i += 2
            elif nxt == "t":
                out.append("\t")
                i += 2
            elif nxt == "r":
                out.append("\r")
                i += 2
            elif nxt in '"\\/':
                out.append(nxt)
                i += 2
            elif nxt == "u" and i + 5 < len(text):
                hex_start = i + 2
                hex_end = i + 6
                try:
                    out.append(chr(int(text[hex_start:hex_end], 16)))
                    i += 6
                except ValueError:
                    out.append(ch)
                    i += 1
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _extract_bracketed_array(text, start):
    """Return the raw [...] slice starting at index start (escape-aware).

    Returns None when no balanced closing bracket is found.
    """
    depth = 0
    in_str = False
    esc = False
    for j in range(start, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                end = j + 1
                return text[start:end]
    return None


def _parse_immunefi_page(html):
    """Extract the embedded bounty list from the Immunefi board page.

    The page embeds React Flight data containing `"bounties":[...]` with one
    record per program (project, slug, url, maxBounty, pausedAt, inviteOnly).
    Returns the raw record list, or [] when the payload is absent/unparseable.
    """
    key = '"bounties\\":['
    at = html.find(key)
    if at < 0:
        return []
    raw = _extract_bracketed_array(html, at + len(key) - 1)
    if not raw:
        return []
    try:
        decoded = _js_unescape_once(_js_unescape_once(raw))
        records, _ = json.JSONDecoder().raw_decode(decoded)
    except ValueError:
        return []
    return records if isinstance(records, list) else []


def _normalize_immunefi_record(item):
    """Normalize one embedded Immunefi bounty record to the program schema.

    Returns None when the record has no usable project name. Paused and
    invite-only programs are kept but marked offers_bounties=False since they
    are not actionable for a public hunter. Per-program scope lives on the
    detail pages, so assets is always [] (see P5 live-sync recipe).
    """
    name = item.get("project") or item.get("name") or ""
    if not name:
        return None
    slug = item.get("slug") or ""
    handle = slug or name.lower().replace(" ", "-").replace(".", "-")
    path = item.get("url") or f"/bug-bounty/{handle}/"
    url = path if path.startswith("http") else f"https://immunefi.com{path}"
    try:
        max_p = float(item.get("maxBounty") or 0)
    except (ValueError, TypeError):
        max_p = 0.0
    actionable = item.get("pausedAt") is None and not item.get("inviteOnly", False)
    return {
        "name": name,
        "handle": handle,
        "url": url,
        "max_payout": max_p,
        "currency": "USD",
        "offers_bounties": bool(max_p > 0 and actionable),
        "assets": [],
    }



def _fetch_public_html(url):
    """GET a public listing page as text. Soft-fail: "" on any error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Scan4Me public metadata sync)"},
        )
        with urllib.request.urlopen(req, timeout=25) as resp:  # nosec B310
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Listing fetch skipped ({url}): {e}")
        return ""


class _AnchorExtractor(HTMLParser):
    """Collect anchors as (href, aria-label, text lines incl. img alt)."""

    def __init__(self):
        super().__init__()
        self._cur = None
        self.anchors = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a":
            self._cur = [d.get("href", ""), d.get("aria-label", ""), []]
        elif self._cur is not None and tag == "img" and d.get("alt"):
            self._cur[2].append(d["alt"].strip())

    def handle_data(self, data):
        if self._cur is not None and data.strip():
            self._cur[2].append(data.strip())

    def handle_endtag(self, tag):
        if tag == "a" and self._cur is not None:
            self.anchors.append(tuple(self._cur))
            self._cur = None


def _unique_lines(lines):
    out = []
    for line in lines:
        if line and line not in out:
            out.append(line)
    return out


def _listing_anchors(html_text, needle):
    """Unique anchors whose href contains needle: (href, aria, lines)."""
    parser = _AnchorExtractor()
    try:
        parser.feed(html_text or "")
    except Exception:
        return []
    seen, out = set(), []
    for href, aria, lines in parser.anchors:
        if needle in href and href not in seen:
            seen.add(href)
            out.append((href, aria, _unique_lines(lines)))
    return out


def _money(text, pattern=r"\$([\d,]+(?:\.\d+)?)"):
    m = re.search(pattern, text or "")
    if not m:
        return 0.0
    try:
        return float(m.group(1).replace(",", ""))
    except (ValueError, TypeError):
        return 0.0


def _parse_human_date(value):
    """'14 Jul 2020' -> epoch seconds (day precision), or None."""
    try:
        return int(datetime.strptime(value.strip(), "%d %b %Y").timestamp())
    except (AttributeError, TypeError, ValueError):
        return None


def _listing_record(name, handle, url, max_payout=0.0, kind="web2",
                    managed=False, offers=None, started=None, rewarded=None,
                    scope_updated=None):
    return {
        "name": name,
        "handle": handle,
        "url": url,
        "max_payout": _safe_non_negative_float(max_payout),
        "currency": "USD",
        "offers_bounties": _safe_non_negative_float(max_payout) > 0
        if offers is None
        else bool(offers),
        "managed_triage": bool(managed),
        "program_kind": kind,
        "official_start_timestamp": started,
        "official_scope_updated_timestamp": scope_updated,
        "rewarded_vulnerabilities": rewarded,
    }


def _parse_hackenproof_page(html_text):
    programs = []
    for href, _aria, lines in _listing_anchors(html_text, "/programs/"):
        slug = href.rstrip("/").split("/")[-1]
        managed = any("Triaged by HackenProof" in line for line in lines)
        names = [l for l in lines if "Triaged by HackenProof" not in l]
        if not slug or not names:
            continue
        text = " | ".join(lines)
        if slug.lower() in {"all", "explore", "new", "submit", "programs"}:
            continue  # navigation/footer anchor, not a program card
        name = re.split(
            r"\s+(?:Up to:|Started date:|Submissions:|Paid:)", names[0]
        )[0].strip()
        started = _parse_human_date(
            (re.search(r"Started date:\s*\|?\s*(\d{1,2} [A-Za-z]{3} \d{4})", text) or [None, ""])[1]
        )
        subs = re.search(r"Submissions:\s*\|?\s*([\d,]+)", text)
        programs.append(_listing_record(
            name, slug, f"https://hackenproof.com{href}",
            _money(text, r"Up to:\s*\|?\s*\$([\d,]+)") or _money(text),
            kind="web3", managed=managed, started=started,
            rewarded=int(subs.group(1).replace(",", "")) if subs else None,
        ))
    return programs


def _cantina_payout(text):
    text = text or ""
    usdc = [
        float(a.replace(",", ""))
        for a in re.findall(r"([\d,]+(?:\.\d+)?)[\s|]*(?:in[\s|]+)?USDC", text)
    ]
    usdc += [
        float(a.replace(",", ""))
        for a in re.findall(r"USDC[\s|]*([\d,]+(?:\.\d+)?)", text)
    ]
    if usdc:
        return max(usdc)
    dollars = [
        float(a.replace(",", ""))
        for a in re.findall(r"\$([\d,]+(?:\.\d+)?)", text)
    ]
    return max(dollars) if dollars else 0.0


def _parse_cantina_page(html_text):
    programs = []
    for href, _aria, lines in _listing_anchors(html_text, "/bounties/"):
        if not lines:
            continue
        slug = href.rstrip("/").split("/")[-1]
        if slug.lower() in {"explore", "all", "bounties", "opportunities", "competitions"}:
            continue  # navigation/footer anchor, not a bounty card
        text = " | ".join(lines)
        payout = _cantina_payout(text)
        if not (payout > 0 or "Live" in lines or "Bug Bounty" in text):
            continue  # no bounty-card evidence on this anchor
        started = _parse_human_date(
            (re.search(r"Started on (\d{1,2} [A-Za-z]{3} \d{4})", text) or [None, ""])[1]
        )
        programs.append(_listing_record(
            lines[0], href.rstrip("/").split("/")[-1],
            f"https://cantina.xyz{href}", payout, kind="web3",
            managed="Cantina-Triaged" in text,
            offers=("Live" in lines) or payout > 0, started=started,
        ))
    return programs


def _parse_patchstack_page(html_text):
    programs = []
    for href, _aria, lines in _listing_anchors(html_text, "/database/wordpress/"):
        parts = [p for p in href.split("/") if p]
        if "vulnerabilities" not in parts or len(parts) < 4:
            continue
        slug = parts[-2]
        names = [l for l in lines if l not in ("Plugin", "Theme")]
        name = names[-1] if names else slug.replace("-", " ").title()
        name = re.sub(r"^(Plugin|Theme)\s+", "", name)
        url = href if href.startswith("http") else f"https://patchstack.com{href}"
        programs.append(_listing_record(name, slug, url, 0.0, kind="web2", offers=True))
    return programs


def _parse_huntr_page(html_text):
    programs = []
    for href, aria, lines in _listing_anchors(html_text, "/challenges/"):
        parts = [p for p in href.split("/") if p]
        if len(parts) < 2:
            continue
        cid = parts[1]
        text = " ".join([aria] + lines)
        m = re.search(r"(?:View details for|View) (.+?) challenge", text)
        generic = {"view details", "view", "details", "challenges"}
        candidates = [l for l in lines if l.strip().lower() not in generic]
        name = (
            m.group(1).strip()
            if m and m.group(1).strip().lower() not in generic
            else (max(candidates, key=len) if candidates else "")
        )
        if not name or name.strip().lower() in generic:
            continue
        programs.append(_listing_record(
            name, cid, f"https://huntr.com/challenges/{cid}",
            _money(text), kind="web2", offers=True,
        ))
    return programs


def _parse_sherlock_bounties_page(html_text):
    programs = []
    for href, _aria, lines in _listing_anchors(html_text, "/bug-bounties/"):
        bounty_id = href.rstrip("/").split("/")[-1]
        if not bounty_id.isdigit() or not lines:
            continue
        text = " | ".join(lines)
        upd = re.search(r"Last Updated[^A-Za-z]*([A-Za-z]{3} \d{1,2}, \d{4})", text)
        scope_updated = None
        if upd:
            try:
                scope_updated = int(
                    datetime.strptime(upd.group(1), "%b %d, %Y").timestamp()
                )
            except ValueError:
                scope_updated = None
        programs.append(_listing_record(
            lines[0], f"sherlock-bb-{bounty_id}",
            f"https://audits.sherlock.xyz{href}",
            _money(text, r"([\d,]+(?:\.\d+)?)\s*(?:USDC|USD)"), kind="web3",
            scope_updated=scope_updated,
        ))
    return programs


def _strip_tags(fragment):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment or ""))


def _parse_codehawks_page(html_text):
    contests = []
    anchors = _listing_anchors(html_text, "/c/")
    body = html_text or ""
    first_pos = {}
    for href, _a, _l in anchors:
        s = href.rstrip("/").split("/")[-1]
        pos = body.find(f'href="/c/{s}"')
        if s and pos >= 0:
            first_pos[s] = pos
    ordered = sorted(first_pos.values())
    for href, _aria, lines in anchors:
        slug = href.rstrip("/").split("/")[-1]
        if not lines or not re.match(r"\d{4}-\d{2}-", slug):
            continue
        start = first_pos.get(slug)
        if start is None:
            window = ""
        else:
            later = [p for p in ordered if p > start]
            end = later[0] if later else len(body)  # last card: no next anchor
            window = _strip_tags(body[start:end])
        status = ""
        for word in ("Live", "Upcoming", "Judging", "Ended"):
            if word in window:
                status = word.upper()
                break
        m = re.match(r"(\d{4})-(\d{2})-", slug)
        contests.append({
            "name": lines[0],
            "handle": slug,
            "url": f"https://codehawks.cyfrin.io{href}",
            "max_payout": _money(window, r"([\d,]+(?:\.\d+)?)\s*USDC"),
            "currency": "USDC",
            "offers_bounties": True,
            "status": status,
            "starts_at": f"{m.group(1)}-{m.group(2)}" if m else None,
            "ends_at": None,
            "description": "",
        })
    return contests


def _parse_bugbase_page(html_text):
    """Bugbase embeds escaped JSON records in its Next.js payload."""
    body = (html_text or "").replace('\\"', '"')
    programs = []
    matches = list(re.finditer(r'"programName":"([^"]+)","programUsername":"([^"]+)"', body))
    for i, m in enumerate(matches):
        name, username = m.group(1), m.group(2)
        end = matches[i + 1].start() if i + 1 < len(matches) else min(len(body), m.start() + 8000)
        chunk = body[m.start():end]
        if '"isPrivate":true' in chunk or '"isVisible":false' in chunk:
            continue
        max_m = re.search(r'"maxBounty":([\d.]+)', chunk)
        created = re.search(r'"createdAt":"([^"]+)"', chunk)
        ptype = re.search(r'"programType":"([^"]+)"', chunk)
        max_payout = _safe_non_negative_float(max_m.group(1)) if max_m else 0.0
        programs.append(_listing_record(
            name, username, f"https://bugbase.ai/programs/{username}",
            max_payout, kind="web2",
            managed='"isManaged":true' in chunk,
            offers=(ptype.group(1) == "bugbounty") if ptype else max_payout > 0,
            started=parse_public_timestamp(created.group(1)) if created else None,
        ))
    seen, out = set(), []
    for p in programs:
        if p["handle"] not in seen:
            seen.add(p["handle"])
            out.append(p)
    return out


def _fetch_bugbase_programs(url=None):
    return _parse_bugbase_page(_fetch_public_html(url or BUGBASE_PROGRAMS_URL))


def _fetch_hackenproof_programs(url=None):
    return _parse_hackenproof_page(_fetch_public_html(url or HACKENPROOF_PROGRAMS_URL))


def _fetch_cantina_programs(url=None):
    return _parse_cantina_page(_fetch_public_html(url or CANTINA_OPPORTUNITIES_URL))


def _fetch_patchstack_programs(url=None):
    return _parse_patchstack_page(_fetch_public_html(url or PATCHSTACK_VDP_URL))


def _fetch_huntr_programs(url=None):
    return _parse_huntr_page(_fetch_public_html(url or HUNTR_CHALLENGES_URL))


def _fetch_sherlock_bounties(url=None):
    return _parse_sherlock_bounties_page(_fetch_public_html(url or SHERLOCK_BOUNTIES_URL))


def _fetch_codehawks_contests(url=None):
    return _parse_codehawks_page(_fetch_public_html(url or CODEHAWKS_CONTESTS_URL))


def _fetch_immunefi_programs(url=None):
    """Fetch the Immunefi bug bounty list from their public board page.

    The board embeds the full bounty list as escaped JSON — no API key needed.
    Returns [] on any fetch/parse failure (soft-fail, like other live feeds).
    """
    url = url or IMMUNEFI_BOUNTIES_URL
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Scan4Me public bug-bounty metadata sync"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[!] Immunefi fetch skipped: {e}")
        return []

    programs = []
    for item in _parse_immunefi_page(html):
        if not isinstance(item, dict):
            continue
        norm = _normalize_immunefi_record(item)
        if norm:
            programs.append(norm)
    return programs


def _fetch_sherlock_contests():
    """Fetch Sherlock audit contest list from their public paginated API.

    Returns a list of normalized dicts: name, handle, url, max_payout, currency,
    offers_bounties, starts_at, ends_at, status.
    Sherlock contests are Web3 smart-contract audit competitions with prize pools
    in USD/USDC. Active/upcoming contests have status in ('JUDGING','OPEN','UPCOMING').
    Returns [] on any fetch/parse failure.
    """
    programs = []
    page = 1
    while True:
        try:
            req = urllib.request.Request(
                f"{SHERLOCK_API_URL}?page={page}",
                headers={
                    "User-Agent": "Scan4Me public bug-bounty metadata sync",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:  # nosec B310
                data = json.load(resp)
        except Exception as e:
            if page == 1:
                print(f"[!] Sherlock fetch skipped: {e}")
            break

        items = data.get("items", [])
        for item in items:
            title = item.get("title", "")
            if not title:
                continue
            handle = f"sherlock-{item.get('id', title.lower().replace(' ', '-'))}"
            url = f"https://audits.sherlock.xyz/contests/{item.get('id', '')}"
            prize_pool = item.get("prize_pool") or item.get("rewards") or 0
            try:
                max_p = float(str(prize_pool).replace(",", "").strip() or 0)
            except (ValueError, TypeError):
                max_p = 0.0
            # Only include public, non-private contests
            if item.get("private", False):
                continue
            status = item.get("status", "")
            offers_bounty = max_p > 0
            programs.append(
                {
                    "name": title,
                    "handle": handle,
                    "url": url,
                    "max_payout": max_p,
                    "currency": item.get("token", "USDC"),
                    "offers_bounties": offers_bounty,
                    "status": status,
                    "starts_at": item.get("starts_at"),
                    "ends_at": item.get("ends_at"),
                    "description": (item.get("short_description") or "")[:200],
                }
            )

        if not data.get("has_next", False):
            break
        page += 1

    return programs


def _contest_ts(value):
    """Normalize a Sherlock contest timestamp for TEXT storage (int/ISO/None)."""
    if value is None or isinstance(value, str):
        return value
    return str(value)


def _load_pd_programs(repo_dir):
    """Load the program list from a projectdiscovery/public-bugbounty-programs checkout.

    Prefers the generated dist/data.json; falls back to src/data.yaml.
    Returns [] when neither exists or neither parses (soft-fail).
    """
    repo_dir = Path(repo_dir)
    json_file = repo_dir / "dist" / "data.json"
    if json_file.is_file():
        try:
            with open(json_file, encoding="utf-8") as f:
                raw = json.load(f)
            programs = raw if isinstance(raw, list) else raw.get("programs", [])
            return programs if isinstance(programs, list) else []
        except (OSError, UnicodeDecodeError, ValueError) as e:
            print(f"[!] ProjectDiscovery dist/data.json parse error: {e}")
    yaml_file = repo_dir / "src" / "data.yaml"
    if yaml_file.is_file():
        try:
            import yaml  # type: ignore[import-untyped]  # lazy: optional dep
        except ImportError:
            print("[*] ProjectDiscovery: PyYAML missing, cannot read src/data.yaml.")
            return []
        try:
            with open(yaml_file, encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            programs = raw if isinstance(raw, list) else (raw or {}).get("programs", [])
            return programs if isinstance(programs, list) else []
        except (OSError, UnicodeDecodeError, ValueError, yaml.YAMLError) as e:
            print(f"[!] ProjectDiscovery src/data.yaml parse error: {e}")
    return []


def _upstream_sha(git_bin, repo_dir):
    """Short upstream commit hash, or an explicit unknown marker (never fake)."""
    if not git_bin or not (repo_dir / ".git").exists():
        return "unknown (no upstream checkout)"
    try:
        proc = subprocess.run(
            [git_bin, "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
            check=True,
            shell=False,  # nosec B603
            capture_output=True,
            text=True,
        )
        sha = (proc.stdout or "").strip()
        return sha or "unknown (rev-parse empty)"
    except (subprocess.CalledProcessError, OSError) as e:
        return f"unknown (rev-parse failed: {e})"


def _set_meta(cur, key, value):
    cur.execute(
        "INSERT INTO sync_metadata(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def _row_last_updated(existing, now_ts, refresh_ok):
    """last_updated for an upsert: new rows stamp now; on a failed refresh
    existing rows keep their stamp (no freshness bump on stale data)."""
    if existing is None:
        return now_ts
    if refresh_ok:
        return now_ts
    try:
        return existing[2] if existing[2] is not None else now_ts
    except (IndexError, TypeError):
        return now_ts


def _record_program_change(cur, program_id, change_type, old_value, new_value, now_ts):
    """Record a program-level change if the value actually changed."""
    if old_value == new_value:
        return
    cur.execute(
        "INSERT INTO program_changes (program_id, change_type, old_value, new_value, detected_at) VALUES (?, ?, ?, ?, ?)",
        (program_id, change_type, str(old_value), str(new_value), now_ts),
    )


def _check_and_record_program_changes(cur, program_id, existing, new_values, now_ts):
    """Check for program-level changes and record them.

    existing: tuple from SELECT (id, first_seen, last_updated, max_payout, currency, rules_text, ...)
    new_values: dict with keys max_payout, currency, rules_text, etc.
    """
    if existing is None:
        return  # New program, no changes to record

    # existing columns: id, first_seen_timestamp, last_updated_timestamp
    # We need to query the full program record
    cur.execute(
        "SELECT max_payout, currency, rules_text, submission_state, offers_bounties FROM programs WHERE id=?",
        (program_id,),
    )
    old = cur.fetchone()
    if not old:
        return

    # Check payout change
    old_max_payout = old["max_payout"] if isinstance(old, dict) else old[0]
    old_currency = old["currency"] if isinstance(old, dict) else old[1]
    old_rules = old["rules_text"] if isinstance(old, dict) else old[2]
    old_submission_state = old["submission_state"] if isinstance(old, dict) else old[3]
    old_offers_bounties = old["offers_bounties"] if isinstance(old, dict) else old[4]

    if "max_payout" in new_values:
        _record_program_change(cur, program_id, "payout_changed", old_max_payout, new_values["max_payout"], now_ts)
    if "currency" in new_values:
        _record_program_change(cur, program_id, "currency_changed", old_currency, new_values["currency"], now_ts)
    if "rules_text" in new_values:
        _record_program_change(cur, program_id, "rules_changed", old_rules, new_values["rules_text"], now_ts)
    if "submission_state" in new_values:
        _record_program_change(cur, program_id, "submission_state_changed", old_submission_state, new_values["submission_state"], now_ts)
    if "offers_bounties" in new_values:
        _record_program_change(cur, program_id, "offers_bounties_changed", old_offers_bounties, new_values["offers_bounties"], now_ts)


def _platform_status(enabled, data, source, auth_used=False, count=None):
    """sync_metadata status entry for one platform feed (a staleness tripwire)."""
    if count is not None and (
        isinstance(count, bool) or not isinstance(count, int) or count < 0
    ):
        raise ValueError(f"platform status count must be an int >= 0, got {count!r}")
    if not enabled:
        return {"status": "skipped", "count": 0, "source": None}
    if not data:
        if auth_used:
            return {
                "status": "auth_empty",
                "count": 0,
                "source": source,
                "note": "authenticated fetch returned no rows;"
                " old rows left untouched",
            }
        return {"status": "empty", "count": 0, "source": source}
    effective_count = len(data) if count is None else count
    if effective_count == 0:
        if auth_used:
            return {
                "status": "auth_empty",
                "count": 0,
                "source": source,
                "note": "authenticated fetch returned rows but none were indexed;"
                " old rows left untouched",
            }
        return {
            "status": "empty",
            "count": 0,
            "source": source,
            "note": "fetch returned rows but none were indexed",
        }
    return {
        "status": "ok",
        "count": effective_count,
        "source": source,
    }


def _reconcile_platform_programs(cur, platform, seen_handles, now_ts):
    """Tombstone programs for ``platform`` that vanished from a valid sync feed.

    Truncation guard: if ``seen_handles`` is empty, or the feed reports at
    most half of the previously live programs, skip tombstoning entirely so
    a truncated upstream feed never mass-deletes active programs. The guard
    applies at every platform size; a genuine >50% platform shrink simply
    waits for the next confirming sync.
    """
    clean_seen = {str(h).strip() for h in (seen_handles or ()) if h}
    if not clean_seen:
        return 0
    existing_live = cur.execute(
        "SELECT id, handle FROM programs WHERE platform=? AND COALESCE(deleted_timestamp, 0)=0",
        (platform,),
    ).fetchall()
    if existing_live and len(clean_seen) * 2 <= len(existing_live):
        return 0
    stale_ids = [
        row["id"]
        for row in existing_live
        if str(row["handle"] or "").strip() not in clean_seen
    ]
    if stale_ids:
        cur.executemany(
            "UPDATE programs SET deleted_timestamp=? WHERE id=?",
            ((now_ts, pid) for pid in stale_ids),
        )
    return len(stale_ids)



def _sync_listing_programs(cur, platform, programs, now_ts):
    """Upsert normalized listing records into programs (caller owns txn)."""
    seen = set()
    for p in programs:
        handle = str(p.get("handle") or "")
        if not handle or not p.get("name") or not p.get("url"):
            continue
        seen.add(handle)
        existing = cur.execute(
            "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
            (platform, handle),
        ).fetchone()
        first_seen = existing[1] if existing else now_ts
        cur.execute(
            """
            INSERT INTO programs (
                platform, name, handle, url, website, offers_bounties, managed_triage,
                max_payout, currency, program_kind, official_start_timestamp,
                official_scope_updated_timestamp,
                rewarded_vulnerabilities, first_seen_timestamp,
                last_updated_timestamp, deleted_timestamp
            ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'USD', ?, ?, ?, ?, ?, ?, 0)
            ON CONFLICT(platform, handle) DO UPDATE SET
                name=excluded.name, url=excluded.url,
                offers_bounties=MAX(COALESCE(programs.offers_bounties, 0), excluded.offers_bounties),
                managed_triage=MAX(COALESCE(programs.managed_triage, 0), excluded.managed_triage),
                max_payout=CASE WHEN excluded.max_payout > 0
                    THEN excluded.max_payout ELSE programs.max_payout END,
                official_start_timestamp=COALESCE(
                    excluded.official_start_timestamp, programs.official_start_timestamp),
                official_scope_updated_timestamp=COALESCE(
                    excluded.official_scope_updated_timestamp,
                    programs.official_scope_updated_timestamp),
                rewarded_vulnerabilities=COALESCE(
                    excluded.rewarded_vulnerabilities, programs.rewarded_vulnerabilities),
                last_updated_timestamp=excluded.last_updated_timestamp,
                deleted_timestamp=0
            """,
            (
                platform, p["name"], handle, p["url"],
                1 if p.get("offers_bounties") else 0,
                1 if p.get("managed_triage") else 0,
                _safe_non_negative_float(p.get("max_payout")),
                p.get("program_kind") or "web2",
                p.get("official_start_timestamp"),
                p.get("official_scope_updated_timestamp"),
                p.get("rewarded_vulnerabilities"),
                first_seen, now_ts,
            ),
        )
    _reconcile_platform_programs(cur, platform, seen, now_ts)
    return len(seen)


def _sync_listing_contests(cur, platform, contests, now_ts):
    """Upsert normalized contest records into contests (caller owns txn)."""
    seen = 0
    for p in contests:
        handle = str(p.get("handle") or "")
        if not handle or not p.get("name"):
            continue
        seen += 1
        existing = cur.execute(
            "SELECT id, first_seen_timestamp FROM contests WHERE platform=? AND handle=?",
            (platform, handle),
        ).fetchone()
        first_seen = existing[1] if existing else now_ts
        cur.execute(
            """
            INSERT INTO contests (
                platform, name, handle, url, offers_bounties, max_payout,
                currency, status, starts_at, ends_at, description,
                first_seen_timestamp, last_updated_timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(platform, handle) DO UPDATE SET
                name=excluded.name, url=excluded.url,
                offers_bounties=MAX(COALESCE(contests.offers_bounties, 0), excluded.offers_bounties),
                max_payout=CASE WHEN excluded.max_payout > 0
                    THEN excluded.max_payout ELSE contests.max_payout END,
                currency=excluded.currency,
                status=COALESCE(NULLIF(excluded.status, ''), contests.status), starts_at=excluded.starts_at,
                ends_at=excluded.ends_at, description=excluded.description,
                last_updated_timestamp=excluded.last_updated_timestamp
            """,
            (
                platform, p["name"], handle, p.get("url", ""),
                1 if p.get("offers_bounties") else 0,
                _safe_non_negative_float(p.get("max_payout")), p.get("currency", "USD"),
                p.get("status"), _contest_ts(p.get("starts_at")),
                _contest_ts(p.get("ends_at")), p.get("description"),
                first_seen, now_ts,
            ),
        )
    return seen


def sync_data(
    refresh=True,
    platforms_cfg=None,
    config=None,
    use_auth=None,
    auth_delay=1.0,
):
    """Sync all enabled feed sources into the local SQLite database.

    By default Scan4Me operates in UNAUTHENTICATED mode (``use_auth=False`` unless
    explicitly enabled via ``use_auth=True`` or ``config["use_auth"]=True``),
    harvesting maximum public program & scope intelligence without signing in so
    Oracle can compare its saved-credential scans against Scan4Me's unauthenticated
    baseline.

    Core feeds (arkadiyt/bounty-targets-data, public unauthenticated):
      HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy

    Authenticated feeds (when use_auth=True and api_key configured):
      HackerOne  — api.hackerone.com/v1/hackers/programs  (Basic username:token)
      Bugcrowd   — api.bugcrowd.com/engagements           (Token header)
      Intigriti  — api.intigriti.com/core/researcher/...  (Bearer token)
      YesWeHack  — api.yeswehack.com/programs             (Bearer token)

    Optional live feeds (fetched directly, no auth needed):
      Immunefi  — bug-bounty board page (embedded JSON, web3)
      Sherlock  — paginated audit contest API (web3)

    Supplemental feed (projectdiscovery/public-bugbounty-programs):
      Machine-readable scope JSON for 800+ programs across many platforms.
      Indexed as platform='PDPrograms'.  Skipped when unavailable.
    """
    platforms_cfg = platforms_cfg or {}
    loaded_cfg = config if config is not None else load_config()
    creds = load_credentials(loaded_cfg)
    # Default: unauthenticated public scan unless use_auth is explicitly True
    # or no public feed file exists for an enabled platform when refresh=True.
    auth_enabled = (
        _coerce_bool(use_auth)
        if use_auth is not None
        else _coerce_bool((loaded_cfg or {}).get("use_auth", False))
    )
    CACHE_DATA_DIR.mkdir(parents=True, exist_ok=True)
    repo_dir = CACHE_DATA_DIR / "repo"
    cached_repo_data = repo_dir / "data"
    local_data_dir = (
        cached_repo_data if cached_repo_data.is_dir() else CACHE_DATA_DIR / "data"
    )

    git_bin = shutil.which("git")
    refresh_ok = True
    refresh_error = ""
    if refresh:
        if not git_bin:
            raise FileNotFoundError("`git` not found on PATH; cannot refresh feeds.")
        if (repo_dir / ".git").exists():
            try:
                subprocess.run(
                    [git_bin, "-C", str(repo_dir), "pull", "--ff-only"],
                    check=True,
                    shell=False,  # nosec B603
                )
            except subprocess.CalledProcessError as e:
                refresh_ok = False
                refresh_error = str(e)
                print(f"[!] Feed repo pull failed ({e}) — using cached snapshot.")
                print(
                    "[!] Stale snapshot: existing rows keep their"
                    " last_updated_timestamp (no freshness bump)."
                )
        else:
            subprocess.run(
                [git_bin, "clone", "--depth", "1", UPSTREAM_REPO, str(repo_dir)],
                check=True,
                shell=False,  # nosec B603
            )
        local_data_dir = repo_dir / "data"
    elif not local_data_dir.exists():
        raise FileNotFoundError(
            f"Offline feed cache not found at {local_data_dir}; run `sync` once with network access."
        )
    upstream_sha = _upstream_sha(git_bin, repo_dir)

    # Core feeds are required only when their platform is enabled.
    feed_for_platform = (
        ("hackerone", "hackerone_data.json"),
        ("bugcrowd", "bugcrowd_data.json"),
        ("intigriti", "intigriti_data.json"),
        ("yeswehack", "yeswehack_data.json"),
    )
    required_feeds = tuple(
        name for plat, name in feed_for_platform if platforms_cfg.get(plat, True)
    )
    missing_feeds = [
        name for name in required_feeds if not (local_data_dir / name).is_file()
    ]
    if missing_feeds:
        raise FileNotFoundError(
            f"Missing feed files in {local_data_dir}: {', '.join(missing_feeds)}"
        )

    conn = get_db()
    ensure_schema(conn)

    cur = conn.cursor()
    baseline_complete = cur.execute(
        "SELECT value FROM sync_metadata WHERE key='baseline_complete'"
    ).fetchone()
    is_baseline_sync = baseline_complete is None

    print(f"[*] Ingesting and normalizing targets from {local_data_dir}...")
    now_ts = int(time.time())

    platform_status = {}
    ingest_stats = {}  # per-platform normalizer reject counts (tripwire)

    # 1. HackerOne — unauthenticated public feed by default; authenticated API when opted in
    h1_creds = creds.get("hackerone", {})
    h1_username = h1_creds.get("username")
    h1_token = h1_creds.get("api_token")
    h1_auth_used = bool(
        refresh
        and auth_enabled
        and h1_username
        and h1_token
        and platforms_cfg.get("hackerone", True)
    )
    if h1_auth_used:
        print(
            "[*] HackerOne: API key found — using authenticated feed (includes private invites)."
        )
        h1_data = _fetch_h1_authenticated(h1_username, h1_token, delay=auth_delay)
        h1_source = "authenticated"
    else:
        if bool(h1_username) != bool(h1_token):
            print(
                "[!] HackerOne: partial credentials (need both username + api_token) — using public feed."
            )
        elif h1_username and h1_token and not refresh:
            print(
                "[*] HackerOne: offline mode — authenticated fetch skipped, using cached public feed."
            )
        elif h1_username and h1_token and not auth_enabled:
            print(
                "[*] HackerOne: unauthenticated mode — using public feed (Oracle compares saved credentials against Scan4Me)."
            )
        h1_file = local_data_dir / "hackerone_data.json"
        if h1_file.exists():
            with open(h1_file, encoding="utf-8") as f:
                h1_data = json.load(f)
        else:
            h1_data = []
        h1_source = "public-file"

    if h1_data and platforms_cfg.get("hackerone", True):
        h1_seen_handles = set()
        with conn:
            for p in h1_data:
                handle = p.get("handle")
                if handle:
                    h1_seen_handles.add(str(handle))
                name = p.get("name") or handle
                url = p.get("url") or f"https://hackerone.com/{handle}"
                website = p.get("website") or ""
                offers_bounty = bool(p.get("offers_bounties"))
                managed = bool(p.get("managed_program"))
                max_p = _safe_non_negative_float(
                    p.get("max_payout")
                    or p.get("top_bounty_upper_amount")
                    or p.get("top_bounty")
                    or 0.0
                )
                resp_time = p.get("average_time_to_first_program_response")
                bounty_time = p.get("average_time_to_bounty_awarded")
                resolved_time = p.get("average_time_to_report_resolved")
                efficiency = p.get("response_efficiency_percentage")
                sub_state = str(p.get("submission_state") or "open")
                offers_swag = bool(p.get("offers_swag", False))
                rules_txt = str(p.get("policy") or p.get("rules_text") or "")

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout,
                        first_response_hours, bounty_awarded_hours, report_resolved_hours,
                        response_efficiency, currency, submission_state, offers_swag, rules_text,
                        first_seen_timestamp, last_updated_timestamp, deleted_timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url, website=excluded.website,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=CASE WHEN excluded.max_payout > 0 THEN excluded.max_payout ELSE programs.max_payout END,
                        first_response_hours=excluded.first_response_hours,
                        bounty_awarded_hours=excluded.bounty_awarded_hours,
                        report_resolved_hours=excluded.report_resolved_hours,
                        response_efficiency=excluded.response_efficiency,
                        currency=excluded.currency,
                        submission_state=excluded.submission_state,
                        offers_swag=excluded.offers_swag,
                        rules_text=CASE WHEN excluded.rules_text != '' THEN excluded.rules_text ELSE programs.rules_text END,
                        last_updated_timestamp=excluded.last_updated_timestamp,
                        deleted_timestamp=0
                """,
                    (
                        "HackerOne",
                        name,
                        handle,
                        url,
                        website,
                        offers_bounty,
                        managed,
                        max_p,
                        resp_time,
                        bounty_time,
                        resolved_time,
                        efficiency,
                        sub_state,
                        offers_swag,
                        rules_txt,
                        first_seen,
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("HackerOne", handle),
                ).fetchone()[0]
                # Record program-level changes (payout, rules, etc.)
                _check_and_record_program_changes(
                    cur,
                    prog_id,
                    existing,
                    {
                        "max_payout": max_p,
                        "currency": "USD",
                        "rules_text": rules_txt,
                        "submission_state": sub_state,
                        "offers_bounties": offers_bounty,
                    },
                    now_ts,
                )
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "asset_identifier",
                    "asset_type",
                    now_ts,
                    stats=ingest_stats.setdefault("hackerone", {}),
                )
            _reconcile_platform_programs(cur, "HackerOne", h1_seen_handles, now_ts)
        print(f"[+] HackerOne indexed: {len(h1_data)} programs.")
    platform_status["hackerone"] = _platform_status(
        platforms_cfg.get("hackerone", True), h1_data, h1_source, h1_auth_used
    )

    # 2. Bugcrowd — unauthenticated public feed by default; authenticated API when opted in
    bc_token = creds.get("bugcrowd", {}).get("api_token")
    bc_auth_used = bool(
        refresh and auth_enabled and bc_token and platforms_cfg.get("bugcrowd", True)
    )
    if bc_auth_used:
        print(
            "[*] Bugcrowd: API key found — using authenticated feed (includes private programs)."
        )
        bc_data = _fetch_bugcrowd_authenticated(bc_token, delay=auth_delay)
        bc_source = "authenticated"
    else:
        bc_file = local_data_dir / "bugcrowd_data.json"
        if bc_file.exists():
            with open(bc_file, encoding="utf-8") as f:
                bc_data = json.load(f)
        else:
            bc_data = []
        bc_source = "public-file"

    if bc_data and platforms_cfg.get("bugcrowd", True):
        bc_seen_handles = set()
        with conn:
            for p in bc_data:
                name = p.get("name", "Unknown")
                url = p.get("url", "")
                if url.startswith("/"):
                    url = f"https://bugcrowd.com{url}"
                handle = url.rstrip("/").split("/")[-1]
                if handle:
                    bc_seen_handles.add(str(handle))
                max_p = _safe_non_negative_float(p.get("max_payout"))
                offers_bounty = max_p > 0
                managed = bool(p.get("managed_by_bugcrowd"))
                safe = p.get("safe_harbor", "Standard")
                allows_disc = bool(p.get("allows_disclosure", False))
                rules_txt = str(p.get("description") or p.get("rules_text") or "")

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, safe_harbor, allows_disclosure, rules_text,
                        first_seen_timestamp, last_updated_timestamp, deleted_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, 'USD', ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=CASE WHEN excluded.max_payout > 0
                            THEN excluded.max_payout ELSE programs.max_payout END,
                        currency=excluded.currency,
                        safe_harbor=excluded.safe_harbor,
                        allows_disclosure=excluded.allows_disclosure,
                        rules_text=CASE WHEN excluded.rules_text != '' THEN excluded.rules_text ELSE programs.rules_text END,
                        last_updated_timestamp=excluded.last_updated_timestamp,
                        deleted_timestamp=0
                """,
                    (
                        "Bugcrowd",
                        name,
                        handle,
                        url,
                        offers_bounty,
                        managed,
                        max_p,
                        safe,
                        allows_disc,
                        rules_txt,
                        first_seen,
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Bugcrowd", handle),
                ).fetchone()[0]
                # Record program-level changes
                _check_and_record_program_changes(
                    cur,
                    prog_id,
                    existing,
                    {
                        "max_payout": max_p,
                        "currency": "USD",
                        "rules_text": rules_txt,
                        "submission_state": "open",
                        "offers_bounties": offers_bounty,
                    },
                    now_ts,
                )
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("bugcrowd", {}),
                )
            _reconcile_platform_programs(cur, "Bugcrowd", bc_seen_handles, now_ts)
        print(f"[+] Bugcrowd indexed: {len(bc_data)} programs.")
    platform_status["bugcrowd"] = _platform_status(
        platforms_cfg.get("bugcrowd", True), bc_data, bc_source, bc_auth_used
    )

    # 3. Intigriti — unauthenticated public feed by default; authenticated API when opted in
    inti_token = creds.get("intigriti", {}).get("api_token")
    inti_auth_used = bool(
        refresh and auth_enabled and inti_token and platforms_cfg.get("intigriti", True)
    )
    if inti_auth_used:
        print(
            "[*] Intigriti: API key found — using authenticated feed (includes private programs)."
        )
        inti_data = _fetch_intigriti_authenticated(inti_token, delay=auth_delay)
        inti_source = "authenticated"
    else:
        inti_file = local_data_dir / "intigriti_data.json"
        if inti_file.exists():
            with open(inti_file, encoding="utf-8") as f:
                inti_data = json.load(f)
        else:
            inti_data = []
        inti_source = "public-file"

    if inti_data and platforms_cfg.get("intigriti", True):
        inti_seen_handles = set()
        with conn:
            for p in inti_data:
                name = p.get("name", "Unknown")
                handle = p.get("handle") or str(p.get("id"))
                if handle:
                    inti_seen_handles.add(str(handle))
                url = p.get("url", "")
                max_b = p.get("max_bounty", {})
                max_val = (
                    float(max_b.get("value", 0) or 0) if isinstance(max_b, dict) else 0
                )
                min_b = p.get("min_bounty", {})
                min_val = (
                    float(min_b.get("value", 0) or 0) if isinstance(min_b, dict) else 0
                )
                curr = (
                    max_b.get("currency", "EUR") if isinstance(max_b, dict) else "EUR"
                )
                offers_bounty = max_val > 0
                company_handle = str(p.get("company_handle") or "")
                sub_state = str(
                    p.get("status") or p.get("confidentiality_level") or "open"
                )

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, min_payout, currency, company_handle, submission_state,
                        first_seen_timestamp, last_updated_timestamp, deleted_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, 1, ?, ?, ?, ?, ?, ?, ?, 0)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=excluded.max_payout,
                        min_payout=excluded.min_payout,
                        currency=excluded.currency,
                        company_handle=excluded.company_handle,
                        submission_state=excluded.submission_state,
                        last_updated_timestamp=excluded.last_updated_timestamp,
                        deleted_timestamp=0
                """,
                    (
                        "Intigriti",
                        name,
                        handle,
                        url,
                        offers_bounty,
                        max_val,
                        min_val,
                        curr,
                        company_handle,
                        sub_state,
                        first_seen,
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Intigriti", handle),
                ).fetchone()[0]
                # Record program-level changes
                _check_and_record_program_changes(
                    cur,
                    prog_id,
                    existing,
                    {
                        "max_payout": max_val,
                        "currency": curr,
                        "rules_text": "",
                        "submission_state": sub_state,
                        "offers_bounties": offers_bounty,
                    },
                    now_ts,
                )
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "endpoint",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("intigriti", {}),
                )
            _reconcile_platform_programs(cur, "Intigriti", inti_seen_handles, now_ts)
        print(f"[+] Intigriti indexed: {len(inti_data)} programs.")
    platform_status["intigriti"] = _platform_status(
        platforms_cfg.get("intigriti", True), inti_data, inti_source, inti_auth_used
    )

    # 4. YesWeHack — unauthenticated public feed by default; authenticated API when opted in
    ywh_token = creds.get("yeswehack", {}).get("api_token")
    ywh_auth_used = bool(
        refresh and auth_enabled and ywh_token and platforms_cfg.get("yeswehack", True)
    )
    if ywh_auth_used:
        print(
            "[*] YesWeHack: API key found — using authenticated feed (includes private programs)."
        )
        ywh_data = _fetch_yeswehack_authenticated(ywh_token, delay=auth_delay)
        ywh_source = "authenticated"
    else:
        ywh_file = local_data_dir / "yeswehack_data.json"
        if ywh_file.exists():
            with open(ywh_file, encoding="utf-8") as f:
                ywh_data = json.load(f)
        else:
            ywh_data = []
        ywh_source = "public-file"

    if ywh_data and platforms_cfg.get("yeswehack", True):
        ywh_seen_handles = set()
        with conn:
            for p in ywh_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id"))
                if handle:
                    ywh_seen_handles.add(handle)
                max_val = float(p.get("max_bounty", 0) or 0)
                min_val = float(p.get("min_bounty", 0) or 0)
                offers_bounty = max_val > 0
                managed = bool(p.get("managed"))
                sub_state = "disabled" if p.get("disabled") else "open"

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, min_payout, currency, submission_state,
                        first_seen_timestamp, last_updated_timestamp, deleted_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 'EUR', ?, ?, ?, 0)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        managed_triage=excluded.managed_triage,
                        max_payout=excluded.max_payout,
                        min_payout=excluded.min_payout,
                        currency=excluded.currency,
                        submission_state=excluded.submission_state,
                        last_updated_timestamp=excluded.last_updated_timestamp,
                        deleted_timestamp=0
                """,
                    (
                        "YesWeHack",
                        name,
                        handle,
                        f"https://yeswehack.com/programs/{handle}",
                        offers_bounty,
                        managed,
                        max_val,
                        min_val,
                        sub_state,
                        first_seen,
                        last_upd,
                    ),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("YesWeHack", handle),
                ).fetchone()[0]
                # Record program-level changes
                _check_and_record_program_changes(
                    cur,
                    prog_id,
                    existing,
                    {
                        "max_payout": max_val,
                        "currency": "EUR",
                        "rules_text": "",
                        "submission_state": sub_state,
                        "offers_bounties": offers_bounty,
                    },
                    now_ts,
                )
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("yeswehack", {}),
                )
            _reconcile_platform_programs(cur, "YesWeHack", ywh_seen_handles, now_ts)
        print(f"[+] YesWeHack indexed: {len(ywh_data)} programs.")
    platform_status["yeswehack"] = _platform_status(
        platforms_cfg.get("yeswehack", True), ywh_data, ywh_source, ywh_auth_used
    )

    # 5. Federacy (optional — present in arkadiyt repo but tiny; skip when absent)
    fed_file = local_data_dir / "federacy_data.json"
    fed_data = []
    if fed_file.exists() and platforms_cfg.get("federacy", False):
        with open(fed_file, encoding="utf-8") as f:
            fed_data = json.load(f)
        fed_seen_handles = set()
        with conn:
            for p in fed_data:
                name = p.get("name", "Unknown")
                handle = str(p.get("id") or name.lower().replace(" ", "-"))
                if handle:
                    fed_seen_handles.add(handle)
                url = p.get("url", "")
                offers_bounty = bool(p.get("offers_awards", False))

                existing = cur.execute(
                    "SELECT id, first_seen_timestamp, last_updated_timestamp"
                    " FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()
                first_seen = existing[1] if existing else now_ts
                last_upd = _row_last_updated(existing, now_ts, refresh_ok)

                cur.execute(
                    """
                    INSERT INTO programs (
                        platform, name, handle, url, website, offers_bounties, managed_triage,
                        max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp,
                        deleted_timestamp
                    ) VALUES (?, ?, ?, ?, '', ?, 0, 0, 'USD', 'web2', ?, ?, 0)
                    ON CONFLICT(platform, handle) DO UPDATE SET
                        name=excluded.name, url=excluded.url,
                        offers_bounties=excluded.offers_bounties,
                        last_updated_timestamp=excluded.last_updated_timestamp,
                        deleted_timestamp=0
                """,
                    ("Federacy", name, handle, url, offers_bounty, first_seen, last_upd),
                )

                prog_id = cur.execute(
                    "SELECT id FROM programs WHERE platform=? AND handle=?",
                    ("Federacy", handle),
                ).fetchone()[0]
                _sync_program_scope(
                    cur,
                    prog_id,
                    p,
                    "target",
                    "type",
                    now_ts,
                    stats=ingest_stats.setdefault("federacy", {}),
                )
            _reconcile_platform_programs(cur, "Federacy", fed_seen_handles, now_ts)
        print(f"[+] Federacy indexed: {len(fed_data)} programs.")
    elif not fed_file.exists():
        print("[*] Federacy feed not found in repo — skipping.")
    platform_status["federacy"] = _platform_status(
        platforms_cfg.get("federacy", False) and fed_file.exists(),
        fed_data,
        "public-file",
    )

    # 6. Immunefi (live fetch — Web3/DeFi; optional, skip on network failure)
    immunefi_programs = []
    immunefi_attempted = bool(refresh and platforms_cfg.get("immunefi", True))
    if immunefi_attempted:
        print("[*] Fetching Immunefi programs (Web3/DeFi live feed)...")
        immunefi_programs = _fetch_immunefi_programs()
        if immunefi_programs:
            im_seen_handles = set()
            with conn:
                for p in immunefi_programs:
                    handle = p["handle"]
                    if handle:
                        im_seen_handles.add(str(handle))
                    existing = cur.execute(
                        "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                        ("Immunefi", handle),
                    ).fetchone()
                    first_seen = existing[1] if existing else now_ts

                    cur.execute(
                        """
                        INSERT INTO programs (
                            platform, name, handle, url, website, offers_bounties, managed_triage,
                            max_payout, currency, program_kind, first_seen_timestamp, last_updated_timestamp,
                            deleted_timestamp
                        ) VALUES (?, ?, ?, ?, '', ?, 0, ?, 'USD', 'web3', ?, ?, 0)
                        ON CONFLICT(platform, handle) DO UPDATE SET
                            name=excluded.name, url=excluded.url,
                            offers_bounties=excluded.offers_bounties,
                            max_payout=excluded.max_payout,
                            last_updated_timestamp=excluded.last_updated_timestamp,
                            deleted_timestamp=0
                    """,
                        (
                            "Immunefi",
                            p["name"],
                            handle,
                            p["url"],
                            p["offers_bounties"],
                            p["max_payout"],
                            first_seen,
                            now_ts,
                        ),
                    )

                    prog_id = cur.execute(
                        "SELECT id FROM programs WHERE platform=? AND handle=?",
                        ("Immunefi", handle),
                    ).fetchone()[0]
                    # Immunefi assets are smart contract addresses / URLs — treat as non-wildcard
                    asset_targets = [
                        {"addr": a, "kind": "SmartContract"} for a in p["assets"]
                    ]
                    sync_assets(cur, prog_id, asset_targets, "addr", "kind", now_ts)
                _reconcile_platform_programs(cur, "Immunefi", im_seen_handles, now_ts)
            print(f"[+] Immunefi indexed: {len(immunefi_programs)} programs.")
        else:
            print(
                "[*] Immunefi: no data returned (network unavailable or feed format changed)."
            )
    platform_status["immunefi"] = _platform_status(
        immunefi_attempted, immunefi_programs, "live-board"
    )

    # 7. Sherlock audit contests (live fetch — Web3 smart-contract; optional, soft-fail)
    sherlock_contests = []
    sherlock_attempted = bool(refresh and platforms_cfg.get("sherlock", True))
    if sherlock_attempted:
        print(
            "[*] Fetching Sherlock audit contests (Web3 smart-contract competitions)..."
        )
        sherlock_contests = _fetch_sherlock_contests()
        if sherlock_contests:
            with conn:
                for p in sherlock_contests:
                    handle = p["handle"]
                    existing = cur.execute(
                        "SELECT id, first_seen_timestamp FROM contests WHERE platform=? AND handle=?",
                        ("Sherlock", handle),
                    ).fetchone()
                    first_seen = existing[1] if existing else now_ts

                    cur.execute(
                        """
                        INSERT INTO contests (
                            platform, name, handle, url, offers_bounties, max_payout,
                            currency, status, starts_at, ends_at, description,
                            first_seen_timestamp, last_updated_timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(platform, handle) DO UPDATE SET
                            name=excluded.name, url=excluded.url,
                            offers_bounties=excluded.offers_bounties,
                            max_payout=excluded.max_payout,
                            currency=excluded.currency,
                            status=excluded.status,
                            starts_at=excluded.starts_at,
                            ends_at=excluded.ends_at,
                            description=excluded.description,
                            last_updated_timestamp=excluded.last_updated_timestamp
                    """,
                        (
                            "Sherlock",
                            p["name"],
                            handle,
                            p["url"],
                            p["offers_bounties"],
                            p["max_payout"],
                            p["currency"],
                            p.get("status"),
                            _contest_ts(p.get("starts_at")),
                            _contest_ts(p.get("ends_at")),
                            p.get("description"),
                            first_seen,
                            now_ts,
                        ),
                    )
                    # Sherlock scopes are the contest URL itself — no sub-assets to enumerate
            print(f"[+] Sherlock indexed: {len(sherlock_contests)} contests.")
        else:
            print("[*] Sherlock: no contest data returned.")
    platform_status["sherlock"] = _platform_status(
        sherlock_attempted, sherlock_contests, "live-api"
    )

    # 8. ProjectDiscovery public-bugbounty-programs (supplemental; soft-fail)
    pd_programs_list = []
    pd_attempted = bool(refresh and platforms_cfg.get("pd_programs", True))
    pd_clone_failed = ""
    if pd_attempted:
        pd_repo_dir = CACHE_DATA_DIR / "pd_programs_repo"
        try:
            if (pd_repo_dir / ".git").exists():
                subprocess.run(
                    [git_bin, "-C", str(pd_repo_dir), "pull", "--ff-only"],
                    check=True,
                    shell=False,  # nosec B603
                    capture_output=True,
                )
            else:
                subprocess.run(
                    [
                        git_bin,
                        "clone",
                        "--depth",
                        "1",
                        PD_PROGRAMS_REPO,
                        str(pd_repo_dir),
                    ],
                    check=True,
                    shell=False,  # nosec B603
                    capture_output=True,
                )
        except subprocess.CalledProcessError as e:
            print(f"[!] ProjectDiscovery repo sync failed — skipping: {e}")
            pd_clone_failed = str(e)
            pd_repo_dir = None

        if pd_repo_dir and pd_repo_dir.exists():
            pd_programs_list = _load_pd_programs(pd_repo_dir)
            if pd_programs_list:
                try:
                    count = 0
                    pd_seen_handles = set()
                    with conn:
                        for p in pd_programs_list:
                            if not isinstance(p, dict):
                                continue
                            name = p.get("name", "")
                            if not name:
                                continue
                            handle = name.lower().replace(" ", "-")[:80]
                            if handle:
                                pd_seen_handles.add(handle)
                            url = p.get("url") or p.get("bounty_url") or ""
                            domains = p.get("domains") or []
                            offers_bounty = bool(p.get("bounty", False))

                            existing = cur.execute(
                                "SELECT id, first_seen_timestamp FROM programs WHERE platform=? AND handle=?",
                                ("PDPrograms", handle),
                            ).fetchone()
                            first_seen = existing[1] if existing else now_ts

                            cur.execute(
                                """
                                INSERT INTO programs (
                                    platform, name, handle, url, website, offers_bounties,
                                    managed_triage, max_payout, currency, program_kind,
                                    first_seen_timestamp, last_updated_timestamp, deleted_timestamp
                                ) VALUES (?, ?, ?, ?, '', ?, 0, 0, 'USD', 'web2', ?, ?, 0)
                                ON CONFLICT(platform, handle) DO UPDATE SET
                                    name=excluded.name, url=excluded.url,
                                    offers_bounties=excluded.offers_bounties,
                                    last_updated_timestamp=excluded.last_updated_timestamp,
                                    deleted_timestamp=0
                            """,
                                (
                                    "PDPrograms",
                                    name,
                                    handle,
                                    url,
                                    offers_bounty,
                                    first_seen,
                                    now_ts,
                                ),
                            )

                            prog_id = cur.execute(
                                "SELECT id FROM programs WHERE platform=? AND handle=?",
                                ("PDPrograms", handle),
                            ).fetchone()[0]
                            domain_targets = [
                                {"d": d, "t": "URL"} for d in domains if d
                            ]
                            sync_assets(cur, prog_id, domain_targets, "d", "t", now_ts)
                            count += 1
                        _reconcile_platform_programs(
                            cur, "PDPrograms", pd_seen_handles, now_ts
                        )
                    print(f"[+] ProjectDiscovery programs indexed: {count} programs.")
                except sqlite3.Error as e:
                    print(f"[!] ProjectDiscovery DB index error — skipping: {e}")
            else:
                print(
                    "[*] ProjectDiscovery: no programs loaded"
                    " (dist/data.json + src/data.yaml missing or unparseable)."
                )
    if pd_clone_failed:
        platform_status["pd_programs"] = {
            "status": "clone_failed",
            "count": 0,
            "source": "pd-repo",
            "note": pd_clone_failed,
        }
    else:
        platform_status["pd_programs"] = _platform_status(
            pd_attempted, pd_programs_list, "pd-repo"
        )

    # 9. Public listing platforms (live fetch, soft-fail; Hats/Federacy excluded)
    _listing_specs = (
        ("bugbase", "Bugbase", _fetch_bugbase_programs),
        ("hackenproof", "HackenProof", _fetch_hackenproof_programs),
        ("cantina", "Cantina", _fetch_cantina_programs),
        ("patchstack", "Patchstack", _fetch_patchstack_programs),
        ("huntr", "Huntr", _fetch_huntr_programs),
        ("sherlock", "Sherlock", _fetch_sherlock_bounties),
    )
    for _cfg_key, _label, _fetcher in _listing_specs:
        _attempted = bool(refresh and platforms_cfg.get(_cfg_key, True))
        _data = []
        _seen_count = None
        if _attempted:
            print(f"[*] Fetching {_label} programs (public listing)...")
            _data = _fetcher()
            if _data:
                with conn:
                    _seen_count = _sync_listing_programs(cur, _label, _data, now_ts)
                print(f"[+] {_label} indexed: {_seen_count} programs.")
            else:
                print(f"[*] {_label}: no listing data returned.")
        platform_status[_cfg_key if _cfg_key != "sherlock" else "sherlock_bounties"] = (
            _platform_status(_attempted, _data, "live-listing", count=_seen_count)
        )

    codehawks_contests = []
    codehawks_attempted = bool(refresh and platforms_cfg.get("codehawks", True))
    if codehawks_attempted:
        print("[*] Fetching CodeHawks contests (public listing)...")
        codehawks_contests = _fetch_codehawks_contests()
        if codehawks_contests:
            with conn:
                _sync_listing_contests(cur, "CodeHawks", codehawks_contests, now_ts)
            print(f"[+] CodeHawks indexed: {len(codehawks_contests)} contests.")
    platform_status["codehawks"] = _platform_status(
        codehawks_attempted, codehawks_contests, "live-listing"
    )


    for _plat, _st in ingest_stats.items():
        if _plat in platform_status and _st.get("rejected"):
            platform_status[_plat]["rejected_assets"] = _st["rejected"]
    # Preserve pre-fix last_sync_ts as last_successful_sync_ts before an offline
    # run overwrites last_sync_ts, so offline syncs never reset feed age (#9).
    if not refresh:
        prev_succ = cur.execute(
            "SELECT value FROM sync_metadata WHERE key='last_successful_sync_ts'"
        ).fetchone()
        prev_sync = cur.execute(
            "SELECT value FROM sync_metadata WHERE key='last_sync_ts'"
        ).fetchone()
        prev_ok = cur.execute(
            "SELECT value FROM sync_metadata WHERE key='last_refresh_ok'"
        ).fetchone()
        if (
            prev_succ is None
            and prev_sync is not None
            and (prev_ok is None or prev_ok[0] != "0")
        ):
            _set_meta(cur, "last_successful_sync_ts", str(prev_sync[0]))
        elif prev_succ is None and prev_sync is None:
            _set_meta(cur, "last_sync_ts_offline_only", "1")
    _set_meta(cur, "upstream_sha", upstream_sha)
    _set_meta(cur, "last_sync_ts", str(now_ts))
    _set_meta(cur, "last_refresh_ok", "1" if refresh_ok else "0")
    # Feed-age anchor: only a real, successful network refresh counts. Offline
    # imports (refresh=False) and failed fetches must not reset feed age (#9).
    if refresh and refresh_ok:
        _set_meta(cur, "last_successful_sync_ts", str(now_ts))
        _set_meta(cur, "last_sync_ts_offline_only", "0")
    if refresh_error:
        _set_meta(cur, "last_refresh_error", refresh_error)
    _set_meta(cur, "platform_status", json.dumps(platform_status, sort_keys=True))

    if is_baseline_sync:
        cur.execute("UPDATE programs SET first_seen_timestamp=0")
        cur.execute("UPDATE assets SET first_seen_timestamp=0")
        cur.execute("UPDATE contests SET first_seen_timestamp=0")
        cur.execute(
            "INSERT INTO sync_metadata(key, value) VALUES('baseline_complete', ?) ",
            (str(now_ts),),
        )
        print("[*] Initial feed baseline recorded; current entries are not marked new.")
    conn.commit()

    total_progs = cur.execute(
        "SELECT count(*) FROM programs WHERE COALESCE(deleted_timestamp, 0)=0"
    ).fetchone()[0]
    total_assets = cur.execute(
        "SELECT count(*) FROM assets WHERE deleted_timestamp=0"
    ).fetchone()[0]
    total_wild = cur.execute(
        "SELECT count(*) FROM assets WHERE is_wildcard=1 AND deleted_timestamp=0"
    ).fetchone()[0]
    total_tombstoned = cur.execute(
        "SELECT count(*) FROM assets WHERE deleted_timestamp!=0"
    ).fetchone()[0]
    print(
        f"\n[✓] Scan4Me Sync Complete: {total_progs} programs, {total_assets} assets"
        f" ({total_wild} wildcards, {total_tombstoned} tombstoned)."
    )
    total_contests = cur.execute("SELECT count(*) FROM contests").fetchone()[0]
    if total_contests:
        print(
            f"[*] Sherlock contests tracked separately: {total_contests} (not counted as programs)."
        )


def cmd_enrich(args):
    limit = getattr(args, "limit", 10)
    if limit is None:
        limit = 10
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"--limit must be an int >= 0, got {limit!r}")
    if limit > 9223372036854775807:
        raise ValueError("--limit exceeds SQLite INTEGER range")
    conn = get_db()
    ensure_schema(conn)
    cur = conn.cursor()
    if args.handle:
        programs = cur.execute(
            """SELECT id, handle, name FROM programs
               WHERE platform='Bugcrowd' AND handle=?""",
            (args.handle,),
        ).fetchall()
        if not programs:
            raise ValueError(f"No Bugcrowd program found for handle {args.handle!r}")
    else:
        programs = cur.execute(
            """SELECT id, handle, name FROM programs
               WHERE platform='Bugcrowd'
               ORDER BY max_payout DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    for index, program in enumerate(programs):
        try:
            result = enrich_bugcrowd_program(conn, program["id"], program["handle"])
        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            ValueError,
        ) as error:
            print(
                f"[!] {program['name']}: public Bugcrowd metadata unavailable: {error}"
            )
            continue
        start = (
            datetime.fromtimestamp(result["program_start"]).date()
            if result["program_start"]
            else "unknown"
        )
        print(
            f"[+] {program['name']}: started {start}; "
            f"{result['scope_versions']} scope versions; "
            f"{result['assets_with_official_dates']} assets dated; "
            f"{result['rewarded_vulnerabilities']} rewarded; "
            f"{result['validation_days']} validation days; "
            f"average payout ${result['average_payout']}"
        )
        if args.delay and index + 1 < len(programs):
            time.sleep(args.delay)


def score_payout_velocity(prog):
    """Expected payout-per-triage-hour rank for a scored program dict.

    Returns ``(payout_per_hour_usd_or_None, velocity_score_0_100, estimated)``.

    Method (documented heuristic, not calibrated economics):
      expected payout = average_payout when published, else 5% of the max
      ceiling as a severity-discounted proxy (most reports pay far under max);
      triage hours = first_response_hours when known, else validation_days*24.
      payout/hour = expected / triage_hours; the 0-100 score is
      20*log10(pph+1) so $10/h ≈ 21, $100/h ≈ 40, $1000/h ≈ 60.
    When payout or triage time is unknown there is no honest $/h number:
    pph is None and the score falls back to (payout+speed)/4, flagged
    estimated=True so callers can sort measured ranks above guesses.
    """
    import math

    avg_p = prog.get("average_payout") or 0
    max_p = prog.get("max_payout") or 0
    if avg_p > 0:
        expected = float(avg_p)
    elif max_p > 0:
        expected = float(max_p) * 0.05
    else:
        expected = 0.0
    triage_hours = None
    if prog.get("first_resp") is not None:
        try:
            triage_hours = float(prog["first_resp"])
        except (TypeError, ValueError):
            triage_hours = None
    if triage_hours is None and prog.get("validation_days") is not None:
        try:
            triage_hours = float(prog["validation_days"]) * 24.0
        except (TypeError, ValueError):
            triage_hours = None
    if expected > 0 and triage_hours is not None and triage_hours > 0:
        pph = expected / triage_hours
        score = round(min(100.0, max(0.0, 20.0 * math.log10(pph + 1.0))), 1)
        return round(pph, 2), score, False
    fallback = round(
        ((prog.get("payout_score") or 0) + (prog.get("speed_score") or 0)) / 4.0, 1
    )
    return None, fallback, True


def evaluate_targets(config=None):
    if config is None:
        config = load_config()
    if not isinstance(config, dict):
        config = {}
    conn = get_db()
    # No ensure_schema here: this library function is query-count-tested and
    # already hard-references migrated columns (official_first_seen_timestamp).
    # Callers on a stale DB must sync (which migrates) first.
    cur = conn.cursor()

    filters = config.get("filters")
    if not isinstance(filters, dict):
        filters = {}

    def _subdict(parent, key):
        value = parent.get(key) if isinstance(parent, dict) else None
        return value if isinstance(value, dict) else {}

    fast_triage = _subdict(filters, "fast_triage")
    surface_cfg = _subdict(filters, "attack_surface_and_scope")
    fresh_cfg = _subdict(filters, "freshness_and_competition")
    payout_cfg = _subdict(filters, "payouts")
    plat_cfg = _subdict(config, "platforms")
    _weights_raw = config.get(
        "ranking_weights",
        {
            "payout_size": 0.35,
            "attack_surface_size": 0.30,
            "freshness_and_low_saturation": 0.20,
            "triage_speed": 0.15,
        },
    )
    weights = _weights_raw if isinstance(_weights_raw, dict) else {}

    _kind_raw = filters.get("program_kind", {"web2": True, "web3": True})
    kind_cfg = _kind_raw if isinstance(_kind_raw, dict) else {}
    allowed_kinds = [k for k, v in kind_cfg.items() if v]

    enabled_plats = [p for p, enabled in plat_cfg.items() if enabled]
    plat_map = {
        "hackerone": "HackerOne",
        "bugcrowd": "Bugcrowd",
        "intigriti": "Intigriti",
        "yeswehack": "YesWeHack",
        "federacy": "Federacy",
        "immunefi": "Immunefi",
        # Sherlock bug bounties are programs (sherlock-bb-* handles);
        # legacy contest handles in programs are excluded in the loop below.
        "sherlock": "Sherlock",
        "pd_programs": "PDPrograms",
        "bugbase": "Bugbase",
        "hackenproof": "HackenProof",
        "cantina": "Cantina",
        "patchstack": "Patchstack",
        "huntr": "Huntr",
    }
    target_plats = [plat_map[p] for p in enabled_plats if p in plat_map]
    if not target_plats:
        return []

    plat_holders = ",".join("?" * len(target_plats))
    # ?-holders only; values stay bound parameters (B608 false positive).
    query = (
        "SELECT p.*, count(a.id) as asset_count, sum(a.is_wildcard) as wildcard_count "  # nosec B608
        "FROM programs p "
        "LEFT JOIN assets a ON p.id = a.program_id "
        "AND a.deleted_timestamp=0 AND a.eligible_for_submission=1 "
        "WHERE COALESCE(p.deleted_timestamp, 0)=0 AND p.platform IN ("
        + plat_holders + ")"
    )
    params = list(target_plats)

    if filters.get("paid_bounties_only", True):
        query += " AND p.offers_bounties = 1"

    # Filter by program kind (web2 / web3) when not both enabled
    if allowed_kinds and len(allowed_kinds) < 2:
        query += " AND p.program_kind IN ({})".format(
            ",".join("?" * len(allowed_kinds))
        )
        params.extend(allowed_kinds)

    # prefer_new_companies: Bugcrowd uses official_start_timestamp; all other platforms
    # use first_seen_timestamp as a universal feed-observation proxy.
    # This is a SCORING signal, not a hard gate — the SQL here only applies the cutoff
    # when strict_new_companies is explicitly true.
    if fresh_cfg.get("strict_new_companies", False):
        new_company_days = fresh_cfg.get("new_company_days", 90)
        cutoff_ts = int(time.time()) - (new_company_days * 86400)
        # STRICT means require Bugcrowd with a recent OFFICIAL start date. Feed
        # first-seen ("observation") dates on other platforms are only a guess at
        # newness and stay a SCORING signal — they must not satisfy a strict gate
        # or non-Bugcrowd programs would slip through as "new" (#7).
        query += (
            " AND p.platform='Bugcrowd'"
            " AND p.official_start_timestamp IS NOT NULL"
            " AND p.official_start_timestamp > ?"
        )
        params.append(cutoff_ts)

    query += " GROUP BY p.id"
    rows = cur.execute(query, params).fetchall()

    now_ts = int(time.time())
    scored_programs = []
    max_first_resp = fast_triage.get("max_first_response_hours", 48.0)
    min_efficiency = fast_triage.get("min_response_efficiency_pct", 80.0)
    wildcard_mult = surface_cfg.get("wildcard_multiplier", 2.5)
    if not surface_cfg.get("prioritize_wildcards", True):
        wildcard_mult = 1.0
    min_max_payout = payout_cfg.get("min_max_payout_usd")
    fast_cash = payout_cfg.get("prioritize_fast_cash", True)
    prefer_large_surface = surface_cfg.get("prefer_large_attack_surface", True)
    prefer_fresh = fresh_cfg.get("prefer_fresh_programs", True)
    low_saturation = fresh_cfg.get("low_report_saturation", True)
    prefer_managed = fast_triage.get("prefer_managed_triage", False)
    award_tier2 = fast_triage.get("max_time_to_bounty_awarded_hours", 336.0) or 336.0
    award_tier1 = award_tier2 / 2.0
    new_asset_days = fresh_cfg.get("new_asset_days", 30)
    new_company_days_score = fresh_cfg.get("new_company_days", 90)
    new_asset_cutoff = now_ts - (new_asset_days * 86400)
    new_company_cutoff = now_ts - (new_company_days_score * 86400)

    # P6: batch the new-asset signals (one GROUP BY each) instead of one query
    # per program. Counts are identical to the former per-program loop.
    new_asset_counts = {}
    enriched_program_ids = set()
    if fresh_cfg.get("prefer_new_assets", False) and rows:
        batched_ids = [r["id"] for r in rows]
        batched_holders = ",".join("?" * len(batched_ids))
        # ?-holders only; values stay bound parameters (B608 false positive).
        for program_id, cnt in cur.execute(
            "SELECT program_id, count(*) FROM assets WHERE program_id IN ("  # nosec B608
            + batched_holders
            + ") AND deleted_timestamp=0 AND ("
            "(official_first_seen_timestamp IS NOT NULL"
            " AND official_first_seen_timestamp > ?)"
            " OR (official_first_seen_timestamp IS NULL"
            " AND first_seen_timestamp > ?)"
            ") GROUP BY program_id",
            (*batched_ids, new_asset_cutoff, new_asset_cutoff),
        ).fetchall():
            new_asset_counts[program_id] = cnt
        if fresh_cfg.get("strict_new_assets", False):
            for (enriched_id,) in cur.execute(
                "SELECT DISTINCT program_id FROM assets WHERE program_id IN ("  # nosec B608
                + batched_holders
                + ") AND deleted_timestamp=0"
                " AND official_first_seen_timestamp IS NOT NULL",
                batched_ids,
            ).fetchall():
                enriched_program_ids.add(enriched_id)

    for r in rows:
        # ── Triage speed hard filters (HackerOne only — only platform with the data) ──
        if fast_triage.get("enabled", True) and r["platform"] == "HackerOne":
            if (
                r["first_response_hours"] is not None
                and r["first_response_hours"] > max_first_resp
            ):
                continue
            if (
                r["response_efficiency"] is not None
                and r["response_efficiency"] < min_efficiency
            ):
                continue

        # require_measured_response_time: hard gate — only passes HackerOne programs with
        # response data or Bugcrowd programs with published validation_days.
        if (
            fast_triage.get("enabled", True)
            and fast_triage.get("require_measured_response_time", False)
            and r["first_response_hours"] is None
            and not (r["platform"] == "Bugcrowd" and r["validation_days"] is not None)
        ):
            continue

        # max_validation_days: only hard-gate Bugcrowd programs that have the data.
        # Non-Bugcrowd platforms (no validation_days field) always pass through.
        max_validation_days = fast_triage.get("max_validation_days")
        if max_validation_days is not None and r["platform"] == "Bugcrowd":
            if (
                r["validation_days"] is not None
                and r["validation_days"] > max_validation_days
            ):
                continue
            # Bugcrowd programs without enrichment data pass through (data unknown ≠ slow)
        # strict_validation_days: Bugcrowd programs WITHOUT the data are out.
        if (
            fast_triage.get("strict_validation_days", False)
            and r["platform"] == "Bugcrowd"
            and r["validation_days"] is None
        ):
            continue

        # min_max_payout_usd: drop programs whose KNOWN ceiling is below the
        # floor. Unknown ceilings (max_payout NULL/0, e.g. all of HackerOne)
        # pass through — unknown ≠ cheap.
        if min_max_payout is not None:
            _ceiling = _to_usd(r["max_payout"], r["currency"])
            if _ceiling > 0 and _ceiling < min_max_payout:
                continue

        # max_rewarded_vulnerabilities: only hard-gate Bugcrowd programs with the data.
        # Non-Bugcrowd platforms always pass through (incomparable metric).
        max_rewarded = fresh_cfg.get("max_rewarded_vulnerabilities")
        if max_rewarded is not None and r["platform"] == "Bugcrowd":
            if (
                r["rewarded_vulnerabilities"] is not None
                and r["rewarded_vulnerabilities"] > max_rewarded
            ):
                continue

        asset_count = r["asset_count"] or 0
        wild_count = r["wildcard_count"] or 0

        # Scope filters: Web3 / Immunefi targets don't store DNS assets in assets table
        r_cols = set(r.keys())
        p_kind = r["program_kind"] if "program_kind" in r_cols else "web2"
        p_plat = r["platform"] if "platform" in r_cols else ""
        is_web3 = bool(p_kind == "web3" or p_plat in ("Immunefi", "Sherlock"))
        is_listing_only = p_plat in LISTING_ONLY_PLATFORMS
        if p_plat == "Sherlock" and not str(
            r["handle"] if "handle" in r_cols else ""
        ).startswith("sherlock-bb-"):
            continue  # legacy contest residue, not a bug-bounty program
        if (
            not is_web3
            and not is_listing_only
            and asset_count < surface_cfg.get("min_in_scope_assets", 1)
        ):
            continue

        # New assets: count official Bugcrowd-dated scope changes; for other platforms
        # fall back to counting assets first-seen within the window from the feed.
        # This is a SCORING signal — programs with no new assets still appear but score lower.
        new_assets_count = 0
        if fresh_cfg.get("prefer_new_assets", False):
            new_assets_count = new_asset_counts.get(r["id"], 0)
            # STRICT means a program must have OFFICIAL evidence of new scope:
            # Bugcrowd, enriched, with new assets dated in-window. Non-Bugcrowd
            # programs and undated/un-enriched Bugcrowd ones are observation-only
            # guesses, so strict mode excludes them rather than admitting them with
            # zero proven new scope (#7). Observation newness stays scoring-only.
            if fresh_cfg.get("strict_new_assets", False) and not (
                r["platform"] == "Bugcrowd"
                and r["id"] in enriched_program_ids
                and new_assets_count > 0
            ):
                continue

        # 1. Triage Speed Score (0-100)
        # HackerOne: first_response_hours drives the base (lower = faster = higher score).
        # Bonus tiers come from max_time_to_bounty_awarded_hours (default 336h:
        # <=168h = +15 pts; <=336h = +8 pts); gated by prioritize_fast_cash.
        # Bugcrowd: validation_days <= 7 = +20 pts; <= 14 = +10 pts (fast-cash proxy).
        # Managed triage earns SLA baseline (70.0) when unmeasured or +5 when measured.
        # No published measurement is LOW-CONFIDENCE 30, not a neutral 50:
        # unknown must never outrank a measured-average program on a guess.
        speed_score = float(fast_triage.get("unmeasured_speed_score", 30.0))
        has_speed_telemetry = False
        if r["platform"] == "HackerOne":
            if r["first_response_hours"] is not None:
                has_speed_telemetry = True
                speed_score = max(0, 100 - (r["first_response_hours"] * 1.5))
            if fast_cash and r["bounty_awarded_hours"] is not None:
                if r["bounty_awarded_hours"] <= award_tier1:
                    speed_score = min(100.0, speed_score + 15)
                elif r["bounty_awarded_hours"] <= award_tier2:
                    speed_score = min(100.0, speed_score + 8)
        elif (
            fast_cash
            and r["platform"] == "Bugcrowd"
            and r["validation_days"] is not None
        ):
            has_speed_telemetry = True
            # A published validation time IS a measurement: start from the
            # measured-neutral 50, not the unknown 30.
            speed_score = 50.0
            if r["validation_days"] <= 7:
                speed_score = min(100.0, speed_score + 20)
            elif r["validation_days"] <= 14:
                speed_score = min(100.0, speed_score + 10)
        elif is_web3:
            has_speed_telemetry = True
            speed_score = 65.0

        # Fast triage proxy across all sites without login:
        # Managed programs have dedicated triage teams with contractual 24-48h SLAs.
        # When unmeasured, managed status elevates triage speed to SLA baseline (70.0).
        if "managed_triage" in r_cols and r["managed_triage"]:
            if not has_speed_telemetry and prefer_managed:
                managed_baseline = float(fast_triage.get("managed_triage_baseline", 70.0))
                speed_score = max(speed_score, managed_baseline)
            elif prefer_managed:
                speed_score = min(100.0, speed_score + 5)
        speed_score = min(100.0, speed_score)

        # 2. Attack Surface Score (0-100) - "More Assets is Better, More Surface Area"
        # Concrete hosts count 1 each; wildcards count wildcard_mult each.
        # (Wildcards are already inside asset_count, so adding wild*mult on
        # top of the raw count would double-count them.)
        # prefer_large_attack_surface=False flattens every program to neutral 50.
        if not prefer_large_surface:
            surface_score = 50.0
        elif (is_web3 or is_listing_only) and asset_count == 0:
            surface_score = 50.0
        else:
            effective_surface = (asset_count - wild_count) + (
                wild_count * wildcard_mult
            )
            if effective_surface >= 40:
                surface_score = 100.0
            elif effective_surface >= 20:
                surface_score = 85.0
            elif effective_surface >= 10:
                surface_score = 70.0
            elif effective_surface >= 5:
                surface_score = 50.0
            else:
                surface_score = 25.0

        # Tier labeling
        if wild_count >= 10 or asset_count >= 30:
            surface_tier = "🔥 MASSIVE SURFACE"
        elif wild_count >= 3 or asset_count >= 10:
            surface_tier = "⚡ WIDE SURFACE"
        elif wild_count >= 1 or asset_count >= 3:
            surface_tier = "🎯 MODERATE"
        else:
            surface_tier = "🔍 NARROW/FOCUSED"

        # 3. Freshness / Competition Score (0-100)
        # Priority: Bugcrowd official_start_timestamp → feed first_seen_timestamp → default 50.
        # Bonuses for:
        #   - program appears new (within new_company_days window)
        #   - has new scope assets (within new_asset_days window)
        #   - Bugcrowd: low rewarded_vulnerabilities (low competition proxy)
        #   - Bugcrowd: low validation_days (fast cash signal, also in speed but echoed here)
        effective_start_ts = (
            r["official_start_timestamp"] or r["first_seen_timestamp"] or 0
        )
        if effective_start_ts <= 0:
            # Unknown age is low-confidence, not neutral.
            fresh_score = 25.0
        elif effective_start_ts > new_company_cutoff:
            fresh_score = 100.0
        else:
            # Known-old programs are stale for freshness purposes; a small
            # bump only when the feed first observed them recently.
            first_seen_ts = r["first_seen_timestamp"] or 0
            if first_seen_ts > now_ts - 90 * 86400:
                fresh_score = 65.0
            else:
                fresh_score = 25.0

        # Freshness bonuses apply only when prefer_fresh_programs is set;
        # the low-competition proxy is additionally gated by low_report_saturation.
        if prefer_fresh:
            # Bonus: program has recently-added in-scope assets (new attack surface)
            if new_assets_count > 0:
                fresh_score = min(100.0, fresh_score + 15)

            # Bonus: prefer_new_companies signal — any platform where we can see it's new
            if (
                fresh_cfg.get("prefer_new_companies", False)
                and effective_start_ts > new_company_cutoff
            ):
                fresh_score = min(100.0, fresh_score + 10)

            # Bonus: low competition (Bugcrowd rewarded_vulnerabilities as proxy)
            rewarded = r["rewarded_vulnerabilities"]
            if low_saturation and rewarded is not None:
                if rewarded <= 25:
                    fresh_score = min(100.0, fresh_score + 20)
                elif rewarded <= 75:
                    fresh_score = min(100.0, fresh_score + 12)
                elif rewarded <= 150:
                    fresh_score = min(100.0, fresh_score + 5)

        # 4. Payout Score (0-100)
        # Base from max_payout band. Bugcrowd average_payout adds a real-money bonus
        # when it confirms high actual payouts even on modest max_payout ceilings.
        payout_score = 50.0
        # Bands are USD: convert first (raw EUR/GBP numbers misrank).
        max_p = _to_usd(r["max_payout"], r["currency"])
        if max_p > 0:
            if max_p >= 100000:
                payout_score = 100.0
            elif max_p >= 20000:
                payout_score = 85.0
            elif max_p >= 5000:
                payout_score = 70.0
            else:
                payout_score = 55.0
        elif r["offers_bounties"]:
            # Paid but unknown ceiling: low-confidence 30, below any known
            # ceiling (even a small known one earns 55).
            payout_score = 30.0
        avg_p = _to_usd(r["average_payout"], r["currency"])
        if fast_cash:
            if avg_p >= 2000:
                payout_score = min(100.0, payout_score + 10)
            elif avg_p >= 500:
                payout_score = min(100.0, payout_score + 5)

        # Composite Fast-Money & Surface Area Score
        total_score = (
            (speed_score * weights["triage_speed"])
            + (surface_score * weights["attack_surface_size"])
            + (fresh_score * weights["freshness_and_low_saturation"])
            + (payout_score * weights["payout_size"])
        )

        _pph, _velocity, _vest = score_payout_velocity(
            {
                "average_payout": r["average_payout"],
                "max_payout": r["max_payout"],
                "first_resp": r["first_response_hours"],
                "validation_days": r["validation_days"],
                "payout_score": payout_score,
                "speed_score": speed_score,
            }
        )

        scored_programs.append(
            {
                "name": r["name"],
                "platform": r["platform"],
                "url": r["url"],
                "website": r["website"],
                "safe_harbor": r["safe_harbor"] or "Standard",
                "score": round(total_score, 1),
                "speed_score": round(speed_score, 1),
                "surface_score": round(surface_score, 1),
                "fresh_score": round(fresh_score, 1),
                "payout_score": round(payout_score, 1),
                "surface_tier": surface_tier,
                "payout_per_hour_usd": _pph,
                "velocity_score": _velocity,
                "velocity_estimated": _vest,
                "max_payout": r["max_payout"],
                "currency": r["currency"],
                "first_resp": r["first_response_hours"],
                "efficiency": r["response_efficiency"],
                "managed": bool(r["managed_triage"]),
                "response_time_known": r["first_response_hours"] is not None,
                "report_resolved_hours": r["report_resolved_hours"],
                "official_start_ts": r["official_start_timestamp"],
                "official_scope_updated_ts": r["official_scope_updated_timestamp"],
                "rewarded_vulnerabilities": r["rewarded_vulnerabilities"],
                "validation_days": r["validation_days"],
                "average_payout": r["average_payout"],
                "assets": asset_count,
                "wildcards": wild_count,
                "new_assets": new_assets_count,
                "first_seen_ts": r["first_seen_timestamp"],
                "program_kind": (
                    r["program_kind"] if "program_kind" in r.keys() else None
                )
                or "web2",
                "id": r["id"],
            }
        )

    scored_programs.sort(key=lambda x: x["score"], reverse=True)
    return scored_programs


STALE_AFTER_HOURS = 48


def feed_provenance(conn=None):
    """Feed provenance stamp for radar/prescan/report artifacts (#5/#9).

    Returns upstream SHA + per-platform fetch status + live row counts +
    feed age + the explicit degraded-mode coverage gaps. Every claim is
    computed from sync_metadata and live tables — never asserted statically.
    Unknowns are reported as unknown, not as zeros.
    """
    own = conn is None
    if own:
        conn = get_db()
    try:
        cur = conn.cursor()
        try:
            meta = {
                r["key"]: r["value"]
                for r in cur.execute("SELECT key, value FROM sync_metadata").fetchall()
            }
        except Exception:
            meta = {}
        try:
            plat_status = json.loads(meta.get("platform_status", "{}") or "{}")
        except (TypeError, ValueError):
            plat_status = {}

        def _cols(table):
            try:
                return {r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()}
            except Exception:
                return set()

        _prog_cols = _cols("programs")
        _asset_cols = _cols("assets")
        _prog_live = (
            "COALESCE(deleted_timestamp, 0)=0"
            if "deleted_timestamp" in _prog_cols
            else "1=1"
        )
        _prog_live_p = (
            "COALESCE(p.deleted_timestamp, 0)=0"
            if "deleted_timestamp" in _prog_cols
            else "1=1"
        )
        _asset_live = (
            "deleted_timestamp=0" if "deleted_timestamp" in _asset_cols else "1=1"
        )
        _asset_live_a = (
            "a.deleted_timestamp=0" if "deleted_timestamp" in _asset_cols else "1=1"
        )
        # Validate all dynamically-built SQL fragments before concatenation.
        _validate_sql_fragment(_prog_live, "scan4me._prog_live")
        _validate_sql_fragment(_prog_live_p, "scan4me._prog_live_p")
        _validate_sql_fragment(_asset_live, "scan4me._asset_live")
        _validate_sql_fragment(_asset_live_a, "scan4me._asset_live_a")
        try:
            n_programs = cur.execute(
                "SELECT count(*) FROM programs WHERE " + _prog_live
            ).fetchone()[0]
        except Exception:
            n_programs = None
        try:
            n_assets = cur.execute(
                "SELECT count(*) FROM assets WHERE " + _asset_live
            ).fetchone()[0]
        except Exception:
            try:
                n_assets = cur.execute("SELECT count(*) FROM assets").fetchone()[0]
            except Exception:
                n_assets = None
        try:
            n_contests = cur.execute("SELECT count(*) FROM contests").fetchone()[0]
        except Exception:
            n_contests = None
        try:
            h1_total, h1_paid = cur.execute(
                "SELECT count(*), sum(CASE WHEN max_payout > 0 THEN 1 ELSE 0 END)"
                " FROM programs WHERE platform='HackerOne' AND " + _prog_live
            ).fetchone()
        except Exception:
            h1_total, h1_paid = None, None
        try:
            im_programs = cur.execute(
                "SELECT count(*) FROM programs WHERE platform='Immunefi' AND " + _prog_live
            ).fetchone()[0]
        except Exception:
            im_programs = None
        try:
            im_assets = cur.execute(
                "SELECT count(*) FROM assets a JOIN programs p ON a.program_id=p.id"
                " WHERE p.platform='Immunefi' AND " + _asset_live_a + " AND " + _prog_live_p
            ).fetchone()[0]
        except Exception:
            im_assets = None
    finally:
        if own:
            conn.close()

    now_ts = int(time.time())

    def _meta_int(key: str) -> int:
        try:
            return int(meta.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    sync_ts = _meta_int("last_sync_ts")
    # Feed age is measured from the last SUCCESSFUL network refresh, never from
    # the last time sync_data merely ran: an offline import or a failed fetch
    # stamps last_sync_ts=now but must not make a stale snapshot look fresh (#9).
    succ_ts = _meta_int("last_successful_sync_ts")
    if not succ_ts and meta.get("last_refresh_ok") != "0":
        # Pre-fix DB whose last run did not fail: fall back to last_sync_ts.
        succ_ts = sync_ts
    age_hours = round((now_ts - succ_ts) / 3600.0, 1) if succ_ts else None

    gaps = [
        # Structural: no feed carries rules/policy text, so Oracle's verify
        # leg 3 can only pass via downgrade-to-advisory, never via data.
        "rules/policy text: carried by no feed — verify leg 3 has no data leg"
    ]
    if h1_total:
        gaps.append(
            f"HackerOne payouts: {h1_paid or 0}/{h1_total} programs carry a"
            " ceiling — the rest cannot pass exact payout verification"
        )
    if im_programs is not None:
        gaps.append(
            f"Immunefi: {im_programs} programs, {im_assets or 0} scope rows"
            " (programs-only until detail-page scope fetch lands)"
        )
    for plat in sorted(plat_status):
        entry = plat_status[plat] or {}
        status = entry.get("status", "unknown")
        if status != "ok":
            gaps.append(
                f"platform {plat}: last sync status={status}"
                f" (rows={entry.get('count', 0)})"
            )
    return {
        "upstream_sha": meta.get("upstream_sha") or "unknown",
        "last_sync_ts": sync_ts or None,
        "last_successful_sync_ts": succ_ts or None,
        "age_hours": age_hours,
        "stale": age_hours is not None and age_hours > STALE_AFTER_HOURS,
        "refresh_ok": meta.get("last_refresh_ok") != "0",
        "platforms": plat_status,
        "row_counts": {
            "programs": n_programs,
            "live_assets": n_assets,
            "contests": n_contests,
        },
        "coverage_gaps": gaps,
    }


def cmd_filter(args, config):
    # Migrate the DB before ranking: evaluate_targets references migrated
    # columns and does not call ensure_schema itself (query-count contract),
    # so an older DB would raise mid-ranking without this.
    _schema_conn = get_db()
    ensure_schema(_schema_conn)
    _schema_conn.close()
    results = evaluate_targets(config)
    _cfg = config if isinstance(config, dict) else {}
    _display_cfg = _cfg.get("display")
    if not isinstance(_display_cfg, dict):
        _display_cfg = {}
    limit = (
        args.limit
        if getattr(args, "limit", None) is not None
        else _display_cfg.get("limit", 20)
    )
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"radar limit must be an int >= 0, got {limit!r}")
    _filters_cfg = _cfg.get("filters")
    if not isinstance(_filters_cfg, dict):
        _filters_cfg = {}
    fresh_cfg = _filters_cfg.get("freshness_and_competition", {})
    if not isinstance(fresh_cfg, dict):
        fresh_cfg = {}
    new_company_days = fresh_cfg.get("new_company_days", 90)
    new_asset_days = fresh_cfg.get("new_asset_days", 30)

    print("\n" + "=" * 88)
    print(
        "🔥 SCAN4ME PRECISION TARGET RADAR (FAST TRIAGE • MASSIVE ATTACK SURFACE • FAST CASH)"
    )
    print("=" * 88)
    _prov = feed_provenance()
    _counts = _prov["row_counts"]
    _age = (
        f"{_prov['age_hours']}h old"
        if _prov["age_hours"] is not None
        else "age unknown (never synced?)"
    )
    print(
        f"[*] Provenance: upstream={str(_prov['upstream_sha'])[:12]}"
        f" | {_age}"
        + (" [STALE]" if _prov["stale"] else "")
        + f" | programs={_counts['programs']} live_assets={_counts['live_assets']}"
        f" contests={_counts['contests']}"
    )
    _bad = sorted(
        p
        for p, e in (_prov["platforms"] or {}).items()
        if (e or {}).get("status", "unknown") != "ok"
    )
    if _bad:
        print(f"[!] Degraded feeds: {', '.join(_bad)} (see coverage gaps below)")
    for _gap in _prov["coverage_gaps"]:
        print(f"[!] Coverage gap: {_gap}")
    if fresh_cfg.get("prefer_new_companies"):
        print(
            "[*] New program filter uses Bugcrowd's published program start date; unsupported platforms are excluded."
        )
    if fresh_cfg.get("prefer_new_assets"):
        print(
            "[*] New asset filter uses Bugcrowd's dated scope history; unsupported/undated assets are excluded."
        )
    if fresh_cfg.get("low_report_saturation"):
        print(
            "[*] Low-saturation bonus uses Bugcrowd rewarded counts only; other"
            " platforms carry no resolved-report signal."
        )
    print(
        f"[*] Displaying Top {min(limit, len(results))} Target Companies (Ranked by Surface & Speed):\n"
    )

    conn = get_db()
    for i, p in enumerate(results[:limit], 1):
        if p["response_time_known"]:
            triage_info = f"{p['first_resp']}h avg first response (HackerOne feed)"
            if p["efficiency"] is not None:
                triage_info += f", {p['efficiency']}% efficiency"
        elif p["platform"] == "Bugcrowd" and p["validation_days"] is not None:
            triage_info = f"{p['validation_days']:g}d validation time (Bugcrowd)"
        elif p["managed"]:
            triage_info = "Managed triage (response time not published)"
        else:
            triage_info = "Response time not published"
        kind_badge = " 🌐 Web3" if p.get("program_kind") == "web3" else ""
        payout_str = (
            f"Max: {p['max_payout']:,.0f} {p['currency']}"
            if (p["max_payout"] and p["max_payout"] > 0)
            else "Paid BBP"
        )

        days_seen = (
            (int(time.time()) - p["official_start_ts"]) // 86400
            if p["official_start_ts"]
            else None
        )
        new_indicator = (
            " 🆕 NEW PROGRAM"
            if days_seen is not None and days_seen < new_company_days
            else ""
        )

        print(
            f"[{i:02d}] ★ SCORE: {p['score']}/100 | {p['surface_tier']}"
            f"{kind_badge} | [{p['platform']}] {p['name']}{new_indicator}"
        )
        print(f"     🏢 Company Info : Policy: {p['url']}")
        if p["website"]:
            print(f"                       Website: {p['website']}")
        print(f"     ⚡ Triage Speed  : {triage_info} | 💰 Payout: {payout_str}")
        print(
            f"     🌐 Surface Scope : {p['assets']} In-Scope Assets ({p['wildcards']} Wildcards)"
            f" | Harbor: {p['safe_harbor']}"
        )
        if p["official_start_ts"]:
            started = datetime.fromtimestamp(p["official_start_ts"]).date()
            print(f"     🗓️ Program Start : {started} (official Bugcrowd metadata)")
        if p["new_assets"] > 0:
            print(
                f"     ✨ New Assets   : {p['new_assets']} in scope changes within "
                f"{new_asset_days} days (Bugcrowd history)"
            )
        if p["report_resolved_hours"] is not None:
            print(
                f"     📊 Report Metric: {p['report_resolved_hours']}h avg resolution (not report count)"
            )
        if p["rewarded_vulnerabilities"] is not None:
            print(
                f"     📊 Competition  : {p['rewarded_vulnerabilities']}"
                f" rewarded vulnerabilities (Bugcrowd lifetime total)"
            )
        if p["average_payout"] is not None:
            print(
                f"     💵 Avg Payout   : ${p['average_payout']:,.2f} historically (Bugcrowd)"
            )
        if p["official_scope_updated_ts"]:
            changed = datetime.fromtimestamp(p["official_scope_updated_ts"]).date()
            print(f"     🗓️ Scope Update : {changed} (Bugcrowd published history)")

        if args.show_assets:
            cur = conn.cursor()
            wildcard_samples = cur.execute(
                "SELECT asset_identifier FROM assets WHERE program_id=?"
                " AND is_wildcard=1 AND deleted_timestamp=0 LIMIT 3",
                (p["id"],),
            ).fetchall()
            other_samples = cur.execute(
                "SELECT asset_identifier FROM assets WHERE program_id=?"
                " AND is_wildcard=0 AND deleted_timestamp=0 LIMIT 3",
                (p["id"],),
            ).fetchall()

            samples = [w[0] for w in wildcard_samples] + [o[0] for o in other_samples]
            if samples:
                print(f"     🔎 Target Sample : {', '.join(samples[:4])}")
        print("-" * 88)


def scope_match(target, asset_identifier, is_wildcard):
    """Fail-closed scope match: True only when target is provably in scope.

    The rule is canonicalized at match time (#4), so legacy verbatim rows
    (scheme-prefixed wildcards like 'http://*.x') match until the next sync
    rewrites them. Non-wildcard assets require an exact (case-insensitive)
    host match. '*.base' wildcards match proper subdomains of base only —
    never the apex itself and never lookalike suffixes ('evilexample.com'
    is NOT in scope). Glued wildcards ('*-prefix.host') match targets
    ending in the literal rest. Anything else returns False.
    """
    t = _strip_host(target)
    rule, _, rule_wild, ok = canonicalize_asset(
        asset_identifier, "wildcard" if is_wildcard else "url"
    )
    if not t or not ok or not rule:
        return False
    if not (is_wildcard or rule_wild):
        return t == rule
    if rule.startswith("*."):
        base = rule[2:]
        if not base or "*" in base:
            return False
        return t.endswith("." + base)
    if rule.startswith("*"):
        rest = rule[1:]
        if not rest or "*" in rest:
            return False
        if not t.endswith(rest):
            return False
        # Trio parity with Oracle's gate: '*' covers a single label
        # segment (no dots), never a multi-label prefix.
        head = t[: -len(rest)]
        return bool(head) and "." not in head
    return False


def _ip_matches_rule(target, rule_identifier) -> bool:
    """True when ``target`` is an IP address contained in ``rule_identifier``.

    ``rule_identifier`` may be a CIDR ('10.0.0.0/8') or a bare IP ('10.1.2.3').
    Used for out-of-scope exclusions: ``scope_match`` compares hosts as strings,
    so a CIDR exclusion would never catch an individual address inside it and
    that address would be wrongly reported as authorized. Returns False for any
    non-IP target or unparseable rule — it only ever adds an exclusion, never
    removes one.
    """
    try:
        ip = ipaddress.ip_address((target or "").strip())
    except ValueError:
        return False
    rule = (rule_identifier or "").strip()
    try:
        return ip in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        try:
            return ip == ipaddress.ip_address(rule)
        except ValueError:
            return False


def clean_asset_identifier(value):
    """Bare host for recon-tool piping: no scheme, path, port, or star."""
    host, _, _, ok = canonicalize_asset(value, "url")
    if ok and host and "*" not in host:
        return host
    # Wildcards / non-DNS: best-effort strip of scheme + star only.
    val = _strip_host(value)
    if val.startswith("*."):
        val = val[2:]
    elif val.startswith("*"):
        val = val[1:]
    return val.lstrip(".").rstrip("/")


def _program_identity_keys(name, handle, url):
    """Strong identity keys linking duplicate rows of one program.

    The same program can exist as a platform-native record and as a
    PDPrograms mirror row (different program_id, disjoint scope data).
    Two rows are duplicates when they share a normalized program URL,
    or the same normalized (name, handle) pair. A bare name collision
    alone never links rows.
    """
    keys = set()
    u = re.sub(r"^https?://", "", (url or "").strip().lower())
    if u.startswith("www."):
        u = u[4:]
    u = u.rstrip("/")
    if u:
        keys.add(("url", u))
    name_norm = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    handle_norm = (handle or "").strip().lower()
    if name_norm and handle_norm:
        keys.add(("namehandle", name_norm, handle_norm))
    return keys


def _sibling_program_ids(cur, program_id, cache=None):
    """All live duplicate program ids for program_id (including itself).

    Out-of-scope authority must union across duplicates: an exclusion
    recorded on the platform-native row has to defeat an in-scope
    asset on its PDPrograms mirror (G7 — the mirror has no OOS list).
    """
    if cache is not None and program_id in cache:
        return cache[program_id]
    row = cur.execute(
        "SELECT id, name, handle, url FROM programs WHERE id=?", (program_id,)
    ).fetchone()
    ids = {program_id}
    if row is not None:
        my_keys = _program_identity_keys(row["name"], row["handle"], row["url"])
        if my_keys:
            for other in cur.execute(
                "SELECT id, name, handle, url FROM programs "
                "WHERE COALESCE(deleted_timestamp, 0)=0 AND id<>?",
                (program_id,),
            ).fetchall():
                if _program_identity_keys(
                    other["name"], other["handle"], other["url"]
                ) & my_keys:
                    ids.add(other["id"])
    result = tuple(sorted(ids))
    if cache is not None:
        cache[program_id] = result
    return result


def cmd_check(args):
    conn = get_db()
    ensure_schema(conn)
    target = (args.domain or "").strip().lower()
    cur = conn.cursor()

    # Only submission-eligible assets can be authorized targets: an asset the
    # program will not accept reports on must not print as [AUTHORIZED IN-SCOPE].
    candidates = cur.execute(
        """
        SELECT p.id AS program_id, p.platform, p.name, p.url, p.website,
               p.offers_bounties, a.asset_identifier, a.is_wildcard
        FROM assets a
        JOIN programs p ON a.program_id = p.id
        WHERE a.deleted_timestamp=0 AND a.eligible_for_submission=1
          AND COALESCE(p.deleted_timestamp, 0)=0
          AND COALESCE(p.submission_state, 'open')='open'
    """
    ).fetchall()
    in_scope = [
        m
        for m in candidates
        if scope_match(target, m["asset_identifier"], m["is_wildcard"])
    ]

    # Live out-of-scope exclusions win over an in-scope wildcard: a target that
    # matches an explicit oos_assets rule for the same program is NOT authorized.
    # Exclusions union across duplicate rows of the program (G7): the
    # platform-native record's OOS list defeats its PDPrograms mirror.
    # Cache the verdict per program_id — several in-scope assets can belong to
    # one program, and the exclusion set is identical for all of them.
    oos_cache = {}
    sibling_cache = {}

    def _is_oos(program_id) -> bool:
        if program_id in oos_cache:
            return oos_cache[program_id]
        verdict = False
        sibling_ids = _sibling_program_ids(cur, program_id, sibling_cache)
        placeholders = ",".join("?" * len(sibling_ids))
        for row in cur.execute(
            "SELECT asset_identifier, is_wildcard FROM oos_assets "
            f"WHERE program_id IN ({placeholders}) AND deleted_timestamp=0",
            sibling_ids,
        ).fetchall():
            if scope_match(target, row["asset_identifier"], row["is_wildcard"]) or (
                _ip_matches_rule(target, row["asset_identifier"])
            ):
                verdict = True
                break
        oos_cache[program_id] = verdict
        return verdict

    # Keep the first ten authorized matches; stop scanning once we have them.
    matches = []
    for m in in_scope:
        if _is_oos(m["program_id"]):
            continue
        matches.append(m)
        if len(matches) >= 10:
            break

    if matches:
        print(
            f"\n✅ [AUTHORIZED IN-SCOPE] '{target}' matches {len(matches)} program(s):"
        )
        for m in matches:
            bbp = "Paid BBP" if m["offers_bounties"] else "VDP"
            wild = "(Wildcard Match)" if m["is_wildcard"] else "(Direct Match)"
            print(f"  • [{m['platform']}] {m['name']} ({bbp})")
            print(f"    Asset Rule  : {m['asset_identifier']} {wild}")
            print(f"    Policy URL  : {m['url']}")
            if m["website"]:
                print(f"    Company Web : {m['website']}")
        print()
    else:
        print(
            f"\n❌ [NOT IN KNOWN SCOPE] '{target}' was not found in active public program scopes."
        )
        print("   CAUTION: Do not probe without explicit authorization!\n")


def _export_blocked_by_oos(cur, program_id, identifier, is_wildcard, cache):
    """True when emitting this scope rule in a plain list could authorize an
    explicitly out-of-scope target.

    A plain list cannot express "in scope except X", so export fails closed:
    an exact OOS match, an asset contained in an OOS rule, and a wildcard
    asset *touched* by any OOS rule (partial carve) are all suppressed.
    Exclusions remain available with full fidelity through the DB API.
    """
    if program_id not in cache:
        # G7: exclusions union across duplicate rows of the program —
        # a mirror asset must not be emitted when the platform-native
        # duplicate lists it (or carves it) out of scope.
        sibling_ids = _sibling_program_ids(cur, program_id)
        placeholders = ",".join("?" * len(sibling_ids))
        cache[program_id] = cur.execute(
            "SELECT asset_identifier, is_wildcard FROM oos_assets "
            f"WHERE program_id IN ({placeholders}) AND deleted_timestamp=0",
            sibling_ids,
        ).fetchall()
    asset_rule, _, asset_wild, asset_ok = canonicalize_asset(
        identifier, "wildcard" if is_wildcard else "url"
    )
    if not asset_ok or not asset_rule:
        return True  # uncanonicalizable scope must not be emitted
    asset_is_wild = bool(is_wildcard or asset_wild)
    for row in cache[program_id]:
        oos_id, oos_wild_flag = row["asset_identifier"], row["is_wildcard"]
        oos_rule, _, oos_wild, oos_ok = canonicalize_asset(
            oos_id, "wildcard" if oos_wild_flag else "url"
        )
        if not oos_ok or not oos_rule:
            continue
        if asset_rule == oos_rule:
            return True
        # IP networks: any overlap between an exported CIDR and an OOS
        # network/address is a carve a plain list cannot express.
        try:
            _asset_net = ipaddress.ip_network(asset_rule, strict=False)
        except ValueError:
            _asset_net = None
        if _asset_net is not None:
            try:
                _oos_net = ipaddress.ip_network(oos_rule, strict=False)
            except ValueError:
                _oos_net = None
            if _oos_net is not None and _asset_net.overlaps(_oos_net):
                return True
        # Concrete exported asset contained in the OOS rule.
        if scope_match(identifier, oos_id, oos_wild_flag) or _ip_matches_rule(
            identifier, oos_id
        ):
            return True
        oos_is_wild = bool(oos_wild_flag or oos_wild)
        # Concrete OOS host inside the exported wildcard: partial carve.
        if asset_is_wild and not oos_is_wild and scope_match(
            oos_id, identifier, is_wildcard
        ):
            return True
        # Wildcard/wildcard overlap on suffix-related bases.
        if asset_is_wild and oos_is_wild:
            a_base = asset_rule.lstrip("*").lstrip(".")
            o_base = oos_rule.lstrip("*").lstrip(".")
            if (
                a_base == o_base
                or a_base.endswith("." + o_base)
                or o_base.endswith("." + a_base)
            ):
                return True
    return False


def cmd_export(args, config):
    # Migrate before ranking (see cmd_filter): evaluate_targets hits migrated
    # columns, so ensure_schema must run first on an older DB.
    conn = get_db()
    ensure_schema(conn)
    results = evaluate_targets(config)
    limit = args.top if getattr(args, "top", None) is not None else 30
    if limit < 0:
        raise ValueError("--top must be >= 0")
    target_ids = [p["id"] for p in results[:limit]]

    cur = conn.cursor()
    if not target_ids:
        return
    placeholders = ",".join("?" * len(target_ids))
    # Export only submission-eligible assets; for paid programs also require
    # bounty eligibility, so a bounty-ineligible asset never enters the paid
    # target list. VDP (offers_bounties=0) programs need only submission.
    sql = (
        "SELECT a.asset_identifier, a.program_id, a.is_wildcard FROM assets a"  # nosec B608
        " JOIN programs p ON a.program_id = p.id"
        " WHERE a.deleted_timestamp=0 AND a.eligible_for_submission=1"
        " AND COALESCE(p.deleted_timestamp, 0)=0"
        " AND (p.offers_bounties=0 OR a.eligible_for_bounty=1)"
        " AND a.program_id IN (" + placeholders + ")"
    )
    if args.wildcards_only:
        sql += " AND a.is_wildcard = 1"

    rows = cur.execute(sql, target_ids).fetchall()
    oos_cache = {}
    seen = set()
    for r in rows:
        val = r[0].strip()
        if val in seen:
            continue
        if _export_blocked_by_oos(cur, r[1], val, r[2], oos_cache):
            continue
        seen.add(val)
        if args.clean:
            val = clean_asset_identifier(val)
        print(val)


def cmd_handoff(args, config):
    """Generate Oracle P12 handoff file from prescan + scan reports."""
    import json
    from datetime import datetime, timezone
    from pathlib import Path

    HANDOFF_SCHEMA = "oracle.p12.handoff/v1"

    def _utc_now():
        return datetime.now(timezone.utc).isoformat()

    def _stamp():
        return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Load prescan report
    prescan_path = Path(args.prescan_file)
    if not prescan_path.exists():
        raise FileNotFoundError(f"Prescan file not found: {prescan_path}")
    with prescan_path.open(encoding="utf-8") as f:
        prescan = json.load(f)

    # Load scan report
    scan_path = Path(args.scan_file)
    if not scan_path.exists():
        raise FileNotFoundError(f"Scan file not found: {scan_path}")
    with scan_path.open(encoding="utf-8") as f:
        scan = json.load(f)

    # Extract triage config from config (used for prescan)
    filters = config.get("filters", {})
    fast_triage = filters.get("fast_triage", {})
    surface_cfg = filters.get("attack_surface_and_scope", {})
    fresh_cfg = filters.get("freshness_and_competition", {})
    payout_cfg = filters.get("payouts", {})
    kind_cfg = filters.get("program_kind", {"web2": True, "web3": True})
    plat_cfg = config.get("platforms", {})
    ranking_weights = config.get("ranking_weights", {})

    # Build triage_config object for handoff
    triage_config = {
        "source": "triage.yaml",
        "payout_floor_usd": payout_cfg.get("min_max_payout_usd"),
        "fast_triage_enabled": fast_triage.get("enabled", True),
        "max_first_response_hours": fast_triage.get("max_first_response_hours"),
        "min_response_efficiency_pct": fast_triage.get("min_response_efficiency_pct"),
        "min_in_scope_assets": surface_cfg.get("min_in_scope_assets"),
        "wildcard_multiplier": surface_cfg.get("wildcard_multiplier"),
        "prefer_new_assets": fresh_cfg.get("prefer_new_assets", False),
        "new_asset_days": fresh_cfg.get("new_asset_days"),
        "prefer_new_companies": fresh_cfg.get("prefer_new_companies", False),
        "new_company_days": fresh_cfg.get("new_company_days"),
        "max_rewarded_vulnerabilities": fresh_cfg.get("max_rewarded_vulnerabilities"),
        "ranking_weights": ranking_weights,
    }

    # Get feed provenance
    feed_prov = feed_provenance()

    # Process verified programs from scan
    verdicts = scan.get("verdicts", [])
    verified = [v for v in verdicts if v.get("verdict") == "verified"]

    # Sort by score descending
    verified.sort(key=lambda v: (v.get("score", 0) or 0), reverse=True)

    # Apply --sites filter if provided
    sites = [s.strip() for s in (args.sites or []) if s and s.strip()]
    excluded_named = []

    if sites:
        # Match sites against verified programs
        picked = []
        for site in sites:
            match = next((v for v in verified if _matches_site(v, site)), None)
            if match is not None:
                if match not in picked:
                    picked.append(match)
                continue
            # No verified hit: check if there's an unverified match
            unverified_hit = next(
                (v for v in verdicts if v.get("verdict") != "verified" and _matches_site(v, site)),
                None,
            )
            if unverified_hit is not None:
                excluded_named.append({
                    "site": site,
                    "reason": f"program not verified (verdict={unverified_hit.get('verdict', 'unknown')})",
                })
            else:
                excluded_named.append({
                    "site": site,
                    "reason": "no such program in scan",
                })
        verified = picked
    elif args.top_n is not None:
        verified = verified[:args.top_n]

    # Build ranked_verified entries with deep_dive
    ranked_verified = []
    for rank, v in enumerate(verified, 1):
        # Find the original prescan program snapshot for additional fields
        prescan_prog = next(
            (p for p in prescan.get("programs", []) if p.get("handle") == v.get("handle") or p.get("name") == v.get("name")),
            {}
        )

        # Build deep_dive object
        scopes = v.get("structured_scopes", []) or []
        company = {
            "name": v.get("name", ""),
            "handle": v.get("handle", ""),
            "platform": v.get("platform", ""),
            "url": v.get("url", ""),
            "website": v.get("website", "") or "",
            "offers_bounties": v.get("offers_bounties", False),
            "managed_program": v.get("managed_triage", False),
            "first_response_hours": v.get("first_response_hours"),
            "bounty_awarded_hours": v.get("bounty_awarded_hours"),
            "report_resolved_hours": v.get("report_resolved_hours"),
            "response_efficiency": v.get("response_efficiency"),
            "rewarded_vulnerabilities": v.get("rewarded_vulnerabilities"),
            "validation_days": v.get("validation_days"),
            "average_payout": v.get("average_payout"),
            "program_kind": v.get("program_kind", "web2"),
            "official_start_timestamp": v.get("official_start_timestamp"),
            "official_scope_updated_timestamp": v.get("official_scope_updated_timestamp"),
            "safe_harbor": v.get("safe_harbor", "Standard"),
        }

        # Build assets list with full detail from DB
        conn = get_db()
        ensure_schema(conn)
        cur = conn.cursor()
        prog_id = v.get("id")
        assets = []
        if prog_id:
            cur.execute(
                """SELECT asset_identifier, asset_type, is_wildcard, eligible_for_bounty,
                          eligible_for_submission, instruction, max_severity, first_seen_timestamp
                   FROM assets WHERE program_id=? AND deleted_timestamp=0""",
                (prog_id,),
            )
            for row in cur.fetchall():
                assets.append({
                    "identifier": row[0],
                    "type": row[1],
                    "is_wildcard": bool(row[2]),
                    "eligible_for_bounty": bool(row[3]),
                    "eligible_for_submission": bool(row[4]),
                    "instruction": row[5] or "",
                    "max_severity": row[6] or "",
                    "first_seen_ts": row[7],
                })
        conn.close()

        deep_dive = {
            "assets": assets,
            "company": company,
            "resources": {
                "program_url": v.get("url", ""),
                "platform": v.get("platform", ""),
                "max_payout_usd": _to_usd(v.get("max_payout"), v.get("currency")),
                "currency": v.get("currency", "USD"),
                "scope_count": len(scopes),
            },
            "sources": ["scan4me:programs+assets"],
            "checks": v.get("checks", {}),
        }

        ranked_verified.append({
            "rank": rank,
            "name": v.get("name", ""),
            "handle": v.get("handle", ""),
            "platform": v.get("platform", ""),
            "url": v.get("url", ""),
            "score": v.get("score", 0),
            "max_payout_usd": _to_usd(v.get("max_payout"), v.get("currency")),
            "currency": v.get("currency", "USD"),
            "verdict": "verified",
            "checks": v.get("checks", {}),
            "deep_dive": deep_dive,
        })

    # Build handoff payload
    payload = {
        "_schema": HANDOFF_SCHEMA,
        "created_utc": _utc_now(),
        "prescan_report": str(prescan_path),
        "scan_report": str(scan_path),
        "no_cloud": args.no_cloud,
        "selector": {"top_n": args.top_n, "sites": sites if sites else None},
        "triage_config": triage_config,
        "ranked_verified": ranked_verified,
        "excluded_named": excluded_named,
        "feed_provenance": feed_prov,
        "note": "unverified programs never appear here; see the scan report",
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"[+] Handoff written to {output_path}")
    print(f"    Verified programs: {len(ranked_verified)}")
    if excluded_named:
        print(f"    Excluded (named): {len(excluded_named)}")


def apply_cli_overrides(config, args):
    """Apply CLI flags onto the loaded config (mutates and returns config).

    --new-companies / --new-assets imply their strict counterparts so the
    flags actually filter, as their help text promises.
    """
    fresh_cfg = config.setdefault("filters", {}).setdefault(
        "freshness_and_competition", {}
    )
    if getattr(args, "new_companies", False):
        fresh_cfg["prefer_new_companies"] = True
        fresh_cfg["strict_new_companies"] = True
        fresh_cfg["new_company_days"] = args.new_company_days
    if getattr(args, "new_assets", False):
        fresh_cfg["prefer_new_assets"] = True
        fresh_cfg["strict_new_assets"] = True
        fresh_cfg["new_asset_days"] = args.new_asset_days
    if getattr(args, "max_validation_days", None) is not None:
        config.setdefault("filters", {}).setdefault("fast_triage", {})[
            "max_validation_days"
        ] = args.max_validation_days
    if getattr(args, "max_rewarded_vulnerabilities", None) is not None:
        fresh_cfg["max_rewarded_vulnerabilities"] = args.max_rewarded_vulnerabilities
    if getattr(args, "require_measured_triage", False):
        config.setdefault("filters", {}).setdefault("fast_triage", {})[
            "require_measured_response_time"
        ] = True
    return config


def _non_negative_int(text):
    """argparse type: canonical int >= 0 (0 means show/export none)."""
    raw = str(text).strip()
    if not re.fullmatch(r"[0-9]+", raw):
        raise argparse.ArgumentTypeError(f"must be an integer >= 0, got {text!r}")
    value = int(raw)
    if value > 9223372036854775807:
        raise argparse.ArgumentTypeError("integer exceeds SQLite INTEGER range")
    return value


def main():
    parser = argparse.ArgumentParser(
        description="Scan4Me: Precision Bug Bounty Target Engine"
    )
    sub = parser.add_subparsers(dest="command")

    p_sync = sub.add_parser("sync", help="Sync latest dataset from upstream feeds")
    p_sync.add_argument(
        "--offline",
        action="store_true",
        help="Use the last cached feed snapshot instead of refreshing it",
    )
    p_sync.add_argument(
        "--no-immunefi", action="store_true", help="Skip Immunefi live fetch"
    )
    p_sync.add_argument(
        "--no-sherlock",
        action="store_true",
        help="Skip Sherlock audit contests live fetch",
    )
    p_sync.add_argument(
        "--no-pd-programs",
        action="store_true",
        help="Skip ProjectDiscovery supplemental repo",
    )
    p_sync.add_argument("--no-federacy", action="store_true", help="Skip Federacy feed")
    p_sync.add_argument(
        "--use-auth",
        dest="use_auth",
        action="store_true",
        default=None,
        help="Sync via authenticated platform APIs (needs keys; "
        "default: config use_auth, else public feeds only)",
    )
    p_sync.add_argument(
        "--no-auth",
        dest="use_auth",
        action="store_false",
        help="Force unauthenticated public feeds, overriding config use_auth",
    )
    p_sync.add_argument(
        "--auth-delay",
        type=float,
        default=1.0,
        help="Seconds between paginated authenticated API requests (default: 1.0)",
    )

    p_enrich = sub.add_parser(
        "enrich",
        help="Fetch official Bugcrowd dates and public competition/validation metrics",
    )
    p_enrich.add_argument(
        "--limit",
        type=_non_negative_int,
        default=10,
        help="Highest-paying Bugcrowd programs to enrich",
    )
    p_enrich.add_argument(
        "--delay", type=float, default=0.25, help="Seconds between program requests"
    )
    p_enrich.add_argument(
        "--handle", help="Enrich one Bugcrowd program by its public handle"
    )

    p_radar = sub.add_parser(
        "radar", help="List top targets filtered by surface area, speed, and cash"
    )
    p_radar.add_argument("--limit", type=_non_negative_int, default=20)
    p_radar.add_argument("--show-assets", action="store_true", default=True)
    p_radar.add_argument(
        "--no-show-assets",
        dest="show_assets",
        action="store_false",
        help="Hide per-program asset samples",
    )
    p_radar.add_argument(
        "--new-companies",
        action="store_true",
        help="Filter to Bugcrowd programs officially started recently",
    )
    p_radar.add_argument(
        "--new-company-days",
        type=int,
        default=90,
        help="Maximum age of official program start",
    )
    p_radar.add_argument(
        "--new-assets",
        action="store_true",
        help="Filter to Bugcrowd programs with recently added in-scope assets",
    )
    p_radar.add_argument(
        "--new-asset-days",
        type=int,
        default=30,
        help="Maximum age of official scope additions",
    )
    p_radar.add_argument(
        "--require-measured-triage",
        action="store_true",
        help="Exclude programs without a published response-time metric",
    )
    p_radar.add_argument(
        "--max-validation-days",
        type=float,
        help="Bugcrowd validation-time ceiling; requires public metadata",
    )
    p_radar.add_argument(
        "--max-rewarded-vulnerabilities",
        type=int,
        help="Bugcrowd historical reward-count ceiling (competition proxy, not open report count)",
    )

    sub.add_parser("keys", help="Show which API keys are configured (values masked)")

    p_check = sub.add_parser(
        "check", help="Verify if target is in authorized legal scope"
    )
    p_check.add_argument("domain", help="Target domain, e.g. api.target.com")

    p_export = sub.add_parser(
        "export",
        help="Export clean target list for httpx/subfinder from filtered programs",
    )
    p_export.add_argument("--top", type=_non_negative_int, default=30)
    p_export.add_argument("--wildcards-only", action="store_true")
    p_export.add_argument("--clean", action="store_true")
    p_export.add_argument(
        "--new-companies",
        action="store_true",
        help="Filter to Bugcrowd programs officially started recently",
    )
    p_export.add_argument(
        "--new-company-days",
        type=int,
        default=90,
        help="Maximum age of official program start",
    )
    p_export.add_argument(
        "--new-assets",
        action="store_true",
        help="Filter to Bugcrowd programs with recently added in-scope assets",
    )
    p_export.add_argument("--new-asset-days", type=int, default=30)
    p_export.add_argument(
        "--max-validation-days", type=float, help="Bugcrowd validation-time ceiling"
    )
    p_export.add_argument(
        "--max-rewarded-vulnerabilities",
        type=int,
        help="Bugcrowd competition-proxy ceiling",
    )

    p_handoff = sub.add_parser(
        "handoff",
        help="Generate Oracle P12 handoff file from prescan + scan reports"
    )
    p_handoff.add_argument(
        "--prescan-file", required=True, help="Path to prescan_*.json report"
    )
    p_handoff.add_argument(
        "--scan-file", required=True, help="Path to scan_*.json report"
    )
    p_handoff.add_argument(
        "--output", required=True, help="Output handoff file path"
    )
    p_handoff.add_argument(
        "--top-n", type=_non_negative_int, default=None, help="Top N verified programs (overridden by --sites)"
    )
    p_handoff.add_argument(
        "--sites", nargs="+", help="Explicit program names/handles/URLs to include (overrides --top-n)"
    )
    p_handoff.add_argument(
        "--no-cloud", action="store_true", help="Mark handoff as no-cloud (local-only)"
    )

    args = parser.parse_args()

    config = load_config()
    apply_cli_overrides(config, args)

    if args.command == "sync":
        plat_override = {}
        if getattr(args, "no_immunefi", False):
            plat_override["immunefi"] = False
        if getattr(args, "no_sherlock", False):
            plat_override["sherlock"] = False
        if getattr(args, "no_pd_programs", False):
            plat_override["pd_programs"] = False
        if getattr(args, "no_federacy", False):
            plat_override["federacy"] = False
        merged_plat_cfg = {**config.get("platforms", {}), **plat_override}
        sync_data(
            refresh=not args.offline,
            platforms_cfg=merged_plat_cfg,
            config=config,
            use_auth=getattr(args, "use_auth", None),
            auth_delay=getattr(args, "auth_delay", 1.0),
        )
    elif args.command == "keys":
        creds = load_credentials(config)
        print("\n=== Scan4Me API Key Status ===\n")
        STATUS = {
            "hackerone": ("username", "api_token"),
            "bugcrowd": ("api_token",),
            "intigriti": ("api_token",),
            "yeswehack": ("api_token",),
            "federacy": ("api_token",),
            "immunefi": ("api_token",),
            "sherlock": ("api_token",),
            "hackenproof": ("api_token",),
            "bugbase": ("api_token",),
            "pd_programs": ("api_token",),
        }
        API_NOTES = {
            "hackerone": "✅ Active API (Basic auth)",
            "bugcrowd": "✅ Active API (Token header)",
            "intigriti": "✅ Active API (Bearer token)",
            "yeswehack": "✅ Active API (Bearer token)",
            "federacy": "⏳ No API yet — slot reserved",
            "immunefi": "🌐 Public board page (no auth needed)",
            "sherlock": "🌐 Public API (no auth needed)",
            "hackenproof": "🌐 Public listing sync (no auth needed)",
            "bugbase": "🌐 Public listing sync (no auth needed)",
            "pd_programs": "🌐 Public GitHub repo (no auth needed)",
        }
        for plat, fields in STATUS.items():
            plat_creds = creds.get(plat, {})
            configured = all(plat_creds.get(f) for f in fields)
            parts = []
            for f in fields:
                v = plat_creds.get(f)
                if v:
                    masked = v[:4] + "****" + v[-2:] if len(v) > 6 else "****"
                    parts.append(f"{f}={masked}")
                else:
                    parts.append(f"{f}=NOT SET")
            status_icon = "🔑" if configured else "○"
            note = API_NOTES.get(plat, "")
            print(f"  {status_icon} {plat:<12} {', '.join(parts)}")
            print(f"               {note}")
        print()
        print("Set keys in config.json api_keys section OR as env vars:")
        print("  HACKERONE_USERNAME, HACKERONE_API_TOKEN")
        print("  BUGCROWD_API_TOKEN, INTIGRITI_API_TOKEN, YESWEHACK_API_TOKEN")
        print("  (env vars take priority over config.json — never commit real keys)\n")
    elif args.command == "enrich":
        cmd_enrich(args)
    elif args.command == "radar":
        cmd_filter(args, config)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "export":
        cmd_export(args, config)
    elif args.command == "handoff":
        cmd_handoff(args, config)
    else:
        p_radar.print_help()


if __name__ == "__main__":
    main()
