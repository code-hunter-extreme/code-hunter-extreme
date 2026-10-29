#!/usr/bin/env python3
# LAYER: find
# DEST: basilisk
# ENDPOINTS: scan_template_seams, template_ids
# TOPICS: none
"""
Oracle Seam Templates — paradox/TTP-driven seam derivation.

The generic code lens finds conflicts, then labels them. This module inverts
the flow: each of Alex's impossible-problem/paradox moves and each MITRE
tactic predicts a specific binary-conflict SHAPE; the templates below hunt
that shape deterministically against recon material (web2) and repo source
(code).

Design rules (the box, mechanically):
  - No LLM in this module. No network. Every check is a pure function of
    material already on disk (recon/*.txt from oracle_deeprecon, repo files).
  - Every candidate is a binary conflict: Assertion A vs Assertion B, one of
    which must be false. That is the iPhone framing as an output contract.
  - Every candidate carries a deterministic `check` command. The existing
    deterministic verifier promotes CANDIDATE -> confirmed; nothing here
    self-promotes.
  - Scope-gated: a candidate whose check URL fails the scope gate is dropped.
    The module itself never sends a packet, so a missing gate only means
    "cannot filter check URLs" — the verifier gates again at probe time.

Card format matches oracle_code_seam.scan_repository_seams exactly, so the
existing _merge_seams / inject_code_seams / report path consumes these with
no changes. origin="seam-template", verdict="CANDIDATE".
"""

from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oracle_foundation import LOGOUT_PATH_PATTERN, SQLI_200_MARKERS
from oracle_foundation import SQLI_ERROR_MARKERS as _SQLI_ERROR_MARKERS

_LOGOUT_PATH_RE = re.compile(LOGOUT_PATH_PATTERN, re.IGNORECASE)

_HERE = Path(__file__).resolve().parent

# ── material ─────────────────────────────────────────────────────────────────


def _read_lines(p: Optional[Path]) -> List[str]:
    if not p:
        return []
    p = Path(p)
    if not p.is_file():
        return []
    try:
        return [
            text_line.strip()
            for text_line in p.read_text(errors="ignore").splitlines()
            if text_line.strip()
        ]
    except OSError:
        return []


def _build_material(
    recon_dir: Optional[Path], repo_path: Optional[Path]
) -> Dict[str, Any]:
    recon = Path(recon_dir) if recon_dir else None
    lh_lines = (
        _read_lines(recon / "clean_live_hosts.txt" if recon else None)
        or _read_lines(recon / "live_hosts.txt" if recon else None)
    )
    wall_codes = {"[502]", "[401]", "[403]", "[530]", "[000]"}
    wall_hosts = set()
    for line in (lh_lines or []):
        if any(c in line for c in wall_codes):
            parts = line.strip().split()
            if parts:
                raw_u = parts[0]
                if "://" not in raw_u:
                    raw_u = "http://" + raw_u
                parsed = urllib.parse.urlparse(raw_u)
                h = (parsed.hostname or parsed.netloc or "").split(":")[0].lower()
                if h:
                    wall_hosts.add(h)

    return {
        "js_endpoints": _read_lines(recon / "js_endpoints.txt" if recon else None),
        "js_secrets": _read_lines(recon / "js_secrets.txt" if recon else None),
        "api_specs": _read_lines(recon / "api_specs.txt" if recon else None),
        "fuzzed": _read_lines(recon / "fuzzed_paths.txt" if recon else None),
        # P14: katana crawl output. Pre-P14 this fed only the LLM prompt —
        # templates never saw it, so crawl-discovered surfaces (DVWA
        # /vulnerabilities/* behind login) got zero probes. Same-host http(s)
        # URLs only; scope gate filters again at scan level.
        "crawled": _read_lines(recon / "crawl.txt" if recon else None),
        # P14: directory-listing children (harvest_listings output).
        "listed": _read_lines(recon / "listed_paths.txt" if recon else None),
        "live_hosts": lh_lines,
        "wall_hosts": wall_hosts,
        "repo": (
            Path(repo_path).resolve()
            if repo_path and Path(repo_path).is_dir()
            else None
        ),
    }


def _has_web(mat: Dict[str, Any]) -> bool:
    return bool(
        mat["js_endpoints"]
        or mat["js_secrets"]
        or mat["api_specs"]
        or mat["fuzzed"]
        or mat.get("crawled")
        or mat.get("listed")
    )


def _base(mat: Dict[str, Any]) -> Optional[str]:
    hosts = mat.get("live_hosts") or []
    return hosts[0].rstrip("/") if hosts else None


def _abs_url(ep: str, mat: Dict[str, Any]) -> Optional[str]:
    """Resolve a js_endpoints entry (path or absolute URL) to a full URL."""
    ep = (ep or "").strip()
    if not ep:
        return None
    if ep.startswith("http://") or ep.startswith("https://"):
        return ep
    base = _base(mat)
    if not base:
        return None
    if not ep.startswith("/"):
        ep = "/" + ep
    return urllib.parse.urljoin(base + "/", ep.lstrip("/"))


_STATIC_EXTS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


def _is_static(ep: str) -> bool:
    low = ep.lower().split("?")[0]
    return low.endswith(_STATIC_EXTS)


# P14: injection-dead suffixes — documents and data files are never SQLi/XSS
# sinks. Probing them only burns budget (DVWA E2E spent 48 sqli cards on
# robots.txt + security.txt). Exposure templates read mat["fuzzed"] raw, so
# this skip is invisible to them — injection-only hygiene.
_INJECTION_DEAD_EXTS = (
    ".txt",
    ".md",
    ".yml",
    ".yaml",
    ".dist",
    ".dtd",
    ".log",
)


def _injection_dead(url: str) -> bool:
    low = url.lower().split("?", 1)[0]
    if "/.git/" in low:
        return True
    return low.endswith(_INJECTION_DEAD_EXTS)


def _has_repeated_segment(url: str) -> bool:
    """Adjacent identical path segments = crawler mis-resolution, not a route.

    Katana resolves page-relative links against the current dir, emitting
    /vulnerabilities/vulnerabilities/sqli/... for real /vulnerabilities/sqli/.
    No application serves the doubled form; it sorts last, never dropped
    (recall-safe: still probed when the corpus is small).
    """
    try:
        segs = [s for s in urllib.parse.urlsplit(url).path.split("/") if s]
    except ValueError:
        return False
    return any(a == b for a, b in zip(segs, segs[1:]))


def _query_param_count(url: str) -> int:
    try:
        q = urllib.parse.urlsplit(url).query
    except ValueError:
        return 0
    return sum(1 for p in q.split("&") if p.strip())


def _parse_bracketed(line: str) -> Tuple[str, str]:
    """`URL [tag]` -> (URL, tag)."""
    if " [" in line and line.endswith("]"):
        url, _, tag = line.rpartition(" [")
        return url.strip(), tag[:-1].strip()
    return line.strip(), ""


# ── scope ────────────────────────────────────────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _check_url(check: str) -> Optional[str]:
    m = _URL_RE.search(check or "")
    return m.group(0) if m else None


def _url_in_scope(url: str, scope_gate) -> bool:
    if scope_gate is None:
        raise ValueError(
            "scan_template_seams requires an explicit scope gate "
            "(a missing gate must never be an open gate; the verifier "
            "re-gates at probe time as defense in depth)"
        )
    try:
        ok, _ = scope_gate.is_in_scope(url)
        return bool(ok)
    except Exception:
        return False


# ── web templates ────────────────────────────────────────────────────────────
# Each check: mat -> List[partial], where partial has assertion_a,
# assertion_b, source_a, line_a, source_b, line_b, check.


def _t_mirror(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Mirror That Remembers Differently / Consensus Equilibrium:
    the remembered state (old API version) vs the live state (new version).
    Both referenced by shipped client code = the mirror disagrees with itself."""
    ver_re = re.compile(r"/v(\d+)(/|$)")
    groups: Dict[str, set] = {}
    for ep in sorted(set(mat["js_endpoints"])):
        m = ver_re.search(ep)
        if not m:
            continue
        route = ver_re.sub("/VX/", ep)  # version-agnostic route key
        groups.setdefault(route, set()).add(m.group(1))
    out = []
    for route in sorted(groups):
        vers = sorted(groups[route], key=int)
        if len(vers) < 2:
            continue
        old, new = vers[0], vers[-1]
        old_ep = route.replace("/VX/", f"/v{old}/")
        url = _abs_url(old_ep, mat)
        if not url:
            continue
        out.append(
            {
                "assertion_a": f"v{new} is the live API contract for {route.replace('/VX/', '/')}",
                "assertion_b": f"v{old} is still referenced by shipped client code — the remembered state is alive",
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # Structural claim (stale version alive and serving API data),
                # so discriminate on the API-data signal — a JSON content
                # type — not on content-leak markers. Envelope words
                # ("id","data",...) can never satisfy Gate 5's non-generic
                # marker rule, and real stale-version endpoints return
                # domain JSON without leak markers. A 200 HTML
                # error/redirect page must not confirm a stale-API finding.
                "expected": 'status 200, header content-type contains "json"',
                "severity": "medium",
            }
        )
    return out[:25]


_PRIV_RE = re.compile(
    r"admin|internal|private|debug|manage|super|root|secret|backup|db[_-]?admin|config",
    re.I,
)


def _t_vacuum(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Vacuum Consciousness / entity-decoupling: the path's NAME asserts a
    privileged identity; its presence in client-reachable surface says the
    exhibited behavior may not match. Claimed identity vs behavior."""
    out = []
    for ep in sorted(set(mat["js_endpoints"])):
        if _is_static(ep) or not _PRIV_RE.search(ep):
            continue
        url = _abs_url(ep, mat)
        if not url:
            continue
        out.append(
            {
                "assertion_a": f"path name asserts privileged identity: {ep}",
                "assertion_b": "referenced in client-reachable surface — behavior may not match the claimed identity",
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # Reachability alone is not a finding — require actual privileged data.
                # A 200 login page or HTML error page must not confirm access control bypass.
                "expected": (
                    "status 200, body contains any of "
                    '"id","email","username","user","role","admin","token","secret",'
                    '"password","api_key","key","internal","config","data","result"'
                ),
                "severity": "low",
            }
        )
    return out[:25]


def _t_observer(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Observer That Consumes Observation / Reflexive Singularity: the watcher
    claims clients only know published operations — but introspection is live,
    so the schema observes (discloses) itself."""
    out = []
    for line in sorted(set(mat["api_specs"])):
        url, tag = _parse_bracketed(line)
        if "graphql-introspection" not in tag and "graphql-playground" not in tag:
            continue
        out.append(
            {
                "assertion_a": "API clients only know the published operations",
                "assertion_b": f"GraphQL self-observation is live at {url} [{tag}] — the schema discloses itself",
                "source_a": "api_specs.txt",
                "line_a": 0,
                "source_b": "api_specs.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}?query=%7B__typename%7D'",
                "expected": 'status 200, body contains "__typename"',
            }
        )
    return out[:10]


def _t_single_token(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Single Token Language / lies-break-symmetry: an endpoint that claims to
    handle its inputs, but fuzzed input produced HTTP 500 — the unhandled
    exception breaks the symmetry (stack/info leak)."""
    out = []
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if tag != "500":
            continue
        out.append(
            {
                "assertion_a": f"endpoint handles its inputs: {url}",
                "assertion_b": "fuzzed input produced HTTP 500 — unhandled exception, symmetry broken (info leak)",
                "source_a": "fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                "expected": "status 500",
                "severity": "low",
            }
        )
    return out[:25]


def _t_repulsive(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Repulsive Gravity / axiom rewrite: the rulebook says the router
    normalizes to one route — but two spellings of the same route both live
    in client code, so auth middleware may bind to only one spelling."""
    groups: Dict[str, set] = {}
    for ep in sorted(set(mat["js_endpoints"])):
        if ep.startswith("http"):
            path = urllib.parse.urlsplit(ep).path
        else:
            path = ep
        norm = path.rstrip("/") or "/"
        groups.setdefault(norm, set()).add(ep)
    out = []
    for norm in sorted(groups):
        spellings = sorted(groups[norm])
        if len(spellings) < 2:
            continue
        a, b = spellings[0], spellings[1]
        ua, ub = _abs_url(a, mat), _abs_url(b, mat)
        if not ua or not ub:
            continue
        out.append(
            {
                "assertion_a": f"router normalizes '{norm}' to a single route",
                "assertion_b": f"two spellings live in client code: '{a}' vs '{b}' — middleware may bind to one only",
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s '{ua}'",
                # Structural claim (alternate spelling serves live API data),
                # so discriminate on the API-data signal — a JSON content
                # type — not on content-leak markers. Envelope words
                # ("id","data",...) can never satisfy Gate 5's non-generic
                # marker rule. A 200 catch-all / SPA shell doesn't prove
                # an auth bypass.
                "expected": 'status 200, header content-type contains "json"',
                "severity": "low",
            }
        )
    return out[:25]


_LEGACY_RE = re.compile(
    r"legacy|/old[_/\-]|deprecated|\.bak$|\.backup$|\.zip$|\.sql$|\.env$|~$", re.I
)
_VERSION_RE = re.compile(r"/v\d+/")


def _t_deathless(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Universe Without Death / hierarchical retrieval: the forgotten deep
    layers. Legacy paths still routable while current policy claims to
    govern the surface. (Version pairs belong to mirror; skipped here.)"""
    out = []
    # Rank candidates so the [:25] cap cannot bury observed-live legacy
    # endpoints under fuzzed-only attempts (hunt-4b law, shared rank key
    # in _cap_rank): crawled js entries are live evidence; fuzzed entries
    # are live only when untagged/2xx (404/500 = attempted, not alive).
    # Filters and _abs_url resolution are unchanged from before the
    # ranking — only the ORDER changes.
    cands: set = set()
    live: Dict[str, bool] = {}
    for ep in sorted(set(mat["js_endpoints"])):
        if _is_static(ep) or _VERSION_RE.search(ep) or not _LEGACY_RE.search(ep):
            continue
        abs_url = _abs_url(ep, mat)
        if not abs_url:
            continue
        cands.add(abs_url)
        live[abs_url] = True
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if (
            _is_static(url)
            or _VERSION_RE.search(url)
            or not _LEGACY_RE.search(url)
        ):
            continue
        abs_url = _abs_url(url, mat)
        if not abs_url:
            continue
        cands.add(abs_url)
        obs = not tag or tag.startswith("2")
        live[abs_url] = live.get(abs_url, False) or obs
    for abs_url in sorted(cands, key=_cap_rank(live)):
        out.append(
            {
                "assertion_a": "current policy governs the exposed surface",
                "assertion_b": (
                    f"forgotten layer still referenced/routable: {abs_url}"
                ),
                "source_a": "js_endpoints.txt/fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt/fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{abs_url}'",
                # Require the legacy path to return API/data content — a 200 HTML redirect
                # or catch-all page is not evidence of a forgotten attack surface.
                "expected": (
                    "status 200, body contains any of "
                    '"id","data","result","token","message","deprecated","legacy","backup",'
                    '"error","version","config","sql","dump"'
                ),
                "severity": "low",
            }
        )
    return out[:25]


_SELF_RE = re.compile(
    r"health|metrics|status|debug|phpinfo|server-status|/info$|/env(\b|/)|/config(\b|/)",
    re.I,
)


def _live_url_map(mat: Dict[str, Any], keep=None) -> Dict[str, bool]:
    """URL → observed-live evidence map (single law for [:25] caps).

    js_endpoints were crawled by recon — observed. fuzzed entries are
    observed-live when they carry no status tag or a 2xx tag; any other
    tag (403/404/500) means the path was attempted but does not evidence
    a living endpoint. Crawled wins conflicts: a js entry keeps a
    candidate live even when a fuzzed probe scored it bad.

    ``keep`` optionally filters both sources (each template keeps its
    own predicate); without it the map covers the full surface.
    """
    live: Dict[str, bool] = {}
    for ep in sorted(set(mat["js_endpoints"])):
        if keep is not None and not keep(ep):
            continue
        if _is_static(ep):
            continue
        url = _abs_url(ep, mat)
        if url:
            live[url] = True
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if keep is not None and not keep(url):
            continue
        live[url] = live.get(url, False) or ((not tag) or tag.startswith("2"))
    return live


def _cap_rank(live: Dict[str, bool]):
    """Rank key over a live map: observed-live first, then
    canonical-short-path, then alphabetical — so a [:25] cap cannot bury
    the strongest evidence (hunt-4b: live /metrics ranked 25th
    alphabetically and was cut)."""

    def _key(u: str) -> Tuple[int, int, str]:
        try:
            paths = urllib.parse.urlsplit(u).path.split("/")
            nseg = len([p for p in paths if p])
        except Exception:
            nseg = 99
        return (0 if live.get(u) else 1, nseg, u)

    return _key


def _t_self_observing(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Self-Observing Equation / Level-5 metasynthesis: the system observes
    itself through health/metrics/status endpoints — self-reference that
    leaks internals while claiming they are not exposed."""
    out = []
    # Rank candidates so the cap cannot bury the best ones (hunt-4b:
    # live /metrics ranked 25th alphabetically and was cut) — shared
    # law in _live_url_map/_cap_rank.
    seen = _live_url_map(mat, keep=lambda u: bool(_SELF_RE.search(u)))
    for url in sorted(seen, key=_cap_rank(seen)):
        out.append(
            {
                "assertion_a": "application internals are not exposed",
                "assertion_b": f"self-observation endpoint reachable: {url}",
                "source_a": "js_endpoints.txt/fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt/fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # Reachability alone is not disclosure. Confirm only when the body
                # actually leaks internals — otherwise a benign /health 200 "confirms".
                "expected": (
                    'status 200, body contains any of "version","secret",'
                    '"token","password","api_key","apikey","aws","akia",'
                    '"private","-----begin","internal","env","stack",'
                    '"traceback","exception","debug","root:","/home/",'
                    '"/var/","/etc/","config","credential"'
                ),
            }
        )
    return out[:25]


def _t_t1552(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """MITRE T1552 Unsecured Credentials: the program's threat model says
    secrets live server-side. The shipped JS disagrees.

    js_secrets.txt format (written by mine_js):
        key=sha256:FINGERPRINT<TAB>source_js_url

    We curl the JS file directly and require the key name to appear in the
    response body — confirming the secret is present, not just guessed.
    Older entries without a URL are silently skipped (no false check emitted).
    """
    out = []
    for line in sorted(set(mat["js_secrets"])):
        # Split on tab to get (key_part, optional_js_url)
        tab_parts = line.split("\t", 1)
        key_part = tab_parts[0].strip()
        js_url = tab_parts[1].strip() if len(tab_parts) > 1 else ""
        key, _, _ = key_part.partition("=")
        key = key.strip()
        if not key or not js_url:
            # No source URL — cannot emit a machine-checkable check; skip.
            continue
        out.append(
            {
                "assertion_a": "secrets live server-side, never ship to clients",
                "assertion_b": f"shipped JS contains secret-shaped assignment: {key}=<redacted>",
                "source_a": "threat model",
                "line_a": 0,
                "source_b": "js_secrets.txt",
                "line_b": 0,
                "check": f"curl -i -s '{js_url}'",
                # Require the key name to actually appear in the JS response.
                "expected": f'status 200, body contains "{key}"',
                "severity": "high",
            }
        )
    return out[:25]


def _t_t1082(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """MITRE T1082 System Information Discovery: the API surface is
    need-to-know — but the full spec is publicly served."""
    out = []
    for line in sorted(set(mat["api_specs"])):
        url, tag = _parse_bracketed(line)
        if "openapi" not in tag and "swagger" not in tag:
            continue
        out.append(
            {
                "assertion_a": "API surface is need-to-know",
                "assertion_b": f"full API specification publicly served: {url}",
                "expected": 'status 200, body contains "openapi"',
                "severity": "low",
                "source_a": "api_specs.txt",
                "line_a": 0,
                "source_b": "api_specs.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
            }
        )
    return out[:10]


_REDIRECT_RE = re.compile(r"redirect|callback|oauth|login|signin|/next|return", re.I)


def _t_t601(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """CWE-601 Open Redirect shape: navigation claims to stay in-app; a
    redirect/callback flow is referenced — you never said the target was
    validated."""
    out = []
    for ep in sorted(set(mat["js_endpoints"])):
        if _is_static(ep) or not _REDIRECT_RE.search(ep):
            continue
        url = _abs_url(ep, mat)
        if not url:
            continue
        out.append(
            {
                "assertion_a": f"navigation stays in the application: {ep}",
                "assertion_b": "redirect/callback flow referenced — client-controlled target possible",
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}?next=https://example.com'",
                # Require the redirect to actually fire to the injected destination.
                # A 200 page rendering a form is not a confirmed open redirect.
                "expected": 'status 302, header location contains "example.com"',
                "severity": "medium",
            }
        )
    return out[:25]


_ARTIFACT_RE = re.compile(
    r"\.git/|\.env$|\.DS_Store|package\.json$|composer\.json$|\.svn/|\.hg/", re.I
)


def _t_t1190_artifact(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """MITRE T1190 Exploit Public-Facing Application: only application routes
    are served — but a config/artifact URL returned HTTP 200."""
    out = []
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if tag != "200" or not _ARTIFACT_RE.search(url):
            continue
        out.append(
            {
                "assertion_a": "only application routes are served",
                "assertion_b": f"artifact exposed with HTTP 200: {url}",
                "source_a": "fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # Require artifact-shaped content — a 200 HTML error page must not confirm.
                # Must NOT be an HTML page AND must contain artifact markers.
                "expected": (
                    'status 200, body not contains "<html",'
                    ' body contains any of "=","PRIVATE KEY","aws_","ref:","dependencies",'
                    '"[core]","HEAD","gitdir","password","secret","token","require"'
                ),
                "severity": "high",
            }
        )
    return out[:25]


# ── Listed-file exposure (directory listing child) ───────────────────────────
_LISTED_TEXT_EXTS = frozenset(
    {
        ".md",
        ".markdown",
        ".txt",
        ".log",
        ".yml",
        ".yaml",
        ".sql",
        ".csv",
        ".env",
        ".key",
        ".pem",
        ".bak",
        ".conf",
        ".cfg",
        ".ini",
    }
)


def _t_listed_file(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Listed files are served as documents, not application routes.

    harvest_listings() already proved the URL came from a real directory
    listing; the card proves it serves document bytes (text/json content
    type), not the SPA shell. Binaries (.png, .ico, ...) are skipped:
    a 200 image is expected site behavior, not evidence of exposure.
    """
    out = []
    for line in sorted(set(mat.get("listed") or [])):
        url = line.split()[0].strip() if line.split() else ""
        if not url.lower().startswith(("http://", "https://")):
            continue
        try:
            fname = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1].lower()
        except ValueError:
            continue
        ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
        if ext == ".json":
            ctype = "json"
        elif ext in _LISTED_TEXT_EXTS:
            ctype = "text"
        else:
            continue
        out.append(
            {
                "assertion_a": "only application routes are served",
                "assertion_b": f"directory listing exposes document: {url}",
                "source_a": "listed_paths.txt",
                "line_a": 0,
                "source_b": "listed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # text/html shells contain "text" too, so the HTML-body
                # exclusion (t1190 precedent) carries the anti-shell load.
                "expected": (
                    f'status 200, body not contains "<html",'
                    f' header content-type contains "{ctype}"'
                ),
                "severity": "medium",
            }
        )
    return out[:25]


# ── code templates (no invisible_seam dependency) ────────────────────────────

_CODE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".sol")
_CONFIG_NAMES = (
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.json",
    ".env.example",
)
_SKIP_REPO_DIRS = {
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "site-packages",
    "dist",
    "build",
    ".git",
    "__pycache__",
    "_seam_checks",
}


def _iter_files(repo: Path, exts) -> List[Path]:
    import os

    out: List[Path] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [
            d
            for d in sorted(dirs)
            if not d.startswith(".") and d.lower() not in _SKIP_REPO_DIRS
        ]
        root_p = Path(root)
        for fname in sorted(files):
            if isinstance(exts, str):
                if fname == exts:
                    out.append(root_p / fname)
            elif not fname.startswith(".") and Path(fname).suffix.lower() in exts:
                out.append(root_p / fname)
    return out


_ASSIGN_RE = re.compile(
    r"^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*([0-9]+|\"[^\"]*\"|'[^']*'|True|False|None)\s*(?:#.*)?$"
)
_JSON_KV_RE = re.compile(
    r'"([A-Z][A-Z0-9_]{2,})"\s*:\s*([0-9]+|\"[^\"]*\"|true|false|null)'
)


def _t_code_mirror(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Mirror / Consensus Equilibrium on code: the config file REMEMBERS one
    value for a setting; the code LIVES another. No invisible_seam needed."""
    repo = mat.get("repo")
    if not repo:
        return []
    cfg_vals: Dict[str, Tuple[str, int, str]] = {}
    for name in _CONFIG_NAMES:
        for p in _iter_files(repo, name):
            try:
                lines = p.read_text(errors="ignore").splitlines()
            except OSError:
                continue
            for i, l in enumerate(lines, 1):
                m = _JSON_KV_RE.search(l)
                if m:
                    cfg_vals.setdefault(m.group(1), (str(p), i, m.group(2)))
    out = []
    for p in _iter_files(repo, _CODE_EXTS):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, l in enumerate(lines, 1):
            m = _ASSIGN_RE.match(l)
            if not m or m.group(1) not in cfg_vals:
                continue
            cpath, cline, cval = cfg_vals[m.group(1)]
            if m.group(2) != cval:
                out.append(
                    {
                        "assertion_a": f"config declares {m.group(1)}={cval}",
                        "assertion_b": f"code lives {m.group(1)}={m.group(2)} — remembered vs live disagree",
                        "source_a": cpath,
                        "line_a": cline,
                        "source_b": str(p),
                        "line_b": i,
                        "check": f"grep -rn '{m.group(1)}' '{cpath}' '{p}'",
                        "expected": "static localized evidence: config and code values differ (see check_output)",
                        "verdict": "CERTAIN",
                        "check_output": (
                            f"{cpath}:{cline} config {m.group(1)}={cval} vs "
                            f"{p}:{i} code {m.group(1)}={m.group(2)}"
                        ),
                    }
                )
    return out[:25]


_DEPRECATED_DEF_RE = re.compile(r"@deprecated|deprecated\s*=\s*True", re.I)
_DEPRECATED_NAME_RE = re.compile(r"def\s+(deprecated_\w+|\w*deprecated\w*)\s*\(")


def _t_code_deathless(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Universe Without Death on code: functions marked deprecated are
    supposed to be dead — but something still invokes them."""
    repo = mat.get("repo")
    if not repo:
        return []
    dead: Dict[str, Tuple[str, int]] = {}
    files = _iter_files(repo, _CODE_EXTS)
    for p in files:
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        prev_deprecated = False
        for i, l in enumerate(lines, 1):
            if _DEPRECATED_DEF_RE.search(l):
                prev_deprecated = True
                continue
            m = re.match(r"\s*def\s+(\w+)\s*\(", l)
            if m:
                if prev_deprecated or m.group(1).startswith("deprecated_"):
                    dead.setdefault(m.group(1), (str(p), i))
                prev_deprecated = False
            elif l.strip() and not l.strip().startswith("#"):
                prev_deprecated = False
    out = []
    for p in files:
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        for fname, (dpath, dline) in sorted(dead.items()):
            for i, l in enumerate(lines, 1):
                if (
                    re.search(rf"(?<![\w.]){re.escape(fname)}\s*\(", l)
                    and not re.match(r"\s*def\s+", l)
                    and not (str(p) == dpath and i == dline)
                ):
                    out.append(
                        {
                            "assertion_a": f"{fname} is marked deprecated ({Path(dpath).name}:{dline})",
                            "assertion_b": f"still invoked at {Path(p).name}:{i} — the dead layer lives",
                            "source_a": dpath,
                            "line_a": dline,
                            "source_b": str(p),
                            "line_b": i,
                            "check": f"grep -rn '{fname}' '{repo}'",
                            "expected": "static localized evidence: deprecated definition still invoked (see check_output)",
                            "verdict": "CERTAIN",
                            "check_output": (
                                f"{dpath}:{dline} def {fname} (deprecated) "
                                f"invoked at {p}:{i}: {l.strip()}"
                            ),
                        }
                    )
    return out[:25]


_CODE_NONPROD_PARTS = {"test", "tests", "spec", "specs", "codefixes", "fixtures", "examples"}

_CODE_SQLI_RE = re.compile(
    r"(?:"
    r"sequelize\.query\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{"
    r"|\bSELECT\b[^;\n]*\bFROM\b[^;\n]*(?:['\"]\s*\+\s*[a-zA-Z_]|'\s*\.\s*\$|'\$[a-zA-Z_]|\{\$[a-zA-Z_])"
    r")",
    re.I,
)

# G6 precision: a regex hit is only CERTAIN when a dynamic site sits in
# value position. Identifier-position interpolation (table/column names,
# usually backtick-wrapped or from prefix/quote helpers) is the dominant
# false-CERTAIN class on real PHP codebases — it proves nothing about
# attacker-controlled values, so it mints nothing.
_SQLI_IDENT_HELPER_RE = re.compile(
    r"(?:[A-Za-z_][\w]*::)?"
    r"(?:prefixTable|quoteIdentifier|quoteTable|quoteColumn|"
    r"quoteDatabaseName)\s*\("
)
_SQLI_CLAUSE_RE = re.compile(
    r"\b(SELECT|FROM|JOIN|INTO|UPDATE|TABLE|WHERE|HAVING|VALUES|SET|"
    r"ORDER\s+BY|GROUP\s+BY)\b",
    re.I,
)
_SQLI_VALUE_CLAUSES = {"WHERE", "HAVING", "VALUES", "SET"}
_SQLI_IDENT_CLAUSES = {
    "FROM", "JOIN", "INTO", "UPDATE", "TABLE", "ORDER BY", "GROUP BY",
}
_SQLI_COMPARISON_RE = re.compile(r"(?:<=|>=|<>|!=|=|<|>)")


def _sqli_dynamic_sites(line: str, start: int) -> List[int]:
    """Positions of interpolation/concatenation sites at/after `start`.

    A plain $var counts only inside a double-quoted/template string or as
    a concat operand — bound parameters after the SQL string (`, $x)`)
    are not sites. Unmodeled shapes yield no sites; callers fall back to
    the legacy regex verdict rather than silently dropping recall.
    """
    sites: List[int] = []
    in_single = in_double = in_template = False
    i = 0  # scan from 0 so quote state at `start` is correct
    n = len(line)
    while i < n:
        ch = line[i]
        if (in_single or in_double or in_template) and ch == "\\":
            i += 2
            continue
        if ch == "'" and not in_double and not in_template:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single and not in_template:
            in_double = not in_double
            i += 1
            continue
        if ch == "`" and not in_single and not in_double:
            in_template = not in_template
            i += 1
            continue
        if in_double or in_template:
            if line.startswith("${", i) or line.startswith("{$", i):
                if i >= start:
                    sites.append(i)
                i += 2
                continue
            if ch == "$" and i + 1 < n and (line[i + 1].isalpha() or line[i + 1] == "_"):
                if i >= start:
                    sites.append(i)
                i += 1
                continue
        if not in_single and not in_double and not in_template and ch in "+.":
            j = i + 1
            while j < n and line[j] in " \t":
                j += 1
            if j < n and (line[j] == "$" or line[j].isalpha() or line[j] == "_"):
                if j >= start:
                    sites.append(j)
                i = j
                continue
        i += 1
    return sites


def _sqli_site_is_value(line: str, sql_start: int, pos: int) -> bool:
    """True when the dynamic site at `pos` interpolates a SQL value."""
    prefix = line[sql_start:pos]
    stripped = prefix.rstrip(" \t'\"+.")
    # Backtick-wrapped site (`FROM `' . $t . '`') is an identifier.
    if stripped.endswith("`"):
        return False
    # Appended tail after a bound placeholder (`... = ?' . $lock`) is a
    # clause fragment (e.g. FOR UPDATE), not the compared value.
    if stripped.endswith("?"):
        return False
    # Site supplying an entire WHERE/HAVING clause is a fragment built
    # elsewhere; this line carries no localized value evidence.
    if re.search(r"\b(?:WHERE|HAVING)$", stripped, re.I):
        return False
    # Table-prefix / identifier-quoting helpers produce identifiers.
    if _SQLI_IDENT_HELPER_RE.match(line[pos:pos + 64]):
        return False
    # `->` / `=>` are code arrows, not SQL comparisons.
    cmp_prefix = prefix.replace("->", "  ").replace("=>", "  ")
    last_value = -1
    last_ident = -1
    seen_select = False
    for m in _SQLI_CLAUSE_RE.finditer(prefix):
        clause = re.sub(r"\s+", " ", m.group(1).upper())
        if clause == "SELECT":
            seen_select = True
        elif clause in _SQLI_VALUE_CLAUSES:
            last_value = m.start()
        elif clause in _SQLI_IDENT_CLAUSES:
            last_ident = m.start()
    comparison_after_ident = bool(
        last_ident >= 0 and _SQLI_COMPARISON_RE.search(cmp_prefix[last_ident:])
    )
    if last_ident > last_value and not comparison_after_ident:
        return False
    # Still in the SELECT column list (no FROM/value clause yet).
    if seen_select and last_ident < 0 and last_value < 0:
        if not _SQLI_COMPARISON_RE.search(cmp_prefix):
            return False
    return True


def _sqli_has_value_site(line: str, sql_start: int) -> bool:
    sites = _sqli_dynamic_sites(line, sql_start)
    if not sites:
        return True  # unmodeled shape: keep legacy regex verdict
    return any(_sqli_site_is_value(line, sql_start, p) for p in sites)
_CODE_CMDI_RE = re.compile(
    r"(?:"
    r"\b(?:subprocess\.(?:Popen|call|run)|os\.system)\s*\([^\n]*\bshell\s*=\s*True"
    r"|\b(?:shell_exec|passthru|system)\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*\$"
    r"|\bvm\.runInContext\s*\("
    r")"
)
_CODE_DESERIAL_RE = re.compile(
    r"(?:"
    r"\bpickle\.loads\s*\("
    r"|\byaml\.unsafe_load\s*\("
    r"|\bsetFeature\s*\(\s*feature_external_ges\s*,\s*True\s*\)"
    r"|\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"
    r")"
)


def _iter_prod_code_files(repo: Path) -> List[Path]:
    out: List[Path] = []
    for p in _iter_files(repo, _CODE_EXTS):
        try:
            rel = p.relative_to(repo)
        except ValueError:
            rel = p
        parts_low = {pt.lower() for pt in rel.parts[:-1]}
        fname_low = p.name.lower()
        if parts_low & _CODE_NONPROD_PARTS:
            continue
        if (
            fname_low.startswith("test_")
            or fname_low.endswith((".spec.ts", ".spec.js", "_test.py"))
            or fname_low == "impossible.php"
        ):
            continue
        out.append(p)
    return out


def _t_code_sqli_sink(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Static code sink: raw SQL string interpolation/concatenation."""
    repo = mat.get("repo")
    if not repo:
        return []
    out: List[Dict[str, Any]] = []
    for p in _iter_prod_code_files(repo):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            _sqli_m = _CODE_SQLI_RE.search(line)
            if _sqli_m and _sqli_has_value_site(line, _sqli_m.start()):
                out.append(
                    {
                        "assertion_a": f"database queries in {p.name} use parameterized bindings",
                        "assertion_b": (
                            f"raw SQL query string interpolation/concatenation at {p.name}:{i}"
                        ),
                        "source_a": str(p),
                        "line_a": i,
                        "source_b": str(p),
                        "line_b": i,
                        "check": f"grep -n 'SELECT' '{p}'",
                        "check_provenance": "lens",
                        "expected": "static localized evidence: unparameterized SQL sink (see check_output)",
                        "verdict": "CERTAIN",
                        "severity": "high",
                        "check_output": f"{p}:{i}: {stripped[:180]}",
                    }
                )
    return out[:25]


def _t_code_cmdi_sink(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Static code sink: unsafe shell/VM command execution."""
    repo = mat.get("repo")
    if not repo:
        return []
    out: List[Dict[str, Any]] = []
    for p in _iter_prod_code_files(repo):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            m = _CODE_CMDI_RE.search(line)
            if m:
                tok = m.group(0).split("(")[0].strip()
                out.append(
                    {
                        "assertion_a": f"command/script execution in {p.name} isolates untrusted input",
                        "assertion_b": (
                            f"unsafe shell/VM execution sink ({tok}) at {p.name}:{i}"
                        ),
                        "source_a": str(p),
                        "line_a": i,
                        "source_b": str(p),
                        "line_b": i,
                        "check": f"grep -n '{tok}' '{p}'",
                        "check_provenance": "lens",
                        "expected": "static localized evidence: unsafe command/VM execution sink (see check_output)",
                        "verdict": "CERTAIN",
                        "severity": "high",
                        "check_output": f"{p}:{i}: {stripped[:180]}",
                    }
                )
    return out[:25]


def _t_code_deserial_sink(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Static code sink: unsafe deserialization or external entity expansion (XXE)."""
    repo = mat.get("repo")
    if not repo:
        return []
    out: List[Dict[str, Any]] = []
    for p in _iter_prod_code_files(repo):
        try:
            lines = p.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            m = _CODE_DESERIAL_RE.search(line)
            if m:
                tok = m.group(0).split("(")[0].strip()
                out.append(
                    {
                        "assertion_a": f"deserialization/XML parser in {p.name} rejects arbitrary objects and external entities",
                        "assertion_b": (
                            f"unsafe deserialization/XXE sink ({tok}) at {p.name}:{i}"
                        ),
                        "source_a": str(p),
                        "line_a": i,
                        "source_b": str(p),
                        "line_b": i,
                        "check": f"grep -n '{tok}' '{p}'",
                        "check_provenance": "lens",
                        "expected": "static localized evidence: unsafe deserialization/XXE sink (see check_output)",
                        "verdict": "CERTAIN",
                        "severity": "high",
                        "check_output": f"{p}:{i}: {stripped[:180]}",
                    }
                )
    return out[:25]


# ── Beautiful Liar — trust-claim bypass (Reflex 9) ──────────────────────────

_TRUST_CLAIM_RE = re.compile(
    r"admin|metrics|internal|private|manage|dashboard|report|billing|secret|role|token",
    re.I,
)
# Patterns that suggest a header or parameter is used for access control
_PRIV_HEADER_RE = re.compile(
    r"X-Original-Role|X-Role|X-User-Role|X-Forwarded-Role|X-Auth-Level|X-Admin|"
    r"X-Internal|X-Real-IP|X-Forwarded-For|Authorization",
    re.I,
)


def _t_beautiful_liar(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The Beautiful Liar / Trust-Claim Bypass: the system claims a role or
    identity is validated server-side; in reality the server trusts a
    client-injectable header as proof. The 'story' the server tells about
    its enforcement is beautiful — and a lie.

    Check MUST carry an injected role header — plain GET cannot prove it.
    Uses -H injection (allowed by sanitizer). The expected body contains a
    privilege marker that only appears when the bypass works.
    """
    out: List[Dict[str, Any]] = []
    base = _base(mat)
    if not base:
        return out
    seen: set = set()
    # Candidate endpoints: privileged-named paths from fuzzed discovery or JS.
    # Dedupe on the RESOLVED url both sides (was: fuzzed side seeded raw
    # paths, js side seeded the stale loop var — cross-source repeats and
    # UnboundLocalError on empty fuzzed; test receipts).
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if tag not in ("200", "403") or not _TRUST_CLAIM_RE.search(url):
            continue
        abs_url = _abs_url(url, mat)
        if not abs_url or abs_url in seen:
            continue
        seen.add(abs_url)
        out.append(
            {
                "assertion_a": (
                    f"access to {abs_url} is enforced by server-side role validation"
                ),
                "assertion_b": "server trusts a client-controlled header as the role proof — "
                "injecting X-Original-Role: admin bypasses validation",
                "source_a": "fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "fuzzed_paths.txt",
                "line_b": 0,
                # -H injection: allowed by sanitizer; no POST needed.
                "check": f"curl -i -s -H 'X-Original-Role: admin' '{abs_url}'",
                # Require privilege markers — a 403 HTML page must not confirm.
                "expected": (
                    "status 200, body contains any of "
                    '"authorized","admin","role","metrics","revenue","dashboard",'
                    '"internal","secret","token","data","users","billing"'
                ),
                "severity": "high",
            }
        )
    for ep in sorted(set(mat["js_endpoints"])):
        if _is_static(ep) or not _TRUST_CLAIM_RE.search(ep):
            continue
        abs_url = _abs_url(ep, mat)
        if not abs_url or abs_url in seen:
            continue
        # seen records the resolved URL (was: the stale fuzzed-loop `url`
        # variable — dedupe missed cross-source repeats and crashed with
        # UnboundLocalError on an empty fuzzed matrix; test receipt).
        seen.add(abs_url)
        out.append(
            {
                "assertion_a": f"access to {ep} requires a validated server-side role",
                "assertion_b": "endpoint referenced in client JS — "
                "server may trust X-Original-Role header injected by the client",
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s -H 'X-Original-Role: admin' '{abs_url}'",
                "expected": (
                    "status 200, body contains any of "
                    '"authorized","admin","role","metrics","revenue","dashboard",'
                    '"internal","secret","token","data","users","billing"'
                ),
                "severity": "high",
            }
        )
    return out[:25]


# ── Cliff and the Current — alternate-path auth gap (Reflex 10) ──────────────

_ALT_PATH_RE = re.compile(
    r"internal|private|secure|api/internal|api/private|v\d+/private|"
    r"v\d+/internal|v\d+/admin|v\d+/secure",
    re.I,
)


def _t_cliff_and_current(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The Cliff and the Current / Alternate-Path Auth Gap: the documented
    path enforces authentication; society (the auth middleware) only covers
    that one path. The current flows around it. Jump off the cliff — try the
    alternate path that the auth rule never reached.

    Check MUST be against the alternate path (not the guarded one). Uses plain
    GET to the unguarded alternate URL. Expected: body contains data that should
    require auth. Benign response (404 / HTML) rejects.
    """
    out = []
    seen_paths: set = set()
    # Build a map: normalized route → list of full fuzzed URLs that resolve to it
    path_map: Dict[str, List[Tuple[str, str]]] = {}
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        try:
            parts = urllib.parse.urlsplit(url)
            norm = parts.path.lower().rstrip("/")
        except Exception:
            continue
        path_map.setdefault(norm, []).append((url, tag))
    # Collect all [200] paths that have sensitive semantics (used for fallback match)
    sensitive_open: List[Tuple[str, str]] = []  # (norm_path, full_url)
    for line in sorted(set(mat["fuzzed"])):
        url2, tag2 = _parse_bracketed(line)
        if tag2 != "200":
            continue
        try:
            p2 = urllib.parse.urlsplit(url2).path.lower().rstrip("/")
        except Exception:
            continue
        if _ALT_PATH_RE.search(p2):
            sensitive_open.append((p2, url2))

    # Look for a guarded path (403) that has an unguarded sibling pattern
    for norm_path, entries in sorted(path_map.items()):
        tags = {t for _, t in entries}
        if "403" not in tags:
            continue
        # --- Pass 1: exact suffix match ---
        # Strip known version prefix and look for /internal/ or /private/ variant
        suffix = re.sub(r"^/api/v\d+", "", norm_path)
        alt_url_candidate = None
        if suffix and suffix != "/":
            for line2 in sorted(set(mat["fuzzed"])):
                url2, tag2 = _parse_bracketed(line2)
                if tag2 not in ("200",) or url2 in seen_paths:
                    continue
                try:
                    p2 = urllib.parse.urlsplit(url2).path.lower().rstrip("/")
                except Exception:
                    continue
                p2_suffix = re.sub(r"^/api/(internal|v0)", "", p2)
                if (p2_suffix == suffix or p2_suffix in suffix or suffix in p2_suffix) and p2 != norm_path:
                    alt_url_candidate = url2
                    break
            # Also check JS endpoints for alternate paths
            if not alt_url_candidate:
                for ep in mat["js_endpoints"]:
                    try:
                        p_ep = (
                            urllib.parse.urlsplit(_abs_url(ep, mat) or "")
                            .path.lower()
                            .rstrip("/")
                        )
                    except Exception:
                        continue
                    p_ep_suffix = re.sub(r"^/api/(internal|v0)", "", p_ep)
                    if (p_ep_suffix == suffix or p_ep_suffix in suffix or suffix in p_ep_suffix) and p_ep != norm_path:
                        _abs_ep = _abs_url(ep, mat)
                        if _abs_ep not in seen_paths:
                            alt_url_candidate = _abs_ep
                            break
        # --- Pass 2: semantic fallback — guarded path itself is sensitive,
        #     any open sensitive path is a potential bypass ---
        if not alt_url_candidate and _ALT_PATH_RE.search(norm_path):
            for p2, url2 in sensitive_open:
                if p2 != norm_path and url2 not in seen_paths:
                    alt_url_candidate = url2
                    break
        if not alt_url_candidate:
            continue
        guarded_url = entries[0][0]
        if guarded_url in seen_paths or alt_url_candidate in seen_paths:
            continue
        seen_paths.add(guarded_url)
        seen_paths.add(alt_url_candidate)
        out.append(
            {
                "assertion_a": f"auth middleware protects {guarded_url} (returns 403 without credentials)",
                "assertion_b": f"alternate path {alt_url_candidate} serves the same resource without auth check",
                "source_a": "fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{alt_url_candidate}'",
                # Require data — a 404 or HTML catch-all must not confirm.
                "expected": (
                    "status 200, body contains any of "
                    '"secret","token","data","revenue","users","internal","private",'
                    '"dashboard","admin","config","id","email"'
                ),
                "severity": "high",
            }
        )
    return out[:20]


# ── Invisible Architect — forgotten infrastructure seam (Reflex 11) ──────────

_INFRA_PATH_RE = re.compile(
    r"package\.json|composer\.json|yarn\.lock|Gemfile\.lock|requirements\.txt|"
    r"\.env\.|config\.ya?ml|docker-compose|Dockerfile|\.tf$|\.pem$|\.key$|"
    r"backup|\.bak$|\.old$|\.orig$|static/|/vendor/|/node_modules/|/dist/|/build/",
    re.I,
)


def _t_invisible_architect(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The Invisible Architect / Forgotten Infrastructure Seam: the builder
    becomes invisible the moment the building becomes infrastructure. Dependency
    manifests, build artifacts, backup files, and config layers are served from
    the same web root — nobody remembers they're there, so nobody protected them.
    'You never said the scaffolding was secret.'

    Broader than _t_t1190_artifact: catches dependency files, lockfiles, backup
    configs, build outputs, and container/IaC files — any infrastructure layer
    the application was built on top of, now exposed.
    """
    out = []
    seen: set = set()
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if tag != "200" or not _INFRA_PATH_RE.search(url):
            continue
        # Skip if already caught by the artifact template (git/env exact matches)
        if _ARTIFACT_RE.search(url):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(
            {
                "assertion_a": "application infrastructure (dependencies, configs, build artifacts) is not publicly accessible",  # noqa: E501
                "assertion_b": f"infrastructure file served with HTTP 200: {url}",
                "source_a": "fuzzed_paths.txt",
                "line_a": 0,
                "source_b": "fuzzed_paths.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url}'",
                # Must not be HTML and must contain infra-shaped content.
                "expected": (
                    'status 200, body not contains "<html",'
                    " body contains any of "
                    '"version","dependencies","require","name","scripts","password",'
                    '"secret","token","key","FROM ","RUN ","ENV ","config","host"'
                ),
                "severity": "medium",
            }
        )
    return out[:25]


# ── active injection templates ───────────────────────────────────────────────
# R1: every template above is a passive existence/shape probe — none sends a
# payload. Bench recall proved the gap: zero injection cards entered the
# funnel, so the SQLi/XSS classes were never even considered. These two
# templates fuzz API routes (js_endpoints) and live pages (fuzzed 200s) with
# real SQLi/XSS payloads. URL payloads are percent-encoded (a raw quote would
# break the shlex parse in _run_check); POST JSON bodies use double-quoted
# shell strings with escaped inner quotes.

_SQLI_ERR_PAYLOAD = "%27%20OR%20%271%27%3D%271"  # ' OR '1'='1
_SQLI_DQ_PAYLOAD = "%22%20OR%20%221%22%3D%221"  # " OR "1"="1 (distinct check)
_SQLI_LOGIN_EMAIL = "' OR 1=1-- "  # raw: JSON bodies are not URL-decoded
_XSS_MARKER = "oraclex1"
_XSS_PAYLOAD = "%3Cimg%20src%3Dx%20onerror%3Dalert%28" + _XSS_MARKER + "%29%3E"
_XSS_RAW = "<img src=x onerror=alert(" + _XSS_MARKER + ")>"
# Marker is alphanumeric so it survives both raw and decoded reflection.
# (SQL error markers live in oracle_foundation.SQLI_200_MARKERS — shared
# with the harvest-form reframe so both agree on database-error evidence.)

_API_ROUTE_RE = re.compile(r"/(?:api|rest|graphql|query|search)\b", re.I)
_LOGIN_ROUTE_RE = re.compile(
    r"log[\s_-]?in|sign[\s_-]?in|/auth\b|/session|/token|/account", re.I
)


def _is_logout(url: str) -> bool:
    """Logout-shaped endpoints are never probe targets (P14).

    Probing one with a session cookie destroys the session (DVWA
    logout.php GET → session_destroy), silently 302ing every later
    probe. Logout endpoints are never injection sinks — skipping loses
    no recall and protects hand-fed/resumed recon too.
    """
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return False
    return bool(_LOGOUT_PATH_RE.search(path))


def _injection_targets(mat: Dict[str, Any]) -> List[Tuple[str, str, bool]]:
    """(url, source, is_api) — API routes first, then live fuzzed pages."""
    out: List[Tuple[str, str, bool]] = []
    seen: set = set()
    base = _base(mat)
    if base:
        for ep in sorted(set(mat["js_endpoints"])):
            if _is_static(ep) or _injection_dead(ep):
                continue
            url = _abs_url(ep, mat)
            if not url or url in seen or _is_logout(url):
                continue
            seen.add(url)
            out.append((url, "js_endpoints.txt", bool(_API_ROUTE_RE.search(ep))))
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if tag != "200" or _is_static(url) or _injection_dead(url) or _is_logout(url):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append((url, "fuzzed_paths.txt", bool(_API_ROUTE_RE.search(url))))
    # P14: crawled URLs last (js + fuzzed keep priority under group caps).
    # Same-host only — crawlers follow off-site links (docs, github) that
    # must never become probe targets. .get: hand-built mats lack the key.
    base_host = urllib.parse.urlsplit(base).netloc.lower() if base else ""
    for line in sorted(set(mat.get("crawled") or [])):
        url = line.split()[0].strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        if base_host and urllib.parse.urlsplit(url).netloc.lower() != base_host:
            continue
        if url in seen or _is_static(url) or _injection_dead(url) or _is_logout(url):
            continue
        seen.add(url)
        out.append((url, "crawl.txt", bool(_API_ROUTE_RE.search(url))))

    # P14: shallow-first within api/page split, misresolutions last.
    # Deepest-first was tried and REVERTED: it ranks crawler junk first
    # (katana emits 4-7-deep misresolutions like /vuln/vuln/x/source/low.php
    # and /var/www/html/... ahead of the real depth-2 app routes — DVWA E2E
    # gave all 32 crawled sqli cards to junk, zero to /vulnerabilities/*).
    # App surface lives shallow; deep paths are files, docs, and params.
    # Fewer query params first: a clean dir outranks its ?doc= variants.
    def _depth(url: str) -> int:
        try:
            segs = urllib.parse.urlsplit(url).path.strip("/").split("/")
            return sum(1 for s in segs if s)
        except ValueError:
            return 0

    out.sort(
        key=lambda t: (
            not t[2],
            _has_repeated_segment(t[0]),
            _depth(t[0]),
            _query_param_count(t[0]),
            t[0],
        )
    )
    return out


def _t_sqli(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Active SQLi probe: error-based GET fuzz plus JSON login bypass POSTs."""
    out: List[Dict[str, Any]] = []
    # FIX-forward-1: the two cards per (url, param) MUST carry distinct
    # checks — scan_template_seams dedups on (tid, check), so identical
    # checks silently drop the marker card. Single-quote payload feeds the
    # 500 card, double-quote payload feeds the in-band marker card.
    # FIX-forward-2: strip any existing query string instead of appending
    # with & — Op1 (validate_card_shape) rejects & anywhere in the check.
    # NB4: stripping (not %26-encoding) is deliberate — the probe still
    # needs a separator to join it to the original query, and that
    # separator must be a literal & which Op1 rejects. %26 preserves the
    # old params but cannot solve the join, so strip and re-? the probe.
    targets = _injection_targets(mat)
    # NB1: login POSTs FIRST — the GET groups below fill 24+16+32=72, so
    # emitting GET first lets the [:80] truncation drop every POST card
    # at production scale. POST-first keeps the bypass budget alive.
    # NB-R2-1: POST SUB-CAP — uncapped POST-first mirrors NB1 in reverse:
    # at scale the login POSTs fill the whole [:80] budget and the
    # truncation drops 100% of GET probes (measured: 40 POST + 0 GET
    # with 20 login routes at the old [:40] budget). Login bypass gets
    # <=8 cards; the GET groups below fill the remaining global budget.
    for url, source, _ in targets:
        if len(out) >= 8:
            break
        if not _LOGIN_ROUTE_RE.search(url):
            continue
        # NB2: strip the query string here too — a ?-query URL would
        # embed a literal & in the check and die at Op1.
        clean = url.split("?", 1)[0]
        for user_field in ("email", "username"):
            if len(out) >= 8:  # NB-R2-1/NB3: hard sub-cap, before EACH append
                break
            body = (
                '{"%s":"%s","password":"x"}' % (user_field, _SQLI_LOGIN_EMAIL)
            ).replace('"', '\\"')
            out.append(
                {
                    "assertion_a": f"login at {url} rejects wrong passwords",
                    "assertion_b": (
                        "SQLi in the login JSON bypasses authentication — "
                        "wrong password returns a session"
                    ),
                    "source_a": source,
                    "line_a": 0,
                    "source_b": source,
                    "line_b": 0,
                    "check": (
                        "curl -i -s -X POST "
                        "-H 'Content-Type: application/json' "
                        f"-d \"{body}\" '{clean}'"
                    ),
                    "expected": (
                        "status 200, body contains any of " '"token","auth","session"'
                    ),
                    "severity": "high",
                }
            )
    api_targets = [t for t in targets if t[2]]
    page_targets = [t for t in targets if not t[2] and t[1] != "crawl.txt"]
    # P14: crawled pages are their own group. Merged alpha order starves
    # late-sorting app routes (DVWA /vulnerabilities/xss_r/ sat 55th of
    # 57 page targets — zero probes E2E). Split caps are ordering-proof
    # (extends the FIX-forward-5 api/page precedent).
    crawled_targets = [t for t in targets if not t[2] and t[1] == "crawl.txt"]
    # FIX-forward-5: split caps so API routes cannot starve live pages.
    # NB3: hard caps — the cap check sits INSIDE the param loop, before
    # EACH append; a per-URL check lets one 4-card URL overshoot a
    # nearly-full group (24→28).
    # P13: param-outer round-robin — one probe pass per param across ALL
    # urls, so the cap spreads the primary probe instead of filling one
    # URL completely before touching the next (within-group starvation:
    # 6 urls ate the whole API budget while /api/search got zero probes).
    for group, cap in ((api_targets, 24), (page_targets, 16), (crawled_targets, 40)):
        start = len(out)
        params = ("q", "id") if group is api_targets else ("id", "name")
        for param in params:
            if len(out) - start >= cap:
                break
            # Pass 1: error-signal probe for EVERY url before any url gets
            # a second card — the cap spreads the primary probe, never
            # starves a late-sorting target.
            for url, source, _is_api in group:
                if len(out) - start >= cap:
                    break
                clean = url.split("?", 1)[0]
                probe_500 = f"{clean}?{param}={_SQLI_ERR_PAYLOAD}"
                out.append(
                    {
                        "assertion_a": f"endpoint handles its inputs: {url}",
                        "assertion_b": (
                            f"SQLi probe in ?{param}= breaks the backend query — "
                            "HTTP 500 (unhandled SQL error)"
                        ),
                        "source_a": source,
                        "line_a": 0,
                        "source_b": source,
                        "line_b": 0,
                        "check": f"curl -i -s '{probe_500}'",
                        "expected": (
                            "status 500, body contains any of "
                            + SQLI_200_MARKERS
                            + ',"sqlite3","OperationalError"'
                        ),
                        # Require database error evidence on 500 so generic
                        # framework/router 500 pages do not false-confirm.
                        "severity": "medium",
                    }
                )
            if len(out) - start >= cap:  # NB3: hard cap, before EACH append
                break
            # Pass 2: in-band marker probe for every url with budget left.
            for url, source, _is_api in group:
                if len(out) - start >= cap:
                    break
                clean = url.split("?", 1)[0]
                probe_msg = f"{clean}?{param}={_SQLI_DQ_PAYLOAD}"
                out.append(
                    {
                        "assertion_a": f"endpoint handles its inputs: {url}",
                        "assertion_b": (
                            f"SQLi probe in ?{param}= leaks a database error "
                            "in a 200 page (in-band SQL error)"
                        ),
                        "source_a": source,
                        "line_a": 0,
                        "source_b": source,
                        "line_b": 0,
                        "check": f"curl -i -s '{probe_msg}'",
                        "expected": (
                            "status 200, body contains any of " + SQLI_200_MARKERS
                        ),
                        "severity": "high",
                    }
                )
    # P14: 8 POST + 24 api + 16 page + 40 crawled = 88 (was 40). The
    # truncation is a safety rail now, not a budget: groups are capped.
    return out[:88]


def _t_xss_reflect(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Active XSS probe: GET reflection fuzz plus JSON persist POSTs."""
    out: List[Dict[str, Any]] = []
    # FIX-forward-2: strip existing query strings (Op1 rejects & in checks).
    # NB4: strip, don't %26-encode — joining the probe still needs a
    # literal & separator which Op1 rejects (see _t_sqli).
    # FIX-forward-5: split caps so API routes cannot starve live pages.
    targets = _injection_targets(mat)
    # NB1: persist POSTs FIRST so the [:68] truncation drops tail GET
    # probes, never the stored-XSS POSTs.
    # NB-R2-1: POST SUB-CAP — uncapped POST-first mirrors NB1 in reverse:
    # 40 API routes yield 32 POST + 0 GET at the old budget. Persist gets
    # <=8 cards; the GET groups below fill the remaining global budget.
    for url, source, is_api in targets:
        if len(out) >= 8:
            break
        if not is_api:
            continue
        # NB2: strip the query string here too (Op1: no & in checks).
        clean = url.split("?", 1)[0]
        body = (
            '{"name":"%s","description":"%s","price":1}' % (_XSS_RAW, _XSS_RAW)
        ).replace('"', '\\"')
        out.append(
            {
                "assertion_a": f"API at {url} encodes stored strings",
                "assertion_b": (
                    "script payload persists via create and echoes back — " "stored XSS"
                ),
                "source_a": source,
                "line_a": 0,
                "source_b": source,
                "line_b": 0,
                "check": (
                    "curl -i -s -X POST "
                    "-H 'Content-Type: application/json' "
                    f"-d \"{body}\" '{clean}'"
                ),
                "expected": f'status 201, body contains "{_XSS_MARKER}"',
                "severity": "high",
            }
        )
    api_targets = [t for t in targets if t[2]]
    page_targets = [t for t in targets if not t[2] and t[1] != "crawl.txt"]
    # P14: crawled pages are their own group (same starvation fix as
    # _t_sqli — late-sorting app routes got zero probes E2E).
    crawled_targets = [t for t in targets if not t[2] and t[1] == "crawl.txt"]
    # NB3: hard caps — check INSIDE the param loop, before EACH append.
    # P13: param-outer round-robin (same within-group starvation fix as
    # _t_sqli — the cap spreads the primary probe across every target).
    for group, cap in ((api_targets, 14), (page_targets, 14), (crawled_targets, 40)):
        start = len(out)
        params = ("q", "search") if group is api_targets else ("q", "name", "search")
        for param in params:
            if len(out) - start >= cap:
                break
            for url, source, _is_api in group:
                if len(out) - start >= cap:
                    break
                clean = url.split("?", 1)[0]
                probe = f"{clean}?{param}={_XSS_PAYLOAD}"
                out.append(
                    {
                        "assertion_a": f"endpoint encodes its outputs: {url}",
                        "assertion_b": (
                            f"script probe in ?{param}= reflects unescaped — "
                            "reflected XSS"
                        ),
                        "source_a": source,
                        "line_a": 0,
                        "source_b": source,
                        "line_b": 0,
                        "check": f"curl -i -s '{probe}'",
                        "expected": f'status 200, body contains "{_XSS_RAW}"',
                        "severity": "high",
                    }
                )
    # P14: 8 POST + 14 api + 14 page + 40 crawled = 76 (was 32).
    return out[:76]


_DOM_MARKER = "oracledom7"
_DOM_PAYLOAD = "%3Cimg%20src%3Dx%20onerror%3Dalert%28" + _DOM_MARKER + "%29%3E"


def _t_dom_xss(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """DOM XSS candidates: page probes confirmed by rendered differential.

    Pure like every template (no network here): each card's curl check is
    the auditable raw leg, but confirmation routes to the headless browser
    (oracle_rendered via the hunter's confirm hook) — the marker counts
    only when the RENDERED DOM contains it. Capped at 12: every confirm
    launches browser work, so the probe budget stays small.
    """
    out: List[Dict[str, Any]] = []
    pages = [t for t in _injection_targets(mat) if not t[2]]
    for url, source, _is_api in pages[:12]:
        clean = url.split("?", 1)[0]
        probe = f"{clean}?q={_DOM_PAYLOAD}"
        out.append(
            {
                "assertion_a": f"page renders user input inertly: {url}",
                "assertion_b": (
                    "script probe executes after JS rendering — DOM XSS"
                ),
                "source_a": source,
                "line_a": 0,
                "source_b": source,
                "line_b": 0,
                "check": f"curl -i -s '{probe}'",
                "expected": f'status 200, body contains "{_DOM_MARKER}"',
                "render_marker": _DOM_MARKER,
                "severity": "high",
            }
        )
    return out[:12]


def _t_csrf_sqli(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """CSRF-gated SQLi candidates: POST forms needing token replay.

    Pure like every template: the curl check is the auditable one-shot
    leg, but confirmation routes to the form-replay engine
    (oracle_harvest.confirm_form_replay via the hunter's confirm hook),
    which GETs the form, extracts csrfmiddlewaretoken, and replays the
    POST with a bare-quote error trigger. Capped at 8.
    """
    out: List[Dict[str, Any]] = []
    pages = [t for t in _injection_targets(mat) if not t[2]]
    for url, source, _is_api in pages[:8]:
        clean = url.split("?", 1)[0]
        out.append(
            {
                "assertion_a": f"POST form rejects untokened input safely: {url}",
                "assertion_b": (
                    "token replay with a quote trigger returns a database"
                    " error — SQLi behind the CSRF gate"
                ),
                "source_a": source,
                "line_a": 0,
                "source_b": source,
                "line_b": 0,
                "check": f"curl -i -s -X POST -d 'q=%27' '{clean}'",
                "expected": (
                    "status 200, body contains any of " + _SQLI_ERROR_MARKERS
                ),
                "csrf_field": "",
                "severity": "high",
            }
        )
    return out[:8]


_IDOR_ID_RE = re.compile(r"/(\d{1,10})(/|$)")


def _t_idor(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Direct object reference: per-user objects addressable with no session.

    Groups client-referenced endpoints by object-id shape (/api/profile/N);
    a shape with two or more distinct ids is an addressable object space.
    The first id is treated as the self-reference baseline; the furthest
    id is probed with a bare request (omission frame — no session IS the
    test). A lone self-reference never fires, so single-object endpoints
    stay silent. Version segments (/v1/) and slug ids (ord_101) are not
    pure-numeric and never group.
    """
    shapes: Dict[str, Dict[str, str]] = {}
    for ep in sorted(set(mat["js_endpoints"])):
        if _is_static(ep):
            continue
        path = urllib.parse.urlsplit(ep).path if ep.startswith("http") else ep
        m = _IDOR_ID_RE.search(path)
        if not m:
            continue
        shape = path[: m.start(1)] + "N" + path[m.end(1) :]
        shapes.setdefault(shape, {})[m.group(1)] = ep
    out = []
    for shape in sorted(shapes):
        ids = sorted(shapes[shape], key=int)
        if len(ids) < 2:
            continue
        first, other = ids[0], ids[-1]
        url_other = _abs_url(shapes[shape][other], mat)
        url_first = _abs_url(shapes[shape][first], mat)
        if not url_other or not url_first:
            continue
        out.append(
            {
                "assertion_a": f"object references under {shape} require per-user authorization",
                "assertion_b": (
                    f"object {other} serves user data without auth — "
                    f"{url_other} answers with no session while {url_first} "
                    "shows the object space is per-user"
                ),
                "source_a": "js_endpoints.txt",
                "line_a": 0,
                "source_b": "js_endpoints.txt",
                "line_b": 0,
                "check": f"curl -i -s '{url_other}'",
                # Require per-user record fields — a 200 envelope or HTML
                # shell must not confirm object-level access.
                "expected": (
                    "status 200, body contains any of "
                    '"email","username","phone","address","ssn",'
                    '"password","token","secret"'
                ),
                "severity": "high",
            }
        )
    return out[:25]


# ── State Invariant Violation — action on finalized resource (Reflex 12) ─────

_STATE_ACTION_RE = re.compile(
    r"(apply[_-]?discount|apply[_-]?coupon|refund|cancel|reopen|reactivate|"
    r"revert|rollback|re[_-]?process|re[_-]?charge|re[_-]?submit|re[_-]?activate)",
    re.I,
)
_STATE_RESOURCE_RE = re.compile(
    r"(order|payment|invoice|transaction|booking|subscription|charge|checkout)",
    re.I,
)
# Canonical state-mutation actions derived under a discovered resource
# instance (…/orders/ord_101 → …/orders/ord_101/apply_discount). ffuf
# wordlists are root-relative and cannot guess nested action sub-paths,
# so without derivation the action endpoint is never mined at all.
_STATE_ACTIONS = (
    "apply_discount",
    "apply_coupon",
    "refund",
    "cancel",
    "reopen",
    "reactivate",
    "revert",
    "rollback",
)
_INSTANCE_SEG_RE = re.compile(r"^(?:[a-z]+[_-])?\d+$|^\d+$|^[0-9a-f]{8,}(?:-[0-9a-f]+)+$", re.I)


def _t_state_invariant(mat: Dict[str, Any]) -> List[Dict[str, Any]]:
    """State Invariant Violation / impossible-problem:
    an action endpoint that mutates a resource accepts POST even when the
    resource is in a terminal state (PAID, CANCELLED, COMPLETED).

    Detect: fuzzed paths matching a state-mutation action verb on a resource
    type (order, payment, invoice, etc.). Probe with POST — if the endpoint
    acknowledges the action (200 + action-acknowledgment body), the state guard
    is absent.

    Also DERIVE canonical action sub-paths under a discovered resource
    instance (…/orders/ord_101 → …/apply_discount, …/refund, …): ffuf
    wordlists are root-relative and cannot guess nested action paths, so
    without derivation the action endpoint is never mined at all. Each
    derived card is an ordinary wire-verifiable candidate — a wrong
    guess 404s at verify and dies there.
    """
    out = []

    def _state_card(url: str) -> Dict[str, Any]:
        return {
            "assertion_a": f"state-machine contract: terminal-state resources must reject mutation (path: {url})",
            "assertion_b": f"no state guard observed — POST {url} may succeed regardless of current resource state",
            "source_a": "fuzzed_paths.txt",
            "line_a": 0,
            "source_b": "fuzzed_paths.txt",
            "line_b": 0,
            "check": (
                f"curl -i -s -X POST -H 'Content-Type: application/json' "
                f"-d '{{\"amount\":20}}' '{url}'"
            ),
            "expected": (
                "status 200, body contains any of "
                '"applied","discount_applied","success","accepted","processed",'
                '"refund","cancelled","completed","ok","result","total","credit"'
            ),
            "severity": "high",
        }

    seen: set = set()
    resource_instances: List[str] = []
    for line in sorted(set(mat["fuzzed"])):
        url, tag = _parse_bracketed(line)
        if not url:
            continue
        try:
            path = urllib.parse.urlsplit(url).path.lower()
        except Exception:
            continue
        segments = [seg for seg in path.split("/") if seg]
        if (
            len(segments) >= 2
            and _STATE_RESOURCE_RE.search(segments[-2])
            and _INSTANCE_SEG_RE.match(segments[-1])
            and not _STATE_ACTION_RE.search(segments[-1])
        ):
            resource_instances.append(url)
        if not _STATE_ACTION_RE.search(path):
            continue
        if not _STATE_RESOURCE_RE.search(path):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(_state_card(url))
    for base_url in resource_instances:
        for action in _STATE_ACTIONS:
            derived = base_url.rstrip("/") + "/" + action
            if derived in seen:
                continue
            seen.add(derived)
            out.append(_state_card(derived))
    return out[:10]


# ── registry ─────────────────────────────────────────────────────────────────

Template = Dict[str, Any]

TEMPLATES: List[Template] = [
    {
        "tid": "mirror-remembered-vs-live",
        "move": "paradox:mirror-that-remembers-differently / Consensus Equilibrium",
        "conflict": "remembered state vs live state of the same API",
        "reflex": "REFLEX 8: Logic Flaw & Underspecified Contract Violation",
        "mitre": "CWE-1068 / T1595",
        "impact": "Stale API version still routable — old auth/validation rules apply.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the old version was turned off.",
        "fn": _t_mirror,
    },
    {
        "tid": "vacuum-identity-decoupling",
        "move": "impossible:vacuum-consciousness / entity-decoupling",
        "conflict": "claimed privileged identity vs exhibited behavior",
        "reflex": "REFLEX 5: Broken Access Control",
        "mitre": "CWE-285 / T1190",
        "impact": "Privileged-named endpoint may not enforce the identity its name claims.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the name was the enforcement.",
        "fn": _t_vacuum,
    },
    {
        "tid": "observer-unwatched-watcher",
        "move": "paradox:observer-that-consumes-observation / Reflexive Singularity",
        "conflict": "published-operations claim vs live self-disclosure",
        "reflex": "REFLEX 1: Information Disclosure",
        "mitre": "CWE-200 / T1082",
        "impact": "GraphQL introspection/playground exposes the full schema to anyone.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the watcher was watched.",
        "fn": _t_observer,
    },
    {
        "tid": "single-token-symmetry-break",
        "move": "impossible:single-token-language / lies-break-symmetry",
        "conflict": "input-handling claim vs 500 on fuzzed input",
        "reflex": "REFLEX 3: Injection / Unhandled Input",
        "mitre": "CWE-20 / T1595",
        "impact": "Unhandled exception on crafted input — stack traces leak internals.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said every input was handled.",
        "fn": _t_single_token,
    },
    {
        "tid": "repulsive-gravity-axiom-rewrite",
        "move": "impossible:repulsive-gravity-universe / axiom-rewrite",
        "conflict": "one-route axiom vs two live spellings",
        "reflex": "REFLEX 5: Broken Access Control — path confusion",
        "mitre": "CWE-289 / T1190",
        "impact": "Auth middleware bound to one spelling; the other spelling bypasses it.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said both spellings were the same route.",
        "fn": _t_repulsive,
    },
    {
        "tid": "deathless-hierarchy",
        "move": "impossible:universe-without-death / hierarchical-retrieval",
        "conflict": "current-policy claim vs forgotten routable layer",
        "reflex": "REFLEX 7: Configuration Drift & Forgotten Surface",
        "mitre": "CWE-1068 / T1595",
        "impact": "Legacy/backup paths escape current access policy.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the old layer was decommissioned.",
        "fn": _t_deathless,
    },
    {
        "tid": "self-observing-equation",
        "move": "impossible:self-observing-equation / Level-5 metasynthesis",
        "conflict": "internals-not-exposed claim vs live self-observation endpoint",
        "reflex": "REFLEX 1: Information Disclosure",
        "mitre": "CWE-200 / T1082",
        "impact": "Health/metrics/debug endpoints leak versions, paths, environment.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the system couldn't observe itself.",
        "fn": _t_self_observing,
    },
    {
        "tid": "t1552-secrets-in-client",
        "move": "mitre:T1552 Unsecured Credentials",
        "conflict": "server-side-secrets claim vs secrets in shipped JS",
        "reflex": "REFLEX 5: Hardcoded Credential",
        "mitre": "CWE-798 / T1552",
        "impact": "API keys/tokens shipped to every visitor — credential exposure.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the bundle was secret-free.",
        "fn": _t_t1552,
    },
    {
        "tid": "t1082-spec-disclosure",
        "move": "mitre:T1082 System Information Discovery",
        "conflict": "need-to-know claim vs publicly served spec",
        "reflex": "REFLEX 1: Information Disclosure",
        "mitre": "CWE-200 / T1082",
        "impact": "Full API spec enumerates every route, parameter, and schema for attackers.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the map wasn't public.",
        "fn": _t_t1082,
    },
    {
        "tid": "t601-open-redirect-shape",
        "move": "mitre:CWE-601 Open Redirect shape",
        "conflict": "in-app-navigation claim vs referenced redirect flow",
        "reflex": "REFLEX 1: Open Redirect",
        "mitre": "CWE-601",
        "impact": "Client-controlled redirect target — phishing/OAuth theft primitive.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the target was validated.",
        "fn": _t_t601,
    },
    {
        "tid": "t1190-artifact-exposure",
        "move": "mitre:T1190 Exploit Public-Facing Application",
        "conflict": "routes-only claim vs artifact served with 200",
        "reflex": "REFLEX 1: Information Disclosure",
        "mitre": "CWE-538 / T1592",
        "impact": ".git/.env/package.json expose credentials, paths, dependency versions.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the artifacts weren't served.",
        "fn": _t_t1190_artifact,
    },
    {
        "tid": "listed-file-exposure",
        "move": "mitre:T1082 System Information Discovery / directory listing",
        "conflict": "routes-only claim vs listing-served document with 200",
        "reflex": "REFLEX 1: Information Disclosure",
        "mitre": "CWE-548 / T1082",
        "impact": "Directory listings expose documents, backups, and configs.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the listing wasn't browsable.",
        "fn": _t_listed_file,
    },
    {
        "tid": "code-mirror-config-drift",
        "move": "paradox:mirror-that-remembers-differently / Consensus Equilibrium (code)",
        "conflict": "config-remembered value vs code-lived value",
        "reflex": "REFLEX 7: Configuration Drift",
        "mitre": "CWE-1068",
        "impact": "Documented setting is not the enforced setting — policy decisions made on fiction.",
        "classification": "PARADOX",
        "applies": ("code",),
        "question": "You never said the config was the truth.",
        "fn": _t_code_mirror,
    },
    {
        "tid": "code-deathless-deprecated",
        "move": "impossible:universe-without-death / hierarchical-retrieval (code)",
        "conflict": "deprecated-means-dead claim vs live invocation",
        "reflex": "REFLEX 8: Logic Flaw",
        "mitre": "CWE-1068",
        "impact": "Deprecated code paths escape current review — unmaintained attack surface.",
        "classification": "PARADOX",
        "applies": ("code",),
        "question": "You never said deprecated meant unreachable.",
        "fn": _t_code_deathless,
    },
    {
        "tid": "code-sqli-raw-interpolation",
        "move": "mitre:T1190 / CWE-89 raw SQL query interpolation in source",
        "conflict": "parameterized-query contract vs direct string interpolation/concatenation",
        "reflex": "REFLEX 3: Injection — Raw SQL Query Interpolation",
        "mitre": "CWE-89 / T1190",
        "impact": "User-controlled variables concatenated or interpolated directly into SQL queries enable authentication bypass and data extraction.",
        "classification": "FIXABLE",
        "applies": ("code",),
        "question": "You never said the query string was parameterized.",
        "severity": "high",
        "fn": _t_code_sqli_sink,
    },
    {
        "tid": "code-cmdi-shell-exec",
        "move": "mitre:T1059 / CWE-78 unsafe shell or VM command execution in source",
        "conflict": "isolated-execution contract vs shell/VM evaluation of dynamic input",
        "reflex": "REFLEX 3: Injection — Command & VM Execution Sink",
        "mitre": "CWE-78 / T1059",
        "impact": "Dynamic input passed to shell execution or unisolated VM context enables arbitrary command/code execution.",
        "classification": "FIXABLE",
        "applies": ("code",),
        "question": "You never said the shell command was parameterized.",
        "severity": "high",
        "fn": _t_code_cmdi_sink,
    },
    {
        "tid": "code-unsafe-deserialization",
        "move": "mitre:T1190 / CWE-502 & CWE-611 unsafe deserialization or XXE in source",
        "conflict": "safe-parsing contract vs arbitrary object deserialization or external entity expansion",
        "reflex": "REFLEX 8: Insecure Deserialization & XXE",
        "mitre": "CWE-502 / T1190",
        "impact": "Untrusted data passed to pickle/unserialize or XML parser with external entities enabled leads to RCE or file disclosure.",
        "classification": "FIXABLE",
        "applies": ("code",),
        "question": "You never said the deserializer restricted object types.",
        "severity": "high",
        "fn": _t_code_deserial_sink,
    },
    {
        "tid": "beautiful-liar-trust-bypass",
        "move": "philosophy:the-beautiful-liar / trust-claim bypass",
        "conflict": "server-side role validation claim vs client-injectable header trusted as proof",
        "reflex": "REFLEX 9: Trust-Claim Bypass — the story the server tells about enforcement is a lie",
        "mitre": "CWE-290 / T1550",
        "impact": "Any client can forge the role header and access privileged endpoints without real credentials.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the server verified the role claim — only that the UI sends it.",
        "severity": "high",
        "fn": _t_beautiful_liar,
    },
    {
        "tid": "cliff-and-current-alt-path",
        "move": "philosophy:the-cliff-and-the-current / alternate-path auth gap",
        "conflict": "auth middleware coverage claim vs unguarded alternate route",
        "reflex": "REFLEX 10: Alternate-Path Auth Gap — the current flows around the protected path",
        "mitre": "CWE-288 / T1190",
        "impact": "Documented endpoint enforces auth; alternate path serves identical data without any check.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the auth check runs on THIS path — only the documented one.",
        "severity": "high",
        "fn": _t_cliff_and_current,
    },
    {
        "tid": "invisible-architect-infra-exposure",
        "move": "philosophy:the-invisible-architect / forgotten-infrastructure seam",
        "conflict": "infrastructure-not-public claim vs accessible build/config/dependency artifacts",
        "reflex": "REFLEX 11: Forgotten Infrastructure — builder disappeared, scaffolding stayed",
        "mitre": "CWE-538 / T1592",
        "impact": "Dependency manifests, lockfiles, build configs, backup files expose internal stack and credentials.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the scaffolding was secret — only the app was.",
        "severity": "medium",
        "fn": _t_invisible_architect,
    },
    {
        "tid": "injection-sqli-probe",
        "move": "mitre:T1190 Exploit Public-Facing Application / error-based SQLi",
        "conflict": "input-handling claim vs SQL error/bypass on crafted input",
        "reflex": "REFLEX 3: Injection — SQL error and auth bypass",
        "mitre": "CWE-89 / T1190",
        "impact": "Crafted input breaks the backend query (error disclosure) or bypasses authentication — injectable endpoint.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the query was parameterized.",
        "severity": "high",
        "fn": _t_sqli,
    },
    {
        "tid": "injection-xss-probe",
        "move": "mitre:T1190 / reflected and persisted XSS",
        "conflict": "output-encoding claim vs unescaped reflection of crafted input",
        "reflex": "REFLEX 3: Injection — XSS reflection",
        "mitre": "CWE-79 / T1190",
        "impact": "Crafted script input is reflected unescaped (reflected XSS) or stored and served back (persisted XSS).",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the output was encoded.",
        "severity": "high",
        "fn": _t_xss_reflect,
    },
    {
        "tid": "dom-xss-rendered-differential",
        "move": "impossible:rendered-mirror / browser-as-oracle",
        "conflict": "raw HTTP body vs rendered DOM for the same probe",
        "reflex": "REFLEX 3: Injection — DOM XSS reflection",
        "mitre": "CWE-79 / T1189",
        "impact": "Script probe executes only after JS rendering — invisible to raw-response checks.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the response was the page.",
        "severity": "high",
        "fn": _t_dom_xss,
    },
    {
        "tid": "csrf-form-replay-sqli",
        "move": "mitre:T1190 / error-based SQLi behind a CSRF gate",
        "conflict": "CSRF-gate safety claim vs database error on tokened replay",
        "reflex": "REFLEX 3: Injection — SQLi via form replay",
        "mitre": "CWE-89 / T1190",
        "impact": "POST form with a CSRF token still concatenates input into SQL — tokened replay returns a database error.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the token parameterized the query.",
        "severity": "high",
        "fn": _t_csrf_sqli,
    },
    {
        "tid": "idor-direct-object-reference",
        "move": "mitre:T1190 / CWE-639 authorization bypass through user-controlled key",
        "conflict": "per-user-authorization claim vs addressable object space with no session",
        "reflex": "REFLEX 5: Broken Access Control — missing object-level authorization",
        "mitre": "CWE-639 / T1190",
        "impact": "Object references serve per-user records without any session — any client can enumerate other users' objects.",
        "classification": "FIXABLE",
        "applies": ("web",),
        "question": "You never said the object IDs were authorized.",
        "severity": "high",
        "fn": _t_idor,
    },
    {
        "tid": "state-invariant-violation",
        "move": "impossible:state-machine-without-terminal / axiom-rewrite",
        "conflict": "state-machine contract claim vs unguarded mutation action",
        "reflex": "REFLEX 12: Business Logic — State Machine Violation",
        "mitre": "CWE-840 / T1190",
        "impact": "State-mutation endpoint accepts POST on terminal-state resource — discounts/refunds applicable to PAID/CANCELLED orders.",
        "classification": "PARADOX",
        "applies": ("web",),
        "question": "You never said the server checks the current state before applying the action.",
        "severity": "high",
        "fn": _t_state_invariant,
    },
]


# ── runner ───────────────────────────────────────────────────────────────────


# Chain vocabulary: what each seam EXPOSES (chain_outputs) and REQUIRES
# (chain_preconditions). The chain engine links A->B when an output of A is a
# declared precondition of B, compounding severity. Shared token vocabulary so
# info-leaks (endpoint / internal_host / secret) feed the access templates.
_CHAIN_IO: Dict[str, Dict[str, List[str]]] = {
    "self-observing-equation": {
        "out": ["endpoint", "internal_host", "secret"],
        "pre": [],
    },
    "t1190-artifact-exposure": {
        "out": ["secret", "internal_host", "source"],
        "pre": [],
    },
    "listed-file-exposure": {
        "out": ["document", "internal_host"],
        "pre": [],
    },
    "t1082-spec-disclosure": {"out": ["endpoint", "api_route"], "pre": []},
    "observer-unwatched-watcher": {
        "out": ["endpoint", "api_route", "schema"],
        "pre": [],
    },
    "t1552-secrets-in-client": {"out": ["secret", "token", "api_key"], "pre": []},
    "single-token-symmetry-break": {"out": ["internal_host", "stack"], "pre": []},
    "vacuum-identity-decoupling": {
        "out": ["admin_data", "user_id"],
        "pre": ["endpoint", "internal_host"],
    },
    "beautiful-liar-trust-bypass": {
        "out": ["admin_data", "user_id"],
        "pre": ["endpoint"],
    },
    "cliff-and-current-alt-path": {
        "out": ["protected_data", "user_id"],
        "pre": ["endpoint"],
    },
    "mirror-remembered-vs-live": {"out": ["legacy_access"], "pre": ["api_route"]},
    "deathless-hierarchy": {"out": ["legacy_data"], "pre": ["endpoint"]},
    "repulsive-gravity-axiom-rewrite": {"out": ["bypass_access"], "pre": ["api_route"]},
    "t601-open-redirect-shape": {"out": ["redirect"], "pre": ["endpoint"]},
    "injection-sqli-probe": {
        "out": ["user_id", "internal_host"],
        "pre": ["endpoint", "api_route"],
    },
    "injection-xss-probe": {"out": ["user_id"], "pre": ["endpoint"]},
    "idor-direct-object-reference": {
        "out": ["protected_data", "user_id"],
        "pre": ["endpoint"],
    },
    "state-invariant-violation": {
        "out": ["business_logic_bypass"],
        "pre": ["endpoint"],
    },
    "code-mirror-config-drift": {"out": ["secret", "internal_host"], "pre": []},
    "code-deathless-deprecated": {"out": ["legacy_access"], "pre": []},
    "code-sqli-raw-interpolation": {
        "out": ["user_id", "protected_data", "admin_data"],
        "pre": [],
    },
    "code-cmdi-shell-exec": {
        "out": ["internal_host", "secret", "admin_data"],
        "pre": [],
    },
    "code-unsafe-deserialization": {
        "out": ["admin_data", "secret"],
        "pre": [],
    },
    "invisible-architect-infra-exposure": {
        "out": ["secret", "internal_host", "source"],
        "pre": [],
    },
    "dom-xss-rendered-differential": {"out": ["user_id"], "pre": ["endpoint"]},
    "csrf-form-replay-sqli": {
        "out": ["user_id", "internal_host"],
        "pre": ["endpoint"],
    },
}


def _card(
    t: Template, p: Dict[str, Any], program: Optional[Dict], n: int
) -> Dict[str, Any]:
    prog_name = (program or {}).get("name", "")
    prog_platform = (program or {}).get("platform", "")
    cid = f"T{n:03d}"
    raw = (
        f"SEAM {cid}: [{t['classification']}] {t['reflex']}\n"
        f"REFLEX: {t['reflex']}\n"
        f"MITRE: {t['mitre']}\n"
        f"TEMPLATE: {t['tid']} — {t['move']}\n"
        f"ASSERTION A: {p['assertion_a']} ({Path(str(p['source_a'])).name}:{p['line_a']})\n"
        f"ASSERTION B: {p['assertion_b']} ({Path(str(p['source_b'])).name}:{p['line_b']})\n"
        f"IMPACT: {t['impact']}\n"
    )
    if prog_name:
        raw += f"PROGRAM: {prog_name} [{prog_platform}]\n"
    raw += (
        f"CHECK: {p['check']}\nPARADOX QUESTION: {t['question']}\nVERDICT: CANDIDATE\n"
    )
    # Default expected: existence-probe templates assert the endpoint responds
    # (status 200). Body-content templates override this inline when they need
    # a body predicate too. Gate 3 of verify_seam_card requires a status code
    # — without this field every template seam is unconditionally rejected.
    _expected = p.get("expected") or "status 200"
    return {
        "n": n,
        "id": cid,
        "classification": t["classification"],
        "claim_type": t["tid"],
        "reflex": t["reflex"],
        "mitre": t["mitre"],
        "impact": t["impact"],
        "severity": p.get("severity") or t.get("severity") or "medium",
        "chain_outputs": _CHAIN_IO.get(t["tid"], {}).get("out", []),
        "chain_preconditions": _CHAIN_IO.get(t["tid"], {}).get("pre", []),
        "assertion_a": p["assertion_a"],
        "assertion_b": p["assertion_b"],
        "assertion_a_source": str(p["source_a"]),
        "source_a": str(p["source_a"]),
        "line_a": p["line_a"],
        "source_b": str(p["source_b"]),
        "line_b": p["line_b"],
        "check": p["check"],
        "expected": _expected,
        "verdict": p.get("verdict") or "CANDIDATE",
        "render_marker": p.get("render_marker", ""),
        "csrf_field": p.get("csrf_field", ""),
        "question": t["question"],
        "check_output": p.get("check_output", ""),
        "program": prog_name,
        "platform": prog_platform,
        "raw": raw.strip(),
        "origin": "seam-template",
        "lens": "seam-template",
    }


def _family(tid: str) -> str:
    """Group template variants into a common family by stripping terminal numeric suffixes."""
    if not tid:
        return ""
    return re.sub(r"[_-]\d+$", "", str(tid))


def scan_template_seams(
    recon_dir: Optional[Path] = None,
    repo_path: Optional[Path] = None,
    program: Optional[Dict] = None,
    scope_gate=None,
    errors: Optional[List[Dict[str, Any]]] = None,
    auth: Optional[str] = None,
    max_per_family: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Hunt paradox/TTP-derived conflict shapes against material on disk.
    Pure function of files: no LLM, no network. Scope-gated check URLs.
    Returns seam cards in oracle_code_seam format (origin='seam-template').

    scope_gate is REQUIRED (fail-closed): a None gate raises ValueError
    instead of treating every URL as in-scope. Pass the hunt's
    ProgramScopeGate; tests use one with a loopback target_fallback.

    errors is an optional out-param (#15): every template exception is
    recorded as {"tid", "error"} there (and the hunt continues with the
    remaining templates). A broken template must show up in the report
    as missing coverage, never as a silent gap.
    """
    if scope_gate is None:
        raise ValueError(
            "scan_template_seams requires an explicit scope gate "
            "(fail-closed: no gate, no cards)"
        )
    if max_per_family is None:
        # Coverage contract: no implicit family cap at the library layer.
        # A default cap silently starved the tail of same-family sources
        # (30 crawled pages -> last page lost its primary). The cap is a
        # regime decision: program.hunt_config (or the live config plumbed
        # by cmd_hunt) must arm it explicitly.
        max_per_family = 0
        if program and isinstance(program, dict):
            _cfg_cap = program.get("hunt_config", {}).get(
                "max_cards_per_family"
            )
            if _cfg_cap is not None:
                max_per_family = _cfg_cap

    mat = _build_material(recon_dir, repo_path)
    web_ok = _has_web(mat)
    wall_hosts = mat.get("wall_hosts") or set()
    wall_drops = 0
    family_counts: Dict[str, int] = {}
    capped_families: set = set()
    out: List[Dict[str, Any]] = []
    seen: set = set()  # dedup: a path in BOTH js_endpoints and fuzzed must not
    # yield the same (template, check) card twice
    for t in TEMPLATES:
        applies = t["applies"]
        if "web" in applies and not web_ok:
            continue
        if "code" in applies and mat["repo"] is None:
            continue
        try:
            partials = t["fn"](mat)
        except Exception as exc:
            # one bad template never kills the hunt — but it is recorded,
            # not swallowed (#15): silent gaps read as clean coverage.
            if errors is not None:
                errors.append(
                    {"tid": t["tid"], "error": f"{type(exc).__name__}: {exc}"}
                )
            continue
        for p in partials:
            fam = _family(t["tid"])
            if max_per_family > 0 and family_counts.get(fam, 0) >= max_per_family:
                capped_families.add(fam)
                continue
            check = p.get("check", "")
            url = _check_url(check)
            if url and not _url_in_scope(url, scope_gate):
                continue  # scope wall: out-of-scope check URLs are dropped
            if url and wall_hosts and not auth:
                check_host = (urllib.parse.urlparse(url).hostname or "").lower()
                if check_host in wall_hosts:
                    wall_drops += 1
                    continue
            key = (t["tid"], check)
            if key in seen:
                continue
            seen.add(key)
            family_counts[fam] = family_counts.get(fam, 0) + 1
            out.append(_card(t, p, program, len(out) + 1))
    if wall_drops > 0:
        try:
            from oracle_hunter import _info
            _info(f"Auth-filter: dropped {wall_drops} card(s) — host returned wall code in recon")
        except Exception:
            pass
    if capped_families:
        try:
            from oracle_hunter import _info
            _info(f"Mint-cap: capped {len(capped_families)} template families at {max_per_family} cards/family")
        except Exception:
            pass
    return out


def template_ids() -> List[str]:
    return [t["tid"] for t in TEMPLATES]
