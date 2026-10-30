#!/usr/bin/env python3
"""Oracle's own HackerOne re-scan (authenticated Hacker API).

No network: ``_request_json`` is faked at its seam. Locks:
  - missing/rejected Oracle credentials are fatal, never "program vanished";
  - structured scopes are shaped like Scan4Me's bridge output;
  - ineligible scopes become out_of_scope, not current in-scope assets;
  - provenance records the API source without ever carrying the token;
  - scan records the independent re-scan per verdict and propagates failures.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_h1_api as h1
import oracle_intake as intake


def _program_payload():
    return {
        "data": {
            "attributes": {
                "name": "Acme",
                "handle": "acme",
                "policy": "RULES v1",
                "triage_active": True,
            }
        }
    }


def _scopes_payload():
    return {
        "data": [
            {
                "attributes": {
                    "asset_identifier": "app.example.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                    "instruction": "primary",
                }
            },
            {
                "attributes": {
                    "asset_identifier": "old.example.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": False,
                    "eligible_for_submission": True,
                    "instruction": "no longer eligible",
                }
            },
        ],
        "links": {"next": None},
    }


def _creds(monkeypatch):
    monkeypatch.setenv("HACKERONE_USERNAME", "oracle-user")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "secret-token")


def test_fetch_program_requires_oracle_credentials(monkeypatch):
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.delenv("HACKERONE_API_KEY", raising=False)
    monkeypatch.setattr(h1, "_ENV_FILES", ())
    assert h1.available() is False
    with pytest.raises(h1.H1AuthError, match="credentials missing"):
        h1.fetch_program("acme")


def test_credentials_fall_back_to_layered_key_files(tmp_path, monkeypatch):
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.delenv("HACKERONE_API_KEY", raising=False)
    lower = tmp_path / "trio.env"
    lower.write_text("HACKERONE_USERNAME=lower-user\nHACKERONE_API_KEY=lower-key\n")
    upper = tmp_path / "repo.env"
    upper.write_text("HACKERONE_API_TOKEN=not a real key placeholder\n")
    monkeypatch.setattr(h1, "_ENV_FILES", (lower, upper))
    # Placeholder sentence never clobbers; API_KEY is the token fallback.
    assert h1.credentials() == ("lower-user", "lower-key")
    monkeypatch.setenv("HACKERONE_API_TOKEN", "env-token")
    assert h1.credentials() == ("lower-user", "env-token")


def test_fetch_program_maps_scopes_and_provenance(monkeypatch):
    _creds(monkeypatch)
    calls = []

    def fake_request(path_or_url, *, username, token, timeout):
        calls.append((path_or_url, username, token))
        if path_or_url.endswith("/structured_scopes?page%5Bsize%5D=100"):
            return _scopes_payload()
        if path_or_url.endswith("/hackers/programs/acme"):
            return _program_payload()
        raise AssertionError(f"unexpected path: {path_or_url}")

    monkeypatch.setattr(h1, "_request_json", fake_request)
    prog = h1.fetch_program("Acme")
    assert prog is not None
    assert prog["handle"] == "acme"
    assert prog["platform"] == "HackerOne"
    assert prog["rules_text"] == "RULES v1"
    assert [s["asset_identifier"] for s in prog["structured_scopes"]] == [
        "app.example.com"
    ]
    assert prog["out_of_scope"] == ["old.example.com"]
    prov = prog["_oracle_rescan"]
    assert prov["source"] == "hackerone-api-authenticated"
    assert prov["independent"] is True
    assert prov["scope_count"] == 1
    assert "secret-token" not in json.dumps(prov)
    assert all(token == "secret-token" for _, _, token in calls)


def test_fetch_program_404_is_vanished_not_auth_error(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setattr(h1, "_request_json", lambda *a, **kw: None)
    assert h1.fetch_program("gone") is None


def test_fetch_program_keeps_full_out_of_scope_records(monkeypatch):
    _creds(monkeypatch)

    def fake_request(path_or_url, *, username, token, timeout):
        if "structured_scopes" in path_or_url:
            return _scopes_payload()
        return _program_payload()

    monkeypatch.setattr(h1, "_request_json", fake_request)
    prog = h1.fetch_program("acme")
    assert prog["out_of_scope"] == ["old.example.com"]
    oos = prog["out_of_scope_scopes"]
    assert [s["asset_identifier"] for s in oos] == ["old.example.com"]
    assert oos[0]["eligible_for_bounty"] is False
    assert oos[0]["instruction"] == "no longer eligible"


def test_missing_eligibility_fields_fail_closed(monkeypatch):
    _creds(monkeypatch)

    def fake_request(path_or_url, *, username, token, timeout):
        if "structured_scopes" in path_or_url:
            return {
                "data": [
                    {"attributes": {"asset_identifier": "mystery.example.com",
                                     "asset_type": "URL"}}
                ],
                "links": {"next": None},
            }
        return _program_payload()

    monkeypatch.setattr(h1, "_request_json", fake_request)
    prog = h1.fetch_program("acme")
    assert prog["structured_scopes"] == []
    assert prog["out_of_scope"] == ["mystery.example.com"]


def test_fetch_program_404_scopes_on_live_program_is_fatal(monkeypatch):
    _creds(monkeypatch)

    def fake_request(path_or_url, *, username, token, timeout):
        if path_or_url.endswith("/hackers/programs/acme"):
            return _program_payload()
        return None

    monkeypatch.setattr(h1, "_request_json", fake_request)
    with pytest.raises(h1.H1APIError, match="structured_scopes returned 404"):
        h1.fetch_program("acme")


def test_program_404_wins_even_if_scopes_still_return(monkeypatch):
    _creds(monkeypatch)

    def fake_request(path_or_url, *, username, token, timeout):
        if path_or_url.endswith("/hackers/programs/acme"):
            return None
        return _scopes_payload()

    monkeypatch.setattr(h1, "_request_json", fake_request)
    assert h1.fetch_program("acme") is None


def test_fetch_program_refuses_partial_pagination(monkeypatch):
    _creds(monkeypatch)
    first = _scopes_payload()
    first["links"] = {"next": "https://api.hackerone.com/v1/next-page"}

    def fake_request(path_or_url, *, username, token, timeout):
        if path_or_url.endswith("/structured_scopes?page%5Bsize%5D=100"):
            return first
        if path_or_url.endswith("/next-page"):
            return {"data": [], "links": {"next": None}}
        if path_or_url.endswith("/hackers/programs/acme"):
            return _program_payload()
        raise AssertionError(path_or_url)

    monkeypatch.setattr(h1, "_request_json", fake_request)
    prog = h1.fetch_program("acme")
    assert prog is not None
    assert prog["_oracle_rescan"]["scope_pages"] == 2


def test_oracle_rescan_unions_known_oos(monkeypatch):
    _creds(monkeypatch)

    def fake_fetch(handle):
        return {
            "name": "Acme",
            "handle": handle,
            "platform": "HackerOne",
            "structured_scopes": [
                {
                    "asset_identifier": "app.example.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                }
            ],
            "out_of_scope": ["new.example.com"],
            "rules_text": "",
            "_oracle_rescan": {
                "source": "hackerone-api-authenticated",
                "independent": True,
            },
        }

    monkeypatch.setattr(h1, "fetch_program", fake_fetch)
    fresh, meta = intake.oracle_rescan(
        {
            "platform": "HackerOne",
            "handle": "acme",
            "out_of_scope": ["old.example.com"],
        }
    )
    assert fresh is not None
    assert fresh["out_of_scope"] == ["new.example.com", "old.example.com"]
    assert meta["independent"] is True
    assert meta["out_of_scope_union"] == ["old.example.com"]


def _trusted_feed(monkeypatch):
    monkeypatch.setattr(
        intake,
        "feed_provenance_block",
        lambda: {
            "refresh_ok": True,
            "age_hours": 1.0,
            "stale": False,
            "platforms": {
                "hackerone": {
                    "count": 1,
                    "source": "authenticated",
                    "status": "ok",
                }
            },
        },
    )


def _prescan_fields():
    prov = {
        "refresh_ok": True,
        "age_hours": 1.0,
        "stale": False,
        "platforms": {
            "hackerone": {
                "count": 1,
                "source": "authenticated",
                "status": "ok",
            }
        },
    }
    return {"feed_provenance": prov, "feed_trust": intake.feed_trust_block(prov)}


def test_scan_records_independent_rescan_and_propagates_failure(tmp_path, monkeypatch):
    _trusted_feed(monkeypatch)
    prescan = {
        "programs": [
            {
                "name": "Acme",
                "handle": "acme",
                "platform": "HackerOne",
                "structured_scopes": [],
                "out_of_scope": [],
                "max_payout_usd": 1000,
                "currency": "USD",
            }
        ],
        **_prescan_fields(),
    }

    def vanished(snap):
        return None, {
            "source": "hackerone-api-authenticated",
            "independent": True,
            "found": False,
        }

    report = intake.run_scan(
        prescan,
        out_dir=tmp_path,
        stamp="rescan",
        require_trusted_prescan=True,
        rescan_fn=vanished,
    )
    assert report["oracle_rescan"]["independent"] is True
    assert report["verdicts"][0]["oracle_rescan"]["found"] is False
    assert report["verdicts"][0]["verdict"] == "unverified"

    def rejected(snap):
        raise RuntimeError("HackerOne API rejected credentials")

    with pytest.raises(RuntimeError, match="Oracle re-scan failed for acme"):
        intake.run_scan(
            prescan,
            out_dir=tmp_path,
            stamp="rejected",
            require_trusted_prescan=True,
            rescan_fn=rejected,
        )


def _h1_prescan(tmp_path):
    import json as _json

    prescan = tmp_path / "prescan_1.json"
    prescan.write_text(
        _json.dumps(
            {
                "programs": [
                    {
                        "name": "Acme",
                        "handle": "acme",
                        "platform": "HackerOne",
                        "structured_scopes": [],
                        "out_of_scope": [],
                        "max_payout_usd": 1000,
                        "currency": "USD",
                    }
                ],
                **_prescan_fields(),
            }
        )
    )
    return prescan


def test_product_scan_without_h1_credentials_fails_before_dispatch(
    tmp_path, monkeypatch
):
    """No API keys AND no CDP browser → fail loud before dispatch.

    The browser IS a credential path (the operator's signed-in session); a
    scan with neither path would silently mint an all-unverified report, so
    the preflight must die instead. "No browser" is the premise, so both CDP
    probes are pinned to None — deterministic on machines that do have a
    Chrome binary.
    """
    import types

    import oracle_hunter as oh
    import oracle_intake as _intake

    _trusted_feed(monkeypatch)
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.delenv("HACKERONE_API_KEY", raising=False)
    monkeypatch.setattr(h1, "_ENV_FILES", ())
    # Premise: no CDP browser is reachable and none can be started.
    monkeypatch.setattr(_intake, "_cdp_tabs", lambda port: None)
    monkeypatch.setattr(
        _intake, "_cdp_ensure_browser", lambda port=_intake._CDP_DEFAULT_PORT: None
    )
    prescan = _h1_prescan(tmp_path)
    args = types.SimpleNamespace(
        prescan_file=str(prescan),
        out_dir=str(tmp_path),
        cloud=True,
        probe_timeout=1,
        no_cloud=False,
        sites=None,
        top_n=None,
        config=None,
    )
    with pytest.raises(SystemExit) as excinfo:
        oh.cmd_scan(args)
    assert excinfo.value.code == 1


def test_product_scan_without_h1_credentials_proceeds_with_cdp_browser(
    tmp_path, monkeypatch
):
    """No API keys but a CDP browser IS available → scan proceeds via CDP.

    The browser session replaces the API key as the credential path; the
    scan must not die. With no structured scope readable from the page the
    rescan returns a clean miss, so the program stays unverified and the
    scan completes normally.
    """
    import types

    import oracle_hunter as oh
    import oracle_intake as _intake

    _trusted_feed(monkeypatch)
    monkeypatch.delenv("HACKERONE_USERNAME", raising=False)
    monkeypatch.delenv("HACKERONE_API_TOKEN", raising=False)
    monkeypatch.delenv("HACKERONE_API_KEY", raising=False)
    monkeypatch.setattr(h1, "_ENV_FILES", ())
    # Premise: a CDP browser is reachable.
    monkeypatch.setattr(
        _intake, "_cdp_tabs", lambda port: [{"type": "page", "url": "about:blank"}]
    )
    # Premise: the page yields no structured scope → clean miss per program.
    monkeypatch.setattr(_intake, "_cdp_rescan_program", lambda handle: None)
    prescan = _h1_prescan(tmp_path)
    args = types.SimpleNamespace(
        prescan_file=str(prescan),
        out_dir=str(tmp_path),
        cloud=True,
        probe_timeout=1,
        no_cloud=False,
        sites=None,
        top_n=None,
        config=None,
    )
    try:
        oh.cmd_scan(args)
    except SystemExit as exc:  # pragma: no cover - diagnostic aid
        raise AssertionError(
            f"cmd_scan must proceed with a CDP browser available; exited {exc.code}"
        )


def test_verified_h1_scope_feeds_deep_dive_without_bridge(tmp_path, monkeypatch):
    _trusted_feed(monkeypatch)
    prescan = {
        "programs": [
            {
                "name": "Acme",
                "handle": "acme",
                "platform": "HackerOne",
                "structured_scopes": [
                    {
                        "asset_identifier": "old.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                    }
                ],
                "out_of_scope": ["old-oos.example.com"],
                "max_payout_usd": 1000,
                "currency": "USD",
            }
        ],
        **_prescan_fields(),
    }

    def h1_rescan(snap):
        return (
            {
                "name": "Acme",
                "handle": "acme",
                "platform": "HackerOne",
                "structured_scopes": [
                    {
                        "asset_identifier": "new.example.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True,
                    }
                ],
                "out_of_scope": ["old-oos.example.com"],
                "rules_text": "RULES v1",
                "policy": "RULES v1",
            },
            {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": True,
            },
        )

    report = intake.run_scan(
        prescan,
        out_dir=tmp_path,
        stamp="h1-dive",
        require_trusted_prescan=True,
        rescan_fn=h1_rescan,
        probe_fn=lambda host, timeout: {
            "host": host,
            "resolves": True,
            "live": True,
        },
    )
    assert report["verdicts"][0]["verdict"] == "verified"
    assert (
        report["verdicts"][0]["_fresh"]["structured_scopes"][0]["asset_identifier"]
        == "new.example.com"
    )

    def must_not_call(_key):
        raise AssertionError("deep-dive re-resolved through the bridge")

    selection = intake.select_deep_dive(
        report,
        prescan_programs=prescan["programs"],
        top_n=1,
        resolve_fn=must_not_call,
    )
    entry = selection["ranked_verified"][0]
    idents = [s["asset_identifier"] for s in entry["deep_dive"]["assets"]]
    assert idents == ["new.example.com"]
    assert entry["oracle_rescan"]["independent"] is True
    assert "scan-rescan:hackerone-api-authenticated" in entry["deep_dive"]["sources"]


def test_scan_reports_mixed_rescan_provenance(tmp_path, monkeypatch):
    _trusted_feed(monkeypatch)
    prescan = {
        "programs": [
            {
                "name": "Acme",
                "handle": "acme",
                "platform": "HackerOne",
                "structured_scopes": [],
                "out_of_scope": [],
            },
            {
                "name": "Beta",
                "handle": "beta",
                "platform": "Bugcrowd",
                "structured_scopes": [],
                "out_of_scope": [],
            },
        ],
        **_prescan_fields(),
    }

    def rescan(snap):
        if snap["platform"] == "HackerOne":
            return None, {
                "source": "hackerone-api-authenticated",
                "independent": True,
                "found": False,
            }
        return None, {
            "source": "scan4me-db",
            "independent": False,
            "found": False,
        }

    report = intake.run_scan(
        prescan,
        out_dir=tmp_path,
        stamp="mixed",
        require_trusted_prescan=True,
        rescan_fn=rescan,
    )
    summary = report["oracle_rescan"]
    assert summary["mode"] == "mixed"
    assert summary["independent"] is False
    assert summary["programs"] == 2
    assert summary["independent_programs"] == 1
    assert summary["sources"] == [
        "hackerone-api-authenticated",
        "scan4me-db",
    ]


def test_exact_max_pages_is_not_a_partial_scope_error(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setattr(h1, "MAX_PAGES", 2)
    first = _scopes_payload()
    first["links"] = {"next": "https://api.hackerone.com/v1/page-2"}
    second = _scopes_payload()
    second["links"] = {"next": None}

    def fake_request(path_or_url, *, username, token, timeout):
        if path_or_url.endswith("/structured_scopes?page%5Bsize%5D=100"):
            return first
        if path_or_url.endswith("/page-2"):
            return second
        if path_or_url.endswith("/hackers/programs/acme"):
            return _program_payload()
        raise AssertionError(path_or_url)

    monkeypatch.setattr(h1, "_request_json", fake_request)
    prog = h1.fetch_program("acme")
    assert prog is not None
    assert prog["_oracle_rescan"]["scope_pages"] == 2


def test_pagination_still_open_at_max_pages_is_fatal(monkeypatch):
    _creds(monkeypatch)
    monkeypatch.setattr(h1, "MAX_PAGES", 2)
    first = _scopes_payload()
    first["links"] = {"next": "https://api.hackerone.com/v1/page-2"}
    second = _scopes_payload()
    second["links"] = {"next": "https://api.hackerone.com/v1/page-3"}

    def fake_request(path_or_url, *, username, token, timeout):
        if path_or_url.endswith("/structured_scopes?page%5Bsize%5D=100"):
            return first
        if path_or_url.endswith("/page-2"):
            return second
        if path_or_url.endswith("/hackers/programs/acme"):
            return _program_payload()
        raise AssertionError(path_or_url)

    monkeypatch.setattr(h1, "_request_json", fake_request)
    with pytest.raises(h1.H1APIError, match="exceeded 2 pages"):
        h1.fetch_program("acme")


def test_hackerone_scope_fetch_prefers_authenticated_api(monkeypatch):
    import oracle_bulk_download as bulk

    monkeypatch.setattr(h1, "available", lambda: True)
    monkeypatch.setattr(
        h1,
        "fetch_program",
        lambda handle: {
            "structured_scopes": [
                {
                    "asset_identifier": "app.example.com",
                    "asset_type": "URL",
                    "eligible_for_bounty": True,
                    "eligible_for_submission": True,
                }
            ]
        },
    )
    scopes = bulk._fetch_hackerone_scopes(
        {"url": "https://hackerone.com/acme", "name": "Acme"}
    )
    assert [s["asset_identifier"] for s in scopes] == ["app.example.com"]


def test_request_json_never_follows_redirects(monkeypatch):
    import urllib.error
    import urllib.request

    seen = {"handlers": None, "opens": 0}

    class _FakeOpener:
        def open(self, req, timeout=None):
            seen["opens"] += 1
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", hdrs=None, fp=None
            )

    def fake_build_opener(*handlers):
        seen["handlers"] = handlers
        return _FakeOpener()

    def forbidden_urlopen(*a, **kw):
        raise AssertionError("default urlopen follows redirects with credentials")

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_urlopen)
    with pytest.raises(h1.H1APIError):
        h1._request_json(
            "/hackers/programs/acme", username="oracle-user", token="secret-token"
        )
    assert seen["opens"] == 1  # the redirect target is never requested
    redirect_handlers = [
        hd() if isinstance(hd, type) else hd
        for hd in seen["handlers"]
        if (isinstance(hd, type) and issubclass(hd, urllib.request.HTTPRedirectHandler))
        or isinstance(hd, urllib.request.HTTPRedirectHandler)
    ]
    assert redirect_handlers, "opener must install a redirect handler"
    assert redirect_handlers[0].redirect_request(
        None, None, 302, "Found", {}, "https://evil.example.com/"
    ) is None
