#!/usr/bin/env python3
"""Wall gaps 4.1 (DOM XSS rendered differential) + 4.3 (CSRF form replay).

Loopback only: stub origins bind 127.0.0.1 ephemeral ports. The DOM stub
reflects the probe ONLY via JavaScript (raw body is clean); the CSRF stub
403s tokenless POSTs and emits a SQL error on tokened quote replays.
"""

import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_hunter as oh
import oracle_rendered as rnd
from oracle_deterministic import (
    extract_status_from_curl_output,
    verify_seam_card,
)
from oracle_harvest import confirm_form_replay
from oracle_hunter import ProgramScopeGate

import pytest

MARK = rnd.DOM_MARKER
requires_rendered_browser = pytest.mark.skipif(
    not rnd.rendered_available(),
    reason="Playwright/Chromium not available for rendered discovery",
)


class _DomStub(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        probe = qs.get("q", [""])[0]
        # Raw body never contains the probe: reflection happens only in JS.
        page = (
            "<html><body><div id=t></div><script>"
            "const p=new URLSearchParams(location.search).get('q')||'';"
            "document.getElementById('t').innerHTML=p;"
            "</script></body></html>"
        )
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _CsrfStub(BaseHTTPRequestHandler):
    TOKEN = "tok257"

    def do_GET(self):
        page = (
            '<html><body><form method="post" action="/form">'
            f'<input type="hidden" name="csrfmiddlewaretoken" value="{self.TOKEN}">'
            '<input type="text" name="username" value="">'
            '<input type="submit" value="Go"></form></body></html>'
        )
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"csrftoken={self.TOKEN}; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        fields = urllib.parse.parse_qs(self.rfile.read(length).decode())
        token = fields.get("csrfmiddlewaretoken", [""])[0]
        if token != self.TOKEN:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"CSRF verification failed")
            return
        user = fields.get("username", [""])[0]
        if "'" in user:
            body = b"<html>error in your SQL syntax near '''</html>"
        else:
            body = b"<html>ok</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _base(server):
    return f"http://127.0.0.1:{server.server_port}"


# ── 4.1 rendered differential ───────────────────────────────────────────────


@requires_rendered_browser
def test_rendered_differential_finds_js_only_reflection():
    server = _serve(_DomStub)
    try:
        url = f"{_base(server)}/page?q={rnd.DOM_PAYLOAD}"
        obs = rnd.rendered_reflection(url, MARK)
        assert obs["error"] == ""
        assert obs["raw_hit"] is False
        assert obs["rendered_hit"] is True
        assert MARK in obs["excerpt"]
    finally:
        server.shutdown()
        rnd.close_browser()


@requires_rendered_browser
def test_confirm_rendered_output_confirms_downstream():
    import oracle_seam_templates as st

    server = _serve(_DomStub)
    try:
        base = _base(server)
        probe = f"{base}/page?q={rnd.DOM_PAYLOAD}"
        # Card exactly as the template emits it.
        mat = {
            "js_endpoints": [],
            "js_secrets": [],
            "api_specs": [],
            "fuzzed": [f"{base}/page [200]"],
            "crawled": [],
            "listed": [],
            "live_hosts": [base],
            "repo": None,
        }
        partials = st._t_dom_xss(mat)
        assert len(partials) == 1
        gate = ProgramScopeGate({}, target_fallback=base)
        cards = st.scan_template_seams(
            recon_dir=None, repo_path=None, program=None, scope_gate=gate
        )
        # recon_dir=None yields no material; build the card directly instead.
        tid = next(t for t in st.TEMPLATES if t["tid"] == "dom-xss-rendered-differential")
        card = st._card(
            tid,
            {**partials[0], "line_a": 0, "line_b": 0},
            program=None,
            n=1,
        )
        assert card["claim_type"] == "dom-xss-rendered-differential"
        assert card["render_marker"] == MARK
        rc, stdout, stderr = oh._execute_confirm(card, card["check"])
        assert rc == 0, stderr
        assert MARK in stdout
        verdict = verify_seam_card(
            card, [probe, base], scope_gate=gate,
            status=extract_status_from_curl_output(stdout), body=stdout,
        )
        assert verdict["verdict"] == "CONFIRMED", verdict
    finally:
        server.shutdown()
        rnd.close_browser()


@requires_rendered_browser
def test_rendered_redirect_never_forwards_credentials_cross_origin():
    received = []
    origin_received = []

    class _Attacker(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    attacker = _serve(_Attacker)

    class _Redirector(BaseHTTPRequestHandler):
        def do_GET(self):
            origin_received.append(dict(self.headers))
            self.send_response(302)
            self.send_header("Location", f"{_base(attacker)}/capture")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector = _serve(_Redirector)
    try:
        rnd.rendered_reflection(
            f"{_base(redirector)}/start",
            headers={"Authorization": "Bearer sentinel", "Cookie": "sid=sentinel"},
        )
        assert origin_received == []
        assert received == []
    finally:
        redirector.shutdown()
        attacker.shutdown()
        rnd.close_browser()


def test_execute_confirm_routes_by_claim(monkeypatch):
    seen = {}

    def fake_run(check, is_testnet=False, provenance=None):
        seen["curl"] = True
        return 0, "HTTP/1.1 200 OK\n\nok", ""

    monkeypatch.setattr(oh, "_run_check", fake_run)
    rc, out, _ = oh._execute_confirm({"claim_type": "other"}, "curl x")
    assert rc == 0 and seen.get("curl") is True

    def fake_rnd(check, marker=None, timeout_ms=15000):
        seen["rnd"] = marker
        return 0, "HTTP/1.1 200 OK\n\nr", ""

    monkeypatch.setattr(rnd, "confirm_rendered_output", fake_rnd)
    oh._execute_confirm(
        {"claim_type": "dom-xss-rendered-differential", "render_marker": "m"},
        "curl x",
    )
    assert seen["rnd"] == "m"


# ── 4.3 CSRF replay ─────────────────────────────────────────────────────────


def test_csrf_replay_confirms_behind_token_gate():
    server = _serve(_CsrfStub)
    try:
        base = _base(server)
        # The gate is real: a tokenless POST is rejected.
        import urllib.request

        req = urllib.request.Request(
            f"{base}/form",
            data=b"username=%27",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            gate_holds = False
        except urllib.error.HTTPError as e:
            gate_holds = e.code == 403
        assert gate_holds
        # The two-step replay passes the gate and triggers the SQL error.
        rc, stdout, stderr = confirm_form_replay(f"curl -i -s '{base}/form'")
        assert rc == 0, stderr
        assert "SQL syntax" in stdout
        assert extract_status_from_curl_output(stdout) == 200
    finally:
        server.shutdown()


def test_csrf_replay_rejects_untokened_forms():
    server = _serve(_DomStub)  # no form at all
    try:
        rc, _, err = confirm_form_replay(
            f"curl -i -s '{_base(server)}/page'"
        )
        assert rc == 1
        assert "no form" in err
    finally:
        server.shutdown()


def test_csrf_template_emits_replayable_cards(tmp_path):
    import oracle_seam_templates as st

    base = "http://127.0.0.1:8765"
    recon = tmp_path / "r"
    recon.mkdir()
    (recon / "live_hosts.txt").write_text(base + "\n")
    (recon / "fuzzed_paths.txt").write_text(f"{base}/login [200]\n")
    gate = ProgramScopeGate({}, target_fallback=base)
    cards = st.scan_template_seams(
        recon_dir=recon, repo_path=None, program=None, scope_gate=gate
    )
    csrf = [c for c in cards if c["claim_type"] == "csrf-form-replay-sqli"]
    assert len(csrf) >= 1
    assert csrf[0]["check"].startswith("curl")
    assert "csrf_field" in csrf[0]
    dom = [c for c in cards if c["claim_type"] == "dom-xss-rendered-differential"]
    assert len(dom) >= 1


def test_form_replay_confines_destination_to_approved_origin():
    """A page-supplied action/redirect may not steer the replay POST off the
    approved origin unless an explicit scope gate approves it."""
    from oracle_harvest import _same_origin, _replay_destination_allowed

    assert _same_origin("http://a.local/x", "http://a.local/y")
    assert not _same_origin("http://a.local/x", "http://evil.com/x")
    assert not _same_origin("http://a.local:8080/x", "http://a.local/x")

    approved = "http://a.local/form"
    # same origin ok; off-origin refused with no gate
    assert _replay_destination_allowed("http://a.local/submit", approved, None)
    assert not _replay_destination_allowed("http://evil.com/x", approved, None)

    class _Gate:
        def is_in_scope(self, url):
            return ("evil.com" not in url, "")

    # default ports 80 and 443 match explicit ports
    assert _same_origin("http://a.local/x", "http://a.local:80/y")
    assert _same_origin("https://a.local/x", "https://a.local:443/y")
    # malformed port does not raise and returns False
    assert not _same_origin("http://a.local/x", "http://a.local:bad/y")
    assert not _replay_destination_allowed("http://a.local:bad/y", approved, None)

    # a scope gate may approve an off-origin destination, but never evil.com
    assert _replay_destination_allowed("http://other.local/x", approved, _Gate())
    assert not _replay_destination_allowed("http://evil.com/x", approved, _Gate())


def test_form_replay_mutation_disabled_skips_post():
    """allow_mutation=False skips the replay POST entirely."""
    from unittest.mock import MagicMock, patch
    from oracle_harvest import confirm_form_replay

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = (
        b'<html><body><form action="/login" method="POST">'
        b'<input name="csrf_token" value="abc"><input name="username"></form></body></html>'
    )
    mock_opener = MagicMock()
    mock_opener.open.return_value.__enter__.return_value = mock_resp

    with patch("urllib.request.build_opener", return_value=mock_opener):
        rc, stdout, stderr = confirm_form_replay(
            "curl -s https://a.local/login",
            field="username",
            allow_mutation=False,
        )
    assert rc == 1
    assert "mutation not permitted" in stderr
