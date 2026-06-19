"""http_request cookie/session handling."""
import shutil
import threading
import time

import pytest

from tools.http_request import (
    http_request, _session_jar, _jar_cookie_names, TOOL_DEFINITION,
)

_HAS_CURL = shutil.which("curl") is not None


# ── schema / helpers ───────────────────────────────────────────────────────────

def test_schema_exposes_cookies_and_session():
    props = TOOL_DEFINITION["input_schema"]["properties"]
    assert "cookies" in props and "session" in props


def test_session_jar_sanitizes_name():
    p = _session_jar("admin login/../x")
    assert "/" not in p.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].replace(".jar", "")
    assert p.endswith(".jar")


def test_jar_cookie_names_parses_netscape(tmp_path):
    jar = tmp_path / "j.jar"
    jar.write_text(
        "# Netscape HTTP Cookie File\n"
        ".example.com\tTRUE\t/\tFALSE\t0\tsession\tabc123\n"
        "#HttpOnly_.example.com\tTRUE\t/\tTRUE\t0\ttoken\txyz\n",
        encoding="utf-8",
    )
    names = _jar_cookie_names(str(jar))
    assert "session" in names and "token" in names


def test_missing_curl(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert "error" in http_request("GET", "http://x")


# ── live behaviour (needs curl) ────────────────────────────────────────────────

class _Handler:
    pass


@pytest.mark.skipif(not _HAS_CURL, reason="curl not in PATH")
def test_session_carries_cookies_across_redirect_and_calls():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/login":
                self.send_response(302)
                self.send_header("Set-Cookie", "sess=abc123; Path=/")
                self.send_header("Location", "/dashboard")
                self.end_headers()
            else:
                got = self.headers.get("Cookie", "(none)")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"cookie={got}".encode())

    srv = HTTPServer(("127.0.0.1", 8732), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    sess = "pytest-sess-8732"
    try:
        # cookie from the 302 must reach the /dashboard hop (within-call carry)
        r1 = http_request("GET", "http://127.0.0.1:8732/login", session=sess)
        assert "sess=abc123" in r1["body"]
        assert r1.get("session_cookies") == ["sess"]

        # a separate call with the same session re-sends the stored cookie
        r2 = http_request("GET", "http://127.0.0.1:8732/echo", session=sess)
        assert "sess=abc123" in r2["body"]

        # without the session, no cookie is sent
        r3 = http_request("GET", "http://127.0.0.1:8732/echo")
        assert "(none)" in r3["body"]
    finally:
        srv.shutdown()
        import os
        try:
            os.unlink(_session_jar(sess))
        except OSError:
            pass
