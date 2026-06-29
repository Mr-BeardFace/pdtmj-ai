"""run_daemon manages long-lived offensive daemons (responder/ntlmrelayx/mitm6):
start detached + return immediately, read captured output, list, stop. Popen is
mocked so no real process is spawned."""
from tools import run_daemon as rd


class _FakePopen:
    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 0


def _patch(monkeypatch, tmp_path, alive=True):
    rd._DAEMONS.clear()
    monkeypatch.setattr(rd, "scratch_dir", lambda: tmp_path)
    monkeypatch.setattr(rd.time, "sleep", lambda *_: None)
    monkeypatch.setattr(rd.shutil, "which", lambda _: "/usr/bin/bash")
    monkeypatch.setattr(rd.subprocess, "Popen", lambda *a, **k: _FakePopen(alive))
    monkeypatch.setattr(rd._proc, "_kill", lambda *a, **k: None)


def test_start_requires_command(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    assert "error" in rd.run_daemon(action="start", command="")


def test_start_returns_immediately_with_id(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, alive=True)
    r = rd.run_daemon(action="start", command="sudo responder -I tun0 -wv")
    assert r["running"] is True and r["name"] == "responder" and r["id"]


def test_start_dies_immediately_is_reported(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, alive=False)
    r = rd.run_daemon(action="start", command="responder -I bad")
    assert "error" in r and "exited immediately" in r["error"]


def test_list_read_stop_lifecycle(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, alive=True)
    did = rd.run_daemon(action="start", command="sudo impacket-ntlmrelayx -t smb://10.0.0.5")["id"]
    assert rd.run_daemon(action="list")["count"] == 1
    rr = rd.run_daemon(action="read", daemon_id=did)
    assert rr["running"] is True and "output" in rr
    st = rd.run_daemon(action="stop", daemon_id=did)
    assert st["stopped"] == 1
    assert rd.run_daemon(action="list")["count"] == 0


def test_read_unknown_id_errors(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path)
    assert "error" in rd.run_daemon(action="read", daemon_id="nope")


def test_stop_all(monkeypatch, tmp_path):
    _patch(monkeypatch, tmp_path, alive=True)
    rd.run_daemon(action="start", command="sudo responder -I tun0")
    rd.run_daemon(action="start", command="sudo mitm6 -d lab.local")
    assert rd.run_daemon(action="stop_all")["stopped"] == 2


def test_tail_reads_log(tmp_path):
    p = tmp_path / "d.log"
    p.write_text("[SMB] NTLMv2-SSP Hash : admin::LAB:...\n")
    assert "NTLMv2-SSP" in rd._tail(p)


def test_first_binary_skips_sudo():
    assert rd._first_binary("sudo /usr/bin/responder -I tun0") == "responder"
    assert rd._first_binary("impacket-ntlmrelayx -t smb://x") == "impacket-ntlmrelayx"
