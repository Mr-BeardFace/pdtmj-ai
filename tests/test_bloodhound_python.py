"""bloodhound-python invocation: DNS pointed at the DC (-ns), no --outputdir flag
(this build doesn't support it), hash normalized, dc-IP vs hostname handled."""
from tools import bloodhound_python as bh


def _run(monkeypatch, tmp_path, **kw):
    calls = {}
    monkeypatch.setattr(bh.shutil, "which", lambda _: "/usr/bin/bloodhound-python")
    monkeypatch.setattr(bh.paths, "downloads_dir", lambda: tmp_path)

    class _P:
        returncode = 0
        stdout = "INFO: Done"
        stderr = ""

    def fake_run(cmd, **k):
        calls["cmd"] = cmd
        calls["cwd"] = k.get("cwd")
        (tmp_path / "20260101_bloodhound.zip").write_bytes(b"PK")   # simulate collection
        return _P()

    monkeypatch.setattr(bh.runner, "run", fake_run)
    args = {"domain": "lab.local", "dc": "10.10.10.5", "username": "u", "password": "p"}
    args.update(kw)
    return bh.bloodhound_python(**args), calls


def test_no_outputdir_flag(tmp_path, monkeypatch):
    _, calls = _run(monkeypatch, tmp_path)
    assert "--outputdir" not in calls["cmd"]
    assert calls["cwd"] == str(tmp_path)        # output via cwd instead


def test_nameserver_defaults_to_dc_ip(tmp_path, monkeypatch):
    _, calls = _run(monkeypatch, tmp_path)
    i = calls["cmd"].index("-ns")
    assert calls["cmd"][i + 1] == "10.10.10.5"
    assert "--dns-tcp" in calls["cmd"]


def test_dc_ip_omits_dc_flag(tmp_path, monkeypatch):
    _, calls = _run(monkeypatch, tmp_path)
    assert "-dc" not in calls["cmd"]            # IP can't be a -dc hostname


def test_dc_hostname_uses_dc_flag_with_nameserver(tmp_path, monkeypatch):
    _, calls = _run(monkeypatch, tmp_path, dc="dc01.lab.local", nameserver="10.10.10.5")
    assert calls["cmd"][calls["cmd"].index("-dc") + 1] == "dc01.lab.local"
    assert calls["cmd"][calls["cmd"].index("-ns") + 1] == "10.10.10.5"


def test_hostname_dc_without_nameserver_errors(tmp_path, monkeypatch):
    res, _ = _run(monkeypatch, tmp_path, dc="dc01.lab.local", nameserver=None)
    assert "error" in res and "nameserver" in res["error"]


def test_bare_nt_hash_normalized(tmp_path, monkeypatch):
    _, calls = _run(monkeypatch, tmp_path, password=None,
                    hash="31d6cfe0d16ae931b73c59d7e0c089c0")
    i = calls["cmd"].index("--hashes")
    assert calls["cmd"][i + 1] == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_success_reports_zip_path(tmp_path, monkeypatch):
    res, _ = _run(monkeypatch, tmp_path)
    assert res["success"] is True
    assert res["output_zip"].endswith(".zip")
