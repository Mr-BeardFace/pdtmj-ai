"""Files pulled off a target land in the assessment loot dir, and the tool result
surfaces the local path so it can be analyzed locally instead of re-fetched."""
import ftplib

from tools import smbclient as smb
from tools.ftp_client import ftp


def test_smbclient_get_saves_to_loot_and_reports_path(tmp_path, monkeypatch):
    loot = tmp_path / "loot"
    loot.mkdir()
    monkeypatch.setattr(smb.paths, "loot_dir", lambda: loot)
    monkeypatch.setattr(smb.shutil, "which", lambda _: "/usr/bin/smbclient")

    class _P:
        stdout = "getting file \\UserInfo.exe.zip of size 277499 as UserInfo.exe.zip\n"
        stderr = ""

    def fake_run(cmd, **k):
        assert k.get("cwd") == str(loot)            # download is directed at loot
        (loot / "UserInfo.exe.zip").write_bytes(b"PK\x03\x04")
        return _P()

    monkeypatch.setattr(smb.runner, "run", fake_run)
    res = smb.smbclient("10.0.0.1", share="support-tools", command="get UserInfo.exe.zip")
    assert res["saved_to"] == str(loot / "UserInfo.exe.zip")
    assert "run_script" in res["note"]


def test_ftp_retrieve_saves_bytes_to_loot(tmp_path, monkeypatch):
    loot = tmp_path / "loot"
    loot.mkdir()
    monkeypatch.setattr("tools.ftp_client.paths.loot_dir", lambda: loot)

    class FakeFTP:
        def connect(self, *a, **k): pass
        def login(self, *a, **k): pass
        def retrbinary(self, cmd, cb): cb(b"PK\x03\x04binary")
        def quit(self): pass
        def close(self): pass

    monkeypatch.setattr(ftplib, "FTP", FakeFTP)
    res = ftp("10.0.0.1", action="retrieve", path="pub/secret.zip")
    assert res["saved_to"] == str(loot / "secret.zip")
    assert (loot / "secret.zip").read_bytes() == b"PK\x03\x04binary"
