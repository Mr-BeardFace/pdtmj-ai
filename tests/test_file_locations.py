"""Pulled files vs analysis workspace: tool downloads land in the assessment
downloads/ dir (proc.run defaults cwd there), run_script works in analysis/
(the /tmp replacement), and the download tools surface the local path."""
import ftplib
import sys
from pathlib import Path

from core import paths, proc
from tools import smbclient as smb
from tools.ftp_client import ftp
from tools.run_script import run_script


def test_proc_run_defaults_cwd_to_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "_current_assessment_dir", tmp_path)
    r = proc.run([sys.executable, "-c", "import os;print(os.getcwd())"],
                 capture_output=True, text=True, timeout=30)
    assert Path(r.stdout.strip()).resolve() == (tmp_path / "downloads").resolve()


def test_run_script_runs_in_analysis_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "_current_assessment_dir", tmp_path)
    r = run_script(language="python", script="import os;print(os.getcwd())",
                   purpose="cwd check")
    assert Path(r["stdout"].strip()).resolve() == (tmp_path / "analysis").resolve()


def test_smbclient_get_reports_downloads_path(tmp_path, monkeypatch):
    dl = tmp_path / "downloads"
    dl.mkdir()
    monkeypatch.setattr(smb.paths, "downloads_dir", lambda: dl)
    monkeypatch.setattr(smb.shutil, "which", lambda _: "/usr/bin/smbclient")

    class _P:
        stdout = "getting file \\UserInfo.exe.zip of size 277499 as UserInfo.exe.zip\n"
        stderr = ""

    def fake_run(cmd, **k):
        (dl / "UserInfo.exe.zip").write_bytes(b"PK\x03\x04")   # simulate the download
        return _P()

    monkeypatch.setattr(smb.runner, "run", fake_run)
    res = smb.smbclient("10.0.0.1", share="support-tools", command="get UserInfo.exe.zip")
    assert res["saved_to"] == str(dl / "UserInfo.exe.zip")


def test_ftp_retrieve_saves_bytes_to_downloads(tmp_path, monkeypatch):
    dl = tmp_path / "downloads"
    dl.mkdir()
    monkeypatch.setattr("tools.ftp_client.paths.downloads_dir", lambda: dl)

    class FakeFTP:
        def connect(self, *a, **k): pass
        def login(self, *a, **k): pass
        def retrbinary(self, cmd, cb): cb(b"PK\x03\x04binary")
        def quit(self): pass
        def close(self): pass

    monkeypatch.setattr(ftplib, "FTP", FakeFTP)
    res = ftp("10.0.0.1", action="retrieve", path="pub/secret.zip")
    assert res["saved_to"] == str(dl / "secret.zip")
    assert (dl / "secret.zip").read_bytes() == b"PK\x03\x04binary"
