"""Scanners/crackers used to report a run FAILURE (bad path, host down, wrong hash
format) as a clean empty result. proc.diagnostic() + per-tool wiring now surface the
tool's own error on a nonzero exit, so a failure isn't mistaken for 'nothing found'."""
import subprocess

from core import proc as runner
import tools.john as jn
import tools.gobuster_dir as gb


def _cp(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


# ── the shared helper ─────────────────────────────────────────────────────────
def test_diagnostic_empty_on_clean_exit():
    assert runner.diagnostic(_cp(0, stderr="progress: 100%")) == ""   # logs, not an error


def test_diagnostic_tail_on_failure():
    d = runner.diagnostic(_cp(1, stderr="Error: unable to connect to host"))
    assert "unable to connect" in d


# ── john: twin of the hashcat fix ─────────────────────────────────────────────
def _patch_john(monkeypatch, crack_proc):
    monkeypatch.setattr(jn.shutil, "which", lambda b: "/usr/bin/john")
    monkeypatch.setattr(jn.os.path, "exists", lambda p: True)
    monkeypatch.setattr(jn, "get", lambda k, d=None: d)
    def run(cmd, **kw):
        return _cp(0, stdout="") if "--show" in cmd else crack_proc
    monkeypatch.setattr(jn.runner, "run", run)


def test_john_no_hashes_loaded_is_error(monkeypatch):
    _patch_john(monkeypatch, _cp(1, stderr="No password hashes loaded (see FAQ)"))
    r = jn.john(hash="notahash")
    assert "error" in r and "john_said" in r
    assert "cracked" not in r


def test_john_genuine_miss_reports_not_cracked(monkeypatch):
    _patch_john(monkeypatch, _cp(0, stdout="0g 0:00:01 DONE"))
    r = jn.john(hash="$1$abc$def")
    assert r["cracked_count"] == 0 and "error" not in r


# ── a scanner: failure vs clean empty ─────────────────────────────────────────
def test_gobuster_failure_surfaces_tool_error(monkeypatch):
    monkeypatch.setattr(gb.shutil, "which", lambda b: "/usr/bin/gobuster")
    monkeypatch.setattr(gb.runner, "run",
                        lambda cmd, **kw: _cp(1, stderr="Error: unable to connect"))
    r = gb.gobuster_dir(url="http://down.host")
    assert r["count"] == 0 and "unable to connect" in r["tool_error"]


def test_gobuster_clean_empty_has_no_tool_error(monkeypatch):
    monkeypatch.setattr(gb.shutil, "which", lambda b: "/usr/bin/gobuster")
    monkeypatch.setattr(gb.runner, "run", lambda cmd, **kw: _cp(0, stdout=""))
    r = gb.gobuster_dir(url="http://ok.host")
    assert r["count"] == 0 and "tool_error" not in r
