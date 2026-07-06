"""ffuf auto-injects FUZZ into the URL path — but must NOT when FUZZ already lives in
a header (vhost fuzzing), else it fuzzes both spots and everything 404s. Also must not
emit a duplicate -mc when the caller passed one via extra_args."""
import subprocess

import tools.ffuf as ff


def _run_capturing(monkeypatch):
    seen = {}
    def run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, "", "")   # no outfile -> parse error path
    monkeypatch.setattr(ff.shutil, "which", lambda b: "/usr/bin/ffuf")
    monkeypatch.setattr(ff.runner, "run", run)
    return seen


def test_vhost_fuzz_does_not_touch_url(monkeypatch):
    seen = _run_capturing(monkeypatch)
    ff.ffuf(url="http://10.129.49.58/", headers={"Host": "FUZZ.snapped.htb"})
    cmd = seen["cmd"]
    u = cmd[cmd.index("-u") + 1]
    assert u == "http://10.129.49.58/"           # not .../FUZZ
    assert cmd.count("-mc") == 1                  # tool default only, no dup


def test_plain_dir_fuzz_still_injects_url(monkeypatch):
    seen = _run_capturing(monkeypatch)
    ff.ffuf(url="http://10.129.49.58/")
    cmd = seen["cmd"]
    assert cmd[cmd.index("-u") + 1].endswith("/FUZZ")


def test_no_duplicate_mc_when_in_extra_args(monkeypatch):
    seen = _run_capturing(monkeypatch)
    ff.ffuf(url="http://x/FUZZ", extra_args="-mc 200,301 -t 50")
    assert seen["cmd"].count("-mc") == 1          # extra_args one only
