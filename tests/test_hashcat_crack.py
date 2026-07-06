"""hashcat used to discard its own stdout/stderr and report a bland 'not cracked'
even when it never ran a real attempt (wrong mode / malformed hash / no device) —
hiding a crackable hash. It now surfaces hashcat's words and flags those cases."""
import subprocess
import shutil

import tools.hashcat_crack as hc


def _fake_run(stdout="", stderr="", writes=None):
    """Stand in for proc.run: optionally write `writes` into the -o outfile (a crack),
    and return the given stdout/stderr."""
    def run(cmd, **kw):
        if writes is not None:
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(writes)
        return subprocess.CompletedProcess(cmd, 0, stdout, stderr)
    return run


def _patch(monkeypatch, **kw):
    monkeypatch.setattr(hc.shutil, "which", lambda b: "/usr/bin/hashcat")
    monkeypatch.setattr(hc.os.path, "exists", lambda p: True)   # wordlist "present"
    monkeypatch.setattr(hc, "get", lambda k, d=None: "" if k == "hashcat_rules" else d)
    monkeypatch.setattr(hc.runner, "run", _fake_run(**kw))


def test_token_length_exception_is_an_error_not_a_miss(monkeypatch):
    _patch(monkeypatch, stderr="Token length exception\nNo hashes loaded.")
    r = hc.hashcat_crack(hash="deadbeef", hash_mode=3200)
    assert "error" in r and "hashcat_said" in r
    assert "Token length exception" in r["hashcat_said"]
    assert "cracked" not in r                       # not reported as a real attempt


def test_genuine_miss_still_reports_not_cracked_with_diag(monkeypatch):
    _patch(monkeypatch, stdout="")                  # ran clean, cracked nothing
    r = hc.hashcat_crack(hash="$2b$12$" + "x" * 53, hash_mode=3200)
    assert r["cracked_count"] == 0 and "hashcat_said" in r
    assert "error" not in r


def test_successful_crack_is_returned(monkeypatch):
    _patch(monkeypatch, writes="hunter2\n")
    r = hc.hashcat_crack(hash="$2b$12$" + "x" * 53, hash_mode=3200, username="bob")
    assert r["cracked_count"] == 1
    assert r["cracked"][0]["plaintext"] == "hunter2"
    assert r["cracked"][0]["username"] == "bob"


def test_already_running_instance_is_an_error(monkeypatch):
    # hashcat single-instances on the session lock; a collision must surface, not
    # read as a silent "not cracked".
    _patch(monkeypatch, stderr="Already an instance '/usr/bin/hashcat' running on pid 315332")
    r = hc.hashcat_crack(hash="$2b$12$" + "x" * 53, hash_mode=3200)
    assert "error" in r and "already an instance" in r["hashcat_said"].lower()


def test_command_uses_a_private_session(monkeypatch):
    # a per-run --session prevents that collision in the first place
    _patch(monkeypatch, writes="pw\n")
    r = hc.hashcat_crack(hash="$2b$12$" + "x" * 53, hash_mode=3200)
    assert "--session pdtmj_" in r["_command"]
