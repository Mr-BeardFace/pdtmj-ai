"""smbclient auth construction. Unauthenticated enumeration tries a pure null
session (`smbclient -L <target> -N`) FIRST, then falls back to an explicit
anonymous user (`-U anonymous%`) — some servers reject a bare null session but
accept anonymous with no password. A real username without a password pins an
empty password (`user%`) so smbclient never drops to an interactive prompt that
blocks the turn. Agents kept passing 'anonymous'/'guest' for what is really an
unauthenticated probe."""
from tools import smbclient as smb


def _capture(monkeypatch, outputs=None) -> dict:
    """Record every smbclient command run; optionally script per-call stdout."""
    calls: dict = {"cmds": []}
    monkeypatch.setattr(smb.shutil, "which", lambda _: "/usr/bin/smbclient")
    outs = list(outputs or [])

    class _P:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.stderr = ""

    def fake_run(cmd, **k):
        calls["cmds"].append(cmd)
        return _P(outs.pop(0) if outs else "")

    monkeypatch.setattr(smb.runner, "run", fake_run)
    return calls


_SHARE_OUT = (
    "\tSharename       Type      Comment\n"
    "\t---------       ----      -------\n"
    "        data            Disk      shared files\n"
)


def test_unauth_tries_null_then_anonymous_user(monkeypatch):
    calls = _capture(monkeypatch)                     # both attempts return nothing
    res = smb.smbclient("10.10.10.10")
    assert calls["cmds"][0] == ["smbclient", "-L", "10.10.10.10", "-p", "445", "-N"]
    assert calls["cmds"][1] == ["smbclient", "-L", "10.10.10.10", "-p", "445",
                                "-U", "anonymous%"]
    assert res["_auth_mode"] == "anonymous"           # last attempt's mode


def test_null_session_short_circuits_when_it_connects(monkeypatch):
    calls = _capture(monkeypatch, outputs=[_SHARE_OUT])
    res = smb.smbclient("10.10.10.10")
    assert len(calls["cmds"]) == 1                     # connected → no fallback
    assert calls["cmds"][0][-1] == "-N"
    assert res["_auth_mode"] == "null"
    assert any(s["name"] == "data" for s in res["shares"])


def test_placeholder_usernames_start_with_null_session(monkeypatch):
    for placeholder in ("anonymous", "guest", "null", "", "ANONYMOUS"):
        calls = _capture(monkeypatch)
        smb.smbclient("10.10.10.10", username=placeholder)
        assert calls["cmds"][0][-1] == "-N", placeholder


def test_real_user_without_password_pins_empty(monkeypatch):
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="admin")
    assert len(calls["cmds"]) == 1                     # real creds → single attempt
    c = calls["cmds"][0]
    assert c[c.index("-U") + 1] == "admin%"            # empty pw → no prompt
    assert "-N" not in c


def test_user_and_password_and_domain(monkeypatch):
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="admin", password="pass", domain="CORP")
    c = calls["cmds"][0]
    assert c[c.index("-U") + 1] == "CORP\\admin%pass"


def test_guest_with_password_is_a_real_login(monkeypatch):
    # A placeholder name BUT with a password is an intentional login, not anonymous.
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="guest", password="x")
    assert len(calls["cmds"]) == 1
    c = calls["cmds"][0]
    assert c[c.index("-U") + 1] == "guest%x"
    assert "-N" not in c


# A real null-session `ls`: smbclient prints a benign NetBIOS-name-resolution
# failure, then lists files whose attributes are multi-char (DH, AH). The parser
# must read this as connected with files — NOT flip to failed and fall through to
# the -U variant (the bug that made agents bail to raw local_exec).
_NULL_LS_OUT = (
    "do_connect: Connection to 10.10.10.10 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)\n"
    "  .                                  DH        0  Fri May 16 20:27:07 2025\n"
    "  Monitoring                         DH        0  Fri May 16 20:32:43 2025\n"
    "  EntityFramework.dll                AH  4991352  Thu Apr 16 15:38:42 2020\n"
    "\t\t7147007 blocks of size 4096.\n"
)


def test_successful_null_ls_does_not_fall_through_to_anonymous(monkeypatch):
    calls = _capture(monkeypatch, outputs=[_NULL_LS_OUT])
    res = smb.smbclient("10.10.10.10", share="software$", command="ls")
    assert len(calls["cmds"]) == 1                     # connected → no -U fallback
    assert res["_auth_mode"] == "null"
    assert res["connected"] is True
    assert {"Monitoring", "EntityFramework.dll"} <= {f["name"] for f in res["files"]}


def test_benign_name_resolution_noise_is_not_an_error(monkeypatch):
    r = smb._parse_output(_NULL_LS_OUT, "10.10.10.10", "software$", "ls")
    assert r["connected"] is True and r["errors"] == []


def test_real_access_denied_is_not_connected(monkeypatch):
    r = smb._parse_output("tree connect failed: NT_STATUS_ACCESS_DENIED",
                          "10.10.10.10", "C$", "ls")
    assert r["connected"] is False and r["errors"]
