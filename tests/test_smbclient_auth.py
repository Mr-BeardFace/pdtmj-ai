"""smbclient auth construction — anonymous/null sessions must be the exact
`smbclient -L <target> -N` (no -U), and a real username without a password must
pin an empty password (`user%`) so smbclient never drops to an interactive prompt
that blocks the turn. Agents kept passing 'anonymous'/'guest' for what is really
an unauthenticated probe."""
from tools import smbclient as smb


def _capture(monkeypatch) -> dict:
    calls: dict = {}
    monkeypatch.setattr(smb.shutil, "which", lambda _: "/usr/bin/smbclient")

    class _P:
        stdout = ""
        stderr = ""

    def fake_run(cmd, **k):
        calls["cmd"] = cmd
        return _P()

    monkeypatch.setattr(smb.runner, "run", fake_run)
    return calls


def test_anonymous_list_is_exactly_dash_N(monkeypatch):
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10")                     # no username at all
    assert calls["cmd"] == ["smbclient", "-L", "10.10.10.10", "-p", "445", "-N"]


def test_placeholder_usernames_map_to_null_session(monkeypatch):
    calls = _capture(monkeypatch)
    for placeholder in ("anonymous", "guest", "null", "", "ANONYMOUS"):
        smb.smbclient("10.10.10.10", username=placeholder)
        assert "-N" in calls["cmd"], placeholder
        assert "-U" not in calls["cmd"], placeholder


def test_real_user_without_password_pins_empty(monkeypatch):
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="admin")
    i = calls["cmd"].index("-U")
    assert calls["cmd"][i + 1] == "admin%"           # empty pw → no prompt
    assert "-N" not in calls["cmd"]


def test_user_and_password_and_domain(monkeypatch):
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="admin", password="pass", domain="CORP")
    i = calls["cmd"].index("-U")
    assert calls["cmd"][i + 1] == "CORP\\admin%pass"


def test_guest_with_password_is_a_real_login(monkeypatch):
    # A placeholder name BUT with a password is an intentional login, not anonymous.
    calls = _capture(monkeypatch)
    smb.smbclient("10.10.10.10", username="guest", password="x")
    i = calls["cmd"].index("-U")
    assert calls["cmd"][i + 1] == "guest%x"
    assert "-N" not in calls["cmd"]
