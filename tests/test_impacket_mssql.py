"""impacket mssqlclient command construction. impacket's mssqlclient has NO
password flag — the password belongs in the target string (user:pass@host). A
lone -p argparse-abbreviates to -port and clobbers the real port with the
password, so the tool must never emit -p."""
from tools import impacket_mssql as m


def _capture(monkeypatch, out="ok", rc=0):
    calls: dict = {}
    monkeypatch.setattr(m.shutil, "which", lambda _: "/usr/bin/impacket-mssqlclient")

    class _P:
        stdout = out
        stderr = ""
        returncode = rc

    def fake_run(cmd, **kw):
        calls["cmd"] = cmd
        return _P()

    monkeypatch.setattr(m.runner, "run", fake_run)
    return calls


def test_password_goes_in_target_not_a_p_flag(monkeypatch):
    calls = _capture(monkeypatch)
    m.impacket_mssql("10.0.0.1", "sqlsvc", password="P@ssw0rd", port=6520, query="SELECT 1")
    cmd = calls["cmd"]
    assert "-p" not in cmd                                  # never the broken flag
    assert "sqlsvc:P@ssw0rd@10.0.0.1" in cmd
    assert cmd[cmd.index("-port") + 1] == "6520"            # custom port survives


def test_domain_account_uses_windows_auth(monkeypatch):
    calls = _capture(monkeypatch)
    m.impacket_mssql("10.0.0.1", "sqlsvc", password="x", domain="corp.htb",
                     port=6520, query="SELECT 1")
    cmd = calls["cmd"]
    assert "corp.htb/sqlsvc:x@10.0.0.1" in cmd
    assert "-windows-auth" in cmd


def test_hash_auth_no_password(monkeypatch):
    calls = _capture(monkeypatch)
    m.impacket_mssql("10.0.0.1", "admin", hash="aad3b:5f4dcc", query="SELECT 1")
    cmd = calls["cmd"]
    assert "admin@10.0.0.1" in cmd                          # no :pass appended
    assert cmd[cmd.index("-hashes") + 1] == "aad3b:5f4dcc"
    assert "-p" not in cmd


# impacket exits 0 even when the login is rejected, so the auth verdict is read from
# the output — a real SQL session vs a "Login failed" line — and feeds the auth ledger.
def test_authenticated_true_on_sql_session(monkeypatch):
    _capture(monkeypatch, out="[*] ENVCHANGE(DATABASE)... SQL (OVERWATCH\\sqlsvc guest@master)> ")
    r = m.impacket_mssql("10.0.0.1", "sqlsvc", password="x", port=6520, query="SELECT 1")
    assert r["authenticated"] is True and r["success"] is True


def test_authenticated_false_on_login_failed(monkeypatch):
    _capture(monkeypatch, out="[-] ERROR(S200401): Login failed for user 'sqlsvc'.")
    r = m.impacket_mssql("10.0.0.1", "sqlsvc", password="x", port=6520, query="SELECT 1")
    assert r["authenticated"] is False and r["success"] is False
