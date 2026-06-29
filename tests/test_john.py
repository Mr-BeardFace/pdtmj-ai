"""john wraps John the Ripper: crack with a wordlist, read the plaintext from
--show, return the hashcat-style cracked shape so the engine records the credential."""
from tools import john as jt


def test_parse_show_extracts_plaintext():
    assert jt._parse_show("?:Password1\n1 password hash cracked, 0 left") == "Password1"
    assert jt._parse_show("admin:Hunt3r:extra\n") == "Hunt3r"
    assert jt._parse_show("0 password hashes cracked, 1 left") is None


def test_missing_binary_errors(monkeypatch):
    monkeypatch.setattr(jt.shutil, "which", lambda _: None)
    assert "error" in jt.john(hash="$zip2$abc")


def test_john_cracks_and_returns_credential(tmp_path, monkeypatch):
    wl = tmp_path / "rockyou.txt"
    wl.write_text("Password1\n")
    monkeypatch.setattr(jt.shutil, "which", lambda _: "/usr/bin/john")
    monkeypatch.setattr(jt, "get",
                        lambda k, d=None: str(wl) if k == "hashcat_wordlist"
                        else ("john" if k == "john_binary" else d))

    calls = []

    class _P:
        def __init__(self, out=""):
            self.stdout = out
            self.stderr = ""

    def fake_run(cmd, **k):
        calls.append(cmd)
        if "--show" in cmd:
            return _P("?:Password1\n1 password hash cracked, 0 left")
        return _P("")

    monkeypatch.setattr(jt.runner, "run", fake_run)
    r = jt.john(hash="$zip2$abc", username="admin", location="secret.zip")
    assert r["cracked_count"] == 1
    c = r["cracked"][0]
    assert c["plaintext"] == "Password1" and c["username"] == "admin"
    # a wordlist crack pass was issued
    assert any("--wordlist=" + str(wl) in " ".join(cmd) for cmd in calls)
