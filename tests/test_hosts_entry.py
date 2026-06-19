"""hosts_entry — idempotent /etc/hosts management for discovered vhosts."""
import tools.hosts_entry as he


class _Done:
    def __init__(self, rc=0, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def test_add_appends_new_mapping(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts", lambda: "127.0.0.1 localhost\n")
    cap = {}
    monkeypatch.setattr(he.runner, "run",
                        lambda cmd, **kw: cap.update(cmd=cmd, input=kw.get("input")) or _Done(0))

    out = he.hosts_entry("add", "10.10.10.5", ["app.htb", "www.app.htb"])

    assert out["added"] == ["app.htb", "www.app.htb"]
    assert "tee" in cap["cmd"] and "-a" in cap["cmd"]
    assert "10.10.10.5" in cap["input"] and "app.htb" in cap["input"]
    assert he._MARKER in cap["input"]


def test_add_is_idempotent(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts", lambda: "10.10.10.5 app.htb  # PDTMJ-AI\n")
    calls = {"n": 0}
    monkeypatch.setattr(he.runner, "run",
                        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1) or _Done(0))

    out = he.hosts_entry("add", "10.10.10.5", ["app.htb"])

    assert out["added"] == [] and "already" in out["note"]
    assert calls["n"] == 0                      # no write attempted


def test_add_only_writes_the_missing_names(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts", lambda: "10.10.10.5 app.htb  # PDTMJ-AI\n")
    cap = {}
    monkeypatch.setattr(he.runner, "run",
                        lambda cmd, **kw: cap.update(input=kw.get("input")) or _Done(0))

    out = he.hosts_entry("add", "10.10.10.5", ["app.htb", "admin.app.htb"])

    assert out["added"] == ["admin.app.htb"]
    assert "admin.app.htb" in cap["input"] and "app.htb" in cap["input"]


def test_add_requires_ip_and_host(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts", lambda: "")
    assert "error" in he.hosts_entry("add", "", ["app.htb"])
    assert "error" in he.hosts_entry("add", "10.10.10.5", [])


def test_remove_prunes_only_managed_matching_lines(monkeypatch):
    content = ("127.0.0.1 localhost\n"
               "10.10.10.5 app.htb  # PDTMJ-AI\n"
               "10.10.10.6 other.htb  # PDTMJ-AI\n")
    monkeypatch.setattr(he, "_read_hosts", lambda: content)
    cap = {}
    monkeypatch.setattr(he.runner, "run",
                        lambda cmd, **kw: cap.update(cmd=cmd, input=kw.get("input")) or _Done(0))

    out = he.hosts_entry("remove", hostnames=["app.htb"])

    assert any("app.htb" in r for r in out["removed"])
    assert "localhost" in cap["input"]          # untouched
    assert "other.htb" in cap["input"]          # other managed line kept
    assert "app.htb" not in cap["input"]        # pruned


def test_list_returns_managed_only(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts",
                        lambda: "127.0.0.1 localhost\n10.10.10.5 app.htb  # PDTMJ-AI\n")
    out = he.hosts_entry("list")
    assert out["count"] == 1 and "app.htb" in out["entries"][0]


def test_write_failure_surfaces_error(monkeypatch):
    monkeypatch.setattr(he, "_read_hosts", lambda: "")
    monkeypatch.setattr(he.runner, "run",
                        lambda *a, **k: _Done(1, "", "sudo: a password is required"))
    out = he.hosts_entry("add", "10.10.10.5", ["app.htb"])
    assert "error" in out


def test_registered_and_in_enumeration_scope():
    from core.registry import build_registry, load_all_agents
    reg = build_registry()
    names = {t.name for t in reg.get_by_scope(load_all_agents()["pentest/enumeration"].scope)}
    assert "hosts_entry" in names
