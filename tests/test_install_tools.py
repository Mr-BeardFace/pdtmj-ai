"""pip_install / apt_install self-provisioning tools + wildcard scope."""
from core.registry import build_registry
from tools.pip_install import pip_install
from tools.apt_install import apt_install


# ── registration + wildcard scope ──────────────────────────────────────────────

def test_install_tools_registered():
    names = build_registry().list_tools()
    assert "pip_install" in names and "apt_install" in names


def test_wildcard_scope_returns_all_tools():
    reg = build_registry()
    assert len(reg.get_by_scope(["*"])) == len(reg.list_tools())
    # a specific scope still filters
    assert [t.name for t in reg.get_by_scope(["nmap_scan"])] == ["nmap_scan"]
    # unknown names are ignored
    assert reg.get_by_scope(["does_not_exist"]) == []


# ── pip_install ────────────────────────────────────────────────────────────────

def test_pip_rejects_flag_injection():
    res = pip_install(["--upgrade-strategy=eager"])
    assert "error" in res and "flag" in res["error"]


def test_pip_rejects_empty():
    assert "error" in pip_install([])


def test_pip_disabled_by_config(monkeypatch):
    monkeypatch.setattr("tools.pip_install.get", lambda k, d=None: False)
    res = pip_install(["requests"])
    assert "error" in res and "disabled" in res["error"]


# ── apt_install ────────────────────────────────────────────────────────────────

def test_apt_disabled_by_config(monkeypatch):
    monkeypatch.setattr("tools.apt_install.get", lambda k, d=None: False)
    assert "error" in apt_install(["gobuster"])


def test_apt_missing_on_non_debian(monkeypatch):
    monkeypatch.setattr("tools.apt_install.shutil.which", lambda _: None)
    res = apt_install(["gobuster"])
    assert "error" in res and "apt-get not found" in res["error"]


def test_apt_rejects_flag_injection(monkeypatch):
    # pretend apt-get exists so the flag guard (not the missing-binary guard) fires
    monkeypatch.setattr("tools.apt_install.shutil.which", lambda _: "/usr/bin/apt-get")
    res = apt_install(["-y", "--reinstall"])
    assert "error" in res and "flag" in res["error"]
