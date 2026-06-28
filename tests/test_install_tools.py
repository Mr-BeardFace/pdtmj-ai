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


def test_apt_skips_already_present(monkeypatch):
    # which() finds apt-get AND every package → all already present → no apt run
    monkeypatch.setattr("tools.apt_install.shutil.which", lambda x: f"/usr/bin/{x}")
    res = apt_install(["impacket", "kerbrute"])
    assert res["success"] and res["installed"] == []
    assert set(res["already_present"]) == {"impacket", "kerbrute"}


def test_apt_installs_only_missing(monkeypatch):
    monkeypatch.setattr("tools.apt_install.shutil.which",
                        lambda x: "/usr/bin/apt-get" if x == "apt-get" else None)
    monkeypatch.setattr("tools.apt_install._already_present", lambda p: p == "impacket")

    class _P:
        returncode = 0
        stdout = "done"
        stderr = ""

    monkeypatch.setattr("tools.apt_install.runner.run", lambda *a, **k: _P())
    res = apt_install(["impacket", "gobuster"])
    assert res["already_present"] == ["impacket"]
    assert res["installed"] == ["gobuster"]
    assert "gobuster" in res["_command"] and "impacket" not in res["_command"]


def test_pip_skips_already_present(monkeypatch):
    monkeypatch.setattr("tools.pip_install._installed_dists",
                        lambda py: {"impacket", "requests"})
    res = pip_install(["impacket", "requests"])
    assert res["success"] and res["installed"] == []
    assert set(res["already_present"]) == {"impacket", "requests"}


def test_pip_version_pinned_passes_through(monkeypatch):
    # a pinned spec is always handed to pip even if the bare dist is present
    monkeypatch.setattr("tools.pip_install._installed_dists", lambda py: {"requests"})

    class _P:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr("tools.pip_install.runner.run", lambda *a, **k: _P())
    res = pip_install(["requests==2.31.0"])
    assert res["installed"] == ["requests==2.31.0"]
