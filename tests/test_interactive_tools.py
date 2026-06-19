import core.config as config
from core.registry import build_registry


# ── registration ──────────────────────────────────────────────────────────────

def test_new_tools_registered():
    names = build_registry().list_tools()
    for t in ("ssh_exec", "ftp", "nc", "telnet"):
        assert t in names


# ── tools fail gracefully on a closed port (no live service needed) ───────────

def test_nc_connection_refused():
    from tools.nc import nc
    res = nc("127.0.0.1", 1, timeout=2)
    assert "error" in res


def test_ftp_connection_refused():
    from tools.ftp_client import ftp
    res = ftp("127.0.0.1", port=1, timeout=2)
    assert "error" in res


def test_telnet_connection_refused():
    from tools.telnet_client import telnet
    res = telnet("127.0.0.1", port=1, timeout=2)
    assert "error" in res


def test_tool_schemas_have_required_host():
    import tools.ftp_client as f, tools.nc as n, tools.telnet_client as t
    assert f.TOOL_DEFINITION["name"] == "ftp"
    assert n.TOOL_DEFINITION["name"] == "nc"
    assert t.TOOL_DEFINITION["name"] == "telnet"
    assert "host" in f.TOOL_DEFINITION["input_schema"]["required"]


# ── exploitation toggle / phases ──────────────────────────────────────────────

def test_resolve_phases_exploit_on(monkeypatch):
    monkeypatch.setattr(config, "get", lambda k, d=None: True if k == "exploitation_enabled" else d)
    from core.intake import resolve_phases
    out = resolve_phases([])
    assert "exploitation" in out and "discovery" in out and "reporting" in out


def test_resolve_phases_exploit_off(monkeypatch):
    monkeypatch.setattr(config, "get", lambda k, d=None: False if k == "exploitation_enabled" else d)
    from core.intake import resolve_phases
    assert "exploitation" not in resolve_phases(["exploitation"])


def test_brief_from_intent_respects_toggle(monkeypatch):
    monkeypatch.setattr(config, "get", lambda k, d=None: True if k == "exploitation_enabled" else d)
    from core.intake import brief_from_intent
    brief = brief_from_intent({"target": "10.0.0.5", "objective": "scan"}, "scan it")
    assert brief.exploitation_allowed is True       # on by default now


def test_handle_exploit_toggles(monkeypatch):
    store = {}
    monkeypatch.setattr(config, "set_value", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr(config, "get", lambda k, d=None: store.get(k, d))
    from ui.commands import handle_exploit
    _, ok = handle_exploit(["off"])
    assert ok and store["exploitation_enabled"] is False
    _, ok = handle_exploit(["on"])
    assert ok and store["exploitation_enabled"] is True
    lines, ok = handle_exploit([])
    assert ok and "ON" in " ".join(lines)


def test_info_shows_exploitation():
    from ui.commands import handle_info
    lines, ok = handle_info()
    assert ok and any("Exploitation" in ln for ln in lines)
