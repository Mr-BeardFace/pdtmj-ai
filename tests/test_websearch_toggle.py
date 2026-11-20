"""Web-research toggle — now set via /config web_search (was /websearch)."""
import core.config as cfg
from ui.commands import dispatch


def _mock_get(special_key, special_val):
    def _get(k, d=None, **_kw):
        if k == "active_persona": return "pentest-ctf"
        return special_val if k == special_key else d
    return _get


def test_off_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", _mock_get("web_search", True))
    lines, ok = dispatch("/config web_search off")
    assert ok and calls == {"web_search": False}


def test_on_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", _mock_get("web_search", False))
    dispatch("/config web_search on")
    assert calls == {"web_search": True}


def test_invalid_value_rejected(monkeypatch):
    monkeypatch.setattr(cfg, "set_value", lambda k, v: None)
    monkeypatch.setattr(cfg, "get", _mock_get("web_search", True))
    lines, ok = dispatch("/config web_search maybe")
    assert not ok and any("on|off" in ln for ln in lines)


def test_old_command_is_gone():
    res = dispatch("/websearch off")
    assert res is not None and res[1] is False
    assert any("Unknown command" in ln for ln in res[0])
