"""Web-research toggle — now set via /config allow_web_search (was /websearch)."""
import core.config as cfg
from ui.commands import dispatch


def test_off_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", lambda k, d=None: True if k == "allow_web_search" else d)
    lines, ok = dispatch("/config allow_web_search off")
    assert ok and calls == {"allow_web_search": False}


def test_on_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", lambda k, d=None: False if k == "allow_web_search" else d)
    dispatch("/config allow_web_search on")
    assert calls == {"allow_web_search": True}


def test_invalid_value_rejected(monkeypatch):
    monkeypatch.setattr(cfg, "set_value", lambda k, v: None)
    lines, ok = dispatch("/config allow_web_search maybe")
    assert not ok and any("on|off" in ln for ln in lines)


def test_old_command_is_gone():
    res = dispatch("/websearch off")
    assert res is not None and res[1] is False
    assert any("Unknown command" in ln for ln in res[0])
