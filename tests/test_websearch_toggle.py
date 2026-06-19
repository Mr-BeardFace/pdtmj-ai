"""/websearch on|off — toggle the web-research tools (web_search + fetch_url)."""
import core.config as cfg
from ui.commands import dispatch, handle_websearch, parse


def test_parse_and_route():
    assert parse("/websearch off") == ("/websearch", ["off"])


def test_off_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    lines, ok = handle_websearch(["off"])
    assert ok and calls == {"allow_web_search": False}
    assert any("DISABLED" in ln for ln in lines)


def test_on_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    handle_websearch(["on"])
    assert calls == {"allow_web_search": True}


def test_status_no_arg(monkeypatch):
    monkeypatch.setattr(cfg, "get", lambda k, d=None: False if k == "allow_web_search" else d)
    lines, ok = handle_websearch([])
    assert ok and any("OFF" in ln for ln in lines)


def test_routed_through_dispatch(monkeypatch):
    monkeypatch.setattr(cfg, "set_value", lambda k, v: None)
    res = dispatch("/websearch off")
    assert res is not None and res[1] is True
