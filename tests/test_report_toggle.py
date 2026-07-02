"""Reporting toggle — now set via /config reporting (was /report on|off).
The /report command itself still renders/regenerates; only its on|off toggle moved."""
import core.config as cfg
from ui.commands import dispatch


def test_report_off_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", lambda k, d=None: True if k == "reporting" else d)
    lines, ok = dispatch("/config reporting off")
    assert ok is True and calls == {"reporting": False}


def test_report_on_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    monkeypatch.setattr(cfg, "get", lambda k, d=None: False if k == "reporting" else d)
    dispatch("/config reporting on")
    assert calls == {"reporting": True}


def test_report_bad_arg_is_usage_error(monkeypatch):
    monkeypatch.setattr(cfg, "set_value", lambda k, v: None)
    lines, ok = dispatch("/config reporting maybe")
    assert ok is False and any("on|off" in ln for ln in lines)


def test_default_reporting_enabled_is_true():
    # Fresh default must keep reporting ON unless explicitly turned off.
    assert cfg._DEFAULTS["reporting"] is True
