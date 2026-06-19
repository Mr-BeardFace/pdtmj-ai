"""/report on|off — toggle the reporting phase (bare /report still generates one)."""
import core.config as cfg
from ui.commands import handle_report, parse


def test_parse_report_variants():
    assert parse("/report") == ("/report", [])
    assert parse("/report off") == ("/report", ["off"])
    assert parse("/report on") == ("/report", ["on"])


def test_report_off_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    lines, ok = handle_report(["off"])
    assert ok is True
    assert calls == {"reporting_enabled": False}
    assert any("DISABLED" in ln for ln in lines)


def test_report_on_sets_flag(monkeypatch):
    calls = {}
    monkeypatch.setattr(cfg, "set_value", lambda k, v: calls.__setitem__(k, v))
    lines, ok = handle_report(["on"])
    assert ok is True
    assert calls == {"reporting_enabled": True}


def test_report_status_no_arg(monkeypatch):
    monkeypatch.setattr(cfg, "get",
                        lambda k, d=None: False if k == "reporting_enabled" else d)
    lines, ok = handle_report([])
    assert ok is True
    assert any("OFF" in ln for ln in lines)


def test_report_bad_arg_is_usage_error():
    lines, ok = handle_report(["maybe"])
    assert ok is False
    assert any("Usage" in ln for ln in lines)


def test_default_reporting_enabled_is_true():
    # Fresh default must keep reporting ON unless explicitly turned off.
    assert cfg._DEFAULTS["reporting_enabled"] is True
