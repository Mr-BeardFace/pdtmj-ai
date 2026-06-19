"""/agent set temp — per-agent sampling temperature from the TUI."""
import core.config as cfgmod
from ui.commands import parse, handle_agent_set_temp


def test_parse_recognizes_set_temp():
    cmd, args = parse("/agent set temp pentest/rce 0.5")
    assert cmd == "/agent set temp" and args == ["pentest/rce", "0.5"]


def test_set_temp_validation():
    assert handle_agent_set_temp(["pentest/rce"])[1] is False          # missing value
    out, ok = handle_agent_set_temp(["pentest/rce", "high"])
    assert ok is False and "between 0.0 and 1.0" in " ".join(out)
    assert handle_agent_set_temp(["pentest/rce", "2.5"])[1] is False   # out of range


def test_set_temp_writes(monkeypatch):
    store = {"agent_temperatures": {}, "temperature_default": 0.4}
    monkeypatch.setattr(cfgmod, "load_config", lambda: store)
    monkeypatch.setattr(cfgmod, "save_config", lambda c: None)

    assert handle_agent_set_temp(["pentest/rce", "0.5"])[1] is True
    assert store["agent_temperatures"]["pentest/rce"] == 0.5

    assert handle_agent_set_temp(["pentest/rce", "default"])[1] is True
    assert "pentest/rce" not in store["agent_temperatures"]            # cleared

    assert handle_agent_set_temp(["global", "0.25"])[1] is True
    assert store["temperature_default"] == 0.25                        # baseline

    assert handle_agent_set_temp(["global", "off"])[1] is True
    assert store["temperature_default"] is None                       # provider default
