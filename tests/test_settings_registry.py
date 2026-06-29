"""Settings registry — the catalogue backing /config and /info."""
import pytest

from core import settings, config


def test_every_setting_has_a_default():
    # A registry key with no _DEFAULTS entry would read default=None and show as
    # perpetually "changed" in /info — guard against that drift.
    missing = [s.key for s in settings.SETTINGS if s.key not in config._DEFAULTS]
    assert missing == [], f"settings missing from _DEFAULTS: {missing}"


def test_keys_unique_and_grouped():
    keys = [s.key for s in settings.SETTINGS]
    assert len(keys) == len(set(keys))
    assert all(s.group for s in settings.SETTINGS)


def test_bool_coercion():
    s = settings.get_setting("parallel_enabled")
    assert settings.coerce(s, "on") == (True, None)
    assert settings.coerce(s, "off") == (False, None)
    val, err = settings.coerce(s, "maybe")
    assert val is None and "on|off" in err


def test_int_coercion_and_floor():
    s = settings.get_setting("max_parallel_agents")   # minimum=1
    assert settings.coerce(s, "4") == (4, None)
    val, err = settings.coerce(s, "0")
    assert val is None and "≥ 1" in err
    val, err = settings.coerce(s, "x")
    assert val is None and "integer" in err


def test_nullable_int_accepts_null():
    s = settings.get_setting("max_total_cycles")      # allow_null
    assert settings.coerce(s, "null") == (None, None)
    assert settings.coerce(s, "100") == (100, None)


def test_is_changed_tracks_default(monkeypatch):
    s = settings.get_setting("max_parallel_agents")
    monkeypatch.setattr(config, "get", lambda k, d=None: s.default if k == s.key else d)
    assert settings.is_changed(s) is False
    monkeypatch.setattr(config, "get", lambda k, d=None: 9 if k == s.key else d)
    assert settings.is_changed(s) is True


def test_format_value():
    assert settings.format_value(True) == "ON"
    assert settings.format_value(False) == "OFF"
    assert settings.format_value(None) == "—"
    assert settings.format_value(60) == "60"
