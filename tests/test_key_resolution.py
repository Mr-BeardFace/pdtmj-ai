"""Key resolution checks the env var BEFORE the OS keyring, so an exported key skips
keyring entirely — the keyring's Secret Service backend can block on a pinentry prompt
when the login keyring is locked (headless / SSH)."""
import sys
import types

import core.llm_client as lc


def _fake_keyring(monkeypatch, get_password):
    mod = types.ModuleType("keyring")
    mod.get_password = get_password
    monkeypatch.setitem(sys.modules, "keyring", mod)


def test_env_var_used_without_touching_keyring(monkeypatch):
    spec = lc.get_provider("anthropic")
    monkeypatch.setenv(spec.env_var, "sk-ant-env")

    def boom(*a, **k):
        raise AssertionError("keyring must not be consulted when the env var is set")
    _fake_keyring(monkeypatch, boom)
    assert lc.resolve_provider_key(spec) == "sk-ant-env"


def test_keyring_still_the_fallback(monkeypatch):
    spec = lc.get_provider("anthropic")
    monkeypatch.delenv(spec.env_var, raising=False)
    _fake_keyring(monkeypatch, lambda svc, key: "sk-ant-ring")
    assert lc.resolve_provider_key(spec) == "sk-ant-ring"


def test_override_beats_everything(monkeypatch):
    spec = lc.get_provider("anthropic")
    monkeypatch.setenv(spec.env_var, "sk-ant-env")
    assert lc.resolve_provider_key(spec, override="sk-ant-override") == "sk-ant-override"
