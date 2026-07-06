"""A locked OS keyring prompts on every get_password. Status/model-refresh paths
resolve keys repeatedly, so the keyring is read at most ONCE per provider per process
and the result cached — otherwise the unlock prompt recurs at 'random' times."""
import sys
import types

import core.llm_client as lc


def _fake_keyring(monkeypatch, counter, ret=None):
    mod = types.ModuleType("keyring")
    def get_password(svc, key):
        counter["n"] += 1
        return ret
    mod.get_password = get_password
    monkeypatch.setitem(sys.modules, "keyring", mod)


def test_keyring_read_once_then_cached(monkeypatch):
    lc.invalidate_key_cache()
    spec = lc.get_provider("openrouter")           # no env var set for it
    monkeypatch.delenv(spec.env_var, raising=False)
    calls = {"n": 0}
    _fake_keyring(monkeypatch, calls, ret=None)     # unconfigured → None, still cached

    for _ in range(5):
        assert lc.resolve_provider_key(spec) is None
    assert calls["n"] == 1                          # not 5 — no repeat prompts


def test_invalidate_forces_reread(monkeypatch):
    lc.invalidate_key_cache()
    spec = lc.get_provider("openrouter")
    monkeypatch.delenv(spec.env_var, raising=False)
    calls = {"n": 0}
    _fake_keyring(monkeypatch, calls, ret="sk-or-x")

    assert lc.resolve_provider_key(spec) == "sk-or-x"
    lc.invalidate_key_cache(spec.keyring_key)       # e.g. after /key set
    assert lc.resolve_provider_key(spec) == "sk-or-x"
    assert calls["n"] == 2                           # read again after invalidation


def test_env_var_never_touches_keyring(monkeypatch):
    lc.invalidate_key_cache()
    spec = lc.get_provider("anthropic")
    monkeypatch.setenv(spec.env_var, "sk-ant-env")
    calls = {"n": 0}
    _fake_keyring(monkeypatch, calls, ret="should-not-be-used")
    assert lc.resolve_provider_key(spec) == "sk-ant-env"
    assert calls["n"] == 0                            # keyring not consulted at all
