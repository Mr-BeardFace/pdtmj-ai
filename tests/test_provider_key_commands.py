"""Command-driven local-provider config: `/provider set local <baseURL>` persists the
URL and switches provider; `/key set [provider] <key>` takes an optional explicit
provider for keys with no recognizable prefix."""
import core.config as cfgmod
import ui.commands as cmds


def _fake_config(monkeypatch):
    """In-memory config so set_value/get don't touch disk."""
    store = {}
    monkeypatch.setattr(cfgmod, "set_value", lambda k, v: store.__setitem__(k, v))
    monkeypatch.setattr(cfgmod, "get", lambda k, d=None: store.get(k, d))
    return store


def _fake_keyring(monkeypatch):
    saved = {}
    import sys, types
    kr = types.SimpleNamespace(
        set_password=lambda svc, key, val: saved.__setitem__((svc, key), val),
        get_password=lambda svc, key: saved.get((svc, key)),
    )
    monkeypatch.setitem(sys.modules, "keyring", kr)
    return saved


# ── /provider set local <url> ─────────────────────────────────────────────────

def test_provider_set_local_persists_url_and_switches(monkeypatch):
    store = _fake_config(monkeypatch)
    lines, ok = cmds.handle_provider_set(["local", "http://localhost:11434/v1"])
    assert ok
    assert store["local_base_url"] == "http://localhost:11434/v1"
    assert store["active_provider"] == "local"
    assert any("local" in ln for ln in lines)


def test_provider_set_local_without_url_errors(monkeypatch):
    _fake_config(monkeypatch)   # empty → no stored base URL
    lines, ok = cmds.handle_provider_set(["local"])
    assert not ok
    assert any("base URL" in ln or "11434" in ln for ln in lines)


def test_provider_set_local_reuses_stored_url(monkeypatch):
    store = _fake_config(monkeypatch)
    store["local_base_url"] = "http://10.0.0.9:11434/v1"
    lines, ok = cmds.handle_provider_set(["local"])     # no URL arg, but one is stored
    assert ok and store["active_provider"] == "local"


def test_provider_set_local_no_key_warning(monkeypatch):
    # key_optional provider must NOT warn about a missing key.
    _fake_config(monkeypatch)
    lines, ok = cmds.handle_provider_set(["local", "http://localhost:11434/v1"])
    assert ok
    assert not any("no Local" in ln and "API key" in ln for ln in lines)


# ── /key set [provider] <key> ─────────────────────────────────────────────────

def test_key_set_explicit_provider(monkeypatch):
    saved = _fake_keyring(monkeypatch)
    lines, ok = cmds.handle_key_set(["local", "my-local-token"])
    assert ok
    assert saved[("pentest-ai", "local_api_key")] == "my-local-token"


def test_key_set_autodetect_still_works(monkeypatch):
    saved = _fake_keyring(monkeypatch)
    lines, ok = cmds.handle_key_set(["sk-ant-abc123def456"])
    assert ok
    assert saved[("pentest-ai", "anthropic_api_key")] == "sk-ant-abc123def456"


def test_key_set_unknown_prefix_without_provider_errors(monkeypatch):
    _fake_keyring(monkeypatch)
    lines, ok = cmds.handle_key_set(["mystery-key-noprefix"])
    assert not ok
    assert any("which provider" in ln.lower() or "provider" in ln.lower() for ln in lines)
