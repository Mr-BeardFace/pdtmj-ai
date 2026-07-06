"""A transient provider connection error is retried, not fatal; a persistent one
raises the resumable APIConnectionError so the engagement is saved for /continue
instead of being torn down."""
import anthropic
import httpx
import pytest

import core.config as cfgmod
from core.llm_client import LLMClient, APIConnectionError


def _client(monkeypatch) -> LLMClient:
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: "anthropic" if k == "active_provider" else d)
    monkeypatch.setattr("core.llm_client.time.sleep", lambda *a: None)   # no real backoff
    return LLMClient(api_key="x")


def _conn_error() -> anthropic.APIConnectionError:
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic.APIConnectionError(request=req)


def test_transient_connection_error_is_retried(monkeypatch):
    client = _client(monkeypatch)
    calls = {"n": 0}

    class FakeMessages:
        def create(self, **kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise _conn_error()     # two blips
            return "OK"

    client._anthropic_client = type("C", (), {"messages": FakeMessages()})()
    out = client.run(model="claude-opus-4-7", system="s",
                     messages=[{"role": "user", "content": "hi"}], tools=[])
    assert out == "OK" and calls["n"] == 3


def test_persistent_connection_error_raises_resumable(monkeypatch):
    client = _client(monkeypatch)

    class FakeMessages:
        def create(self, **kwargs):
            raise _conn_error()

    client._anthropic_client = type("C", (), {"messages": FakeMessages()})()
    # the resumable custom error, NOT the SDK's — the pipeline saves + offers /continue
    with pytest.raises(APIConnectionError):
        client.run(model="claude-opus-4-7", system="s",
                   messages=[{"role": "user", "content": "hi"}], tools=[])
