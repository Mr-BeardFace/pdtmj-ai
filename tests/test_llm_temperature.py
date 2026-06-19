"""LLMClient drops `temperature` and retries when a model rejects it
(newer Opus models deprecate the parameter) instead of hard-failing the agent."""
import anthropic
import httpx

import core.config as cfgmod
from core.llm_client import LLMClient, _is_temperature_rejected


def _bad_request(msg: str) -> anthropic.BadRequestError:
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    resp = httpx.Response(400, request=req)
    return anthropic.BadRequestError(msg, response=resp, body=None)


def _client(monkeypatch) -> LLMClient:
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: "anthropic" if k == "active_provider" else d)
    return LLMClient(api_key="x")


# ── message matcher ───────────────────────────────────────────────────────────

def test_is_temperature_rejected():
    assert _is_temperature_rejected("temperature is deprecated for this model")
    assert _is_temperature_rejected("`temperature` is not supported with this model")
    assert not _is_temperature_rejected("max_tokens is too large")
    assert not _is_temperature_rejected("model is deprecated")   # no temperature mention


# ── self-heal on the Anthropic backend ────────────────────────────────────────

def test_drops_temperature_and_retries(monkeypatch):
    client = _client(monkeypatch)
    calls: list[dict] = []

    class FakeMessages:
        def create(self, **kwargs):
            calls.append(kwargs)
            if "temperature" in kwargs:
                raise _bad_request("temperature is deprecated for this model")
            return "OK"

    client._anthropic_client = type("C", (), {"messages": FakeMessages()})()

    out = client.run(model="claude-opus-4-7", system="s",
                     messages=[{"role": "user", "content": "hi"}],
                     tools=[], temperature=0.4)

    assert out == "OK"
    assert len(calls) == 2                          # failed-with-temp, then retry-without
    assert "temperature" in calls[0]
    assert "temperature" not in calls[1]
    assert "claude-opus-4-7" in client._no_temperature_models


def test_remembers_model_and_skips_temperature_next_time(monkeypatch):
    client = _client(monkeypatch)
    client._no_temperature_models.add("claude-opus-4-7")
    calls: list[dict] = []

    class FakeMessages:
        def create(self, **kwargs):
            calls.append(kwargs)
            return "OK"

    client._anthropic_client = type("C", (), {"messages": FakeMessages()})()

    client.run(model="claude-opus-4-7", system="s",
               messages=[{"role": "user", "content": "hi"}],
               tools=[], temperature=0.4)

    assert len(calls) == 1                           # no failed first attempt
    assert "temperature" not in calls[0]


def test_unrelated_bad_request_still_raises(monkeypatch):
    client = _client(monkeypatch)

    class FakeMessages:
        def create(self, **kwargs):
            raise _bad_request("max_tokens: must be <= 8192")

    client._anthropic_client = type("C", (), {"messages": FakeMessages()})()

    import pytest
    with pytest.raises(anthropic.BadRequestError):
        client.run(model="claude-opus-4-7", system="s",
                   messages=[{"role": "user", "content": "hi"}],
                   tools=[], temperature=0.4)
