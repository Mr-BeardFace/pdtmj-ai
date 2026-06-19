"""NVIDIA provider — routes through the shared OpenAI-compatible backend
(integrate.api.nvidia.com), Bearer auth, OpenAI→Anthropic response conversion."""
import httpx

import core.config as cfgmod
from core.llm_client import LLMClient, PROVIDERS, APIAuthError


def _client(monkeypatch, provider="nvidia") -> LLMClient:
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: provider if k == "active_provider" else d)
    c = LLMClient()
    c._oai_key = "nvapi-test"          # skip keyring/env resolution
    return c


def test_nvidia_is_registered_openai_compat():
    spec = PROVIDERS["nvidia"]
    assert spec.chat_url == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert not spec.native and spec.auth_style == "bearer"
    assert spec.key_prefixes == ("nvapi-",)


def test_nvidia_routes_to_openai_compat_backend(monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return httpx.Response(
            200, request=httpx.Request("POST", url),
            json={"choices": [{"finish_reason": "stop",
                               "message": {"content": "hello from nemotron"}}],
                  "usage": {"prompt_tokens": 5, "completion_tokens": 3}})

    monkeypatch.setattr(httpx, "post", fake_post)
    c = _client(monkeypatch)

    out = c.run(model="nvidia/llama-3.3-nemotron-super-49b-v1", system="s",
                messages=[{"role": "user", "content": "hi"}], tools=[])

    # hit the NVIDIA endpoint with Bearer auth, not OpenRouter
    assert captured["url"] == "https://integrate.api.nvidia.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer nvapi-test"
    # OpenAI response normalised to our Anthropic-like _Message
    assert out.stop_reason == "end_turn"
    assert out.content[0].text == "hello from nemotron"
    assert out.usage.input_tokens == 5


def test_nvidia_missing_key_raises_auth_error(monkeypatch):
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: "nvidia" if k == "active_provider" else d)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    # force key resolution to return nothing (ignore any real keychain entry)
    import core.llm_client as llm
    monkeypatch.setattr(llm, "resolve_provider_key", lambda spec, override=None: None)
    c = LLMClient()
    import pytest
    with pytest.raises(APIAuthError):
        c.run(model="x", system="s",
              messages=[{"role": "user", "content": "hi"}], tools=[])
