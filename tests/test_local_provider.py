"""Local (OpenAI-compatible) provider — Ollama/LM Studio/llama.cpp/vLLM. The base
URL is operator-supplied (config / `/provider set local <url>`) and the API key is
optional, so the chat/models endpoints derive from config and a missing key sends
no auth header."""
import httpx
import pytest

import core.config as cfgmod
import core.llm_client as llm
from core.llm_client import (
    LLMClient, PROVIDERS, auth_headers, chat_url_for, models_url_for, APIAuthError,
)


def _cfg(monkeypatch, **vals):
    monkeypatch.setattr(cfgmod, "get", lambda k, d=None: vals.get(k, d))


# ── registry / helpers ────────────────────────────────────────────────────────

def test_local_registered_key_optional_config_driven():
    spec = PROVIDERS["local"]
    assert spec.key_optional and spec.base_url_config == "local_base_url"
    assert spec.key_prefixes == ()          # nothing to auto-detect — selected explicitly
    assert not spec.native and spec.chat_url == ""   # endpoint comes from config


def test_auth_headers_omitted_without_key():
    spec = PROVIDERS["local"]
    assert auth_headers(spec, "") == {}                       # no key → no auth
    assert auth_headers(spec, "tok") == {"Authorization": "Bearer tok"}


def test_endpoints_derive_from_config(monkeypatch):
    _cfg(monkeypatch, local_base_url="http://localhost:11434/v1")
    spec = PROVIDERS["local"]
    assert chat_url_for(spec) == "http://localhost:11434/v1/chat/completions"
    assert models_url_for(spec) == "http://localhost:11434/v1/models"


def test_trailing_slash_normalized(monkeypatch):
    _cfg(monkeypatch, local_base_url="http://localhost:11434/v1/")
    assert chat_url_for(PROVIDERS["local"]) == "http://localhost:11434/v1/chat/completions"


# ── request path ──────────────────────────────────────────────────────────────

def test_local_run_hits_configured_url_without_auth(monkeypatch):
    _cfg(monkeypatch, active_provider="local", local_base_url="http://127.0.0.1:11434/v1")
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["url"], captured["headers"] = url, headers
        return httpx.Response(200, request=httpx.Request("POST", url),
                              json={"choices": [{"finish_reason": "stop",
                                                 "message": {"content": "hi from llama"}}],
                                    "usage": {"prompt_tokens": 4, "completion_tokens": 2}})

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(llm, "resolve_provider_key", lambda spec, override=None: None)
    c = LLMClient()                          # no key resolved → key_optional path
    out = c.run(model="llama3.1:8b", system="s",
                messages=[{"role": "user", "content": "hi"}], tools=[])

    assert captured["url"] == "http://127.0.0.1:11434/v1/chat/completions"
    assert "Authorization" not in captured["headers"]    # no key → no auth header
    assert out.content[0].text == "hi from llama"


def test_local_without_base_url_raises(monkeypatch):
    _cfg(monkeypatch, active_provider="local", local_base_url=None)
    monkeypatch.setattr(llm, "resolve_provider_key", lambda spec, override=None: None)
    c = LLMClient()
    with pytest.raises(APIAuthError):
        c.run(model="x", system="s",
              messages=[{"role": "user", "content": "hi"}], tools=[])
