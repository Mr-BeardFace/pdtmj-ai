"""Provider-agnostic LLM client.

Supports Anthropic (native SDK) and OpenRouter (httpx, OpenAI-compat API).
The orchestrator always works with Anthropic-format messages and responses;
this module handles all conversion internally when using OpenRouter.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

import anthropic


# ── Custom exceptions ─────────────────────────────────────────────────────────

class APIAuthError(Exception):
    """API key rejected or access denied — not retryable."""


class APIAccountLimitError(Exception):
    """Account credit or hard quota limit reached — not retryable."""


class APIConnectionError(Exception):
    """Network connection to the provider failed and survived all retries. Resumable —
    the engagement is saved so /continue picks it up once connectivity is back."""


class ModelRefusalError(Exception):
    """The model declined to respond to the request content (stop_reason='refusal').
    Not retryable by re-sending the same turn — the persona/objective content is what
    tripped it, so looping to the next lead just repeats the refusal for free. Halts
    the engagement like an auth failure so the operator can switch models."""


# ── Helpers ───────────────────────────────────────────────────────────────────

_QUOTA_KEYWORDS = (
    "quota", "credit", "billing", "balance", "insufficient",
    "exceeded your", "monthly", "daily limit", "account limit",
    "out of tokens",
)


def _is_quota_exhaustion(msg: str) -> bool:
    lower = msg.lower()
    return any(kw in lower for kw in _QUOTA_KEYWORDS)


def _is_temperature_rejected(msg: str) -> bool:
    """A 400 caused by the model not accepting `temperature` (newer Opus models
    deprecate it). Matched so we can drop the param and retry instead of crashing."""
    lower = msg.lower()
    return "temperature" in lower and any(
        kw in lower for kw in ("deprecat", "not support", "unsupported",
                               "not allowed", "cannot", "invalid")
    )


# OS keyring service name. Deliberately kept as "pentest-ai" through the PDTMJ-AI
# rebrand: it is the lookup key for already-stored API keys, so renaming it would
# orphan the operator's saved credentials. Invisible to the user — leave it.
_KEYRING_SERVICE = "pentest-ai"


# ── Provider registry — the single source of truth ──────────────────────────────
# Adding a provider means adding ONE ProviderSpec here. Everything downstream —
# key storage/lookup, key-prefix auto-detection, /provider, /models, /info, and
# the request backend — derives from this table by iterating it. Nothing about a
# provider is hardcoded anywhere else.

@dataclass(frozen=True)
class ProviderSpec:
    name:         str                       # registry key, e.g. "anthropic"
    label:        str                       # human label, e.g. "Anthropic"
    keyring_key:  str                       # keychain entry name
    env_var:      str                       # fallback environment variable
    key_prefixes: tuple[str, ...]           # for auto-detecting which provider a key belongs to
    native:       bool = False              # True → Anthropic SDK path; False → OpenAI-compat HTTP
    chat_url:     str  = ""                 # OpenAI-compat chat-completions endpoint
    models_url:   str  = ""                 # GET endpoint backing /models list
    auth_style:   str  = "bearer"           # "bearer" (Authorization) | "x-api-key" (Anthropic)
    free_only:    bool = False              # /models list filters to zero-cost models (OpenRouter)
    extra_headers: dict = field(default_factory=dict)
    key_optional:    bool = False           # True → no API key required (local servers)
    base_url_config: str  = ""              # config.yaml key holding the base URL (local provider);
                                            # when set, chat/models endpoints derive from it at runtime
    # Optional operator-private extension points. Populated ONLY by an external
    # providers module (see _load_external_providers); nothing in the shipped tree
    # sets them, so both stay None for every provider in the table above. They let a
    # provider whose auth/transport can't live in the public repo be wired up locally.
    login:           Callable | None = None  # interactive auth: (args: list[str]) -> (lines, ok)
    request_handler: Callable | None = None  # custom transport: replaces the built-in run() path

    @property
    def key_hint(self) -> str:
        pfx = self.key_prefixes[0] if self.key_prefixes else "<key>"
        return (f"{self.label} API key not set — use /key set {pfx}... "
                f"then /provider set {self.name}")


def _bedrock_converse_messages(messages: list[dict]) -> list[dict]:
    """Convert Anthropic-format messages to Bedrock Converse format."""
    result: list[dict] = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        blocks: list[dict] = []

        if isinstance(content, str):
            blocks.append({"text": content})
            result.append({"role": role, "content": blocks})
            continue

        for raw in content:
            b = _block_as_dict(raw) if not isinstance(raw, dict) else raw
            btype = b.get("type", "")
            if btype == "text" and b.get("text"):
                blocks.append({"text": b["text"]})
            elif btype == "tool_use":
                blocks.append({"toolUse": {
                    "toolUseId": b.get("id", ""),
                    "name": b.get("name", ""),
                    "input": b.get("input", {}),
                }})
            elif btype == "tool_result":
                body = b.get("content", "")
                if isinstance(body, list):
                    body = " ".join(
                        (_block_as_dict(x).get("text", "")) for x in body
                    )
                status = "error" if b.get("is_error") else "success"
                blocks.append({"toolResult": {
                    "toolUseId": b.get("tool_use_id", ""),
                    "content": [{"text": str(body)}],
                    "status": status,
                }})

        if blocks:
            result.append({"role": role, "content": blocks})
    return result


def _bedrock_converse_tools(tools: list[dict]) -> dict:
    """Convert Anthropic tool schemas to Bedrock Converse toolConfig."""
    specs = []
    for tool in tools:
        schema = dict(tool.get("input_schema", {}))
        schema.pop("cache_control", None)
        specs.append({"toolSpec": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "inputSchema": {"json": schema},
        }})
    return {"tools": specs}


def _bedrock_converse_response(resp: dict) -> "_Message":
    """Convert Bedrock Converse response to our internal _Message format."""
    content: list = []
    output_msg = resp.get("output", {}).get("message", {})
    for block in output_msg.get("content", []):
        if "text" in block:
            content.append(_TextBlock(type="text", text=block["text"]))
        elif "toolUse" in block:
            tu = block["toolUse"]
            content.append(_ToolUseBlock(
                type="tool_use",
                id=tu.get("toolUseId", ""),
                name=tu.get("name", ""),
                input=tu.get("input", {}),
            ))

    stop_reason = resp.get("stopReason", "end_turn")
    usage_data = resp.get("usage", {})
    usage = _Usage(
        input_tokens=usage_data.get("inputTokens", 0),
        output_tokens=usage_data.get("outputTokens", 0),
    )
    return _Message(stop_reason=stop_reason, content=content, usage=usage)


_bedrock_model_cache: dict[str, str] = {}


def _bedrock_resolve_model(session, region: str, model: str) -> str:
    """Resolve a model name to a cross-region Bedrock inference profile ID.

    Newer Bedrock models require an inference profile ID (e.g.
    ``us.anthropic.claude-sonnet-4-6-20250514-v1:0``) instead of a bare
    foundation model ID.  This function:
    1. Looks up the foundation model ID via list_foundation_models
    2. Prepends the regional prefix (``us.``, ``eu.``, ``ap.``, …)

    Already-resolved inference profile IDs and ARNs pass through unchanged.
    """
    # Full inference profile ID or ARN — return as-is
    if model.startswith("arn:") or (model.count(".") >= 2 and ":" in model):
        return model
    if model in _bedrock_model_cache:
        return _bedrock_model_cache[model]

    resolved = model
    try:
        br = session.client("bedrock", region_name=region)
        summaries = br.list_foundation_models().get("modelSummaries", [])
        for m in summaries:
            mid = m.get("modelId", "")
            if model in mid:
                resolved = mid
                break
    except Exception:
        pass

    # Prepend regional prefix for cross-region inference profile
    prefix = region.split("-")[0]
    if not resolved.startswith(f"{prefix}."):
        resolved = f"{prefix}.{resolved}"

    _bedrock_model_cache[model] = resolved
    return resolved


def _bedrock_request_handler(client, model, system, messages, tools, max_tokens, temperature):
    """Transport for AWS Bedrock — uses boto3 Converse API (provider-agnostic)."""
    import boto3
    from core.config import get
    spec = PROVIDERS.get("bedrock")
    ak = resolve_provider_key(spec) if spec else None

    session_kwargs: dict = {}
    if ak:
        import os
        prev = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
        os.environ["AWS_BEARER_TOKEN_BEDROCK"] = ak
    else:
        profile = get("bedrock.profile", "")
        if profile:
            session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
        region = get("bedrock.region", "us-east-1")
        model = _bedrock_resolve_model(session, region, model)
        br = session.client("bedrock-runtime", region_name=region)

        kwargs: dict = {
            "modelId": model,
            "messages": _bedrock_converse_messages(messages),
            "system": [{"text": system}] if system else [],
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if temperature is not None:
            kwargs["inferenceConfig"]["temperature"] = temperature
        if tools:
            kwargs["toolConfig"] = _bedrock_converse_tools(tools)

        resp = br.converse(**kwargs)
        return _bedrock_converse_response(resp)
    finally:
        if ak:
            if prev is None:
                os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
            else:
                os.environ["AWS_BEARER_TOKEN_BEDROCK"] = prev


PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic", label="Anthropic",
        keyring_key="anthropic_api_key", env_var="ANTHROPIC_API_KEY",
        key_prefixes=("sk-ant-",), native=True,
        models_url="https://api.anthropic.com/v1/models", auth_style="x-api-key",
    ),
    "bedrock": ProviderSpec(
        name="bedrock", label="AWS Bedrock",
        keyring_key="bedrock_api_key", env_var="AWS_BEARER_TOKEN_BEDROCK",
        key_prefixes=("ABSKQ",),
        key_optional=True,          # IAM profile (~/.aws) is the fallback auth method
        request_handler=_bedrock_request_handler,
    ),
    "openrouter": ProviderSpec(
        name="openrouter", label="OpenRouter",
        keyring_key="openrouter_api_key", env_var="OPENROUTER_API_KEY",
        key_prefixes=("sk-or-",),
        chat_url="https://openrouter.ai/api/v1/chat/completions",
        models_url="https://openrouter.ai/api/v1/models", free_only=True,
        extra_headers={"HTTP-Referer": "https://pdtmj-ai", "X-Title": "PDTMJ-AI"},
    ),
    "nvidia": ProviderSpec(
        name="nvidia", label="NVIDIA",
        keyring_key="nvidia_api_key", env_var="NVIDIA_API_KEY",
        key_prefixes=("nvapi-",),
        chat_url="https://integrate.api.nvidia.com/v1/chat/completions",
        models_url="https://integrate.api.nvidia.com/v1/models",
    ),
    # Local OpenAI-compatible server (Ollama, LM Studio, llama.cpp, vLLM). The base
    # URL is the operator's, so it comes from config (`local_base_url`, set with
    # `/provider set local <url>`); the chat/models endpoints derive from it. Most
    # local servers need no key, so one is optional.
    "local": ProviderSpec(
        name="local", label="Local (OpenAI-compatible)",
        keyring_key="local_api_key", env_var="LOCAL_API_KEY",
        key_prefixes=(),                    # no prefix to auto-detect — select explicitly
        base_url_config="local_base_url",
        key_optional=True,
    ),
}


def _base_url_for(spec: ProviderSpec) -> str:
    """The configured base URL for a config-driven provider (local), trailing slash
    stripped; empty for providers with static endpoints."""
    if not spec.base_url_config:
        return ""
    from core.config import get
    return (get(spec.base_url_config, "") or "").rstrip("/")


def chat_url_for(spec: ProviderSpec) -> str:
    """Chat-completions endpoint — derived from the configured base URL for a local
    provider, else the spec's static `chat_url`."""
    base = _base_url_for(spec)
    return f"{base}/chat/completions" if base else spec.chat_url


def models_url_for(spec: ProviderSpec) -> str:
    """/models endpoint — derived from the configured base URL for a local provider,
    else the spec's static `models_url`."""
    base = _base_url_for(spec)
    return f"{base}/models" if base else spec.models_url


def get_provider(name: str | None) -> ProviderSpec:
    """The spec for a provider name, defaulting to Anthropic for an unknown name.

    Handles compound names like 'bedrock.anthropic' — matches on the base
    provider ('bedrock') so the same ProviderSpec covers all vendors.
    """
    key = (name or "").lower()
    if key in PROVIDERS:
        return PROVIDERS[key]
    base = key.split(".")[0]
    return PROVIDERS.get(base, PROVIDERS["anthropic"])


# keyring_key -> resolved secret (or None). The OS keyring is read at most ONCE per
# provider per process: a locked Secret Service prompts on every get_password, and
# status/model-refresh paths resolve keys repeatedly, so without this the prompt
# recurs at "random" times. Invalidated by invalidate_key_cache() on set/delete.
_KEY_CACHE: dict[str, str | None] = {}


def invalidate_key_cache(keyring_key: str | None = None) -> None:
    """Drop cached key resolutions (all, or one) after a /key set|delete changes them."""
    if keyring_key is None:
        _KEY_CACHE.clear()
    else:
        _KEY_CACHE.pop(keyring_key, None)


def resolve_provider_key(spec: ProviderSpec, override: str | None = None) -> str | None:
    """Resolve a provider's API key: explicit override → env var → keychain.

    Env var is checked before the keychain because the OS keyring (Secret Service on
    Linux) can BLOCK on a pinentry prompt when the login keyring is locked (headless /
    SSH sessions), so an exported key wins and avoids the prompt entirely. The keychain
    result is cached per process so a locked keyring is never prompted more than once."""
    if override:
        return override
    env = os.environ.get(spec.env_var)
    if env:
        return env
    if spec.keyring_key in _KEY_CACHE:
        return _KEY_CACHE[spec.keyring_key]
    stored = None
    try:
        import keyring
        stored = keyring.get_password(_KEYRING_SERVICE, spec.keyring_key)
    except Exception:
        stored = None
    _KEY_CACHE[spec.keyring_key] = stored
    return stored


def provider_for_key(api_key: str) -> ProviderSpec | None:
    """Which provider a raw key belongs to, matched by its prefix (for /key set)."""
    for spec in PROVIDERS.values():
        if any(api_key.startswith(p) for p in spec.key_prefixes):
            return spec
    return None


def auth_headers(spec: ProviderSpec, key: str) -> dict:
    """Auth headers for a plain HTTP call (chat or /models) to this provider. No key
    → no auth header (a local server that doesn't require one)."""
    if not key:
        return {}
    if spec.auth_style == "x-api-key":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    return {"Authorization": f"Bearer {key}"}


def _resolve_anthropic_key(api_key: str | None = None) -> str | None:
    """Back-compat shim (core.intake imports this) — Anthropic via the registry."""
    return resolve_provider_key(PROVIDERS["anthropic"], api_key)


# ── Anthropic-compatible response objects (used to normalise OpenRouter output) ─

@dataclass
class _TextBlock:
    type: str = "text"
    text: str = ""


@dataclass
class _ToolUseBlock:
    type: str = "tool_use"
    id:   str = ""
    name: str = ""
    input: dict = field(default_factory=dict)


@dataclass
class _Usage:
    input_tokens:               int = 0
    output_tokens:              int = 0
    cache_read_input_tokens:    int = 0
    cache_creation_input_tokens: int = 0


@dataclass
class _Message:
    stop_reason: str  = "end_turn"
    content:     list = field(default_factory=list)
    usage:       _Usage = field(default_factory=_Usage)


# ── Format converters ─────────────────────────────────────────────────────────

def _block_as_dict(block) -> dict:
    """Normalise an Anthropic SDK content block or plain dict to a dict."""
    if isinstance(block, dict):
        return block
    return {
        "type":  getattr(block, "type",  ""),
        "text":  getattr(block, "text",  ""),
        "id":    getattr(block, "id",    ""),
        "name":  getattr(block, "name",  ""),
        "input": getattr(block, "input", {}),
    }


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Convert Anthropic-format message list to OpenAI-compat format."""
    result: list[dict] = []
    for msg in messages:
        role    = msg["role"]
        content = msg["content"]

        if isinstance(content, str):
            result.append({"role": role, "content": content})
            continue

        if role == "assistant":
            text_parts: list[str] = []
            tool_calls: list[dict] = []
            for raw in content:
                b = _block_as_dict(raw)
                if b.get("type") == "text" and b.get("text"):
                    text_parts.append(b["text"])
                elif b.get("type") == "tool_use":
                    tool_calls.append({
                        "id":   b["id"],
                        "type": "function",
                        "function": {
                            "name":      b["name"],
                            "arguments": json.dumps(b.get("input", {})),
                        },
                    })
            out: dict = {"role": "assistant", "content": " ".join(text_parts) or None}
            if tool_calls:
                out["tool_calls"] = tool_calls
            result.append(out)

        elif role == "user":
            text_parts = []
            for raw in content:
                b = _block_as_dict(raw)
                btype = b.get("type", "")
                if btype == "tool_result":
                    body = b.get("content", "")
                    if isinstance(body, list):
                        body = " ".join(
                            (_block_as_dict(x).get("text", "")) for x in body
                        )
                    result.append({
                        "role":         "tool",
                        "tool_call_id": b.get("tool_use_id", ""),
                        "content":      str(body),
                    })
                elif btype == "text" and b.get("text"):
                    text_parts.append(b["text"])
            if text_parts:
                result.append({"role": "user", "content": "\n\n".join(text_parts)})

    return result


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Convert Anthropic tool-schema list to OpenAI function-calling format."""
    result = []
    for tool in tools:
        params = dict(tool.get("input_schema", {}))
        params.pop("cache_control", None)
        result.append({
            "type": "function",
            "function": {
                "name":        tool["name"],
                "description": tool.get("description", ""),
                "parameters":  params,
            },
        })
    return result


def _openai_response_to_anthropic(data: dict) -> _Message:
    """Convert an OpenAI-compat response body to our Anthropic-like _Message."""
    choice        = data.get("choices", [{}])[0]
    finish_reason = choice.get("finish_reason", "stop")
    message       = choice.get("message", {})

    stop_reason = {
        "tool_calls": "tool_use",
        "length":     "max_tokens",
    }.get(finish_reason, "end_turn")

    content: list = []
    text = message.get("content")
    if text:
        content.append(_TextBlock(type="text", text=text))

    for tc in message.get("tool_calls") or []:
        fn = tc.get("function", {})
        try:
            inputs = json.loads(fn.get("arguments", "{}"))
        except Exception:
            inputs = {}
        content.append(_ToolUseBlock(
            type="tool_use",
            id=tc.get("id", ""),
            name=fn.get("name", ""),
            input=inputs,
        ))

    usage_data = data.get("usage", {})
    usage = _Usage(
        input_tokens=usage_data.get("prompt_tokens", 0),
        output_tokens=usage_data.get("completion_tokens", 0),
    )
    return _Message(stop_reason=stop_reason, content=content, usage=usage)


# ── Main client ───────────────────────────────────────────────────────────────

class LLMClient:
    def __init__(
        self,
        api_key:  str | None = None,
        on_retry: Callable[[int, float, str], None] | None = None,
    ):
        from core.config import get
        self._provider = get("active_provider", "anthropic")
        self._spec     = get_provider(self._provider)
        self.on_retry  = on_retry

        # Transport selection. A provider may supply its own request_handler (an
        # operator-private extension); otherwise native (Anthropic SDK) vs
        # OpenAI-compatible (shared httpx backend).
        if self._spec.request_handler:
            # The custom transport owns its own auth — no SDK client, no key here.
            self._anthropic_client = None
            self._oai_key          = None
        elif self._spec.native:
            self._anthropic_client = anthropic.Anthropic(
                api_key=resolve_provider_key(self._spec, api_key)
            )
            self._oai_key = None
        else:
            self._anthropic_client = None
            self._oai_key          = resolve_provider_key(self._spec)

        # Models that have rejected the `temperature` parameter this session
        # (newer Opus models deprecate it). Once a model 400s on temperature we
        # stop sending it, so we pay the failed round-trip at most once.
        self._no_temperature_models: set[str] = set()

    def run(
        self,
        model:      str,
        system:     str,
        messages:   list[dict],
        tools:      list[dict],
        max_tokens: int = 8192,
        temperature: float | None = None,
        thinking: dict | None = None,
    ):
        # Temperature self-heal at the top level, so it also covers a provider's custom
        # request_handler (e.g. the subscription path) — not just the built-in backends.
        # A model that rejects `temperature` (newer Opus/Sonnet) would otherwise 400 and
        # fail the whole run instead of retrying without it.
        if model in self._no_temperature_models:
            temperature = None
        # Subscription / custom-transport providers never accept temperature — drop it
        # unconditionally so we don't pay a failed round-trip waiting for a 400.
        if self._spec.request_handler:
            temperature = None
        # Extended thinking requires temperature=1 on the Anthropic API.
        if thinking:
            temperature = 1.0
        try:
            return self._dispatch(model, system, messages, tools, max_tokens, temperature, thinking)
        except Exception as e:  # noqa: BLE001 — only the temperature 400 is swallowed
            if temperature is not None and _is_temperature_rejected(str(e)):
                self._no_temperature_models.add(model)
                return self._dispatch(model, system, messages, tools, max_tokens, None, thinking)
            raise

    def _dispatch(self, model, system, messages, tools, max_tokens, temperature, thinking=None):
        if self._spec.request_handler:
            return self._spec.request_handler(
                self, model, system, messages, tools, max_tokens, temperature)
        if not self._spec.native:
            return self._run_openai_compat(model, system, messages, tools, max_tokens, temperature)
        return self._run_anthropic(model, system, messages, tools, max_tokens, temperature, thinking)

    # ── Anthropic backend ─────────────────────────────────────────────────────

    @staticmethod
    def _with_conversation_cache(messages: list[dict]) -> list[dict]:
        """Mark the last block of the final user message with cache_control.

        The breakpoint moves forward each turn, so every call re-reads the
        previous turn's prefix from cache instead of re-billing the full
        (growing) conversation as uncached input. Only the copied last message
        is modified — the caller's list is left untouched, so stale
        cache_control markers never accumulate across turns.
        """
        if not messages or messages[-1].get("role") != "user":
            return messages
        last    = messages[-1]
        content = last.get("content")
        if isinstance(content, str):
            new_content = [{"type": "text", "text": content,
                            "cache_control": {"type": "ephemeral"}}]
        elif isinstance(content, list) and content and isinstance(content[-1], dict):
            new_content       = list(content)
            blk               = dict(new_content[-1])
            blk["cache_control"] = {"type": "ephemeral"}
            new_content[-1]   = blk
        else:
            return messages
        return messages[:-1] + [{**last, "content": new_content}]

    def _run_anthropic(self, model, system, messages, tools, max_tokens, temperature=None, thinking=None):
        system_block = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]

        cached_tools = None
        if tools:
            cached_tools = list(tools)
            last = dict(cached_tools[-1])
            last["cache_control"] = {"type": "ephemeral"}
            cached_tools[-1] = last

        kwargs = {
            "model":      model,
            "max_tokens": max_tokens,
            "system":     system_block,
            "messages":   self._with_conversation_cache(messages),
        }
        if thinking:
            kwargs["thinking"] = thinking
            kwargs["temperature"] = 1  # required by Anthropic when thinking is enabled
        elif temperature is not None and model not in self._no_temperature_models:
            kwargs["temperature"] = temperature
        if cached_tools:
            kwargs["tools"] = cached_tools

        max_retries = 5
        wait        = 4.0

        for attempt in range(max_retries + 1):
            try:
                return self._anthropic_client.messages.create(**kwargs)

            except anthropic.RateLimitError as e:
                if _is_quota_exhaustion(str(e)):
                    raise APIAccountLimitError("Request quota exhausted") from e
                if attempt >= max_retries:
                    raise APIAccountLimitError(
                        "Rate limit persists — quota may be exhausted"
                    ) from e
                self._notify_retry(attempt + 1, wait, "Rate limited")
                time.sleep(wait)
                wait = min(wait * 2, 60)

            except anthropic.InternalServerError:
                if attempt >= max_retries:
                    raise
                self._notify_retry(attempt + 1, wait, "Server error")
                time.sleep(wait)
                wait = min(wait * 2, 60)

            except anthropic.APIConnectionError as e:  # transient network blip / timeout
                if attempt >= max_retries:
                    raise APIConnectionError("Connection to the provider failed after retries") from e
                self._notify_retry(attempt + 1, wait, "Connection error")
                time.sleep(wait)
                wait = min(wait * 2, 60)

            except anthropic.AuthenticationError as e:
                raise APIAuthError(
                    "API key rejected — verify your key with /key set"
                ) from e

            except anthropic.PermissionDeniedError as e:
                if _is_quota_exhaustion(str(e)):
                    raise APIAccountLimitError("Account limit reached") from e
                raise APIAuthError("API access denied") from e

            except anthropic.BadRequestError as e:
                if _is_quota_exhaustion(str(e)):
                    raise APIAccountLimitError("Account limit reached") from e
                # Model rejected `temperature` — drop it, remember the model, and
                # retry this call so the agent doesn't hard-fail.
                if "temperature" in kwargs and _is_temperature_rejected(str(e)):
                    self._no_temperature_models.add(model)
                    kwargs.pop("temperature", None)
                    continue
                raise

        raise RuntimeError("LLMClient retry loop exited unexpectedly")

    # ── OpenAI-compatible backend (OpenRouter / NVIDIA) ─────────────────────────

    def _run_openai_compat(self, model, system, messages, tools, max_tokens, temperature=None):
        import httpx

        spec  = self._spec
        label = spec.label

        if not self._oai_key and not spec.key_optional:
            raise APIAuthError(spec.key_hint)
        if spec.base_url_config and not _base_url_for(spec):
            raise APIAuthError(
                f"{label}: no base URL set — run /provider set local <http://host:port/v1>")

        openai_messages = [{"role": "system", "content": system}] + _to_openai_messages(messages)
        openai_tools    = _to_openai_tools(tools) if tools else None

        payload: dict = {"model": model, "messages": openai_messages, "max_tokens": max_tokens}
        if temperature is not None and model not in self._no_temperature_models:
            payload["temperature"] = temperature
        if openai_tools:
            payload["tools"]       = openai_tools
            payload["tool_choice"] = "auto"

        headers = {
            **auth_headers(spec, self._oai_key),
            "Content-Type": "application/json",
            **spec.extra_headers,
        }

        max_retries = 5
        wait        = 4.0

        for attempt in range(max_retries + 1):
            try:
                resp = httpx.post(
                    chat_url_for(spec),
                    headers=headers,
                    json=payload,
                    timeout=120,
                )

                if resp.status_code == 200:
                    return _openai_response_to_anthropic(resp.json())

                # Parse error body — truncate to avoid leaking full response headers.
                try:
                    err_msg = resp.json().get("error", {}).get("message", resp.text)
                except Exception:
                    err_msg = resp.text
                err_msg = str(err_msg)[:200]

                if resp.status_code == 401:
                    raise APIAuthError(f"{label} API key rejected — check /key set")
                elif resp.status_code == 402 or _is_quota_exhaustion(err_msg):
                    raise APIAccountLimitError("Account credit limit reached")
                elif resp.status_code == 429:
                    if _is_quota_exhaustion(err_msg):
                        raise APIAccountLimitError("Request quota exhausted")
                    if attempt >= max_retries:
                        raise APIAccountLimitError(
                            "Rate limit persists — quota may be exhausted"
                        )
                    self._notify_retry(attempt + 1, wait, "Rate limited")
                    time.sleep(wait)
                    wait = min(wait * 2, 60)
                elif resp.status_code in (500, 502, 503, 529):
                    if attempt >= max_retries:
                        raise RuntimeError(f"{label} server error {resp.status_code}: {err_msg}")
                    self._notify_retry(attempt + 1, wait, "Server error")
                    time.sleep(wait)
                    wait = min(wait * 2, 60)
                elif (resp.status_code == 400 and "temperature" in payload
                      and _is_temperature_rejected(err_msg)):
                    # Model rejected `temperature` — drop it, remember, and retry.
                    self._no_temperature_models.add(model)
                    payload.pop("temperature", None)
                    continue
                else:
                    raise RuntimeError(f"{label} error {resp.status_code}: {err_msg}")

            except (APIAuthError, APIAccountLimitError, RuntimeError):
                raise
            except httpx.RequestError as e:           # timeout / connection / transport blip
                if attempt >= max_retries:
                    raise APIConnectionError(f"{label} connection failed: {type(e).__name__}") from e
                self._notify_retry(attempt + 1, wait, "Connection error")
                time.sleep(wait)
                wait = min(wait * 2, 60)

        raise RuntimeError("LLMClient retry loop exited unexpectedly")

    def _notify_retry(self, attempt: int, wait: float, reason: str) -> None:
        if self.on_retry:
            self.on_retry(attempt, wait, reason)


# ── Operator-private provider extensions ────────────────────────────────────────
# An optional seam for providers that can't ship in the public repo (e.g. one whose
# transport/auth depends on the operator's own setup). The repo ships NO such module;
# this is inert unless the operator drops one in. Resolution order:
#   1. $PDTMJ_LOCAL_PROVIDERS — explicit path to a .py file
#   2. ~/.config/pdtmj-ai/providers_local.py — the default location
# The module must expose `register(api)`, where `api` carries ProviderSpec, the
# PROVIDERS dict to insert into, and the response classes for building results.

def _external_api():
    from types import SimpleNamespace
    return SimpleNamespace(
        ProviderSpec=ProviderSpec,
        PROVIDERS=PROVIDERS,
        Message=_Message,
        TextBlock=_TextBlock,
        ToolUseBlock=_ToolUseBlock,
        Usage=_Usage,
        KEYRING_SERVICE=_KEYRING_SERVICE,
        APIAuthError=APIAuthError,
        APIAccountLimitError=APIAccountLimitError,
        APIConnectionError=APIConnectionError,
    )


def _external_providers_path():
    from pathlib import Path
    override = os.environ.get("PDTMJ_LOCAL_PROVIDERS")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "pdtmj-ai" / "providers_local.py"


def _load_external_providers() -> None:
    import importlib.util
    path = _external_providers_path()
    if not path.is_file():
        return
    try:
        spec = importlib.util.spec_from_file_location("pdtmj_providers_local", str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        register = getattr(module, "register", None)
        if callable(register):
            register(_external_api())
    except Exception as e:
        # A broken or absent private module must never take the app down — the
        # built-in providers still work. Surface the reason on stderr and move on.
        import sys
        print(f"[providers_local] failed to load {path}: {e}", file=sys.stderr)


_load_external_providers()
