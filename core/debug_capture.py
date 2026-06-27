"""Full LLM/command transcript capture for debugging.

When enabled (config `debug_capture`, toggled with /debug), every agent turn is
written to `<engagement results dir>/llm_debug.log` in the order it happens:

    ▶ REQUEST   (full system prompt + tool list + full message history)
    ◀ RESPONSE  (full model output: text + tool_use blocks + token usage)
    ⚙ COMMAND   (each tool call the model made this turn — name + full input)

so a turn reads top-to-bottom as request → response → command(s). One file per
engagement, appended across all agents, thread-safe for parallel workers.

SENSITIVE: this is a *full* transcript. The model is given real secrets/loot so it
can authenticate, so the request/command bodies contain those values in plaintext
(unredacted — that's the point of a debug trace). The file lands in the engagement
results dir (gitignored). Treat it as you would captured engagement data.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path

_lock = threading.Lock()
_path: Path | None = None
_enabled = False


def configure(path: Path | str | None, enabled: bool) -> None:
    """Point capture at an engagement's log file and turn it on/off. Re-read each
    agent run so a mid-engagement /debug toggle takes effect on the next agent."""
    global _path, _enabled
    _path = Path(path) if path else None
    _enabled = bool(enabled and _path)


def enabled() -> bool:
    return _enabled and _path is not None


def _write(text: str) -> None:
    if not enabled():
        return
    with _lock:
        try:
            with open(_path, "a", encoding="utf-8") as f:
                f.write(text)
        except Exception:
            pass  # debug capture must never break a run


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _block_to_dict(b) -> dict:
    if isinstance(b, dict):
        return b
    t = getattr(b, "type", "")
    if t == "text":
        return {"type": "text", "text": getattr(b, "text", "")}
    if t == "tool_use":
        return {"type": "tool_use", "id": getattr(b, "id", ""),
                "name": getattr(b, "name", ""), "input": getattr(b, "input", {})}
    return {"type": t or "unknown", "repr": str(b)}


def log_request(agent, turn, model, system, messages, tools) -> None:
    if not enabled():
        return
    tool_names = ", ".join(t.get("name", "?") for t in (tools or [])) or "(none)"
    sys_text = system if isinstance(system, str) else json.dumps(system, indent=2, default=str)
    _write(
        f"\n{'─' * 100}\n"
        f"▶ REQUEST   [{_ts()}]  agent={agent}  turn={turn}  model={model}\n"
        f"{'─' * 100}\n"
        f"--- SYSTEM ---\n{sys_text}\n"
        f"--- TOOLS ({len(tools or [])}) ---\n{tool_names}\n"
        f"--- MESSAGES ---\n{json.dumps(messages, indent=2, default=str)}\n"
    )


def log_response(agent, turn, response) -> None:
    if not enabled():
        return
    try:
        content = [_block_to_dict(b) for b in response.content]
    except Exception:
        content = str(response)
    u = getattr(response, "usage", None)
    usage = {k: getattr(u, k, 0) for k in
             ("input_tokens", "output_tokens",
              "cache_read_input_tokens", "cache_creation_input_tokens")} if u else {}
    _write(
        f"\n◀ RESPONSE  [{_ts()}]  agent={agent}  turn={turn}  "
        f"stop={getattr(response, 'stop_reason', None)}  usage={usage}\n"
        f"{json.dumps(content, indent=2, default=str)}\n"
    )


def log_error(agent, turn, exc) -> None:
    """Log a failed LLM call (429/404/auth/timeout/etc.) where the response would go,
    so a turn still reads request → error. Captures the exception type, full message
    (which for HTTP errors carries the status + provider reason), and traceback."""
    if not enabled():
        return
    import traceback
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    _write(
        f"\n✖ ERROR     [{_ts()}]  agent={agent}  turn={turn}  "
        f"{type(exc).__name__}: {exc}\n{tb}\n"
    )


def log_command(agent, turn, name, tool_input) -> None:
    if not enabled():
        return
    _write(
        f"\n⚙ COMMAND   [{_ts()}]  agent={agent}  turn={turn}  tool={name}\n"
        f"{json.dumps(tool_input, indent=2, default=str)}\n"
    )
