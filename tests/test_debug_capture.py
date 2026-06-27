"""Full-transcript debug capture — off by default, writes request→response→command
in order when enabled."""
from dataclasses import dataclass, field

import core.debug_capture as dc


@dataclass
class _Blk:
    type: str = "text"
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)


@dataclass
class _Usage:
    input_tokens: int = 10
    output_tokens: int = 5
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass
class _Resp:
    stop_reason: str = "tool_use"
    content: list = field(default_factory=list)
    usage: _Usage = field(default_factory=_Usage)


def test_disabled_by_default_is_noop(tmp_path):
    dc.configure(None, False)
    assert dc.enabled() is False
    dc.log_request("a", 0, "m", "sys", [], [])   # must not raise, must not write
    assert not (tmp_path / "llm_debug.log").exists()


def test_writes_request_response_command_in_order(tmp_path):
    log = tmp_path / "llm_debug.log"
    dc.configure(log, True)
    assert dc.enabled() is True

    dc.log_request("enum", 3, "claude-x",
                   "SYSTEM PROMPT", [{"role": "user", "content": "hi"}],
                   [{"name": "nmap_scan"}])
    resp = _Resp(content=[_Blk(type="text", text="thinking"),
                          _Blk(type="tool_use", id="t1", name="nmap_scan",
                               input={"target": "10.0.0.1"})])
    dc.log_response("enum", 3, resp)
    dc.log_command("enum", 3, "nmap_scan", {"target": "10.0.0.1"})

    text = log.read_text(encoding="utf-8")
    # All three present, and in request → response → command order.
    i_req = text.index("▶ REQUEST")
    i_res = text.index("◀ RESPONSE")
    i_cmd = text.index("⚙ COMMAND")
    assert i_req < i_res < i_cmd
    # Full content captured.
    assert "SYSTEM PROMPT" in text
    assert "nmap_scan" in text and "10.0.0.1" in text
    assert "thinking" in text
    dc.configure(None, False)   # reset for other tests


def test_toggle_off_stops_writing(tmp_path):
    log = tmp_path / "llm_debug.log"
    dc.configure(log, True)
    dc.log_request("a", 0, "m", "s", [], [])
    size_after_one = log.stat().st_size
    dc.configure(log, False)
    dc.log_request("a", 1, "m", "s", [], [])    # ignored
    assert log.stat().st_size == size_after_one
    dc.configure(None, False)


def test_command_handler_toggles_config():
    import ui.commands as commands
    from core.config import get
    commands.handle_debug(["on"])
    assert get("debug_capture", False) is True
    commands.handle_debug(["off"])
    assert get("debug_capture", False) is False
