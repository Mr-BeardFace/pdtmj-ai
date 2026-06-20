"""/assessment load replays the saved engagement.jsonl through the live _handle_event
renderer (render-only). This fixes the reload bug where tool output showed literal
"\n" — the flat engagement.log stores compact JSON, while the live view expands
output into real lines via _output_snippet."""
from types import SimpleNamespace
from ui.app import PentestApp


class _Stub:
    """Minimal stand-in for the app so _handle_event/_output_snippet run without a
    Textual runtime. Mirrors the class attrs those methods read."""
    _SNIPPET_TEXT_KEYS = PentestApp._SNIPPET_TEXT_KEYS
    _SNIPPET_MAX_LINES = PentestApp._SNIPPET_MAX_LINES
    _SNIPPET_MAX_WIDTH = PentestApp._SNIPPET_MAX_WIDTH

    def __init__(self, replaying=True):
        self._replaying = replaying
        self.activity: list[str] = []
        self.findings: list[dict] = []
        self._agent_held = False
        self._current_agent = ""
        self._total_tokens = {"input": 0, "output": 0, "cache_read": 0}
        self._total_cost = 0.0

    def _output_snippet(self, output):
        return PentestApp._output_snippet(self, output)

    def _handle_event(self, ev):
        return PentestApp._handle_event(self, ev)

    def _activity(self, msg):
        self.activity.append(msg)

    def _add_finding(self, f):
        self.findings.append(f)

    def _update_status(self):
        pass

    def query_one(self, *a, **k):
        return SimpleNamespace(write=lambda *a, **k: None)


def test_output_snippet_expands_multiline_body():
    # The bug: a JSON body with embedded newlines must render as real lines, not
    # one blob containing literal "\n".
    out = PentestApp._output_snippet(_Stub(), {"body": "line1\nline2\nline3"})
    assert out == ["line1", "line2", "line3"]


def test_tool_done_renders_output_as_separate_lines():
    s = _Stub()
    PentestApp._handle_event(s, {
        "type": "tool_done", "command_str": "id",
        "summary": "exit 0", "output": {"stdout": "uid=0(root)\ngid=0(root)"},
    })
    blob = "\n".join(s.activity)
    assert "uid=0(root)" in blob and "gid=0(root)" in blob
    # each output line was emitted on its own — not as a single escaped string
    assert not any("uid=0(root)\\ngid=0(root)" in m for m in s.activity)


def test_replay_renders_annotation_without_adding_finding():
    s = _Stub(replaying=True)
    PentestApp._handle_event(s, {
        "type": "annotation", "severity": "high", "title": "RCE", "verified": True,
        "finding_id": "f1",
    })
    assert s.findings == []                       # findings come from saved runs, not replay
    assert any("RCE" in m for m in s.activity)     # but the line is still rendered


def test_live_annotation_still_adds_finding():
    s = _Stub(replaying=False)
    PentestApp._handle_event(s, {
        "type": "annotation", "severity": "high", "title": "RCE", "finding_id": "f1",
    })
    assert len(s.findings) == 1


def test_replay_does_not_move_token_counters():
    s = _Stub(replaying=True)
    PentestApp._handle_event(s, {"type": "token_update", "input_delta": 100,
                                 "output_delta": 50, "cost_delta": 1.23})
    assert s._total_tokens["input"] == 0 and s._total_cost == 0.0


def test_replay_engagement_tolerates_bad_lines(tmp_path):
    # A malformed jsonl line must not abort the whole replay, and _replaying is reset.
    p = tmp_path / "engagement.jsonl"
    p.write_text('{"type":"agent_reasoning","text":"hello"}\n'
                 'not json at all\n'
                 '{"type":"tool_done","summary":"ok","output":{}}\n', encoding="utf-8")
    s = _Stub(replaying=False)
    PentestApp._replay_engagement(s, p)
    assert s._replaying is False                    # reset in finally
    blob = "\n".join(s.activity)
    assert "hello" in blob and "ok" in blob         # both valid events rendered
