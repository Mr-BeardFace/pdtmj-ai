"""PentestApp._output_snippet — the inline tool-output preview in the activity log."""
from ui.app import PentestApp

# _output_snippet ignores self, so call it unbound with a stand-in.
_snip = PentestApp._output_snippet


class _Dummy:
    _SNIPPET_TEXT_KEYS = PentestApp._SNIPPET_TEXT_KEYS
    _SNIPPET_MAX_LINES = PentestApp._SNIPPET_MAX_LINES
    _SNIPPET_MAX_WIDTH = PentestApp._SNIPPET_MAX_WIDTH


def test_prefers_stdout(self_=_Dummy()):
    out = _snip(self_, {"stdout": "line1\nline2\n", "rc": 0})
    assert out == ["line1", "line2"]


def test_caps_lines_and_flags_more():
    d = _Dummy()
    text = "\n".join(f"l{i}" for i in range(20))
    out = _snip(d, {"output": text})
    assert len(out) == d._SNIPPET_MAX_LINES + 1          # N lines + a "more" footer
    assert "more line(s)" in out[-1]


def test_truncates_wide_lines():
    d = _Dummy()
    out = _snip(d, {"text": "x" * 500})
    assert out[0].endswith("…")
    assert len(out[0]) <= d._SNIPPET_MAX_WIDTH + 1


def test_structured_only_falls_back_to_json():
    out = _snip(_Dummy(), {"hosts": [{"ip": "10.0.0.1"}], "_command": "nmap ..."})
    assert out and "10.0.0.1" in out[0]
    assert "_command" not in out[0]                       # _command is filtered out


def test_empty_output_yields_nothing():
    assert _snip(_Dummy(), {}) == []
    assert _snip(_Dummy(), {"stdout": "   \n  "}) == []


def test_non_dict_output():
    out = _snip(_Dummy(), "just a string\nsecond")
    assert out == ["just a string", "second"]
