"""LLM engine decisions (agent routing, surface choice, exhaustion) + call-sig."""
from core.agent_router import choose_agent, choose_surface, judge_continue
from core.orchestrator import _call_sig


# ── fake llm ───────────────────────────────────────────────────────────────────

class _Block:
    type = "text"
    def __init__(self, text): self.text = text


class _Resp:
    def __init__(self, text): self.content = [_Block(text)]


class _LLM:
    def __init__(self, text=None, exc=None):
        self.text = text; self.exc = exc; self.called = 0
    def run(self, **kw):
        self.called += 1
        if self.exc:
            raise self.exc
        return _Resp(self.text)


_CANDS = [("pentest/web", "web app testing"), ("pentest/rce", "foothold specialist")]


# ── choose_agent ───────────────────────────────────────────────────────────────

def test_picks_llm_choice():
    llm = _LLM(text='{"agent":"pentest/rce","reason":"file upload → RCE"}')
    name, reason, src = choose_agent(llm, "m", "exploit", "sd", "fd", _CANDS, "pentest/web")
    assert name == "pentest/rce" and src == "llm" and "RCE" in reason


def test_unknown_agent_falls_back():
    llm = _LLM(text='{"agent":"pentest/nope"}')
    name, _, src = choose_agent(llm, "m", "exploit", "sd", "fd", _CANDS, "pentest/web")
    assert name == "pentest/web" and src == "fallback"


def test_exception_falls_back():
    llm = _LLM(exc=RuntimeError("api down"))
    name, _, src = choose_agent(llm, "m", "exploit", "sd", "fd", _CANDS, "pentest/web")
    assert name == "pentest/web" and src == "fallback"


def test_markdown_fence_tolerated():
    llm = _LLM(text='```json\n{"agent":"pentest/web","reason":"it is a web app"}\n```')
    name, _, src = choose_agent(llm, "m", "enum", "sd", "fd", _CANDS, "pentest/rce")
    assert name == "pentest/web" and src == "llm"


def test_single_candidate_skips_llm():
    llm = _LLM(text='{"agent":"pentest/web"}')
    name, _, src = choose_agent(llm, "m", "enum", "sd", "fd", [("pentest/web", "d")], "pentest/web")
    assert src == "fallback" and llm.called == 0


# ── choose_surface ─────────────────────────────────────────────────────────────

_SURFACES = [("s1", "http MinIO"), ("s2", "ssh OpenSSH")]


def test_surface_picks_llm_choice():
    llm = _LLM(text='{"surface_id":"s1","reason":"object storage, anon read"}')
    sid, reason, src = choose_surface(llm, "m", _SURFACES, "guidance", "s2")
    assert sid == "s1" and src == "llm"


def test_surface_unknown_id_falls_back():
    llm = _LLM(text='{"surface_id":"s9"}')
    sid, _, src = choose_surface(llm, "m", _SURFACES, "guidance", "s2")
    assert sid == "s2" and src == "fallback"


def test_surface_single_skips_llm():
    llm = _LLM(text='{"surface_id":"s1"}')
    sid, _, src = choose_surface(llm, "m", [("s1", "d")], "g", "s1")
    assert src == "fallback" and llm.called == 0


# ── judge_continue (exhaustion) ─────────────────────────────────────────────────

def test_judge_returns_llm_bool():
    llm = _LLM(text='{"exhausted":false,"reason":"open lead remains"}')
    ex, reason, src = judge_continue(llm, "m", "sd", "found admin panel", True)
    assert ex is False and src == "llm"


def test_judge_non_bool_falls_back():
    llm = _LLM(text='{"exhausted":"maybe"}')
    ex, _, src = judge_continue(llm, "m", "sd", "summary", True)
    assert ex is True and src == "fallback"      # falls back to heuristic value


def test_judge_exception_falls_back():
    llm = _LLM(exc=RuntimeError("down"))
    ex, _, src = judge_continue(llm, "m", "sd", "summary", False)
    assert ex is False and src == "fallback"


# ── call signature (loop-nudge dedup) ──────────────────────────────────────────

def test_call_sig_identical():
    assert _call_sig("http_request", {"url": "x"}) == _call_sig("http_request", {"url": "x"})


def test_call_sig_ignores_background_flag():
    assert _call_sig("ffuf", {"url": "x", "background": True}) == _call_sig("ffuf", {"url": "x"})


def test_call_sig_differs_on_args_and_name():
    assert _call_sig("http_request", {"url": "x"}) != _call_sig("http_request", {"url": "y"})
    assert _call_sig("http_request", {"url": "x"}) != _call_sig("nc", {"url": "x"})
