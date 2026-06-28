"""Orchestrator loop tests using a scripted fake LLM — no API calls."""
import json

from core.agent_loader import AgentDefinition
from core.engagement_state import EngagementState
from core.llm_client import _Message, _TextBlock, _ToolUseBlock, _Usage
from core.models import Finding
from core.orchestrator import Orchestrator
from core.tool_registry import Tool, ToolRegistry


class FakeLLM:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
        self.calls += 1
        return self._responses.pop(0)


def _msg(*blocks):
    return _Message(content=list(blocks), usage=_Usage(input_tokens=10, output_tokens=5))


def _agent(scope):
    return AgentDefinition(
        name="test/agent", description="", scope=scope,
        model="claude-sonnet-4-6", system_prompt="You are a test agent.",
        metadata={},
    )


def _registry(func, name="fake_tool"):
    reg = ToolRegistry()
    reg.register(Tool(name=name, description="", input_schema={"type": "object"}, func=func))
    return reg


def _orchestrator(tmp_path, llm, registry, state=None):
    return Orchestrator(
        llm, registry, tmp_path, quiet=True,
        engagement_state=state, save_individual_runs=False,
    )


def test_annotation_then_final_json_enrichment(tmp_path):
    llm = FakeLLM([
        _msg(_ToolUseBlock(id="t1", name="annotate_finding", input={
            "title": "Anonymous FTP access", "type": "exposure",
            "severity": "high", "description": "ftp open", "verified": False,
        })),
        _msg(_TextBlock(text=(
            "Done.\n```json\n" + json.dumps({
                "technical_overview": "An attacker could...",
                "findings": [{
                    "title": "Anonymous FTP access",
                    "type": "exposure", "severity": "high",
                    "description": "A much longer description of the exposure.",
                    "impact": "Data disclosure.",
                    "remediation": ["Disable anonymous login"],
                    "cvss": {"vector": "CVSS:3.1/AV:N", "base_score": 7.5,
                             "temporal_score": 7.0, "environmental_score": 7.5},
                }],
            }) + "\n```"
        ))),
    ])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}))
    run = orch.run(_agent([]), "10.10.10.5", max_turns=5)

    assert run.status == "complete"
    assert len(run.findings) == 1
    f = run.findings[0]
    assert f.impact == "Data disclosure."
    assert f.cvss.base_score == 7.5
    assert f.description.startswith("A much longer")
    assert run.technical_overview == "An attacker could..."


def test_cvss_with_null_scores_does_not_crash(tmp_path):
    # The model emitting `null` CVSS scores must NOT raise "float ... NoneType" — the
    # key exists with value None, so float(None) used to blow up at run end.
    llm = FakeLLM([
        _msg(_ToolUseBlock(id="t1", name="annotate_finding", input={
            "title": "WinRM Exposed", "type": "exposure", "severity": "medium",
            "description": "open", "verified": False})),
        _msg(_TextBlock(text=(
            "Done.\n```json\n" + json.dumps({
                "technical_overview": "ov",
                "findings": [{
                    "title": "WinRM Exposed", "type": "exposure", "severity": "medium",
                    "description": "A fuller description.", "impact": "x",
                    "cvss": {"vector": None, "base_score": None,
                             "temporal_score": None, "environmental_score": "N/A"},
                }],
            }) + "\n```"))),
    ])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}))
    run = orch.run(_agent([]), "10.10.10.5", max_turns=5)
    assert run.status == "complete"                  # no crash
    f = run.findings[0]
    assert f.cvss is not None and f.cvss.base_score == 0.0 and f.cvss.vector == ""


def test_cross_agent_annotation_dedup(tmp_path):
    prior = Finding(type="exposure", severity="high", title="Anonymous FTP access",
                    description="d", target="10.10.10.5", verified=False)
    llm = FakeLLM([
        _msg(_ToolUseBlock(id="t1", name="annotate_finding", input={
            "title": "Anonymous FTP access", "type": "exposure",
            "severity": "high", "description": "again", "verified": True,
        })),
        _msg(_TextBlock(text="done")),
    ])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}), state)
    run = orch.run(_agent([]), "10.10.10.5", max_turns=5, all_findings=[prior])

    # No new finding created — the prior run's finding was updated instead
    assert run.findings == []
    assert prior.verified is True


def test_followup_scope_enforcement(tmp_path):
    llm = FakeLLM([
        _msg(
            _ToolUseBlock(id="t1", name="queue_followup", input={
                "agent_name": "pentest/web", "target": "10.10.10.5"}),
            _ToolUseBlock(id="t2", name="queue_followup", input={
                "agent_name": "pentest/web", "target": "172.16.99.1"}),
        ),
        _msg(_TextBlock(text="done")),
    ])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}), state)
    orch.run(_agent([]), "10.10.10.5", max_turns=5)

    queued = state.drain_followup_queue()
    assert [q["target"] for q in queued] == ["10.10.10.5"]   # out-of-scope rejected


def test_scan_cache_prevents_second_execution(tmp_path):
    calls = []

    def fake_tool(**kwargs):
        calls.append(kwargs)
        return {"host_count": 1, "hosts": []}

    llm = FakeLLM([
        _msg(_ToolUseBlock(id="t1", name="fake_tool", input={"target": "10.10.10.5"})),
        _msg(_ToolUseBlock(id="t2", name="fake_tool", input={"target": "10.10.10.5"})),
        _msg(_TextBlock(text="done")),
    ])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(fake_tool), state)
    run = orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=5)

    assert len(calls) == 1                      # second call served from cache
    assert run.status == "complete"
    cached = state.check_cache("fake_tool", {"target": "10.10.10.5"})
    assert cached["result"] == {"host_count": 1, "hosts": []}


def test_temperature_resolution_per_agent():
    from core.config import get_temperature_for_agent
    assert get_temperature_for_agent("pentest/report") == 0.2          # explicit override
    assert get_temperature_for_agent("pentest/rce") == 0.4             # falls to default
    assert get_temperature_for_agent("pentest/enumeration") == 0.4     # falls to default


def test_resolved_temperature_passed_to_llm(tmp_path):
    from core.config import get_temperature_for_agent
    captured = {}

    class TempLLM(FakeLLM):
        def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
            captured["t"] = temperature
            return super().run(model, system, messages, tools, max_tokens, temperature)

    llm = TempLLM([_msg(_TextBlock(text="done"))])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}))
    orch.run(_agent([]), "10.10.10.5", max_turns=3)
    assert captured["t"] == get_temperature_for_agent("test/agent") == 0.4


def test_max_turns_status(tmp_path):
    llm = FakeLLM([
        _msg(_ToolUseBlock(id=f"t{i}", name="fake_tool", input={"n": i}))
        for i in range(3)
    ])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}))
    run = orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=3)
    assert run.status == "max_turns"


# ── sliding turn budget (don't kill a working exploit) ────────────────────────

def _bank(i):
    # Each turn banks a DISTINCT credential — real, non-dedup progress.
    return _msg(_ToolUseBlock(id=f"t{i}", name="record_credential", input={
        "secret": f"pw-{i}-abcdef", "username": f"user{i}", "cred_type": "password"}))


def test_budget_not_exhausted_while_banking_progress(tmp_path):
    # max_turns=2, but the agent banks something NEW every turn → the no-progress
    # window keeps resetting, so it is NOT killed at the old hard cap of 2. This is
    # the "don't kill an agent mid-working-exploit" fix.
    llm = FakeLLM([_bank(i) for i in range(4)] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.0.0.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}), state)
    run = orch.run(_agent([]), "10.0.0.5", max_turns=2)
    assert run.status == "complete"        # ran past 2 because every turn progressed
    assert llm.calls == 5


def test_budget_stops_after_window_without_progress(tmp_path):
    # No state, no progress banked → the sliding window behaves like the old hard cap.
    llm = FakeLLM([_msg(_ToolUseBlock(id=f"t{i}", name="fake_tool", input={"n": i}))
                   for i in range(10)])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}))
    run = orch.run(_agent(["fake_tool"]), "10.0.0.5", max_turns=3)
    assert run.status == "max_turns" and llm.calls == 3


def test_absolute_ceiling_bounds_a_runaway(tmp_path):
    # Even banking progress every turn, the absolute ceiling (max_turns × factor,
    # default 5) bounds it — 2 × 5 = 10 turns, then stop.
    llm = FakeLLM([_bank(i) for i in range(40)])
    state = EngagementState(target="10.0.0.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}), state)
    run = orch.run(_agent([]), "10.0.0.5", max_turns=2)
    assert run.status == "max_turns" and llm.calls == 10


def test_shell_command_counts_as_progress(tmp_path):
    # Driving a held shell is forward progress for the budget even when nothing is
    # annotated yet — the local-enum-after-a-reverse-shell case.
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}),
                         EngagementState(target="t"))
    from core.models import EngagementRun
    run = EngagementRun(agent="a", target="t")
    fp0 = orch._progress_fingerprint(run)
    orch._shell_exec_ok += 1                          # a successful shell_exec
    fp1 = orch._progress_fingerprint(run)
    assert orch._forward_progress(fp1, fp0) is True


# ── live foothold handoff (next agent must know the shell exists) ─────────────

def test_live_shells_surfaced_in_opening_context(tmp_path):
    import types
    captured = {}

    class CapLLM(FakeLLM):
        def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
            captured.setdefault("user", messages[0]["content"])
            return super().run(model, system, messages, tools, max_tokens)

    llm = CapLLM([_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.0.0.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}), state)
    orch._shells = types.SimpleNamespace(
        sessions=lambda: [{"id": "ab12cd", "from": "10.0.0.5:4444",
                           "alive": True, "os_hint": "linux"}],
        poll_new_sessions=lambda: [])
    orch.run(_agent([]), "10.0.0.5", max_turns=3)
    # the new agent is told, up front, about the shell it inherited
    assert "ab12cd" in captured["user"]
    assert "shell_exec" in captured["user"]
    assert "ALREADY HOLD" in captured["user"]


def test_no_shell_block_when_none_held(tmp_path):
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}),
                         EngagementState(target="t"))
    assert orch._live_shells_block() == ""


class NudgeWatchLLM(FakeLLM):
    """Records whether a loop-nudge text block ever reached the model."""
    def __init__(self, responses):
        super().__init__(responses)
        self.saw_nudge = False

    def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
        for m in messages:
            c = m.get("content")
            if isinstance(c, list):
                for b in c:
                    if isinstance(b, dict) and b.get("type") == "text" \
                            and "Engine notice" in b.get("text", ""):
                        self.saw_nudge = True
        return super().run(model, system, messages, tools, max_tokens)


def test_loop_nudge_on_repeated_identical_call(tmp_path):
    # Same tool + identical args three times → a nudge is injected on the 3rd
    # (default threshold), then the agent finishes.
    same = {"target": "10.10.10.5"}
    llm = NudgeWatchLLM([
        _msg(_ToolUseBlock(id="t1", name="fake_tool", input=same)),
        _msg(_ToolUseBlock(id="t2", name="fake_tool", input=same)),
        _msg(_ToolUseBlock(id="t3", name="fake_tool", input=same)),
        _msg(_TextBlock(text="done")),
    ])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}), state)
    orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=6)
    assert llm.saw_nudge is True


def test_no_nudge_when_calls_differ(tmp_path):
    llm = NudgeWatchLLM([
        _msg(_ToolUseBlock(id=f"t{i}", name="fake_tool", input={"n": i}))
        for i in range(3)
    ] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}), state)
    orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=6)
    assert llm.saw_nudge is False


class NoticeWatchLLM(FakeLLM):
    """Captures the engine-notice text injected back into the model."""
    def __init__(self, responses):
        super().__init__(responses)
        self.notices = []

    def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
        for m in messages:
            if m.get("role") == "user" and isinstance(m.get("content"), list):
                for b in m["content"]:
                    if isinstance(b, dict) and b.get("type") == "text" \
                            and "Engine notice" in b.get("text", ""):
                        self.notices.append(b["text"])
        return super().run(model, system, messages, tools, max_tokens)


def test_pivot_nudge_after_consecutive_failures(tmp_path):
    # Four failing tool calls in a row (default threshold) → a pivot notice fires,
    # even though each call is different (the exact-match nudge would not catch it).
    llm = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"t{i}", name="fake_tool", input={"n": i}))
        for i in range(4)
    ] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.10.10.5")
    # tool always errors → unproductive each time
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"error": "nope"}), state)
    orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=8)
    assert any("dead end" in n for n in llm.notices)


def test_no_pivot_nudge_when_calls_succeed(tmp_path):
    llm = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"t{i}", name="fake_tool", input={"n": i}))
        for i in range(4)
    ] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}), state)
    orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=8)
    assert not any("dead end" in n for n in llm.notices)


def test_reuse_nudge_on_heavy_run_script(tmp_path):
    from core.tool_registry import Tool, ToolRegistry
    reg = ToolRegistry()
    reg.register(Tool(name="run_script", description="", input_schema={"type": "object"},
                      func=lambda **kw: {"ok": True, "exit_code": 0}))
    # 10 run_script calls (default volume threshold), list_scripts never used.
    llm = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"s{i}", name="run_script", input={"purpose": f"p{i}"}))
        for i in range(10)
    ] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="10.10.10.5")
    orch = _orchestrator(tmp_path, llm, reg, state)
    orch.run(_agent(["run_script"]), "10.10.10.5", max_turns=14)
    assert any("list_scripts" in n for n in llm.notices)


def test_capped_output_keeps_record_small(tmp_path):
    from core.orchestrator import _cap_for_persist
    big = "A" * 50000
    capped = _cap_for_persist({"stdout": big, "small": "ok"})
    assert len(capped["stdout"]) < 5000
    assert "truncated" in capped["stdout"]
    assert capped["small"] == "ok"


def _script_registry():
    from core.tool_registry import Tool, ToolRegistry
    r = ToolRegistry()
    r.register(Tool(name="run_script", description="", input_schema={"type": "object"},
                    func=lambda **kw: {"ok": True, "exit_code": 0}))   # clean, banks nothing
    return r


def test_state_grind_counters_and_reset():
    st = EngagementState(target="t")
    for _ in range(5):
        st.note_script_call()
    assert st.grind_nudge_due(12) == 0          # below threshold
    for _ in range(7):
        st.note_script_call()                    # now 12
    assert st.grind_nudge_due(12) == 12          # due
    st.note_progress()                           # banked a result
    assert st.grind_nudge_due(12) == 0           # streak reset


def test_grind_nudge_fires_on_no_progress_scripts(tmp_path):
    # 12 clean scripts that bank nothing → no-progress grind nudge.
    llm = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"s{i}", name="run_script", input={"purpose": f"p{i}"}))
        for i in range(12)
    ] + [_msg(_TextBlock(text="done"))])
    state = EngagementState(target="t")
    orch = _orchestrator(tmp_path, llm, _script_registry(), state)
    orch.run(_agent(["run_script"]), "t", max_turns=16)
    assert any("no-progress grind" in n for n in llm.notices)


def test_grind_streak_persists_across_agent_runs(tmp_path):
    # The counter lives on state, so thrash spread over two agent runs still trips —
    # the exact case per-run counters missed in the Helix logs.
    state = EngagementState(target="t")
    llm1 = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"a{i}", name="run_script", input={"purpose": f"p{i}"}))
        for i in range(8)
    ] + [_msg(_TextBlock(text="d"))])
    _orchestrator(tmp_path, llm1, _script_registry(), state).run(_agent(["run_script"]), "t", max_turns=12)
    assert not any("no-progress grind" in n for n in llm1.notices)   # 8 < 12

    llm2 = NoticeWatchLLM([
        _msg(_ToolUseBlock(id=f"b{i}", name="run_script", input={"purpose": f"q{i}"}))
        for i in range(8)
    ] + [_msg(_TextBlock(text="d"))])
    _orchestrator(tmp_path, llm2, _script_registry(), state).run(_agent(["run_script"]), "t", max_turns=12)
    assert any("no-progress grind" in n for n in llm2.notices)        # cumulative 16 ≥ 12


def test_exempt_tool_never_nudges_on_repeat(tmp_path):
    # Polling-style tools (oob_listener) are exempt: repeating the identical call
    # is normal operation, so it must NOT trigger a nudge even past the threshold.
    same = {"port": 4444}
    llm = NudgeWatchLLM([
        _msg(_ToolUseBlock(id="t1", name="oob_listener", input=same)),
        _msg(_ToolUseBlock(id="t2", name="oob_listener", input=same)),
        _msg(_ToolUseBlock(id="t3", name="oob_listener", input=same)),
        _msg(_ToolUseBlock(id="t4", name="oob_listener", input=same)),
        _msg(_TextBlock(text="done")),
    ])
    state = EngagementState(target="10.10.10.5")
    reg = _registry(lambda **kw: {"ok": True}, name="oob_listener")
    orch = _orchestrator(tmp_path, llm, reg, state)
    orch.run(_agent(["oob_listener"]), "10.10.10.5", max_turns=6)
    assert llm.saw_nudge is False


# ── /abort hold-gate (mid-agent operator control) ──────────────────────────────

import types


def _ctl_run():
    return types.SimpleNamespace(agent="test/agent", status="running", summary="")


def test_handle_control_no_signal_passes_through(tmp_path):
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}))
    assert orch._handle_control(_ctl_run()) is False


def test_handle_control_abort_then_resume(tmp_path):
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}))
    orch.control_queue.put("abort")
    orch.control_queue.put("resume")   # release left queued for the blocking wait
    run = _ctl_run()
    assert orch._handle_control(run) is False     # resumed → keep going
    assert run.status == "running"


def test_handle_control_abort_then_skip(tmp_path):
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}))
    orch.control_queue.put("abort")
    orch.control_queue.put("skip")
    run = _ctl_run()
    assert orch._handle_control(run) is True       # skip → stop this agent
    assert run.status == "aborted"
    assert "skipped" in run.summary.lower()


def test_run_skips_agent_when_aborted(tmp_path):
    # Operator aborts mid-run: the first turn's call queues abort+skip (as a stand-in
    # for the UI doing it), so the NEXT boundary parks the agent and skips it.
    class AbortingLLM(FakeLLM):
        def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
            if self.calls == 0:                    # mid-run /abort then /skip
                orch.control_queue.put("abort")
                orch.control_queue.put("skip")
            return super().run(model, system, messages, tools, max_tokens)

    llm = AbortingLLM([
        _msg(_ToolUseBlock(id="t1", name="fake_tool", input={})),
        _msg(_TextBlock(text="should not reach here")),
    ])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {"ok": True}))
    run = orch.run(_agent(["fake_tool"]), "10.10.10.5", max_turns=6)
    assert run.status == "aborted"
    assert llm.calls == 1                          # parked at the next boundary


def test_run_clears_stale_control_signals(tmp_path):
    # A leftover signal from a prior agent must not park the next run.
    llm = FakeLLM([_msg(_TextBlock(text="done"))])
    orch = _orchestrator(tmp_path, llm, _registry(lambda **kw: {}))
    orch.control_queue.put("skip")                 # stale, no matching abort
    run = orch.run(_agent([]), "10.10.10.5", max_turns=3)
    assert run.status == "complete"
    assert llm.calls == 1


# ── secret redaction (first-appearance masking) ────────────────────────────────

def test_unproven_secret_not_masked_until_verified(tmp_path):
    # A guess/spray value stays visible; masked only once recorded verified.
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}),
                         EngagementState(target="10.10.10.5"))
    orch._register_input_secrets({"password": "SuperSecret123!", "username": "admin"}, "ssh_exec")
    assert orch._redact_secrets("login admin:SuperSecret123!") == "login admin:SuperSecret123!"
    orch.state.add_credential(secret="SuperSecret123!", username="admin", verified=True)
    assert "SuperSecret123!" not in orch._redact_secrets("login admin:SuperSecret123!")


def test_redact_obj_no_crash_and_leaves_unproven_visible(tmp_path):
    orch = _orchestrator(tmp_path, FakeLLM([]), _registry(lambda **kw: {}),
                         EngagementState(target="x"))
    orch._register_input_secrets({"password": "LongSecretValue"}, "ssh_exec")
    out = orch._redact_obj({"inputs": {"password": "LongSecretValue"}})
    assert "LongSecretValue" in json.dumps(out)
