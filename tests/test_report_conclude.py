"""A concluded engagement must NOT short-circuit the reporting agent.

Regression: the report agent shares the orchestrator's EngagementState. Once a
prior agent called conclude_engagement, `state.concluded` was truthy and the
orchestrator's turn loop returned immediately for EVERY subsequent agent — so the
report agent made zero LLM calls, produced no executive summary, and the report
fell back to the un-synthesized DRAFT. The reporting phase is now exempt.
"""
import json

from core.agent_loader import AgentDefinition
from core.engagement_state import EngagementState
from core.llm_client import _Message, _TextBlock, _Usage
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


def _orch(tmp_path, llm, state):
    reg = ToolRegistry()
    reg.register(Tool(name="noop", description="", input_schema={"type": "object"}, func=lambda **k: {}))
    return Orchestrator(llm, reg, tmp_path, quiet=True,
                        engagement_state=state, save_individual_runs=False)


def _agent(name, phase):
    return AgentDefinition(name=name, description="", scope=[],
                           model="claude-sonnet-4-6", system_prompt="x",
                           metadata={"phase": phase})


def test_report_agent_runs_even_when_concluded(tmp_path):
    state = EngagementState(target="10.10.10.5")
    state.concluded = "root flag captured"
    llm = FakeLLM([_msg(_TextBlock(text=(
        "Report.\n```json\n" + json.dumps({
            "executive_summary": "The host was fully compromised to root.",
            "technical_overview": "anon FTP -> RCE -> privesc -> root.",
            "findings": [],
        }) + "\n```"
    )))])

    run = _orch(tmp_path, llm, state).run(_agent("pentest/report", "reporting"),
                                          "10.10.10.5", max_turns=5)

    assert llm.calls == 1                              # the report agent actually ran
    assert run.executive_summary                       # → no DRAFT banner
    assert "compromised" in run.executive_summary


def test_non_report_agent_still_short_circuits_when_concluded(tmp_path):
    state = EngagementState(target="10.10.10.5")
    state.concluded = "root flag captured"
    llm = FakeLLM([_msg(_TextBlock(text="should never be called"))])

    run = _orch(tmp_path, llm, state).run(_agent("pentest/rce", "exploitation"),
                                          "10.10.10.5", max_turns=5)

    assert llm.calls == 0                              # short-circuited before any call
    assert run.status == "concluded"
