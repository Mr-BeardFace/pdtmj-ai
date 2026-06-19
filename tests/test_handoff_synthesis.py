"""Handoff synthesis on cap-stop + background-result-as-progress.

When a run ends without a clean text close-out, the handoff must be built from
what the run actually did (findings, recent actions, live shells) instead of a
bare scrap of reasoning — otherwise the next agent inherits nothing. And a
delivered background job counts toward the sliding turn budget.
"""
from types import SimpleNamespace

from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator
from core.tool_registry import Tool, ToolRegistry


def _orch(tmp_path, state=None):
    reg = ToolRegistry()
    reg.register(Tool(name="noop", description="", input_schema={"type": "object"}, func=lambda **k: {}))
    return Orchestrator(object(), reg, tmp_path, quiet=True,
                        engagement_state=state, save_individual_runs=False)


def _run(findings=(), tool_calls=()):
    return SimpleNamespace(findings=list(findings), tool_calls=list(tool_calls))


# ── handoff synthesis ─────────────────────────────────────────────────────────

def test_synthesizes_from_findings_and_actions(tmp_path):
    orch = _orch(tmp_path)
    run = _run(
        findings=[SimpleNamespace(title="Wing FTP NULL-byte RCE")],
        tool_calls=[
            SimpleNamespace(tool_name="web_exec", command_str="id"),
            SimpleNamespace(tool_name="check_jobs", command_str=""),   # skip-listed
            SimpleNamespace(tool_name="run_script", command_str="linpeas"),
        ],
    )
    out = orch._synthesize_handoff(run, "Was mid-privesc, enumerating sudo -l.")

    assert "mid-privesc" in out                       # last reasoning kept
    assert "Wing FTP NULL-byte RCE" in out            # findings carried
    assert "web_exec" in out and "run_script" in out  # actions carried
    assert "check_jobs" not in out                    # poller skipped


def test_empty_run_yields_empty_handoff(tmp_path):
    orch = _orch(tmp_path)
    assert orch._synthesize_handoff(_run(), "") == ""


def test_last_text_alone_is_still_carried(tmp_path):
    orch = _orch(tmp_path)
    out = orch._synthesize_handoff(_run(), "Only reasoning, no tools yet.")
    assert "Only reasoning" in out


# ── background result counts as progress ──────────────────────────────────────

def test_delivered_job_is_forward_progress(tmp_path):
    orch = _orch(tmp_path, state=EngagementState(target="10.10.10.5"))
    run = _run()
    before = orch._progress_fingerprint(run)
    orch._jobs_progress += 1                            # a scan/crack delivered
    after = orch._progress_fingerprint(run)
    assert orch._forward_progress(after, before)
