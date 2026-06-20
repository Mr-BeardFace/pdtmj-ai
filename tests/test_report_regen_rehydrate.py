"""/report regen used to write from the masked state.json alone (no tool_log, no
handoffs) → the report agent saw only finding titles and reproduced the same shallow
report. Regen now rehydrates the evidence trail and each agent's narrative from the
full (already-redacted) assessment runs, so it re-synthesizes from the real engagement."""
from core.models import Assessment, EngagementRun, ToolCall, Finding
from core.engagement_state import EngagementState
from ui.app import PentestApp


def _assessment() -> Assessment:
    enum = EngagementRun(
        agent="pentest/enumeration", target="10.0.0.5",
        tool_calls=[ToolCall(id="t1", tool_name="nmap_scan",
                             inputs={"target": "10.0.0.5"},
                             output={"ports": [80, 8080]}, command_str="nmap 10.0.0.5")],
        findings=[Finding(type="recon", severity="info", title="Open ports",
                          description="80, 8080 open", target="10.0.0.5")],
        technical_overview="Mapped two web services; 8080 runs an admin console.")
    exploit = EngagementRun(
        agent="pentest/exploitation", target="10.0.0.5",
        tool_calls=[ToolCall(id="t2", tool_name="web_exec",
                             inputs={"cmd": "id"},
                             output={"body": "uid=998(svc) gid=998(svc)"},
                             command_str="curl ...")],
        findings=[],   # the Helix pattern: exec proven, nothing banked
        technical_overview="Achieved RCE via the admin console as svc; chained to "
                           "an internal OPC-UA service. Not recorded as a finding.")
    report = EngagementRun(
        agent="pentest/report", target="10.0.0.5",
        findings=[Finding(type="vuln", severity="critical", title="RCE",
                          description="…", target="10.0.0.5")])
    return Assessment(id="a1", target="10.0.0.5", runs=[enum, exploit, report])


def test_rehydrate_restores_tool_log_and_narratives():
    a = _assessment()
    st = EngagementState(target="10.0.0.5")
    assert not st.tool_log and not st.handoffs
    PentestApp._rehydrate_report_state(st, a)
    # every tool call across runs is back in the log
    assert len(st.tool_log) == 2
    assert {e.tool_name for e in st.tool_log} == {"nmap_scan", "web_exec"}
    # the exec output survived into the evidence trail
    assert any("uid=998(svc)" in e.truncated_output for e in st.tool_log)


def test_rehydrate_seeds_agent_narratives_excluding_report():
    a = _assessment()
    st = EngagementState(target="10.0.0.5")
    PentestApp._rehydrate_report_state(st, a)
    agents = {h["agent"] for h in st.handoffs}
    assert agents == {"pentest/enumeration", "pentest/exploitation"}
    # the exploitation narrative — describing a chain that was never banked as a
    # finding — is now available to the report writer
    assert any("OPC-UA" in h["summary"] for h in st.handoffs)
    # the report agent's own prior narration is NOT fed back to itself
    assert "pentest/report" not in agents


def test_rehydrated_context_block_includes_evidence():
    a = _assessment()
    st = EngagementState(target="10.0.0.5")
    PentestApp._rehydrate_report_state(st, a)
    ctx = st.build_context_block(a.merged_findings())
    assert "**Work already completed**" in ctx
    assert "**Handoff from prior agents**" in ctx
    assert "uid=998(svc)" in ctx
