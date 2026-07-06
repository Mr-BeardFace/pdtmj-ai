"""Operational-fact ledger: confirmed act-on-this scaffolding that survives run
boundaries so an engagement stops re-deriving (or contradicting) what it proved —
the 062 logging.htb 32-bit↔64-bit flip is the failure this exists to prevent."""
from core.engagement_state import EngagementState


def _state():
    return EngagementState(target="10.0.0.1")


def test_record_and_render():
    s = _state()
    s.record_fact("target", "native DLL must be x64 (process is .NET AnyCPU)",
                  evidence="file UpdateMonitor.exe → PE32 Mono/.Net assembly", scope="dc01")
    block = s.build_context_block(all_findings=[])
    assert "Confirmed operational facts" in block
    assert "native DLL must be x64" in block
    assert "evidence:" in block


def test_dedup_same_statement_scope_refreshes_not_duplicates():
    s = _state()
    s.record_fact("channel", "WinRM as msa_health$ is the command channel", evidence="nxc winrm → Pwn3d!", scope="dc01")
    s.record_fact("channel", "winrm as MSA_HEALTH$ is the command channel", evidence="nxc winrm → Pwn3d!", scope="dc01")
    assert len([f for f in s.operational_facts if f.status == "confirmed"]) == 1


def test_supersede_marks_old_invalidated_and_renders_correction():
    s = _state()
    wrong = s.record_fact("target", "target needs a 32-bit DLL", evidence="assumed", scope="dc01")
    s.record_fact("target", "target needs a 64-bit DLL", evidence="Error 193 = BAD_EXE_FORMAT on x86 build",
                  scope="dc01", supersedes=wrong.id)
    confirmed = [f for f in s.operational_facts if f.status == "confirmed"]
    assert len(confirmed) == 1 and "64-bit" in confirmed[0].statement
    block = s.build_context_block(all_findings=[])
    assert "CORRECTED" in block and "32-bit" in block


def test_cap_evicts_oldest_confirmed():
    s = _state()
    for i in range(12):
        s.record_fact("target", f"fact number {i}", evidence=f"cmd{i}", scope="dc01")
    confirmed = [f for f in s.operational_facts if f.status == "confirmed"]
    assert len(confirmed) == s._FACT_CAP
    assert "fact number 0" not in {f.statement for f in confirmed}
    assert any("fact number 11" == f.statement for f in confirmed)


def test_snapshot_and_merge_roundtrip():
    s = _state()
    s.record_fact("channel", "shell is blind — exfil via OOB", evidence="empty stdout", scope="dc01")
    assert s.state_snapshot()["operational_facts"][0]["statement"].startswith("shell is blind")
    # a worker fork pins a fact; merge_from replays it through record_fact (dedup applies)
    worker = _state()
    marks = worker.merge_marks()
    worker.record_fact("target", "IIS 10 on port 80", evidence="server header", scope="dc01")
    s.merge_from(worker, marks)
    assert any(f.statement == "IIS 10 on port 80" for f in s.operational_facts)
