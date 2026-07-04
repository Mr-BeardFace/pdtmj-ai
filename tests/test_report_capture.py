"""The report deliverable is captured through structured tool calls (annotate_finding
enrichment + write_report), not scraped from one fragile final ```json``` blob. These
lock in that capture path and the merge preferring the report writer's cohesive
narrative over the stitched per-agent fallback."""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _INTERCEPTED, _first_json_object, _coerce_cvss
from core.models import EngagementRun, Finding
from core.tool_registry import ToolRegistry
from reporting.formatter import merge_runs


def _orch(tmp_path, state=None):
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=state or EngagementState(target="10.0.0.1"))


# ── brace-matched JSON extraction (robust to inner code fences) ───────────────

def test_first_json_object_ignores_inner_code_fence():
    # A value containing ``` used to truncate the old fence-terminated regex — the
    # object must still parse in full.
    text = 'prose\n```json\n{"technical_overview": "ran:\\n```bash\\nid\\n```\\ndone", "n": 1}\n```'
    obj = _first_json_object(text)
    assert obj is not None and obj["n"] == 1 and "```bash" in obj["technical_overview"]


def test_first_json_object_ignores_braces_in_strings():
    obj = _first_json_object('{"a": "a } brace { in a string", "b": 2}')
    assert obj == {"a": "a } brace { in a string", "b": 2}


def test_first_json_object_none_on_garbage():
    assert _first_json_object("no json here") is None
    assert _first_json_object('{"unterminated": ') is None   # truncated → no match


def test_extract_ignores_incidental_json(tmp_path):
    # A handoff message that happens to contain a JSON snippet (not a report block)
    # must not be treated as report data.
    o = _orch(tmp_path)
    run = EngagementRun(agent="a", target="t")
    o._extract_and_enrich('Recovered config: {"port": 8080, "tls": false}', run, "t")
    assert run.technical_overview is None and run.findings == []


def test_extract_backstop_applies_report_block(tmp_path):
    o = _orch(tmp_path)
    run = EngagementRun(agent="a", target="t")
    o._extract_and_enrich('```json\n{"technical_overview": "the tale"}\n```', run, "t")
    assert run.technical_overview == "the tale"


# ── annotate_finding now carries CVSS / impact / remediation ──────────────────

def test_annotate_enriches_cvss_impact_remediation(tmp_path):
    o = _orch(tmp_path)
    run = EngagementRun(agent="pentest/exploitation", target="10.0.0.1")
    res = o._handle_annotation({
        "title": "SQL Injection", "type": "vuln", "severity": "high",
        "description": "d", "verified": True,
        "impact": "Full DB read.",
        "remediation": ["Parameterize queries", "Least privilege"],
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                 "base_score": 9.8, "temporal_score": 9.1, "environmental_score": 9.8},
    }, run, "10.0.0.1")
    f = run.findings[0]
    assert res["status"] == "annotated"
    assert f.impact == "Full DB read."
    assert f.remediation == ["Parameterize queries", "Least privilege"]
    assert f.cvss and f.cvss.base_score == 9.8


def test_annotate_enrichment_survives_bad_cvss(tmp_path):
    # A null/non-numeric score must not drop the whole enrichment.
    o = _orch(tmp_path)
    run = EngagementRun(agent="a", target="t")
    o._handle_annotation({"title": "X", "type": "vuln", "severity": "low",
                          "description": "d", "impact": "some",
                          "cvss": {"vector": "CVSS:3.1/AV:N", "base_score": None}},
                         run, "t")
    f = run.findings[0]
    assert f.impact == "some"
    assert f.cvss and f.cvss.base_score == 0.0        # coerced, not crashed


def test_annotate_by_finding_id_applies_enrichment(tmp_path):
    o = _orch(tmp_path)
    run = EngagementRun(agent="a", target="t")
    fid = o._handle_annotation({"title": "X", "type": "vuln", "severity": "low",
                                "description": "d"}, run, "t")["finding_id"]
    o._handle_annotation({"finding_id": fid, "impact": "later",
                          "remediation": "Patch it"}, run, "t")
    f = next(f for f in run.findings if f.id == fid)
    assert f.impact == "later" and f.remediation == ["Patch it"]


# ── write_report captures the narrative onto the run ──────────────────────────

def test_write_report_sets_run_narrative(tmp_path):
    o = _orch(tmp_path)
    run = EngagementRun(agent="pentest/report", target="t")
    res = o._handle_write_report(
        {"executive_summary": "exec para", "technical_overview": "the story"}, run)
    assert res["status"] == "recorded"
    assert run.executive_summary == "exec para"
    assert run.technical_overview == "the story"


def test_write_report_rejects_empty(tmp_path):
    o = _orch(tmp_path)
    run = EngagementRun(agent="pentest/report", target="t")
    assert o._handle_write_report({"executive_summary": " ", "technical_overview": ""}, run)["status"] == "error"


def test_write_report_intercepted():
    assert "write_report" in _INTERCEPTED


# ── merge prefers the report writer's cohesive narrative over the stitch ──────

def _run(agent, overview):
    r = EngagementRun(agent=agent, target="10.10.10.5")
    r.technical_overview = overview
    return r


def test_merge_prefers_report_overview_not_stitch():
    runs = [_run("pentest/enumeration", "enum chunk"),
            _run("pentest/exploitation", "exploit chunk"),
            _run("pentest/report", "ONE cohesive story, start to finish.")]
    merged = merge_runs(runs)
    assert merged.technical_overview == "ONE cohesive story, start to finish."
    assert "enum chunk" not in merged.technical_overview   # per-agent chunks not stitched in


def test_merge_falls_back_to_stitch_when_no_report_run():
    runs = [_run("pentest/enumeration", "enum chunk"),
            _run("pentest/exploitation", "exploit chunk")]
    merged = merge_runs(runs)
    assert "enum chunk" in merged.technical_overview and "exploit chunk" in merged.technical_overview
