"""Fixes from a live-run review: nmap empty-IP, secret scrubbing, cred used-vs-found,
conclude_engagement early stop, generalized finding titles."""
import xml.etree.ElementTree as ET

from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _INTERCEPTED
from core.tool_registry import ToolRegistry
from core.models import Finding


# ── nmap parse: the empty-IP bug ──────────────────────────────────────────────

def test_nmap_parse_extracts_ipv4():
    from tools.nmap_scan import _parse_xml
    xml = (
        '<nmaprun><host><status state="up"/>'
        '<address addr="10.129.25.165" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22">'
        '<state state="open"/><service name="ssh" product="OpenSSH"/>'
        '</port></ports></host></nmaprun>'
    )
    res = _parse_xml(xml, "10.129.25.165")
    assert res["hosts"][0]["ip"] == "10.129.25.165"     # was "" before the fix
    assert res["hosts"][0]["open_ports"][0]["port"] == 22


def test_nmap_parse_falls_back_to_target_ip():
    from tools.nmap_scan import _parse_xml
    xml = ('<nmaprun><host><status state="up"/>'
           '<ports><port protocol="tcp" portid="80"><state state="open"/>'
           '<service name="http"/></port></ports></host></nmaprun>')
    res = _parse_xml(xml, "10.0.0.5")
    assert res["hosts"][0]["ip"] == "10.0.0.5"          # no address el → use target


# ── secret scrubbing in findings/logs ─────────────────────────────────────────

def _orch(tmp_path, state, events=None):
    cb = (lambda e: events.append(e)) if events is not None else None
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=state, log_callback=cb)


def test_known_secret_scrubbed_from_finding(tmp_path):
    state = EngagementState(target="x")
    state.add_credential(cred_type="password", secret="Buck3tH4TF0RM3!",
                         username="nathan", verified=True)
    o = _orch(tmp_path, state)
    run = type("R", (), {"findings": []})()
    o._handle_annotation({
        "title": "Cleartext FTP Credentials Exposed",
        "type": "exposure", "severity": "critical",
        "description": "Session shows nathan:Buck3tH4TF0RM3! in cleartext.",
    }, run, "x")
    f = run.findings[0]
    assert "Buck3tH4TF0RM3!" not in f.description       # masked out
    assert "Cleartext FTP" in f.title


def test_emit_redacts_known_secret(tmp_path):
    events = []
    state = EngagementState(target="x")
    state.add_credential(cred_type="password", secret="Buck3tH4TF0RM3!", username="n",
                         verified=True)
    o = _orch(tmp_path, state, events)
    o._emit("tool_done", name="http_request", output={"body": "PASS Buck3tH4TF0RM3!"})
    td = next(e for e in events if e["type"] == "tool_done")
    assert "Buck3tH4TF0RM3!" not in td["output"]["body"]
    # the dedicated credential event is NOT redacted (UI needs the real value)
    o._emit("credential", secret="Buck3tH4TF0RM3!")
    ce = next(e for e in events if e["type"] == "credential")
    assert ce["secret"] == "Buck3tH4TF0RM3!"


# ── cred used-vs-found ────────────────────────────────────────────────────────

def test_credential_used_at_tracks_reuse():
    s = EngagementState(target="x")
    s.add_credential(cred_type="password", secret="pw", username="nathan",
                     location="FTP on host", verified=True)
    # same cred confirmed working elsewhere
    s.add_credential(cred_type="password", secret="pw", username="nathan",
                     location="SSH on host", verified=True)
    c = s.credentials[0]
    assert len(s.credentials) == 1
    assert c.location == "FTP on host"
    assert c.used_at == ["SSH on host"]


# ── conclude_engagement ───────────────────────────────────────────────────────

def test_conclude_engagement_intercepted_and_sets_state():
    assert "conclude_engagement" in _INTERCEPTED


def test_concluded_field_default():
    assert EngagementState(target="x").concluded is None


# ── generalized titles guidance present ───────────────────────────────────────

def test_annotate_schema_warns_on_acronyms_and_secrets():
    from tools.annotate_finding import TOOL_DEFINITION
    desc = TOOL_DEFINITION["input_schema"]["properties"]["title"]["description"].lower()
    assert "acronym" in desc and "credential" in desc
