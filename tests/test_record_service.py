"""record_service meta-tool: agent-annotated structured service detail."""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _INTERCEPTED
from core.tool_registry import ToolRegistry
from tools.record_service import TOOL_DEFINITION


def _orch(state, events=None):
    cb = (lambda e: events.append(e)) if events is not None else None
    return Orchestrator(object(), ToolRegistry(), __import__("pathlib").Path("."),
                        quiet=True, engagement_state=state, log_callback=cb)


# ── schema / interception ──────────────────────────────────────────────────────

def test_is_intercepted_and_requires_host():
    assert "record_service" in _INTERCEPTED
    assert TOOL_DEFINITION["input_schema"]["required"] == ["host"]


# ── state model ────────────────────────────────────────────────────────────────

def test_annotate_service_upgrades_same_row():
    s = EngagementState(target="10.0.0.5")
    s.annotate_service(host="10.0.0.5", port=22, service="ssh", app="OpenSSH", version="9.9p1", os="Ubuntu")
    assert len(s.services) == 1
    # a later call refines without wiping prior non-empty fields
    s.annotate_service(host="10.0.0.5", port=22, tech="libssl")
    row = s.services[0]
    assert row["app"] == "OpenSSH" and row["version"] == "9.9p1" and row["tech"] == "libssl"
    assert len(s.services) == 1


def test_os_feeds_os_info():
    s = EngagementState(target="10.0.0.5")
    s.annotate_service(host="10.0.0.5", port=80, app="nginx", os="Ubuntu")
    assert s.recon.os_info.get("10.0.0.5") == "Ubuntu"


def test_distinct_ports_are_distinct_rows():
    s = EngagementState(target="10.0.0.5")
    s.annotate_service(host="10.0.0.5", port=22, app="OpenSSH")
    s.annotate_service(host="10.0.0.5", port=80, app="nginx")
    assert len(s.services) == 2


# ── orchestrator handler ───────────────────────────────────────────────────────

def test_handler_records_and_emits():
    events = []
    s = EngagementState(target="10.0.0.5")
    o = _orch(s, events)
    res = o._handle_record_service(
        {"host": "10.0.0.5", "port": 80, "service": "http",
         "app": "Camaleon CMS", "tech": "Ruby on Rails"}, "pentest/web")
    assert res["recorded"] is True
    assert any(e.get("type") == "service" and e.get("app") == "Camaleon CMS" for e in events)


def test_handler_rejects_missing_host():
    o = _orch(EngagementState(target="x"))
    res = o._handle_record_service({"port": 80, "app": "nginx"}, "a")
    assert res["recorded"] is False
