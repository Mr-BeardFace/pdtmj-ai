from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _INTERCEPTED
from core.tool_registry import ToolRegistry


def test_add_flag_dedup_and_verify():
    s = EngagementState(target="x")
    f1 = s.add_flag("flag{abc}", location="web", source_agent="a")
    f2 = s.add_flag("flag{abc}", verified=True)        # same value → updates, no dup
    assert f1 is f2
    assert f1.verified is True
    assert len(s.flags) == 1
    assert s.add_flag("   ") is None                   # empty rejected


def test_record_flag_handler_records_and_emits(tmp_path):
    events = []
    s = EngagementState(target="x")
    o = Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                     engagement_state=s, log_callback=lambda e: events.append(e))
    res = o._handle_record_flag({"value": "flag{win}", "location": "pwn01", "verified": True}, "agent")
    assert res["recorded"] is True
    assert s.flags[0].value == "flag{win}" and s.flags[0].location == "pwn01"
    assert any(e.get("type") == "flag" and e.get("value") == "flag{win}" for e in events)


def test_record_flag_requires_value(tmp_path):
    s = EngagementState(target="x")
    o = Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True, engagement_state=s)
    assert o._handle_record_flag({"location": "x"}, "a")["recorded"] is False
    assert s.flags == []


def test_record_flag_intercepted():
    assert "record_flag" in _INTERCEPTED


def test_active_persona_stored(tmp_path):
    # record_flag injection is gated on this in run()
    assert Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        active_persona="pentest-ctf")._active_persona == "pentest-ctf"
    assert Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        active_persona="pentest")._active_persona == "pentest"
