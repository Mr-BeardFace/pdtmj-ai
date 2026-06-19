"""Phase B: enumeration runs a broad, non-modifying safe-check sweep up front and
hands concrete access leads to the specialists — observe-only, never exploit."""
from types import SimpleNamespace

from core.engagement_state import EngagementState
from core.models import EngagementBrief
from core.frontier_driver import FrontierDriver
from core.registry import build_registry, load_all_agents


def _driver():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])
    orch = SimpleNamespace(_active_persona="pentest", llm=None)
    return FrontierDriver(orch, {}, state, brief, confirm_exploitation=False)


def test_service_id_objective_includes_safe_check_sweep():
    obj = _driver()._service_id_objective("10.0.0.5")
    # still the service-identification stage…
    assert "SERVICE IDENTIFICATION" in obj
    # …now also runs the cheap non-modifying access checks and flags hits
    for token in ("safe check", "anonymous", "register_surface"):
        assert token.lower() in obj.lower(), f"objective missing {token!r}"
    # and keeps the observe-only boundary
    assert "modif" in obj.lower() and ("no exploit" in obj.lower() or "exploitation" in obj.lower())


def test_enumeration_has_safe_check_tools_but_not_the_foothold_kit():
    reg = build_registry()
    enum = load_all_agents()["pentest/enumeration"]
    tools = {t.name for t in reg.get_by_scope(enum.scope)}
    # the safe-check workhorses are present…
    for t in ("netexec", "enum4linux_ng", "ldapsearch_query", "snmp_enum", "ftp"):
        assert t in tools, f"enumeration missing safe-check tool {t}"
    # …but enumeration is observe-only: no @foothold include, so no shell/exploit kit
    assert "@foothold" not in enum.scope
    assert "ysoserial" not in tools
