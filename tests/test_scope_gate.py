"""Scope gate: scanning/enum tools are HARD-BLOCKED against out-of-scope targets,
so a DNS-discovered IP can't be scanned just because the model wants to pivot."""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator, _SCOPE_GATED_TOOLS
from core.tool_registry import ToolRegistry


def _orch(tmp_path, state):
    return Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=state)


def _state():
    # exactly what the Support run had: one authorized host + its hostnames
    s = EngagementState(target="10.129.32.116")
    s.scope_targets = ["10.129.32.116", "support.htb", "dc.support.htb"]
    return s


def test_out_of_scope_scan_is_blocked(tmp_path):
    o = _orch(tmp_path, _state())
    # the exact violation from the run: nmap against the DC's second DNS A record
    msg = o._scope_block("nmap_scan", {"target": "10.129.230.181"})
    assert msg and "OUTSIDE the engagement scope" in msg
    assert "10.129.230.181" in msg
    # the red-herring management host on another subnet, too
    assert o._scope_block("netexec", {"target": "10.10.10.4"}) is not None


def test_in_scope_target_is_allowed(tmp_path):
    o = _orch(tmp_path, _state())
    assert o._scope_block("nmap_scan", {"target": "10.129.32.116"}) is None
    assert o._scope_block("ldapsearch_query", {"target": "support.htb"}) is None
    assert o._scope_block("netexec", {"target": "dc.support.htb"}) is None


def test_non_gated_tools_are_never_blocked(tmp_path):
    # channel/foothold + research tools legitimately reference the attacker host
    o = _orch(tmp_path, _state())
    for tool in ("oob_listener", "nc", "ssh_exec", "web_exec", "fetch_url", "web_search"):
        assert o._scope_block(tool, {"target": "10.129.230.181"}) is None
        assert tool not in _SCOPE_GATED_TOOLS


def test_url_target_is_resolved_for_the_check(tmp_path):
    o = _orch(tmp_path, _state())
    # a gated tool taking a url → host extracted and checked
    assert o._scope_block("nuclei_scan", {"target": "http://10.129.32.116/"}) is None
    assert o._scope_block("nuclei_scan", {"target": "http://10.129.230.181/"}) is not None


def test_no_state_means_no_gate(tmp_path):
    o = Orchestrator(object(), ToolRegistry(), tmp_path, quiet=True)
    assert o._scope_block("nmap_scan", {"target": "10.129.230.181"}) is None
