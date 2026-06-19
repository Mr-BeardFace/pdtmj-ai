"""@-prefixed scope groups expand to their tool lists, so a shared toolset is
declared once (tool_registry._SCOPE_GROUPS) instead of copied across agents."""
from core.tool_registry import expand_scope, _SCOPE_GROUPS
from core.registry import build_registry, load_all_agents


def test_expand_scope_resolves_group_and_dedups():
    out = expand_scope(["http_request", "@foothold", "ssh_exec"])
    # group members are pulled in…
    assert "ssh_exec" in out and "oob_listener" in out
    # …plain entries pass through, and a duplicate (ssh_exec is in the group) is deduped
    assert out.count("ssh_exec") == 1
    assert "http_request" in out


def test_unknown_group_expands_to_nothing():
    assert expand_scope(["@nope"]) == []


def test_web_specialist_resolves_foothold_tools():
    reg = build_registry()
    agents = load_all_agents()
    web_tools = {t.name for t in reg.get_by_scope(agents["pentest/web"].scope)}
    # the exploit/foothold kit is available to the web specialist now
    for t in ("oob_listener", "ssh_exec", "ssh_keygen", "ysoserial", "nc"):
        assert t in web_tools, f"web specialist missing {t}"
    # and it still has its own web tooling
    assert "sqlmap_scan" in web_tools


def test_foothold_group_members_are_real_tools():
    reg = build_registry()
    registered = set(reg.list_tools())
    missing = [t for t in _SCOPE_GROUPS["foothold"] if t not in registered]
    assert not missing, f"@foothold lists unregistered tools: {missing}"
