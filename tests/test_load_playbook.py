"""load_playbook — retrieval of domain methodology (the playbook-vs-agent prototype).
The generalist pulls a playbook into context instead of routing to a specialist."""
from tools.load_playbook import load_playbook, _available, TOOL_DEFINITION


def test_active_directory_playbook_available():
    assert "active-directory" in _available()


def test_loads_ad_playbook_whole():
    res = load_playbook(["active-directory"])
    assert res["loaded"] == ["active-directory"]
    body = res["playbooks"]
    # methodology content present; frontmatter stripped
    assert "Active Directory playbook" in body
    assert "Kerberoast" in body or "AS-REP" in body
    assert "services:" not in body            # YAML frontmatter removed


def test_accepts_string_and_comma_forms():
    assert load_playbook("active-directory")["loaded"] == ["active-directory"]
    assert load_playbook("active-directory, web")["loaded"] == ["active-directory"]  # web n/a yet
    assert "web" in load_playbook("active-directory, web").get("not_found", [])


def test_unknown_playbook_lists_available():
    res = load_playbook(["nonsense"])
    assert res["loaded"] == []
    assert "nonsense" in res["not_found"]
    assert "active-directory" in res["available"]
    assert "error" in res


def test_path_traversal_blocked():
    res = load_playbook(["../core/orchestrator"])
    assert res["loaded"] == [] and res.get("not_found")


def test_tool_definition_shape():
    assert TOOL_DEFINITION["name"] == "load_playbook"
    assert "names" in TOOL_DEFINITION["input_schema"]["properties"]


def test_registered_as_intercepted_meta_tool():
    # Wired so its result bypasses offload and lands whole in context.
    from core.orchestrator import _INTERCEPTED
    assert "load_playbook" in _INTERCEPTED
