"""Shared methodology partials: `includes:` appends agents/_shared/<name>.md, and
the _shared partials are not themselves loaded as standalone agents."""
from core.agent_loader import load_agent, discover_agents
from core.paths import AGENTS_DIR


def test_exploitation_includes_foothold_methodology():
    a = load_agent("pentest/exploitation", AGENTS_DIR)
    # the shared foothold block is appended to the agent's own prompt
    assert "Turning code execution into a foothold" in a.system_prompt
    assert "oob_listener" in a.system_prompt          # methodology content present
    # and the agent's own body is still there
    assert "exploitation phase" in a.system_prompt.lower()


def test_shared_partials_are_not_loaded_as_agents():
    agents = discover_agents(AGENTS_DIR)
    assert not any(name.startswith("_") or "/_" in name for name in agents)
    assert "_shared/foothold" not in agents
    # the retired RCE agent is gone
    assert "pentest/rce" not in agents


def test_missing_include_raises():
    import pytest
    from pathlib import Path
    import tempfile
    # an agent that includes a non-existent partial should fail loudly
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "_shared").mkdir()
        (root / "x.md").write_text(
            "---\nname: x\nincludes:\n  - nope\n---\nbody", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            load_agent("x", root)
