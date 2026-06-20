"""Persona-scoped agent set: a persona's `agents:` frontmatter pins the routable
agent pool. The CTF persona declares only the generalist spine, so specialist
routing finds nothing loaded and exploitation deterministically uses the generalist
— no per-surface router fork off the generic exploitation agent."""
from core.registry import load_all_agents, AGENTS_DIR
from core.agent_loader import persona_agents

_SPECIALISTS = {"pentest/web", "pentest/database",
                "pentest/active-directory", "pentest/network", "pentest/cloud"}


def test_ctf_persona_pins_to_generalist_spine():
    agents = persona_agents("pentest-ctf", AGENTS_DIR, load_all_agents())
    # generalist spine present
    for a in ("pentest/enumeration", "pentest/exploitation",
              "pentest/post-exploitation", "pentest/report"):
        assert a in agents, a
    # no domain specialists in the routable pool
    assert not (_SPECIALISTS & set(agents))


def test_ctf_safety_net_keeps_only_same_namespace_reporter():
    agents = persona_agents("pentest-ctf", AGENTS_DIR, load_all_agents())
    assert "pentest/report" in agents          # always_last, kept
    assert "code/report" not in agents          # always_last but other namespace — dropped


def test_full_pentest_persona_is_unfiltered():
    # No `agents:` allowlist → the whole pool, specialists included.
    alla = load_all_agents()
    agents = persona_agents("pentest", AGENTS_DIR, alla)
    assert set(agents) == set(alla)
    assert _SPECIALISTS <= set(agents)


def test_unknown_persona_is_unfiltered():
    alla = load_all_agents()
    assert set(persona_agents("does-not-exist", AGENTS_DIR, alla)) == set(alla)
    assert set(persona_agents("", AGENTS_DIR, alla)) == set(alla)


def test_exploit_routing_falls_back_to_generalist_without_specialists():
    # With the CTF pool, _exploit_agent_for finds no loaded specialist for an HTTP
    # surface and returns the generic agent — no router call needed.
    from core.pipeline import EngagementDriver, EXPLOIT_AGENT
    from core.models import Surface
    agents = persona_agents("pentest-ctf", AGENTS_DIR, load_all_agents())
    drv = EngagementDriver.__new__(EngagementDriver)   # avoid full engagement wiring
    drv.agents = agents
    surface = Surface(label="web", service="http", host="10.0.0.5", port=80)
    assert drv._exploit_agent_for(surface) == EXPLOIT_AGENT

    # Sanity: with the FULL pool, the same HTTP surface DOES surface a loaded
    # specialist (pentest/web), so routing would consider it — the behavior the CTF
    # pin removes.
    drv.agents = load_all_agents()
    from core.pipeline import _SERVICE_SPECIALISTS
    assert _SERVICE_SPECIALISTS.get("http") in drv.agents
