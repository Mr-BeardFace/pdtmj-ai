"""EngagementDriver state-machine tests with a fake orchestrator (no LLM)."""
from core.engagement_state import EngagementState
from core.models import EngagementBrief, EngagementRun
from core.pipeline import (
    EngagementDriver, ENUM_AGENT, PLAN_AGENT, EXPLOIT_AGENT, VALIDATE_AGENT, REPORT_AGENT,
)


class _Agent:
    def __init__(self, name):
        self.name = name
        self.metadata = {}


def _agents():
    return {name: _Agent(name) for name in
            (ENUM_AGENT, PLAN_AGENT, EXPLOIT_AGENT, VALIDATE_AGENT, REPORT_AGENT)}


class FakeOrch:
    """Records agent calls and applies scripted state mutations per agent."""
    def __init__(self, state, script=None):
        self.state = state
        self.script = script or {}
        self.calls = []
        self._counts = {}

    def run(self, agent_def, target, objective, max_turns=25, all_findings=None):
        name = agent_def.name
        self.calls.append(name)
        i = self._counts.get(name, 0)
        self._counts[name] = i + 1
        findings = []
        fn = self.script.get(name)
        if fn:
            findings = fn(self.state, i) or []
        run = EngagementRun(agent=name, target=target)
        run.findings = findings
        run.status = "complete"
        return run

    def names(self):
        return self.calls


def _driver(state, brief, orch, **kw):
    kw.setdefault("confirm_exploitation", False)
    kw.setdefault("max_cycles_per_surface", 4)
    kw.setdefault("max_total_cycles", 40)
    return EngagementDriver(orch, _agents(), state, brief, **kw)


def _add_port(state):
    state.ingest_tool_result("nmap_scan", {"hosts": [{
        "ip": "10.0.0.5", "open_ports": [{"port": 80, "protocol": "tcp", "service": "http"}],
    }]})


# ── happy path: enumerate → plan, single surface, immediate exhaustion ────────

def test_recon_only_loop_terminates_on_exhaustion():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])

    def enum(state, i):
        # Staged initial enum: i==0 discovery, i==1 service-id; deeper cycles i>=2.
        if i == 0:
            _add_port(state)     # discovery sweep finds a service
        return []                # service-id + deep cycles find nothing new → exhaust

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    runs = _driver(state, brief, orch).run()

    # Assessment-only (no exploitation): staged initial enum (discovery + service-id)
    # then one deep cycle that exhausts the surface.
    assert orch.names().count(ENUM_AGENT) == 3
    assert PLAN_AGENT not in orch.names()
    assert EXPLOIT_AGENT not in orch.names()
    assert VALIDATE_AGENT not in orch.names()
    assert state.surfaces[0].status == "exhausted"
    # No findings → no report agent
    assert REPORT_AGENT not in orch.names()
    assert runs


# ── re-cycling: a cycle that yields new intel runs again ───────────────────────

def test_surface_recycles_until_exhausted():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])

    def enum(state, i):
        # Staged initial enum consumes i==0 (discovery) and i==1 (service-id);
        # deep surface cycles are i>=2. New intel on the first deep cycle forces
        # a re-cycle before exhaustion.
        if i == 0:
            _add_port(state)
        elif i == 2:
            state.add_credential("plaintext", "hunter2", "agent", username="u")  # new intel
        # i == 1 (service-id) and i >= 3: nothing → exhaust
        return []

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    _driver(state, brief, orch).run()

    assert state.surfaces[0].cycles == 2
    assert orch.names().count(ENUM_AGENT) == 4   # discovery + service-id + 2 deep cycles


# ── exploitation gating via confirm callback ───────────────────────────────────

def test_exploitation_denied_skips_exploit_and_validate():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    orch = FakeOrch(state, {ENUM_AGENT: lambda s, i: _add_port(s) if i == 0 else None})

    d = _driver(state, brief, orch, confirm_exploitation=True,
                confirm_cb=lambda agent, findings: "n")
    d.run()
    assert EXPLOIT_AGENT not in orch.names()
    assert VALIDATE_AGENT not in orch.names()


def test_exploitation_approved_runs_exploit_not_validate_by_default():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    orch = FakeOrch(state, {ENUM_AGENT: lambda s, i: _add_port(s) if i == 0 else None})

    d = _driver(state, brief, orch, confirm_exploitation=True,
                confirm_cb=lambda agent, findings: "y")
    d.run()
    # Exploitation enabled → planning runs and feeds exploit. Validation is
    # opt-in (validation_enabled defaults False), so it does NOT run.
    assert PLAN_AGENT in orch.names()
    assert EXPLOIT_AGENT in orch.names()
    assert VALIDATE_AGENT not in orch.names()


def test_validation_runs_when_enabled(monkeypatch):
    import core.config as cfg
    _orig = cfg.get
    monkeypatch.setattr(cfg, "get",
                        lambda k, d=None: True if k == "validation_enabled" else _orig(k, d))
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    orch = FakeOrch(state, {ENUM_AGENT: lambda s, i: _add_port(s) if i == 0 else None})

    d = _driver(state, brief, orch, confirm_exploitation=True,
                confirm_cb=lambda agent, findings: "y")
    d.run()
    assert VALIDATE_AGENT in orch.names()


def test_approve_all_stops_prompting():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    # two surfaces so exploitation is reached twice
    def enum(s, i):
        if i == 0:
            s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
                {"port": 445, "protocol": "tcp", "service": "smb"},
            ]}]})
        return []

    prompts = []

    def cb(agent, findings):
        prompts.append(agent)
        return "a"

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    _driver(state, brief, orch, confirm_exploitation=True, confirm_cb=cb).run()
    assert len(prompts) == 1            # "approve all" → asked only once
    assert orch.names().count(EXPLOIT_AGENT) == 2


# ── safety backstop ────────────────────────────────────────────────────────────

def test_backstop_stops_nonconverging_loop():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])
    # Every deep cycle adds a new credential → never exhausts naturally
    counter = {"n": 0}

    def enum(state, i):
        if i == 0:
            _add_port(state)
        else:
            counter["n"] += 1
            state.add_credential("plaintext", f"s{counter['n']}", "agent", username=f"u{counter['n']}")
        return []

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    d = _driver(state, brief, orch, max_total_cycles=3, max_cycles_per_surface=999)
    d.run()
    assert d.total_cycles == 3          # stopped by backstop, not exhaustion


def test_dry_cycle_guard_stops_unverified_grind():
    from core.models import Finding
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])

    # A new UNVERIFIED finding each cycle: the intel signature keeps changing (so the
    # exhaustion heuristic says "keep going"), but no verified finding/cred/flag is
    # ever banked → the dry-cycle guard must stop the grind well before the caps.
    def enum(state, i):
        if i == 0:
            _add_port(state)
        return [Finding(type="vuln", severity="low", title=f"thing-{i}",
                        description="d", target="10.0.0.5", verified=False)]

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    d = _driver(state, brief, orch, max_total_cycles=99, max_cycles_per_surface=99)
    d.run()
    assert d.total_cycles <= 6           # dry guard stopped it, not the 99 caps


# ── control: /stop and /end ────────────────────────────────────────────────────

def test_planning_skipped_when_exploitation_disabled():
    # Regression: planning used to run even with exploitation off, producing a
    # plan that was never executed and making the engagement "end after planning".
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])
    orch = FakeOrch(state, {ENUM_AGENT: lambda s, i: _add_port(s) if i == 0 else None})
    _driver(state, brief, orch).run()
    assert PLAN_AGENT not in orch.names()
    assert EXPLOIT_AGENT not in orch.names()


def test_enum_agent_specialist_selection():
    from core.models import Surface
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"], allowed_phases=["discovery", "assessment", "reporting"])

    agents = _agents()
    agents["pentest/web"] = _Agent("pentest/web")
    agents["pentest/active-directory"] = _Agent("pentest/active-directory")
    d = EngagementDriver(FakeOrch(state), agents, state, brief)

    assert d._enum_agent_for(Surface(host="h", service="http", port=80)) == "pentest/web"
    assert d._enum_agent_for(Surface(host="h", service="smb", port=445)) == "pentest/active-directory"
    # Unknown service → generic
    assert d._enum_agent_for(Surface(host="h", service="weird", port=1)) == ENUM_AGENT
    # Known service but specialist not loaded → generic fallback
    assert d._enum_agent_for(Surface(host="h", service="mysql", port=3306)) == ENUM_AGENT


def test_specialist_runs_for_matching_service():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"], allowed_phases=["discovery", "assessment", "reporting"])

    def enum(s, i):
        if i == 0:
            s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
            ]}]})
        return []

    agents = _agents()
    agents["pentest/web"] = _Agent("pentest/web")
    orch = FakeOrch(state, {ENUM_AGENT: enum})
    EngagementDriver(orch, agents, state, brief,
                     confirm_exploitation=False, max_cycles_per_surface=4).run()
    # The http surface's deep enumeration went to the web specialist
    assert "pentest/web" in orch.names()


def test_select_surface_honors_llm_pick():
    # With an LLM available, _select_surface should choose the surface the model
    # names — even when it's the lower-priority one the heuristic wouldn't pick.
    from core.models import Surface

    class _Block:
        type = "text"
        def __init__(self, t): self.text = t

    class _Resp:
        def __init__(self, t): self.content = [_Block(t)]

    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"], allowed_phases=["discovery", "assessment", "reporting"])
    web = state.add_surface("10.0.0.5", service="http", port=80)   # high priority
    ssh = state.add_surface("10.0.0.5", service="ssh", port=22)    # low priority

    orch = FakeOrch(state)
    orch.llm = type("L", (), {"run": lambda self, **kw: _Resp(
        '{"surface_id":"%s","reason":"chasing the ssh lead"}' % ssh.id)})()

    d = EngagementDriver(orch, _agents(), state, brief)
    chosen = d._select_surface()
    assert chosen is ssh                                   # LLM overrode the weight table
    assert state.next_surface() is web                     # heuristic alone still prefers web


def test_select_surface_falls_back_without_llm():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"], allowed_phases=["discovery", "assessment", "reporting"])
    state.add_surface("10.0.0.5", service="ssh", port=22)
    web = state.add_surface("10.0.0.5", service="http", port=80)
    d = EngagementDriver(FakeOrch(state), _agents(), state, brief)   # FakeOrch has no .llm
    assert d._select_surface() is web                      # priority heuristic


def test_legacy_followup_absorbed_as_surface():
    state = EngagementState(target="10.0.0.0/24")
    brief = EngagementBrief(targets=["10.0.0.0/24"], allowed_phases=["discovery", "assessment", "reporting"])

    def enum(s, i):
        if i == 0:
            # initial sweep finds one host AND queues a followup on a new host
            s.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"},
            ]}]})
            s.request_followup("pentest/network", "10.0.0.9", "second host")
        return []

    orch = FakeOrch(state, {ENUM_AGENT: enum})
    EngagementDriver(orch, _agents(), state, brief,
                     confirm_exploitation=False, max_cycles_per_surface=1).run()
    hosts = {s.host for s in state.surfaces}
    assert "10.0.0.9" in hosts          # followup target became a surface


def test_stop_control_skips_reporting():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(targets=["10.0.0.5"],
                            allowed_phases=["discovery", "assessment", "reporting"])
    orch = FakeOrch(state, {ENUM_AGENT: lambda s, i: _add_port(s) if i == 0 else None,
                            # produce a finding so report would otherwise run
                            PLAN_AGENT: lambda s, i: None})

    state_flags = {"stop": False}

    def control():
        return "stop" if state_flags["stop"] else "continue"

    # Trip stop right after the initial sweep
    orig = orch.run
    def run_then_stop(agent_def, *a, **k):
        r = orig(agent_def, *a, **k)
        if agent_def.name == ENUM_AGENT:
            state_flags["stop"] = True
        return r
    orch.run = run_then_stop

    d = _driver(state, brief, orch, control=control)
    d.run()
    assert d.stopped is True
    assert REPORT_AGENT not in orch.names()
