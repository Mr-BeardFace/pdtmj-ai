"""Tests for the 2.0 parallel layer: state fork/merge isolation + serial merge,
the fan_out concurrency primitive (first-success cancellation), and the
ParallelDriver fanning surfaces and hypotheses through a fork-aware fake orch."""
import threading
import time

from core.concurrency import AgentGate, fan_out
from core.engagement_state import EngagementState
from core.models import EngagementBrief, EngagementRun, Finding
from core.parallel_driver import ParallelDriver, _Hypothesis
from core.pipeline import ENUM_AGENT, PLAN_AGENT, EXPLOIT_AGENT, REPORT_AGENT


def _seeded():
    s = EngagementState(target="10.10.10.5")
    s.scope_targets = ["10.10.10.5", "10.10.10.6"]
    s.recon.open_ports.append({"host": "10.10.10.5", "port": 80,
                               "protocol": "tcp", "service": "http", "version": ""})
    s._port_keys.add(EngagementState._port_key(s.recon.open_ports[0]))
    s.add_surface("10.10.10.5", service="http", port=80, origin="initial")
    s.add_surface("10.10.10.5", service="smb", port=445, origin="initial")
    return s


# ── fork isolation ──────────────────────────────────────────────────────────

def test_fork_is_isolated():
    base = _seeded()
    fork = base.fork()
    fork.add_credential(secret="hunter2", username="admin", service="smb", verified=True)
    fork.surfaces[0].cycles = 2
    # base is untouched — the fork mutates its own copy only
    assert base.credentials == []
    assert base.surfaces[0].cycles == 0
    # fork rebuilt its own private indexes (not shared with base)
    assert fork._surface_keys is not base._surface_keys


def test_fork_carries_nudge_counters():
    base = _seeded()
    base.note_script_call()
    base.note_script_call()
    fork = base.fork()
    assert fork._eng_script_calls == 2
    assert fork._scripts_since_progress == 2


# ── merge folds deltas back ───────────────────────────────────────────────────

def test_merge_folds_new_credentials_and_recon():
    base = _seeded()
    marks = base.merge_marks()
    fork = base.fork()
    fork.add_credential(secret="hunter2", username="admin", service="smb", verified=True)
    fork.recon.open_ports.append({"host": "10.10.10.5", "port": 445,
                                  "protocol": "tcp", "service": "smb", "version": ""})
    fork._port_keys.add(EngagementState._port_key(fork.recon.open_ports[-1]))
    fork.recon.users.append("administrator")

    base.merge_from(fork, marks)
    assert any(c.secret == "hunter2" for c in base.credentials)
    assert len(base.recon.open_ports) == 2
    assert "administrator" in base.recon.users


def test_merge_dedups_snapshot_items():
    base = _seeded()
    base.add_credential(secret="seed-pw", username="svc", service="ftp")
    marks = base.merge_marks()
    fork = base.fork()                       # fork already has seed-pw
    fork.add_credential(secret="new-pw", username="root", service="ssh")
    base.merge_from(fork, marks)
    secrets = [c.secret for c in base.credentials]
    assert secrets.count("seed-pw") == 1     # not duplicated
    assert "new-pw" in secrets


def test_merge_syncs_only_owned_surface_progress():
    base = _seeded()
    http_id = base.surfaces[0].id
    smb_id = base.surfaces[1].id
    marks = base.merge_marks()

    # Worker A forks the whole board but only OWNS the http surface; it advances
    # http and (wrongly, from a stale fork) would also carry smb unchanged.
    fork_a = base.fork()
    fork_a.surfaces[0].cycles = 1
    fork_a.surfaces[0].status = "exhausted"

    # Meanwhile the canonical smb surface was advanced by worker B (simulated).
    base.surfaces[1].cycles = 3

    base.merge_from(fork_a, marks, owned_surface_ids={http_id})
    http = next(s for s in base.surfaces if s.id == http_id)
    smb = next(s for s in base.surfaces if s.id == smb_id)
    assert http.cycles == 1 and http.status == "exhausted"   # owned → synced
    assert smb.cycles == 3                                    # NOT clobbered by stale fork


def test_merge_adds_new_surface_and_appends_tool_log():
    base = _seeded()
    marks = base.merge_marks()
    fork = base.fork()
    fork.add_surface("10.10.10.6", service="http", port=8080, origin="lateral")
    fork.log_tool("web", "gobuster_dir", "gobuster ...", "12 paths", {"count": 12})

    n_surfaces = len(base.surfaces)
    base.merge_from(fork, marks)
    assert len(base.surfaces) == n_surfaces + 1
    assert any(e.tool_name == "gobuster_dir" for e in base.tool_log)


def test_merge_first_conclude_wins():
    base = _seeded()
    marks = base.merge_marks()
    fork = base.fork()
    fork.concluded = "root via SUID"
    base.merge_from(fork, marks)
    assert base.concluded == "root via SUID"


# ── fan_out concurrency ───────────────────────────────────────────────────────

def test_fan_out_collects_all_results():
    jobs = [lambda c, n=n: n * 2 for n in range(4)]
    res = fan_out(jobs)
    assert sorted(res.results) == [0, 2, 4, 6]
    assert res.solved is None


def test_fan_out_first_solve_cancels_rest():
    started = []
    cancelled = []

    def winner(cancel):
        started.append("win")
        return {"solve": True, "tag": "win"}

    def loser(cancel):
        started.append("lose")
        # cooperatively poll the cancel flag like a real bounded worker
        for _ in range(200):
            if cancel.wait(0.005):
                cancelled.append("lose")
                return {"solve": False, "tag": "lose", "cancelled": True}
        return {"solve": False, "tag": "lose"}

    res = fan_out([winner, loser, loser],
                  is_solve=lambda r: r.get("solve") is True)
    assert res.solved is not None and res.solved["tag"] == "win"
    # the losers observed the cancel and bailed out early
    assert cancelled, "losers should have seen the cancel event"


def test_fan_out_isolates_a_crash():
    def boom(cancel):
        raise RuntimeError("worker exploded")

    res = fan_out([boom, lambda c: "ok"])
    assert "ok" in res.results
    assert res.errors and isinstance(res.errors[0][1], RuntimeError)


def test_agent_gate_caps_concurrency():
    gate = AgentGate(2)
    live = []
    peak = [0]
    lock = threading.Lock()

    def job(cancel):
        with gate:
            with lock:
                live.append(1)
                peak[0] = max(peak[0], len(live))
            time.sleep(0.02)
            with lock:
                live.pop()
        return "done"

    res = fan_out([job for _ in range(6)])
    assert len(res.results) == 6
    assert peak[0] <= 2          # never more than the gate limit ran at once


# ── ParallelDriver: surface + hypothesis fan-out ──────────────────────────────

class _Agent:
    def __init__(self, name):
        self.name = name
        self.metadata = {}


def _agents():
    return {name: _Agent(name) for name in
            (ENUM_AGENT, PLAN_AGENT, EXPLOIT_AGENT, REPORT_AGENT)}


class ForkFakeOrch:
    """Fork-aware fake orchestrator. clone_for_worker hands back a sibling bound to
    the worker's forked state but SHARING the scripted behaviour, the call log, and
    a lock — so concurrent worker runs are recorded safely."""
    def __init__(self, state, script=None, calls=None, lock=None, detail=None):
        self.state = state
        self.script = script or {}
        self.calls = calls if calls is not None else []
        self.detail = detail if detail is not None else []   # [{agent,objective,max_turns}]
        self._lock = lock or threading.Lock()
        self.llm = None                       # no LLM routing → deterministic heuristics

    def clone_for_worker(self, state, label=""):
        return ForkFakeOrch(state, self.script, self.calls, self._lock, self.detail)

    def run(self, agent_def, target, objective, max_turns=25, all_findings=None):
        name = agent_def.name
        with self._lock:
            self.calls.append(name)
            self.detail.append({"agent": name, "objective": objective or "",
                                "max_turns": max_turns})
        fn = self.script.get(name)
        findings = fn(self.state, objective) if fn else None
        run = EngagementRun(agent=name, target=target)
        run.findings = findings or []
        run.status = "complete"
        return run


def _brief(exploit=False):
    phases = ["discovery", "assessment", "reporting"]
    if exploit:
        phases.insert(2, "exploitation")
    return EngagementBrief(targets=["10.0.0.5"], allowed_phases=phases)


def _two_ports(state):
    state.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
        {"port": 80, "protocol": "tcp", "service": "http"},
        {"port": 445, "protocol": "tcp", "service": "smb"},
    ]}]})


def test_parallel_surface_fanout_merges_both_results():
    state = EngagementState(target="10.0.0.5")

    def enum(st, objective):
        if "DISCOVERY" in objective:
            _two_ports(st)
            return []
        if "SERVICE IDENT" in objective:
            return []
        # deep enum runs on a per-surface FORK — distinguish by the surface in the
        # objective. Each banks distinct intel that must survive the merge.
        if "smb" in objective or ":445" in objective:
            return [Finding(type="config", severity="medium", title="SMB Signing Disabled",
                            description="d", target="10.0.0.5", verified=True)]
        if "http" in objective or ":80" in objective:
            st.add_credential("password", "webpass", "agent", username="admin", verified=True)
        return []

    orch = ForkFakeOrch(state, {ENUM_AGENT: enum})
    driver = ParallelDriver(
        orch, _agents(), state, _brief(), confirm_exploitation=False,
        max_cycles_per_surface=1, gate=AgentGate(4),
        surface_fanout=2, hypothesis_fanout=1)
    driver.run()

    # both surfaces were deep-enumerated (discovery + service-id + 2 deep) ...
    assert orch.calls.count(ENUM_AGENT) == 4
    # ... and BOTH workers' distinct deltas landed in canonical state
    assert any(c.secret == "webpass" for c in state.credentials)        # http fork → cred
    assert any(f.title == "SMB Signing Disabled" for f in driver.all_findings)  # smb fork → finding
    assert all(s.status == "exhausted" for s in state.surfaces)
    assert REPORT_AGENT in orch.calls                                   # findings → report ran


def test_parallel_hypothesis_fanout_first_solve_concludes():
    state = EngagementState(target="10.0.0.5")

    def enum(st, objective):
        if "DISCOVERY" in objective:
            st.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"}]}]})
        return []

    def plan(st, objective):
        sid = st.surfaces[0].id
        st.record_plan(sid, [
            {"action": "Brute-force the admin login", "technique": "brute-force"},  # expensive
            {"action": "Try default credentials admin:admin", "technique": "default-creds"},  # cheap
            {"action": "Probe for an auth bypass", "technique": "auth-bypass"},  # medium
        ])
        return []

    def exploit(st, objective):
        # The default-creds worker reaches the objective and concludes.
        if "default" in objective.lower():
            st.concluded = "root via default credentials"
            return [Finding(type="vuln", severity="critical", title="Default Credentials Accepted",
                            description="d", target="10.0.0.5", verified=True)]
        return []

    orch = ForkFakeOrch(state, {ENUM_AGENT: enum, PLAN_AGENT: plan, EXPLOIT_AGENT: exploit})
    driver = ParallelDriver(
        orch, _agents(), state, _brief(exploit=True), confirm_exploitation=False,
        max_cycles_per_surface=1, gate=AgentGate(4),
        surface_fanout=1, hypothesis_fanout=3, hypothesis_worker_turns=5)
    driver.run()

    assert state.concluded == "root via default credentials"   # first solve folded back
    assert any(f.title == "Default Credentials Accepted" for f in driver.all_findings)
    assert orch.calls.count(EXPLOIT_AGENT) >= 1                 # at least the winner ran


def test_rank_hypotheses_puts_cheap_over_expensive():
    from core.models import TestPlan, TestPlanItem
    plan = TestPlan(surface_id="s1", items=[
        TestPlanItem(action="Crack the captured hash with rockyou", technique="hashcat"),  # expensive, prior 0.90
        TestPlanItem(action="Use default credentials", technique="default-creds"),          # cheap,      prior 0.78
    ])
    driver = ParallelDriver.__new__(ParallelDriver)   # no __init__ needed for pure ranking
    ranked = ParallelDriver._rank_hypotheses(driver, plan)
    # Despite a lower ordinal prior, the cheap path outranks the expensive one by EV.
    assert ranked[0].technique == "default-creds"
    assert ranked[0].ev > ranked[1].ev


def test_parallel_serial_equivalent_with_fanout_one():
    # surface_fanout=1, hypothesis_fanout=1 → ParallelDriver should behave like the
    # serial driver: single surface exhausts, no parallel machinery engaged.
    state = EngagementState(target="10.0.0.5")

    def enum(st, objective):
        if "DISCOVERY" in objective:
            st.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"}]}]})
        return []

    orch = ForkFakeOrch(state, {ENUM_AGENT: enum})
    driver = ParallelDriver(
        orch, _agents(), state, _brief(), confirm_exploitation=False,
        max_cycles_per_surface=1, gate=AgentGate(2),
        surface_fanout=1, hypothesis_fanout=1)
    driver.run()
    assert state.surfaces[0].status == "exhausted"
    assert orch.calls.count(ENUM_AGENT) == 3        # discovery + service-id + 1 deep


# ── foothold-class hypotheses are exempt from the bounded prove/refute ─────────

def test_is_foothold_hypothesis_classifier():
    from core.parallel_driver import _Hypothesis

    def cls(tech, act):
        return ParallelDriver._is_foothold_hypothesis(
            _Hypothesis(action=act, rationale="", technique=tech, prior=0.5, cost="cheap"))

    assert cls("command-injection", "exec a command via the NiFi processor")
    assert cls("ssti", "Jinja2 server-side template injection")
    assert cls("test", "Achieve remote code execution through the upload")
    assert cls("file-upload", "upload a web shell")
    # not a foothold primitive on its own
    assert not cls("default-creds", "try admin:admin")
    assert not cls("sqli", "union-based data extraction")
    assert not cls("idor", "enumerate other users' objects")


def test_foothold_hypothesis_runs_exploit_agent_full_budget():
    state = EngagementState(target="10.0.0.5")

    def enum(st, objective):
        if "DISCOVERY" in objective:
            st.ingest_tool_result("nmap_scan", {"hosts": [{"ip": "10.0.0.5", "open_ports": [
                {"port": 80, "protocol": "tcp", "service": "http"}]}]})
        return []

    def plan(st, objective):
        sid = st.surfaces[0].id
        st.record_plan(sid, [
            {"action": "Exploit NiFi ExecuteProcess for remote code execution",
             "technique": "command-injection"},                  # foothold-class
            {"action": "Try default credentials admin:admin",
             "technique": "default-creds"},                      # bounded
        ])
        return []

    orch = ForkFakeOrch(state, {ENUM_AGENT: enum, PLAN_AGENT: plan})
    agents = _agents()
    driver = ParallelDriver(
        orch, agents, state, _brief(exploit=True), confirm_exploitation=False,
        max_cycles_per_surface=1, gate=AgentGate(4),
        surface_fanout=1, hypothesis_fanout=2, hypothesis_worker_turns=5, max_turns=40)
    driver.run()

    # Both hypotheses run on the exploitation agent now (RCE was folded in); the
    # foothold one is distinguished by a FULL kill-chain budget + objective, the
    # other stayed a bounded prove/refute worker.
    runs = [d for d in orch.detail if d["agent"] == EXPLOIT_AGENT]
    foot = [d for d in runs if d["max_turns"] == 40]
    assert foot, "the command-injection hypothesis should run with the full foothold budget"
    assert "CARRY IT THROUGH" in foot[0]["objective"]       # kill-chain objective, not prove/refute
    # the default-creds hypothesis stayed a bounded prove/refute worker
    bounded = [d for d in runs if d["max_turns"] == 5]
    assert bounded
