"""FrontierController — the lead-driven control loop, proven with a scripted
work_lead (no LLM). The scenario mirrors the real Silentium chain:

    web enum -> Flowise RCE -> SSH foothold (user.txt) -> [docker dead end |
    root-Flowise on host (root.txt)]

so the test encodes the exact mindset: follow the hottest thread, take user, try
the cheap root path, find it dead, RELEASE, take the other root path, capture root,
and HALT (ctf) — while pentest keeps going into leftover breadth.
"""
from core.leads import Lead, LeadStore, objective_for
from core.frontier import FrontierController, WorkResult


def _scripted_work():
    """A scripted Silentium-shaped scenario keyed on lead id."""
    def work(lead: Lead) -> WorkResult:
        i = lead.id
        if i == "web":
            return WorkResult(i, "advanced", reach_level="vuln", new_leads=[
                Lead(id="rce", kind="vuln", description="Flowise MCP config-injection RCE",
                     reach_level="exploited", prior=0.7, cost="medium")])
        if i == "rce":
            return WorkResult(i, "advanced", reach_level="exploited",
                findings=[{"title": "Remote Code Execution via Flowise", "verified": True}],
                new_leads=[Lead(id="ssh", kind="cred", description="SSH as ben via reused SMTP password",
                                reach_level="user", prior=0.8, cost="cheap")])
        if i == "ssh":
            return WorkResult(i, "advanced", reach_level="user",
                flags=[{"location": "/home/ben/user.txt"}],
                new_leads=[
                    # cheap-looking root path that's actually a dead end (docker/newgrp)
                    Lead(id="docker", kind="escalation", description="newgrp docker to root socket",
                         reach_level="root", prior=0.6, cost="cheap"),
                    # the real root path: re-use the proven RCE against the root-running Flowise
                    Lead(id="hostflowise", kind="escalation",
                         description="exploit second Flowise running as root on host",
                         reach_level="root", prior=0.6, cost="medium"),
                    # a low-value lateral lead that should only be touched in pentest mode
                    Lead(id="ftp", kind="surface", description="enumerate ftp",
                         reach_level="service", prior=0.4, cost="cheap"),
                ])
        if i == "docker":
            return WorkResult(i, "refuted", note="ben not in docker group; group pw locked")
        if i == "hostflowise":
            return WorkResult(i, "advanced", reach_level="root",
                              flags=[{"location": "/root/root.txt"}])
        if i == "ftp":
            return WorkResult(i, "refuted", note="nothing on ftp")
        return WorkResult(i, "inconclusive")
    return work


def _seed():
    store = LeadStore()
    store.add(Lead(id="web", kind="surface", description="enumerate web application",
                   reach_level="vuln", prior=0.7, cost="cheap"))
    return store


# ── the core behaviour ────────────────────────────────────────────────────────

def test_ctf_runs_chain_to_root_and_halts():
    store = _seed()
    obj = objective_for("pentest-ctf", "10.129.28.32")
    events = []
    ctrl = FrontierController(store, obj, _scripted_work(),
                              on_event=lambda k, p: events.append(k))
    out = ctrl.run()

    assert out.objective_complete is True
    assert out.frontier == "root"
    assert out.halted_on_objective is True
    assert "objective_met" in events

    # the cheap root path was tried FIRST, refuted, and released ...
    assert store.get("docker").status == "refuted"
    # ... then the real root path was confirmed
    assert store.get("hostflowise").status == "confirmed"
    # ctf halted at root — the low-value lateral lead was NEVER worked
    assert store.get("ftp").status == "open"


def test_frontier_advances_in_order():
    store = _seed()
    obj = objective_for("pentest-ctf", "t")
    seen = []
    def on_event(kind, payload):
        if kind == "advance":
            seen.append(payload.reach_level)
    FrontierController(store, obj, _scripted_work(), on_event=on_event).run()
    # the frontier climbed the kill chain in order
    assert seen == ["vuln", "exploited", "user", "root"]


def test_refuted_lead_is_released_not_reworked():
    store = _seed()
    obj = objective_for("pentest-ctf", "t")
    worked = []
    base = _scripted_work()
    def counting_work(lead):
        worked.append(lead.id)
        return base(lead)
    FrontierController(store, obj, counting_work).run()
    # docker was worked exactly once (refuted → released, never re-picked)
    assert worked.count("docker") == 1


def test_pentest_does_not_halt_and_works_leftover_breadth():
    store = _seed()
    obj = objective_for("pentest", "t")          # halt_on_complete = False
    worked = []
    base = _scripted_work()
    def counting_work(lead):
        worked.append(lead.id)
        return base(lead)
    out = FrontierController(store, obj, counting_work).run()
    assert out.halted_on_objective is False
    # unlike ctf, pentest carried on past the objective and ran down the leftover lead
    assert "ftp" in worked
    assert store.get("ftp").status == "refuted"


def test_inconclusive_lead_caps_out():
    store = LeadStore()
    store.add(Lead(id="loop", kind="x", description="never resolves", reach_level="vuln"))
    obj = objective_for("pentest-ctf", "t")
    n = {"c": 0}
    def work(lead):
        n["c"] += 1
        return WorkResult(lead.id, "inconclusive")
    FrontierController(store, obj, work, attempts_cap=3, max_actions=50).run()
    assert n["c"] == 3                              # tried up to the cap, then exhausted
    assert store.get("loop").status == "exhausted"
