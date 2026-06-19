"""FrontierDriver — the live wiring, proven with a scripted _run_agent (no LLM).

Covers lead→agent routing, the run-outcome classifier on a real worked lead, and
a full driver.run() that walks a Silentium-shaped chain to root and halts (ctf).
"""
from types import SimpleNamespace

from core.engagement_state import EngagementState
from core.models import EngagementBrief, EngagementRun, Finding
from core.leads import Lead
from core.frontier_driver import FrontierDriver
from core.pipeline import ENUM_AGENT, EXPLOIT_AGENT, AD_AGENT, REPORT_AGENT


def _agents(extra=()):
    names = [ENUM_AGENT, EXPLOIT_AGENT, REPORT_AGENT, *extra]
    return {n: SimpleNamespace(name=n, description="d", scope=[], system_prompt="",
                               model="", metadata={}) for n in names}


def _driver(persona="pentest-ctf", agents=None):
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(
        targets=["10.0.0.5"],
        allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    orch = SimpleNamespace(_active_persona=persona, llm=None)
    return FrontierDriver(orch, agents or _agents(), state, brief,
                          confirm_exploitation=False)


# ── lead → agent routing ──────────────────────────────────────────────────────

def test_plan_lead_routes_by_kind_and_reach():
    d = _driver()
    # escalation / root → exploitation (foothold owner) with a full kill-chain budget
    agent, obj, budget = d._plan_lead(
        Lead(kind="escalation", description="exploit root flowise", reach_level="root",
             prior=0.6, target="10.0.0.5"))
    assert agent == EXPLOIT_AGENT and "PRIORITY LEAD" in obj and budget >= 20

    # surface / service → deep enumeration
    agent, obj, _ = d._plan_lead(
        Lead(kind="surface", description="enumerate web", reach_level="service",
             target="10.0.0.5"))
    assert agent == ENUM_AGENT and "enumerate" in obj.lower()

    # credential reuse → exploitation agent, spray-the-known-secret objective
    agent, obj, _ = d._plan_lead(
        Lead(kind="cred", description="auth as ben", reach_level="user", target="10.0.0.5"))
    assert agent == EXPLOIT_AGENT and "credential" in obj.lower()


def test_ad_leads_route_to_ad_specialist_when_loaded():
    # With the AD agent loaded, a domain technique must reach it — NOT get handed to
    # the generic RCE/foothold specialist. This is the "rce twice, no ad agent" fix.
    d = _driver(agents=_agents(extra=[AD_AGENT]))

    # escalation framed as an AD technique → AD agent (not RCE)
    agent, _, _ = d._plan_lead(
        Lead(kind="escalation", description="kerberoast SPN accounts and crack",
             technique="kerberoast", reach_level="privesc", target="10.0.0.5"))
    assert agent == AD_AGENT

    # an exploited-reach lead reading like DCSync → AD agent
    agent, _, _ = d._plan_lead(
        Lead(kind="exploit", description="DCSync the domain for krbtgt",
             reach_level="exploited", target="10.0.0.5"))
    assert agent == AD_AGENT

    # generic vuln whose technique is AS-REP roasting → AD agent
    agent, _, _ = d._plan_lead(
        Lead(kind="vuln", description="AS-REP roast users without preauth",
             technique="asrep", reach_level="vuln", target="10.0.0.5"))
    assert agent == AD_AGENT


def test_non_ad_escalation_routes_to_exploitation():
    # A plain Linux/web foothold-class lead goes to the exploitation agent, not AD.
    d = _driver(agents=_agents(extra=[AD_AGENT]))
    agent, _, _ = d._plan_lead(
        Lead(kind="escalation", description="abuse sudo entry for root shell",
             reach_level="root", target="10.0.0.5"))
    assert agent == EXPLOIT_AGENT


def test_post_access_escalation_routes_to_local_enum():
    # Once a session exists (foothold+) or the lead is an escalation, post-foothold
    # work goes to the local-enum / privesc owner — not the foothold specialist.
    from core.pipeline import POST_EXPLOIT_AGENT
    d = _driver(agents=_agents(extra=[POST_EXPLOIT_AGENT]))

    agent, _, _ = d._plan_lead(
        Lead(kind="escalation", description="enumerate sudo -l and SUID for root",
             reach_level="privesc", target="10.0.0.5"))
    assert agent == POST_EXPLOIT_AGENT

    agent, _, _ = d._plan_lead(
        Lead(kind="exploit", description="abuse a writable root cron from the shell",
             reach_level="foothold", target="10.0.0.5"))
    assert agent == POST_EXPLOIT_AGENT


def test_raw_code_exec_routes_to_exploitation_not_local_enum():
    # Code-exec without a session yet (reach 'exploited') is get-the-shell work — the
    # exploitation agent's job (it carries the foothold methodology), NOT local-enum.
    from core.pipeline import POST_EXPLOIT_AGENT
    d = _driver(agents=_agents(extra=[POST_EXPLOIT_AGENT]))
    agent, _, _ = d._plan_lead(
        Lead(kind="exploit", description="prove command execution via file upload",
             reach_level="exploited", target="10.0.0.5"))
    assert agent == EXPLOIT_AGENT


def test_ad_routing_inert_without_ad_agent():
    # If the AD agent isn't loaded, AD leads fall back to exploitation (no crash, no None).
    d = _driver()                                  # no AD agent
    agent, _, _ = d._plan_lead(
        Lead(kind="escalation", description="kerberoast and DCSync",
             technique="kerberoast", reach_level="privesc", target="10.0.0.5"))
    assert agent == EXPLOIT_AGENT


# ── work_lead classifier on a real worked lead ────────────────────────────────

def _script(d, fn):
    """Replace _run_agent with a scripted effect on state/all_findings."""
    def _run_agent(name, target, objective, max_turns=None):
        run = EngagementRun(agent=name, target=target)
        fn(name, objective, run)
        d.runs.append(run)
        return run
    d._run_agent = _run_agent


def test_work_lead_advances_on_verified_exec_and_spawns_leads():
    d = _driver()
    lead = Lead(kind="exploit", description="prove RCE", reach_level="exploited",
                prior=0.6, target="10.0.0.5")

    def effect(name, objective, run):
        f = Finding(type="vuln", severity="high", title="Remote Code Execution via Flowise",
                    description="d", target="10.0.0.5", verified=True)
        run.findings.append(f)
        d.all_findings.append(f)
    _script(d, effect)

    res = d._work_lead(lead)
    assert res.status == "advanced" and res.reach_level == "exploited"
    assert res.new_leads                              # the verified finding became a child lead


def test_work_lead_refutes_dead_end():
    d = _driver()
    lead = Lead(kind="escalation", description="newgrp docker to root", reach_level="root",
                prior=0.6, target="10.0.0.5")
    _script(d, lambda name, objective, run: None)    # the run banks nothing
    res = d._work_lead(lead)
    assert res.status == "refuted"                   # nothing + no new thread → release


def test_work_lead_inconclusive_when_only_a_new_thread_surfaces():
    d = _driver()
    lead = Lead(kind="surface", description="enumerate web", reach_level="service",
                prior=0.5, target="10.0.0.5")

    def effect(name, objective, run):
        # an unverified candidate — a new lead, but nothing confirmed
        f = Finding(type="vuln", severity="medium", title="Potential SQL Injection",
                    description="d", target="10.0.0.5", verified=False)
        run.findings.append(f)
        d.all_findings.append(f)
    _script(d, effect)

    res = d._work_lead(lead)
    assert res.status == "inconclusive" and res.new_leads


# ── exploit approval: ctf auto-approves, pentest defers + enforces ────────────

def test_ctf_auto_approves_exploitation_without_prompting():
    d = _driver(persona="pentest-ctf")
    assert d.confirm_exploitation is False        # never gated
    assert d._exploit_allowed() is True           # no confirm_cb consulted


def test_pentest_defers_and_enforces_exploit_approval():
    state = EngagementState(target="10.0.0.5")
    brief = EngagementBrief(
        targets=["10.0.0.5"],
        allowed_phases=["discovery", "assessment", "exploitation", "reporting"])
    orch = SimpleNamespace(_active_persona="pentest", llm=None)
    calls = []

    def confirm_cb(agent, findings):
        calls.append(agent)
        return "n"                                 # operator denies

    d = FrontierDriver(orch, _agents(), state, brief,
                       confirm_exploitation=True, confirm_cb=confirm_cb)
    assert calls == []                             # NOT asked at construction/launch

    # an enumeration lead never gates exploitation
    assert d._is_exploit_lead(
        Lead(kind="surface", description="enum web", reach_level="service")) is False

    # the first exploit-class lead asks once; denial releases it
    _script(d, lambda *a: None)
    res = d._work_lead(Lead(kind="exploit", description="prove RCE",
                            reach_level="exploited", target="10.0.0.5"))
    assert res.status == "refuted" and calls == [EXPLOIT_AGENT]

    # a later exploit lead is NOT re-asked (verdict resolved once)
    res2 = d._work_lead(Lead(kind="escalation", description="root",
                             reach_level="root", target="10.0.0.5"))
    assert res2.status == "refuted" and len(calls) == 1


# ── full run: chain to root, halt (ctf) ───────────────────────────────────────

def test_run_walks_chain_to_root_and_halts_ctf():
    d = _driver(persona="pentest-ctf")

    def effect(name, objective, run):
        if "DISCOVERY" in objective:
            d.state.recon.open_ports.append(
                {"host": "10.0.0.5", "port": 80, "service": "http", "version": "nginx"})
            d.state._port_keys.add("10.0.0.5:80/tcp")
        elif "SERVICE IDENTIFICATION" in objective:
            pass
        elif "Deep-enumerate" in objective or "enumerate" in objective.lower():
            # working the web surface lead lands the whole chain: a reused cred,
            # the user flag, and the root flag (the win).
            d.state.add_credential(secret="s3cr3t", username="ben", service="smtp",
                                   verified=True)
            d.state.add_flag("HTB{user}", location="/home/ben/user.txt", verified=True)
            d.state.add_flag("HTB{root}", location="/root/root.txt", verified=True)
    _script(d, effect)

    d.run()
    assert d.objective.complete() is True            # foothold + user_flag + root_flag
    assert d.objective.halt_on_complete is True       # ctf persona
    assert d.store.frontier_name() == "root"
