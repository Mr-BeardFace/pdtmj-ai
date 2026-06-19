"""Frontier-first data model: Lead EV/ranking, frontier tracking, win-state."""
from core.leads import (
    Lead, LeadStore, Objective, Goal, objective_for, update_objective,
    level_of, FRONTIER_LEVELS,
)


# ── Lead EV / depth bias ──────────────────────────────────────────────────────

def test_ev_depth_bias_prefers_further_reach():
    # Holding prior + cost equal, the lead that reaches FURTHER toward the objective
    # wins — the depth bias. (Confidence/cost still matter: a low-prior forward shot
    # does NOT auto-beat a solid cheap lead; the hard "this is now priority" focus
    # comes from CONFIRMED advances at the controller level, not from ranking
    # unconfirmed candidates.)
    far = Lead(kind="x", description="root path", reach_level="root", prior=0.5, cost="cheap")
    near = Lead(kind="x", description="just a vuln", reach_level="vuln", prior=0.5, cost="cheap")
    assert far.ev(0) > near.ev(0)


def test_ev_cheap_beats_expensive_at_same_reach():
    cheap = Lead(kind="x", description="a", reach_level="user", prior=0.5, cost="cheap")
    pricey = Lead(kind="x", description="b", reach_level="user", prior=0.5, cost="expensive")
    assert cheap.ev(0) > pricey.ev(0)


def test_refuted_and_exhausted_leads_score_zero():
    base = dict(kind="x", description="dead", reach_level="root", prior=0.9, cost="cheap")
    assert Lead(status="refuted", **base).ev(0) == 0.0
    assert Lead(status="exhausted", **base).ev(0) == 0.0


def test_forward_lead_dominates_stale_one_at_high_frontier():
    # At frontier 'user' (5), a stale low-rung lead still scores a little (it's not
    # dead), but a same-confidence lead that reaches root dominates it.
    behind = Lead(kind="x", description="old service", reach_level="service", prior=0.5, cost="cheap")
    ahead = Lead(kind="x", description="root path", reach_level="root", prior=0.5, cost="cheap")
    assert behind.ev(5) > 0
    assert ahead.ev(5) > behind.ev(5)


# ── LeadStore: frontier + ranking + dedup ─────────────────────────────────────

def test_store_pick_top_and_frontier_advance():
    store = LeadStore()
    a = store.add(Lead(kind="vuln", description="rce", reach_level="exploited", prior=0.6))
    store.add(Lead(kind="surface", description="ssh", reach_level="service", prior=0.3))
    assert store.pick_top().id == a.id           # higher reach/EV wins
    assert store.current_frontier() == 0          # nothing confirmed yet
    a.status = "confirmed"
    assert store.current_frontier() == level_of("exploited")
    assert store.frontier_name() == "exploited"


def test_store_dedups_same_lead():
    store = LeadStore()
    store.add(Lead(kind="vuln", description="RCE   here", target="h"))
    store.add(Lead(kind="vuln", description="rce here", target="h"))   # same normalized key
    assert len(store.leads) == 1


def test_store_pick_top_none_when_cold():
    store = LeadStore()
    l = store.add(Lead(kind="x", description="a", reach_level="vuln"))
    l.status = "refuted"
    assert store.pick_top() is None              # no open leads → frontier cold


# ── Objective / win-state predicates ──────────────────────────────────────────

def test_ctf_objective_completes_on_user_then_root_flag():
    obj = objective_for("pentest-ctf", "10.0.0.5")
    assert obj.open() and not obj.complete()

    update_objective(obj, flags=[{"location": "/home/ben/user.txt"}])
    assert obj.goal("user_flag").met
    assert obj.goal("foothold").met              # holding a flag implies access
    assert not obj.goal("root_flag").met
    assert obj.open()                            # root still missing

    update_objective(obj, flags=[{"location": "/root/root.txt"}])
    assert obj.goal("root_flag").met
    assert obj.complete() and not obj.open()


def test_foothold_marked_by_verified_cred_or_rce_finding():
    obj = objective_for("pentest-ctf", "t")
    update_objective(obj, creds=[{"verified": True}])
    assert obj.goal("foothold").met

    obj2 = objective_for("pentest-ctf", "t")
    update_objective(obj2, findings=[{"title": "Remote Code Execution via X", "verified": True}])
    assert obj2.goal("foothold").met


def test_persona_knobs():
    ctf = objective_for("pentest-ctf", "t")
    pen = objective_for("pentest", "t")
    assert ctf.halt_on_complete is True and ctf.breadth_after is False
    assert pen.halt_on_complete is False and pen.breadth_after is True
