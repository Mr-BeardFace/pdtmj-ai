"""Frontier-first control model: Objectives and Leads.

This is the data foundation for the lead-driven re-architecture. It replaces
"work every surface to coverage" with "always push the single most promising lead
toward the objective, preempt on confirmation, release on refutation."

Two models:

  * Objective — the mission as CHECKABLE conditions (a win-state), not a string.
    `Objective.open()` answers "are we done?" as a machine question, so the engine
    can refuse to stop while the objective is unmet and a viable lead exists.

  * Lead — the unit of work. Surfaces, vulns, creds, footholds, misconfigs all
    become leads, each placed on the kill-chain ladder (`reach_level`) and scored
    by EXPECTED PROGRESS TOWARD THE OBJECTIVE, not by generic service weight. A
    confirmed-but-unexecuted critical finding becomes a high-`reach` lead and rises
    to the top automatically — which is the structural fix for "catalogued the path
    to root but never walked it."

Nothing here is wired into the driver yet; it's inert and independently tested.
The frontier controller (next step) consumes it.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from core.timeutil import now_local


# ── the kill-chain ladder ─────────────────────────────────────────────────────
# Where a lead sits if it SUCCEEDS. Ranking has a strong depth bias: a lead that
# would push the frontier further forward outranks a lateral one at a lower rung,
# even with a lower prior — this is what makes the engine follow a hot thread to
# ground instead of spreading across the board.
FRONTIER_LEVELS: dict[str, int] = {
    "recon": 0,        # ports/hosts discovered
    "service": 1,      # service identified/fingerprinted
    "vuln": 2,         # a vulnerability/weakness identified (not yet exploited)
    "exploited": 3,    # a code-exec / access primitive proven (e.g. RCE works)
    "foothold": 4,     # a stable, framed session held
    "user": 5,         # local user access / user-level creds / user flag
    "privesc": 6,      # a concrete privilege-escalation path identified
    "root": 7,         # root / administrator / root flag
}
MAX_FRONTIER = max(FRONTIER_LEVELS.values())

_COST_WEIGHT = {"cheap": 1.0, "medium": 3.0, "expensive": 8.0}

# Lead lifecycle:
#   open      — known, not yet worked
#   active    — currently being worked by a worker
#   advancing — worked, produced progress, still has more to give (re-queue hot)
#   confirmed — succeeded; it moved the frontier (terminal-positive)
#   refuted   — proven a dead end; release focus, never re-pick (terminal-negative)
#   exhausted — worked without resolving and no longer worth re-trying
_OPEN_STATES = ("open", "active", "advancing")
_DEAD_STATES = ("refuted", "exhausted")


def level_of(name: str) -> int:
    return FRONTIER_LEVELS.get((name or "").lower(), 0)


class Lead(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    kind: str                       # surface|vuln|cred|foothold|misconfig|pivot|escalation|recon
    description: str                # the concrete next action to attempt
    technique: str = ""
    target: str = ""                # host/surface/url this pertains to
    reach_level: str = "vuln"       # the kill-chain rung this lead reaches IF it succeeds
    prior: float = 0.5              # 0..1 likelihood it actually advances
    cost: str = "medium"            # cheap|medium|expensive
    status: str = "open"
    origin_id: str = ""             # the lead/finding this was spawned from (leads form a tree)
    created_by: str = ""            # agent/strategist that surfaced it
    attempts: int = 0
    notes: str = ""
    timestamp: datetime = Field(default_factory=now_local)

    def ev(self, current_frontier: int = 0) -> float:
        """Expected progress toward the objective from the current frontier.

        `gain` is how many rungs past the current frontier this lead would push
        (clamped ≥ 1 so an at-or-below-frontier lead still has *some* value but is
        dominated by anything that advances). Dead leads score 0 so they're never
        re-picked."""
        if self.status in _DEAD_STATES:
            return 0.0
        gain = max(1, level_of(self.reach_level) - current_frontier + 1)
        return gain * self.prior / _COST_WEIGHT.get(self.cost, 3.0)

    @property
    def is_open(self) -> bool:
        return self.status in _OPEN_STATES


class LeadStore(BaseModel):
    leads: list[Lead] = []

    def add(self, lead: Lead) -> Lead:
        """Add a lead, de-duplicating on (kind, target, normalized description) so
        repeated discovery of the same thing doesn't pile up. Returns the stored
        lead (existing one on a dup)."""
        key = self._key(lead)
        for ex in self.leads:
            if self._key(ex) == key:
                return ex
        self.leads.append(lead)
        return lead

    @staticmethod
    def _key(lead: Lead) -> str:
        return f"{lead.kind}|{lead.target}|{' '.join(lead.description.lower().split())[:80]}"

    def get(self, lead_id: str) -> Optional[Lead]:
        return next((l for l in self.leads if l.id == lead_id), None)

    def mark(self, lead_id: str, status: str) -> Optional[Lead]:
        l = self.get(lead_id)
        if l is not None:
            l.status = status
        return l

    def current_frontier(self) -> int:
        """Highest rung reached by a CONFIRMED lead — the engagement's current
        position on the kill chain."""
        levels = [level_of(l.reach_level) for l in self.leads if l.status == "confirmed"]
        return max(levels) if levels else 0

    def frontier_name(self) -> str:
        cur = self.current_frontier()
        return next((n for n, v in FRONTIER_LEVELS.items() if v == cur), "recon")

    def open_leads(self) -> list[Lead]:
        return [l for l in self.leads if l.is_open]

    def ranked(self) -> list[Lead]:
        """Open leads, best-first by EV against the current frontier (depth-biased).
        Ties broken toward the higher rung, then the cheaper lead."""
        cur = self.current_frontier()
        return sorted(
            self.open_leads(),
            key=lambda l: (l.ev(cur), level_of(l.reach_level), -_COST_WEIGHT.get(l.cost, 3.0)),
            reverse=True,
        )

    def pick_top(self) -> Optional[Lead]:
        """The single highest-value lead to work next, or None when the frontier is
        cold (no open leads) — the controller's signal to fall back to breadth."""
        r = self.ranked()
        return r[0] if r else None


# ── Objective / win-state ─────────────────────────────────────────────────────

class Goal(BaseModel):
    name: str
    met: bool = False
    evidence: str = ""


class Objective(BaseModel):
    description: str = ""
    goals: list[Goal] = []
    # Persona knobs: ctf halts the moment the objective is complete; pentest does
    # not (it runs each lead to impact, then returns to breadth over the full scope).
    halt_on_complete: bool = True
    breadth_after: bool = False

    def open(self) -> bool:
        """True while any goal is unmet — the engine must not drift into reporting
        while this is true and a viable lead exists."""
        return any(not g.met for g in self.goals)

    def complete(self) -> bool:
        return bool(self.goals) and all(g.met for g in self.goals)

    def goal(self, name: str) -> Optional[Goal]:
        return next((g for g in self.goals if g.name == name), None)

    def mark(self, name: str, evidence: str = "") -> None:
        g = self.goal(name)
        if g is not None and not g.met:
            g.met = True
            if evidence:
                g.evidence = evidence

    def next_open(self) -> Optional[Goal]:
        """The next unmet goal in declared order — what the frontier is driving at."""
        return next((g for g in self.goals if not g.met), None)


# ── persona objective templates ───────────────────────────────────────────────

def objective_for(persona: str, target: str = "") -> Objective:
    """Build the win-state for a persona. ctf drives to root and halts; pentest
    drives each lead to impact and keeps going (breadth after)."""
    if persona == "pentest-ctf":
        return Objective(
            description=f"Capture user and root flags on {target}".strip(),
            goals=[Goal(name="foothold"), Goal(name="user_flag"), Goal(name="root_flag")],
            halt_on_complete=True,
            breadth_after=False,
        )
    # generic pentest: get access, escalate, then cover the rest of the scope
    return Objective(
        description=f"Demonstrate impact across scope on {target}".strip(),
        goals=[Goal(name="foothold"), Goal(name="privilege_escalation")],
        halt_on_complete=False,
        breadth_after=True,
    )


def update_objective(obj: Objective, *, flags=None, creds=None, findings=None) -> Objective:
    """Evidence-gated goal evaluation — predicates over banked state, NOT an agent's
    say-so. Pure-data inputs (no EngagementState import) so it stays decoupled and
    testable; the controller passes the relevant collections.

      foothold              — any captured flag, any verified credential, or a
                              verified exploited/foothold-class finding
      user_flag / root_flag — a captured flag whose location points at user.txt /
                              home (user) or root.txt / /root (root)
      privilege_escalation  — a captured root flag or a verified root-level finding
    """
    flags = flags or []
    creds = creds or []
    findings = findings or []

    def loc(f):
        return (f.get("location", "") if isinstance(f, dict) else getattr(f, "location", "")).lower()

    def fval_is_user(f):
        l = loc(f)
        return "user.txt" in l or "/home/" in l
    def fval_is_root(f):
        l = loc(f)
        return "root.txt" in l or "/root" in l

    any_verified_cred = any((c.get("verified") if isinstance(c, dict) else getattr(c, "verified", False))
                            for c in creds)
    if flags or any_verified_cred or _has_verified_level(findings, ("exploited", "foothold", "rce", "code execution")):
        obj.mark("foothold", "access established")

    if any(fval_is_user(f) for f in flags):
        obj.mark("user_flag", "user flag captured")
    if any(fval_is_root(f) for f in flags):
        obj.mark("root_flag", "root flag captured")
        obj.mark("privilege_escalation", "root achieved")

    return obj


def _has_verified_level(findings, needles) -> bool:
    for f in findings:
        if not (f.get("verified") if isinstance(f, dict) else getattr(f, "verified", False)):
            continue
        blob = ((f.get("title", "") if isinstance(f, dict) else getattr(f, "title", "")) or "").lower()
        if any(n in blob for n in needles):
            return True
    return False
