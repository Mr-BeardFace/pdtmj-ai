"""The frontier controller — the lead-driven engagement loop.

This is the "brain" of the re-architecture. It replaces the surface-coverage
scheduler with the operator mindset: always work the single highest-value lead
toward the objective, advance the frontier when a lead confirms (and preempt the
rest), release a lead when it's refuted (and fall back to the next-best), and stop
when the objective is captured.

It is deliberately decoupled from the LLM/orchestrator: it takes a `work_lead`
callable that, given a Lead, does the work and returns a WorkResult. In tests that
callable is scripted; in production (a later step) it spawns agent run(s) — possibly
in parallel via fork/fan_out — against the lead. That seam is what lets us prove the
control logic in isolation before paying for a single token.

The loop, in one breath:

    while objective open and budget remains:
        lead = pick the top lead by EV toward the objective
        if none: frontier is cold -> (breadth fallback hook) -> stop
        result = work_lead(lead)
        fold result's new leads + evidence into state
        advanced -> confirm the lead (frontier moves), preempt lower work
        refuted  -> release the lead (loop pops the next-best automatically)
        if objective complete and persona halts: stop
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from core.leads import Lead, LeadStore, Objective, update_objective


@dataclass
class WorkResult:
    """What working a lead produced. The controller turns this into frontier
    movement, new leads, and objective progress.

      status      — 'advanced' (it moved us forward), 'refuted' (proven dead), or
                    'inconclusive' (no resolution; re-queue until the attempt cap)
      reach_level — on 'advanced', the kill-chain rung actually reached
      new_leads   — leads discovered while working this one (children in the tree)
      flags/creds/findings — evidence banked, fed to the objective predicates
    """
    lead_id: str
    status: str
    reach_level: str = ""
    new_leads: list = field(default_factory=list)
    flags: list = field(default_factory=list)
    creds: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    note: str = ""


@dataclass
class Outcome:
    objective_complete: bool
    frontier: str
    actions: int
    open_leads: int
    halted_on_objective: bool


class FrontierController:
    def __init__(
        self,
        store: LeadStore,
        objective: Objective,
        work_lead: Callable[[Lead], WorkResult],
        *,
        on_event: Optional[Callable[[str, object], None]] = None,
        breadth_fallback: Optional[Callable[[], bool]] = None,
        should_continue: Optional[Callable[[], bool]] = None,
        max_actions: int = 200,
        attempts_cap: int = 3,
    ):
        self.store = store
        self.objective = objective
        self.work_lead = work_lead
        self._on_event = on_event
        # Optional external stop gate (operator /stop or /end, an engine backstop).
        # Returns False to halt the loop cleanly at the next checkpoint. None → never
        # externally halted (the test default).
        self._should_continue = should_continue
        # Called when no open lead exists (frontier cold) to DISCOVER new leads.
        # Returns True if it surfaced any (loop continues), False to stop. None →
        # treat a cold frontier as a stop (the skeleton default).
        self._breadth_fallback = breadth_fallback
        self._max_actions = max_actions
        self._attempts_cap = attempts_cap

        self._actions = 0
        self._halted_on_objective = False
        # accumulated evidence the objective predicates read
        self._flags: list = []
        self._creds: list = []
        self._findings: list = []

    # ── the loop ────────────────────────────────────────────────────────────────

    def run(self) -> Outcome:
        self._refresh_objective()
        # The loop runs while there's BUDGET and WORK — not "while the objective is
        # open". Objective completion is an *early halt* (ctf) checked at the top of
        # each pass; a non-halting persona (pentest) keeps going into the remaining
        # leads after the objective is met.
        while self._actions < self._max_actions:
            if self._should_continue and not self._should_continue():
                self._emit("halted", "external stop")
                break
            if self.objective.complete() and self.objective.halt_on_complete:
                self._halted_on_objective = True
                self._emit("objective_met", self.objective)
                break
            lead = self.store.pick_top()
            if lead is None:
                # Frontier is cold — nothing hot to push. Only now do we go wide.
                self._emit("frontier_cold", self.store.frontier_name())
                if self._breadth_fallback and self._breadth_fallback():
                    continue
                break
            self._work(lead)
            self._refresh_objective()
        return self._outcome()

    # ── working a single lead ─────────────────────────────────────────────────────

    def _work(self, lead: Lead) -> None:
        lead.status = "active"
        lead.attempts += 1
        self._emit("work_lead", lead)

        result = self.work_lead(lead)
        self._actions += 1

        # Fold in everything the work produced — discovered leads + banked evidence.
        for nl in result.new_leads:
            if not nl.origin_id:
                nl.origin_id = lead.id
            self.store.add(nl)
        self._flags.extend(result.flags)
        self._creds.extend(result.creds)
        self._findings.extend(result.findings)

        # Resolve the lead and move (or don't move) the frontier.
        if result.status == "advanced":
            if result.reach_level:
                lead.reach_level = result.reach_level
            lead.status = "confirmed"
            self._emit("advance", lead)
            self._preempt(lead)
        elif result.status == "refuted":
            lead.status = "refuted"
            self._emit("refute", lead)
        else:  # inconclusive — re-queue until it's burned its attempt budget
            lead.status = "exhausted" if lead.attempts >= self._attempts_cap else "open"
            if lead.status == "exhausted":
                self._emit("exhaust", lead)

    def _preempt(self, lead: Lead) -> None:
        """A lead confirmed and the frontier advanced — focus shifts.

        In this serial skeleton there is nothing in flight to cancel: re-ranking on
        the next `pick_top` already refocuses onto whatever now best extends the new
        frontier. In parallel mode (a later step) this is where in-flight workers
        below the new frontier get cancelled via the fan_out cancel Event / abort.
        """
        self._emit("preempt", self.store.current_frontier())

    # ── helpers ───────────────────────────────────────────────────────────────────

    def _refresh_objective(self) -> None:
        update_objective(self.objective, flags=self._flags, creds=self._creds,
                         findings=self._findings)

    def _emit(self, kind: str, payload: object) -> None:
        if self._on_event:
            self._on_event(kind, payload)

    def _outcome(self) -> Outcome:
        return Outcome(
            objective_complete=self.objective.complete(),
            frontier=self.store.frontier_name(),
            actions=self._actions,
            open_leads=len(self.store.open_leads()),
            halted_on_objective=self._halted_on_objective,
        )
