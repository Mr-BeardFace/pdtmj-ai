"""ParallelDriver — the 2.0 breadth-first engagement driver.

Same methodology as the serial EngagementDriver (enumerate → plan → exploit →
validate per surface), but two places that were a serial SUM become a parallel
MAX:

  Layer 1 — surface fan-out. Instead of working the single highest-value surface
  and then the next, it works the top-K *independent* surfaces at once. Web on
  :80 and SMB on :445 no longer wait on each other.

  Layer 2 — hypothesis fan-out. Inside one surface's exploit phase, instead of
  one agent grinding the plan top-to-bottom, it ranks the plan items by expected
  value (prior ÷ cost) and runs the top few as bounded "prove or refute" workers
  in parallel. The first to reach the engagement objective cancels the rest. A
  worker has a hard turn budget, so it *cannot* grind a dead end by construction —
  the structural cure for the 100+ attempt decrypt loop.

Concurrency model (mirrors the JobManager): each worker gets an isolated `fork()`
of the engagement state and a sibling Orchestrator (`clone_for_worker`) that
shares the live process/job/shell/secret singletons but writes only to the fork.
After the workers join, the driver folds every fork back into the canonical state
serially with `merge_from`. No locks in the worker hot path.

A single AgentGate, shared across BOTH layers (and every nesting level), caps how
many LLM agent loops run at once — so surfaces × hypotheses can't multiply into a
quota blowout. The gate is acquired only around a leaf agent run, never held
across a nested fan-out, so it cannot deadlock.

The class is reused as its own per-surface child: a surface worker is just a
ParallelDriver running one `_cycle_surface`, whose exploit phase fans out
hypotheses one level down. The recursion bottoms out because a hypothesis worker
runs a single bounded agent (`_run_hypothesis`), not another cycle.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.concurrency import AgentGate, fan_out
from core.engagement_state import surface_priority
from core.models import Surface, TestPlan
from core.pipeline import EngagementDriver, EXPLOIT_AGENT, RCE_AGENT


# Cost → EV discount. An attractive-but-expensive path (offline crack, prior 0.5,
# cost expensive → EV 0.06) ranks BELOW a modest-but-cheap one (default creds,
# prior 0.35, cost cheap → EV 0.35): the operator "gut feeling" made explicit.
_COST_WEIGHT = {"cheap": 1.0, "medium": 3.0, "expensive": 8.0}

# Technique/action keywords → cost class. Brute/spray/crack/decrypt/fuzz are the
# slow, low-yield grinds; anonymous/default/misconfig/reuse are the cheap wins.
_EXPENSIVE_HINTS = ("brute", "bruteforce", "brute-force", "spray", "crack", "hashcat",
                    "john", "decrypt", "fuzz", "wordlist", "rockyou", "exhaustive",
                    "enumerate all", "every")
_CHEAP_HINTS = ("default", "anonymous", "unauth", "null session", "null-session",
                "idor", "misconfig", "exposed", "reuse", "cred-reuse", "sudo -l",
                "suid", "known cve", "public exploit", "guest", "directory listing")

# Technique/action keywords that mark a hypothesis as a code-execution / foothold
# primitive. These are NOT a "prove it then stop" question — confirming the vector
# is only step one of a kill chain (channel → stable session → privesc → flag), so
# such a hypothesis is exempted from the bounded prove/refute treatment and run by
# the foothold specialist with a full budget instead.
_FOOTHOLD_HINTS = ("rce", "remote code execution", "command injection", "command exec",
                   "code execution", "code injection", "deserial", "ssti",
                   "template injection", "file upload", "arbitrary upload",
                   "ssrf", "web shell", "webshell", "reverse shell", "foothold",
                   "exec primitive")


@dataclass
class _Hypothesis:
    """A plan item lifted to a prove/refute hypothesis with a prior and a cost so
    it can be EV-ranked. Priors are ordinal (the planner already ordered items by
    likelihood/impact); cost is inferred from the technique."""
    action: str
    rationale: str
    technique: str
    prior: float
    cost: str

    @property
    def ev(self) -> float:
        return self.prior / _COST_WEIGHT.get(self.cost, 3.0)


class ParallelDriver(EngagementDriver):
    def __init__(self, *args, gate: Optional[AgentGate] = None,
                 surface_fanout: int = 3, hypothesis_fanout: int = 3,
                 hypothesis_worker_turns: int = 12, **kwargs):
        super().__init__(*args, **kwargs)
        if gate is None:
            from core.config import get
            gate = AgentGate(int(get("max_parallel_agents", 3) or 3))
        self._gate = gate
        self._surface_fanout = max(1, int(surface_fanout))
        self._hyp_fanout = max(1, int(hypothesis_fanout))
        self._hyp_turns = max(1, int(hypothesis_worker_turns))
        self._exploit_resolved = False
        self._owned_surface_id: Optional[str] = None

    # ── Layer 1: surface fan-out ────────────────────────────────────────────────

    def _surface_loop(self, target: str) -> None:
        # Resolve the exploit go/no-go ONCE on this (main) thread — workers must
        # never raise a UI prompt from a background thread.
        self._resolve_exploit_approval()
        while True:
            if self.state and getattr(self.state, "concluded", None):
                self._activity(f"■ Objective achieved — {self.state.concluded}. Concluding.")
                break
            ctrl = self._check_control()
            if ctrl == "stop":
                self._stopped = True
                self._activity("⏸ Engagement paused (/stop).")
                break
            if ctrl == "end":
                self._ended_early = True
                self._activity("■ Wrapping up (/end) — proceeding to reporting.")
                break
            if self._backstop_tripped():
                self._capped = True
                break
            batch = self._select_surface_batch()
            if not batch:
                self._activity("✓ All surfaces exhausted.")
                break
            if len(batch) == 1:
                # One surface — no fork overhead; the exploit phase still fans out.
                self._cycle_surface(batch[0], target)
            else:
                self._cycle_surfaces_parallel(batch, target)

    def _select_surface_batch(self) -> list[Surface]:
        """The top-K eligible surfaces by value, to work concurrently. Deterministic
        (priority-ordered) — the LLM exhaustion judge still rules each one per
        cycle, but batch selection itself stays cheap and lock-free."""
        eligible = self.state.eligible_surfaces(self.max_cycles_per_surface)
        if not eligible:
            return []
        ranked = sorted(eligible, key=lambda s: surface_priority(s, self.all_findings),
                        reverse=True)
        k = max(1, min(self._surface_fanout, len(ranked)))
        return ranked[:k]

    def _cycle_surfaces_parallel(self, batch: list[Surface], target: str) -> None:
        labels = ", ".join(s.label for s in batch)
        self._banner(f"Parallel surfaces ×{len(batch)} — {labels}")
        marks = self.state.merge_marks()
        children = []
        jobs = []
        for s in batch:
            fork = self.state.fork()
            worker_orch = self.orch.clone_for_worker(fork, label=s.label)
            child = self._make_child(worker_orch, fork)
            child._owned_surface_id = s.id
            fsurf = next((fs for fs in fork.surfaces if fs.id == s.id), None)

            def job(cancel, child=child, fsurf=fsurf):
                child._control = self._child_control(cancel)
                if fsurf is None or cancel.is_set():
                    return child
                child._cycle_surface(fsurf, target)
                return child

            children.append(child)
            jobs.append(job)

        res = fan_out(jobs, is_solve=lambda c: bool(c.state.concluded))
        self._report_worker_errors(res)
        self._merge_children(res.results, marks)
        self.total_cycles += len(batch)
        if res.solved is not None:
            self._activity("★ Objective reached — concluding; remaining surface work cancelled.")

    # ── Layer 2: hypothesis fan-out (overrides the serial exploit phase) ────────

    def _run_exploit(self, surface: Surface) -> None:
        plan = self.state.get_plan_for(surface.id)
        hyps = self._rank_hypotheses(plan)
        # Nothing to parallelize → fall back to the single-agent exploit phase.
        if self._hyp_fanout <= 1 or len(hyps) <= 1:
            return super()._run_exploit(surface)

        chosen = hyps[: self._hyp_fanout]
        exploit_agent = self._exploit_agent_for(surface)
        have_rce = RCE_AGENT in self.agents
        self._banner(f"Exploitation — {surface.label}  (parallel ×{len(chosen)} hypotheses)")
        for h in chosen:
            tag = "  [foothold→kill-chain]" if self._is_foothold_hypothesis(h) and have_rce else ""
            self._activity(f"   • EV {h.ev:.2f} [{h.cost:>9}] {h.technique}: {h.action[:80]}{tag}")

        marks = self.state.merge_marks()
        children = []
        jobs = []
        for h in chosen:
            fork = self.state.fork()
            worker_orch = self.orch.clone_for_worker(fork, label=f"{surface.label}:{h.technique}")
            child = self._make_child(worker_orch, fork)
            child._owned_surface_id = surface.id
            fsurf = next((fs for fs in fork.surfaces if fs.id == surface.id), None)

            # A code-exec / foothold hypothesis is NOT a prove-then-stop question —
            # confirming the vector is only step one of the kill chain. Run it on the
            # foothold specialist with a full budget and the stabilise→escalate→flag
            # objective. Everything else stays a bounded prove/refute worker.
            if self._is_foothold_hypothesis(h) and have_rce:
                agent = RCE_AGENT
                budget = self._foothold_budget()
                objective = self._foothold_objective(surface, h)
            else:
                agent = exploit_agent
                budget = self._hyp_turns
                objective = self._hypothesis_objective(surface, h)

            def job(cancel, child=child, agent=agent, budget=budget,
                    objective=objective, fsurf=fsurf):
                child._control = self._child_control(cancel)
                if fsurf is None or cancel.is_set():
                    return child
                child._run_agent(agent, fsurf.host, objective, max_turns=budget)
                return child

            children.append(child)
            jobs.append(job)

        res = fan_out(jobs, is_solve=lambda c: bool(c.state.concluded))
        self._report_worker_errors(res)
        self._merge_children(res.results, marks)
        if res.solved is not None:
            self._activity(f"★ Objective reached on {surface.label} — other hypotheses cancelled.")

    def _rank_hypotheses(self, plan: Optional[TestPlan]) -> list[_Hypothesis]:
        if not plan or not plan.items:
            return []
        hyps: list[_Hypothesis] = []
        for i, item in enumerate(plan.items):
            # Ordinal prior: the planner ordered by likelihood/impact, so earlier
            # items are likelier. EV re-ranking then lets a cheap item lower in the
            # plan leapfrog an expensive one above it.
            prior = max(0.15, 0.9 - i * 0.12)
            cost = self._infer_cost(item.technique, item.action)
            hyps.append(_Hypothesis(action=item.action, rationale=item.rationale,
                                    technique=item.technique or "test",
                                    prior=prior, cost=cost))
        hyps.sort(key=lambda h: h.ev, reverse=True)
        return hyps

    @staticmethod
    def _infer_cost(technique: str, action: str) -> str:
        blob = f"{technique} {action}".lower()
        if any(k in blob for k in _EXPENSIVE_HINTS):
            return "expensive"
        if any(k in blob for k in _CHEAP_HINTS):
            return "cheap"
        return "medium"

    @staticmethod
    def _is_foothold_hypothesis(h: _Hypothesis) -> bool:
        """True if proving this hypothesis means a code-exec / foothold primitive —
        the start of a kill chain, not a one-shot prove/refute."""
        # Normalise separators so "command-injection"/"command_injection" match the
        # spaced hints.
        blob = f"{h.technique} {h.action}".lower().replace("-", " ").replace("_", " ")
        return any(k in blob for k in _FOOTHOLD_HINTS)

    def _foothold_budget(self) -> int:
        """Generous, bounded budget for a foothold worker — the full per-agent turn
        budget (the kill chain needs room), with a sane cap when turns are unlimited."""
        return self.max_turns if (self.max_turns and self.max_turns > 0) else 40

    def _foothold_objective(self, surface: Surface, h: _Hypothesis) -> str:
        lines = [
            f"You have a candidate code-execution path on {surface.label} "
            f"(host {surface.host}): {h.action}.",
        ]
        if h.rationale:
            lines.append(f"Why it should work: {h.rationale}")
        lines += [
            "",
            "CONFIRM it executes, then CARRY IT THROUGH toward the objective. First establish a "
            "reliable output channel (OOB exfil or a caught reverse shell). Then make a BRIEF, "
            "time-boxed try at a more durable channel — it's nicer to work through, but it is a "
            "means, not the goal:",
            "  • Linux: inject a key you generate into the user's ~/.ssh/authorized_keys, then "
            "ssh_exec(key_file=...); or add a user; or hold a reverse shell.",
            "  • Windows: add a local admin (generated password, record_credential it) and drive "
            "it with netexec winrm; or enable RDP.",
            "If a durable channel doesn't land in a couple of tries, STOP chasing it and USE the "
            "primitive you already have. A fragile-but-working primitive (even OOB HTTP exfil that "
            "returns output) is enough to enumerate, read files, harvest creds, run sudo -l / SUID "
            "/ cron, and capture the objective — reading output a command at a time is real "
            "progress. Do NOT loop re-planting keys / re-firing reverse shells at a target that "
            "isn't accepting them (daemon user with no login, filtered egress, session limits).",
            "If the primitive runs a binary WITHOUT a shell (e.g. NiFi ExecuteProcess, many "
            "injection points), shell redirection like `>& /dev/tcp/...` will NOT work — wrap "
            "the whole payload as a single argument to `bash -c '<payload>'`, or stage a "
            "script to disk (write it, chmod +x, execute it). Verify exec with one callback "
            "before building on it.",
            "Through whichever channel you have: record_persistence for anything you plant, "
            "enumerate for privilege escalation (sudo -l / SUID / capabilities / cron), "
            "escalate where a clear path exists, capture any flag/objective, and call "
            "conclude_engagement when the objective is met. Record every credential with "
            "record_credential. Stay in scope and keep every change reversible and "
            "non-destructive.",
        ]
        return "\n".join(lines)

    def _hypothesis_objective(self, surface: Surface, h: _Hypothesis) -> str:
        lines = [
            f"PROVE OR REFUTE one specific hypothesis on {surface.label} "
            f"(host {surface.host}), then STOP — do not chase other paths.",
            "",
            f"Hypothesis: {h.action}",
        ]
        if h.rationale:
            lines.append(f"Why it might work: {h.rationale}")
        lines += [
            f"Technique: {h.technique}",
            "",
            f"You have ~{self._hyp_turns} turns. Gather just enough evidence to "
            "CONFIRM (annotate_finding verified=true with concrete evidence; "
            "record_credential / record_flag for anything you obtain) or REFUTE this "
            "one hypothesis. If proving it reaches the engagement objective (root, the "
            "flag, full control), call conclude_engagement. Work the cheap, "
            "high-probability checks first; if you confirm it or rule it out, finish — "
            "do not grind variations of the same payload. If you happen to notice a "
            "different promising path, note it in a finding and still conclude on THIS "
            "one. Stay strictly non-destructive and reversible.",
        ]
        return "\n".join(lines)

    # ── worker plumbing ─────────────────────────────────────────────────────────

    def _make_child(self, worker_orch, fork) -> "ParallelDriver":
        """A worker driver bound to a cloned orch + forked state. on_run_complete is
        None (the parent fires it after merge); exploitation approval is inherited
        and pre-resolved so a worker never prompts."""
        child = ParallelDriver(
            worker_orch, self.agents, fork, self.brief,
            max_turns=self.max_turns,
            confirm_exploitation=True,
            max_cycles_per_surface=self.max_cycles_per_surface,
            max_total_cycles=self.max_total_cycles,
            max_surfaces=self.max_surfaces,
            emit_activity=self._emit_activity,
            confirm_cb=None,
            control=None,
            on_run_complete=None,
            gate=self._gate,
            surface_fanout=1,                       # a worker never re-fans surfaces
            hypothesis_fanout=self._hyp_fanout,     # but still fans its own hypotheses
            hypothesis_worker_turns=self._hyp_turns,
        )
        child._exploit_approved_all = self._exploit_approved_all
        child._exploit_resolved = True
        child.all_findings = list(self.all_findings)   # dedup context (private copy)
        return child

    def _child_control(self, cancel):
        """Worker control: a set cancel Event (a sibling solved / operator abort)
        reads as 'stop', which makes the worker's cycle bail at its next checkpoint;
        otherwise defer to the parent's control."""
        parent = self._control

        def _control() -> str:
            if cancel.is_set():
                return "stop"
            return parent() if parent else "continue"

        return _control

    def _merge_children(self, children: list, marks: dict) -> None:
        """Fold each worker fork back into canonical state, serially, then ingest
        their runs (findings + UI + cross-run dedup) exactly as the serial path's
        _run_agent would have."""
        for child in children:
            owned = {child._owned_surface_id} if child._owned_surface_id else None
            self.state.merge_from(child.state, marks, owned_surface_ids=owned)
            for run in child.runs:
                self._ingest_worker_run(run)
        self._absorb_followups()

    def _ingest_worker_run(self, run) -> None:
        self.runs.append(run)
        self.all_findings.extend(run.findings)
        if self._on_run_complete:
            self._on_run_complete(run)

    def _report_worker_errors(self, res) -> None:
        for idx, exc in res.errors:
            self._activity(f"[red]⚠ parallel worker {idx} crashed: {exc}[/red]")

    def _resolve_exploit_approval(self) -> None:
        """Decide exploit go/no-go once, up front, on the main thread. Workers then
        inherit the verdict (confirm_cb=None) so none of them blocks on a prompt."""
        if self._exploit_resolved or not self.brief.exploitation_allowed:
            return
        self._exploit_resolved = True
        if not self.confirm_exploitation:
            self._exploit_approved_all = True
            return
        if self._confirm_cb is None:
            self._exploit_approved_all = False
            return
        ans = self._confirm_cb(EXPLOIT_AGENT, self.all_findings)
        self._exploit_approved_all = ans in ("a", "y")
