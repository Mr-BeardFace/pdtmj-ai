"""FrontierDriver — the lead-driven engagement driver (frontier-first).

This is the live wiring of the re-architecture. Where ParallelDriver works the
board for *coverage* (every surface, breadth-first), FrontierDriver works it for
*the objective*: it always pushes the single highest-value lead toward the win
state, advancing the frontier when a lead confirms and releasing it when it dies —
the operator mindset the Silentium post-mortem showed the coverage scheduler lacked
(it catalogued the path to root but never walked it).

It subclasses ParallelDriver purely to reuse the orchestration plumbing — agent
invocation, the exploit-approval gate, fork/merge, the concurrency gate, run
bookkeeping — and replaces the *control loop*: instead of `_surface_loop`, it
seeds a LeadStore from recon and hands a `work_lead` callable to a
`FrontierController`. The controller decides what to work; `work_lead` runs the
right agent for the lead, reads what came back, and reports an advance/refute/
inconclusive verdict plus any new leads.

The objective is built from the active persona (ctf halts at root; pentest carries
on into breadth after impact), so termination is objective-driven, not exhaustion-
driven. The deterministic ingest + the strategist keep the board current between
steps; the strategist's LLM consult fires only on material change.
"""
from __future__ import annotations

from typing import Optional

from core.parallel_driver import ParallelDriver
from core.pipeline import (
    ENUM_AGENT, AD_AGENT, POST_EXPLOIT_AGENT, REPORT_AGENT, is_ad_lead,
)
from core.frontier import FrontierController, WorkResult
from core.leads import Lead, LeadStore, objective_for, level_of
from core.ingest import (
    leads_from_findings, leads_from_credentials, reach_from_evidence, classify_outcome,
)
from core.strategist import Strategist
from core.models import Surface


# Controller events → operator-facing activity lines.
_EVENT_LABELS = {
    "work_lead":      lambda p: f"▶ lead [{p.reach_level}] {p.description[:72]}",
    "advance":        lambda p: f"★ frontier → {p.reach_level}  ({p.description[:56]})",
    "refute":         lambda p: f"✗ dead end — released: {p.description[:60]}",
    "exhaust":        lambda p: f"⊘ exhausted after retries: {p.description[:56]}",
    "preempt":        lambda p: None,   # internal; advance already announced
    "frontier_cold":  lambda p: f"… frontier cold at '{p}' — widening for new leads",
    "objective_met":  lambda p: "■ Objective captured — halting (ctf).",
    "halted":         lambda p: None,
}


class FrontierDriver(ParallelDriver):
    def __init__(self, *args, frontier_max_actions: Optional[int] = None,
                 attempts_cap: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self._persona = getattr(self.orch, "_active_persona", "") or "pentest"
        self.target = self.brief.primary_target or self.state.target
        self.objective = objective_for(self._persona, self.target)
        # CTF is authorized, own-the-box work — exploitation IS the objective, so it
        # is approved by default (never prompts). A real-engagement persona still
        # confirms, but lazily, right before the first exploit-class lead — not at
        # launch (the frontier loop is serial, so there is no background worker that
        # needs the verdict resolved up front the way parallel coverage does).
        if self._persona == "pentest-ctf":
            self.confirm_exploitation = False
        self.store = LeadStore()
        self._attempts_cap = max(1, int(attempts_cap))
        # A frontier "action" is one worked lead (one agent run). Reuse the cycle
        # backstop as the budget so the existing config knob still bounds runtime.
        self._frontier_max_actions = int(
            frontier_max_actions or self.max_total_cycles or 60)
        llm = getattr(self.orch, "llm", None)
        self.strategist = Strategist(
            llm, self._router_model() if self._llm_routing() else None,
            on_event=lambda k, p: self._activity(f"  [magenta]⇢ strategist[/magenta] {p}"),
            enable_llm=self._llm_routing(),
        )
        self._breadth_enum_done = False

    # ── the loop ────────────────────────────────────────────────────────────────

    def run(self) -> list:
        target = self.brief.primary_target or self.state.target

        # Frontier mode is about driving an exploit chain to the objective. With
        # exploitation disabled there is nothing to drive — fall back to the
        # coverage driver's assessment-only behaviour (enumerate + report).
        if not self.brief.exploitation_allowed:
            self._activity("Frontier mode needs exploitation enabled — running assessment-only.")
            return super(ParallelDriver, self).run()

        self._activity(
            f"◎ Frontier mode — objective: {self.objective.description}. "
            "Working the hottest lead toward the goal, not every surface.")

        # Phase 0 — staged discovery. The port sweep itself is deterministic and
        # hardcoded (no LLM deliberation): a fast top-1000 TCP version scan up
        # front, with the deeper TCP and UDP sweeps kicked off in the background.
        # The LLM agent then only does service *identification* on the ports the
        # sweep already mapped, so it stops re-running nmap by hand.
        if not self.state.surfaces:
            self._staged_port_sweep(target)
            self.state.derive_surfaces_from_recon(origin="initial")
            self._refresh_ui()   # staged sweep ingests state directly — push it to the panels now
            self._banner("Service identification — fingerprinting discovered ports")
            self._run_agent(ENUM_AGENT, target, self._service_id_objective(target),
                            max_turns=self._stage_turns(12))
            self.state.derive_surfaces_from_recon(origin="initial")
            if not self.state.surfaces:
                self.state.add_surface(target, origin="initial")

        # Seed the board from recon + any carried-over findings, and let the
        # strategist take a first board-level look.
        self.strategist.consider(self.store, self.state, self.objective,
                                 self.all_findings, force=True)

        controller = FrontierController(
            self.store, self.objective, self._work_lead,
            on_event=self._on_frontier_event,
            breadth_fallback=self._breadth_fallback,
            should_continue=self._frontier_should_continue,
            max_actions=self._frontier_max_actions,
            attempts_cap=self._attempts_cap,
        )
        outcome = controller.run()
        self._announce_outcome(outcome)

        # Fold in any still-running background jobs before reporting.
        flush = getattr(self.orch, "flush_jobs", None)
        if callable(flush):
            try:
                flush()
            except Exception:
                pass

        # A /pause is a TEMPORARY halt — resume later with /continue. The write-up
        # belongs to /end or a natural finish, not a pause, so don't synthesize a
        # report here when paused (it would also reset the resume point's "no report
        # yet" state). /end (ended_early), a cap, or completion all still report.
        from core.config import get as _cfg_get
        if self.all_findings and not self._stopped and _cfg_get("reporting_enabled", True):
            self._banner("Reporting — synthesizing the engagement")
            self._run_agent(REPORT_AGENT, target, None)
        return self.runs

    # ── deterministic discovery (no LLM) ─────────────────────────────────────────

    def _staged_port_sweep(self, target: str) -> None:
        """Hardcoded staged nmap discovery so the initial scan is fast and
        consistent instead of an agent improvising sweep after sweep.

          ① top-1000 TCP, -sV  — synchronous, returns in seconds → immediate board
          ② top-45000 TCP      — background job (port discovery, no -sV)
          ③ top-250  UDP       — background job

        Stages ② and ③ fold into recon automatically as they finish (the
        orchestrator drains completed jobs at each turn boundary and before the
        report), so the agent can start working ① while the deep scans run.
        """
        self._banner(f"Discovery — staged port sweep of {target}")
        try:
            nmap = self.orch.tools.get("nmap_scan")
        except Exception as e:  # noqa: BLE001 — tool registry miss shouldn't kill the run
            self._activity(f"  port sweep unavailable ({e}); falling back to agent discovery.")
            self._run_agent(ENUM_AGENT, target, self._discovery_objective(target),
                            max_turns=self._stage_turns(8))
            return

        # ① fast top-1000 TCP with version detection — blocking, seconds.
        self._activity("  ① top-1000 TCP (-sV) …")
        try:
            res = nmap.execute(target=target, fast=True, flags="-sV", timeout=300)
            if isinstance(res, dict) and "error" not in res:
                self.state.ingest_tool_result("nmap_scan", res, source_agent=ENUM_AGENT)
                self._note_sweep(res)
            else:
                self._activity(f"  ① sweep returned no hosts ({(res or {}).get('error', 'unknown')}).")
        except Exception as e:  # noqa: BLE001
            self._activity(f"  ① sweep error: {e}")

        # ② + ③ deeper TCP and UDP — backgrounded so they never stall the engagement.
        jobs = getattr(self.orch, "_jobs", None)
        if jobs is None:
            return
        self._activity("  ② top-45000 TCP + ③ top-250 UDP → background")
        jobs.start("nmap_scan", {"target": target, "flags": "--top-ports 45000"},
                   lambda t=target, n=nmap: n.execute(
                       target=t, fast=True, flags="--top-ports 45000", timeout=1200))
        jobs.start("nmap_scan", {"target": target, "flags": "-sU --top-ports 250"},
                   lambda t=target, n=nmap: n.execute(
                       target=t, fast=True, flags="-sU --top-ports 250", timeout=1200))

    def _note_sweep(self, res: dict) -> None:
        """One-line activity summary of what the synchronous stage-1 sweep found."""
        n = sum(len(h.get("open_ports", [])) for h in res.get("hosts", []))
        self._activity(f"  ① {n} open TCP port(s) on top-1000 — board seeded.")

    def _refresh_ui(self) -> None:
        """Push current recon/surfaces to the panels. The staged sweep ingests
        state directly (it does not go through the per-tool emit), so without this
        the Hosts tab wouldn't show the discovered ports/versions until the next
        agent turn."""
        fn = getattr(self.orch, "_emit_state_update", None)
        if callable(fn):
            try:
                fn()
            except Exception:
                pass

    # ── work a single lead (the controller's callback) ──────────────────────────

    def _work_lead(self, lead: Lead) -> WorkResult:
        # Exploit-class leads need go/no-go. Resolved lazily here (serial loop → this
        # is the main worker thread, so prompting is safe) so the operator is asked at
        # the moment exploitation actually starts, not at launch. Enumeration leads
        # never gate. ctf auto-approves (see __init__), so it is never asked.
        if self._is_exploit_lead(lead) and not self._exploit_allowed():
            self._activity(f"⊘ Exploitation not approved — releasing lead: {lead.description[:56]}")
            return WorkResult(lead.id, "refuted", note="exploitation not approved")

        findings_before = len(self.all_findings)
        creds_before = len(self.state.credentials)
        flags_before = len(self.state.flags)
        frontier_before = self.store.current_frontier()

        agent, objective, budget = self._plan_lead(lead)
        spec = agent.split("/")[-1]
        self._banner(f"Lead [{lead.reach_level}] → {spec}  ·  {lead.description[:64]}")
        self._run_agent(agent, lead.target or self.target, objective, max_turns=budget)

        new_findings = self.all_findings[findings_before:]
        new_creds = self.state.credentials[creds_before:]
        new_flags = self.state.flags[flags_before:]

        # Child leads: what this step uncovered. Returned to the controller so it
        # links them to this lead (origin) and re-ranks. The strategist consult
        # below adds inferred/board-level leads on top.
        new_leads: list[Lead] = leads_from_findings(new_findings, created_by=f"lead:{lead.id}")
        new_leads += leads_from_credentials(self.state, creds=new_creds,
                                            created_by=f"lead:{lead.id}")

        # Evidence in the shape the objective predicates read.
        flag_dicts = [{"location": f.location, "value": f.value} for f in new_flags]
        cred_dicts = [{"verified": c.verified} for c in new_creds]
        finding_dicts = [{"title": f.title, "verified": f.verified} for f in new_findings]

        achieved = reach_from_evidence(
            flag_dicts, any(c.verified for c in new_creds), finding_dicts)
        concluded = bool(self.state.concluded)
        made_progress = bool(new_creds or new_flags
                             or any(f.verified for f in new_findings))
        refuted = self._judge_refuted(lead, made_progress, bool(new_leads))
        status, reach = classify_outcome(
            lead, achieved, frontier_before, concluded=concluded,
            made_progress=made_progress, spawned_leads=bool(new_leads), refuted=refuted)

        # Keep the board current (recon breadth + strategist LLM on material change).
        self._maybe_strategize()

        return WorkResult(
            lead.id, status, reach_level=reach, new_leads=new_leads,
            flags=flag_dicts, creds=cred_dicts, findings=finding_dicts,
            note=lead.description)

    def _is_exploit_lead(self, lead: Lead) -> bool:
        """An action that actually exploits — anything past enumeration. Surface /
        service / recon leads are observation and never gate."""
        if lead.kind in ("surface", "service", "recon"):
            return level_of(lead.reach_level) >= level_of("vuln")
        return True

    def _exploit_allowed(self) -> bool:
        """Lazily resolve exploit go/no-go (idempotent — asks at most once), then
        report the verdict. confirm_exploitation False (incl. ctf) → always allowed."""
        self._resolve_exploit_approval()
        return self._exploit_approved_all or not self.confirm_exploitation

    def _judge_refuted(self, lead: Lead, made_progress: bool, spawned: bool) -> bool:
        """A lead is a dead end when a worked step banked nothing and surfaced no new
        thread. The bounded agent budget means 'nothing came back' is a real signal,
        not impatience — release it and let the next-best lead take focus. (Partial
        progress / new leads → not refuted; the controller re-queues to the cap.)"""
        return not made_progress and not spawned

    # ── lead → agent + objective + budget ────────────────────────────────────────

    def _plan_lead(self, lead: Lead) -> tuple[str, str, int]:
        reach = level_of(lead.reach_level)
        surface = self._surface_for(lead)

        # Credential reuse → exploitation agent, spray-the-known-secret objective.
        # Checked first: a cred lead's reach ('user') is high enough to otherwise
        # fall into the foothold branch, but it's an auth attempt, not a kill chain.
        if lead.kind == "cred":
            return (self._exploit_agent_for(surface),
                    self._cred_objective(lead), max(self._hyp_turns, 10))

        # Surface / service / recon → deep enumeration by the right specialist.
        if lead.kind in ("surface", "service") or reach <= level_of("service"):
            return (self._enum_agent_for(surface),
                    self._enum_objective(surface, self.target), self._stage_turns(16))

        # Escalation / foothold / code-exec → the foothold specialist, full budget:
        # this is a kill chain (channel → session → privesc → flag), not a one-shot.
        if lead.kind in ("escalation", "exploit") or reach >= level_of("exploited"):
            agent = self._foothold_agent_for(lead, surface)
            return agent, self._kill_chain_objective(lead, surface), self._foothold_budget()

        # Generic vuln → exploitation agent against the plan/finding. A domain
        # technique (kerberoast, AS-REP, DCSync, relay…) goes to the AD specialist
        # even on a surface whose service tag isn't an AD service.
        plan = self.state.get_plan_for(surface.id) if surface else None
        ad = self._domain_specialist_for(lead, surface)
        agent = ad or self._exploit_agent_for(surface)
        return (agent, self._lead_exploit_objective(lead, surface, plan), self.max_turns or 20)

    def _domain_specialist_for(self, lead: Lead, surface: Optional[Surface]) -> Optional[str]:
        """The AD specialist when the lead OR its surface reads like Active Directory,
        else None. Catches domain techniques whose surface service tag is generic."""
        if AD_AGENT not in self.agents:
            return None
        svc = (surface.service or "").lower() if surface else ""
        from core.pipeline import _SERVICE_SPECIALISTS
        if _SERVICE_SPECIALISTS.get(svc) == AD_AGENT:
            return AD_AGENT
        extra = []
        if surface:
            extra = [surface.fingerprint or "", surface.notes or "", surface.label or ""]
        return AD_AGENT if is_ad_lead(lead.technique, lead.description, *extra) else None

    def _foothold_agent_for(self, lead: Lead, surface: Optional[Surface]) -> str:
        """Route a foothold/escalation lead to its owner:
          • an AD domain kill chain (kerberoast → crack → PtH → DCSync) → AD specialist
          • work that runs FROM an existing session (privesc, local enum) → local-enum
          • turning raw code-exec into a stable session → the exploitation agent

        The local-enum step is reasoning-friendly, not a hard switch: it only fires
        once the lead has actually reached a session (foothold+) or is explicitly an
        escalation, so 'I have access, now escalate' goes to the post-exploitation
        owner while 'I have exec, get me a shell' goes to the exploitation agent."""
        ad = self._domain_specialist_for(lead, surface)
        if ad:
            return ad
        # Local-enum escalates FROM a session — so only route there once a foothold
        # actually exists. Otherwise an 'escalation' lead (often just a privesc CVE
        # flagged during enumeration, before any access) would skip straight to
        # post-exploitation with nothing to escalate from; send it to the specialist
        # to ESTABLISH access first.
        post_access = (lead.kind == "escalation"
                       or level_of(lead.reach_level) >= level_of("foothold"))
        if post_access and self._have_foothold() and POST_EXPLOIT_AGENT in self.agents:
            return POST_EXPLOIT_AGENT
        return self._exploit_agent_for(surface)

    def _have_foothold(self) -> bool:
        """True once there is an actual session to escalate from: a live caught
        reverse shell, or a CONFIRMED frontier that has reached foothold (e.g. a
        verified credential that established access)."""
        shells = getattr(self.orch, "_shells", None)
        if shells is not None and any(s.get("alive") for s in shells.sessions()):
            return True
        return self.store.current_frontier() >= level_of("foothold")

    def _surface_for(self, lead: Lead) -> Optional[Surface]:
        """Find (or register) the surface a lead pertains to, so the existing
        per-surface routing/objective builders can be reused."""
        host = lead.target or self.target
        match = next((s for s in self.state.surfaces if s.host == host), None)
        if match is not None:
            return match
        # Register a host-level surface so routing has something concrete to chew on.
        return self.state.add_surface(host, origin="lateral", notes=lead.description[:120]) \
            or (self.state.surfaces[0] if self.state.surfaces else None)

    def _kill_chain_objective(self, lead: Lead, surface: Optional[Surface]) -> str:
        host = (surface.host if surface else lead.target) or self.target
        lines = [
            f"PRIORITY LEAD — drive this to ground: {lead.description}",
            f"Target: {host}." + (f"  Technique: {lead.technique}." if lead.technique else ""),
        ]
        if lead.notes:
            lines.append(f"Context: {lead.notes}")
        lines += [
            "",
            "This is the hottest thread on the board. Do NOT stop at 'it works'. CONFIRM "
            "execution, then CARRY IT THROUGH toward the objective:",
            "  • Make a BRIEF, time-boxed try at a more durable channel (e.g. inject an SSH "
            "key then ssh_exec, add a user, or catch a reverse shell). It's nicer to work "
            "through — but it is a means, not the goal.",
            "  • If a durable channel doesn't land in a couple of tries, STOP chasing it and "
            "USE the primitive you already have to do the work. A fragile-but-working primitive "
            "(even OOB HTTP exfil that returns output) is enough to enumerate, read files, "
            "harvest creds, run sudo -l / SUID / cron, and capture the objective. Reading output "
            "a command at a time is real progress — do not loop re-planting keys / re-firing "
            "reverse shells at a target that isn't accepting them (daemon user, filtered egress, "
            "session limits).",
            "  • If the primitive runs a binary without a shell, wrap the payload as a single "
            "argument to `bash -c '<payload>'` or stage a script to disk (write, chmod +x, run).",
            "  • record_persistence for anything planted; enumerate for privilege escalation "
            "(sudo -l / SUID / capabilities / cron / services running as root) and escalate where "
            "a path exists; capture any flag/objective.",
            "Record every credential with record_credential and every flag with record_flag. "
            "Call conclude_engagement when the objective is met. Stay in scope; keep every change "
            "reversible and non-destructive.",
        ]
        return "\n".join(lines)

    def _cred_objective(self, lead: Lead) -> str:
        return (
            f"PRIORITY LEAD: {lead.description}. Use the credential(s) already in the engagement "
            "state VERBATIM against every applicable service on reachable hosts (SSH, SMB, WinRM, "
            "FTP, database, web login) — operators reuse passwords across services, so spray the "
            "known secret broadly before anything else. Do NOT brute-force. When a login lands, "
            "establish a session, record_credential the working pair (and where it works), capture "
            "any flag, and look immediately for the next step toward the objective. If none of the "
            "known credentials authenticate anywhere new, say so plainly and stop — that releases "
            "this lead. Stay in scope and non-destructive."
        )

    def _lead_exploit_objective(self, lead: Lead, surface: Optional[Surface], plan) -> str:
        head = self._exploit_objective(surface, plan) if surface else \
            f"Exploit the following on {lead.target or self.target}."
        return (f"PRIORITY LEAD: {lead.description}.\n\n{head}\n\n"
                "First list the concrete techniques worth trying here as a short ordered checklist "
                "(highest-value first), then work it top-down — execute each item, record its result, "
                "and move to the next; do not oscillate between ideas. "
                "Prove real impact with concrete evidence (annotate_finding verified=true). If this "
                "lead turns out to be a dead end, bank what you learned and say so — do not grind.")

    # ── breadth fallback + control ───────────────────────────────────────────────

    def _breadth_fallback(self) -> bool:
        """Frontier cold (no open lead). Try to surface more before giving up:
        re-derive surfaces from recon and re-ingest; if still nothing, run ONE broad
        enumeration pass to discover new ports/services. Returns True if it produced
        new leads (loop continues), False to stop."""
        if not (self.max_surfaces and len(self.state.surfaces) >= self.max_surfaces):
            self.state.derive_surfaces_from_recon(origin="lateral")
        if self.strategist.refresh(self.store, self.state, self.all_findings) > 0:
            return True
        if not self._breadth_enum_done and self._frontier_should_continue():
            self._breadth_enum_done = True
            self._banner("Breadth sweep — no hot lead; broad enumeration for new threads")
            self._run_agent(ENUM_AGENT, self.target,
                            self._enum_objective(None, self.target),
                            max_turns=self._stage_turns(12))
            self.state.derive_surfaces_from_recon(origin="lateral")
            return self.strategist.refresh(self.store, self.state, self.all_findings) > 0
        return False

    def _maybe_strategize(self) -> None:
        """Consult the strategist (deterministic ingest always; LLM only on material
        change) so a chained next step — 'reuse this SMTP password on SSH' — becomes
        a lead without waiting for the keyword ingest to stumble onto it."""
        try:
            self.strategist.consider(self.store, self.state, self.objective, self.all_findings)
        except Exception:
            pass

    def _frontier_should_continue(self) -> bool:
        """External stop gate for the controller — operator /stop or /end, and the
        cycle backstop. Mirrors the coverage loop's control handling so termination
        reasons (paused / ended_early / cycle_cap) report identically."""
        if self.state and getattr(self.state, "concluded", None):
            return True   # objective predicates handle halt; concluding isn't a stop
        ctrl = self._check_control()
        if ctrl == "stop":
            self._stopped = True
            self._activity("⏸ Engagement paused (/stop).")
            return False
        if ctrl == "end":
            self._ended_early = True
            self._activity("■ Wrapping up (/end) — proceeding to reporting.")
            return False
        return True

    # ── events / reporting ───────────────────────────────────────────────────────

    def _on_frontier_event(self, kind: str, payload) -> None:
        fn = _EVENT_LABELS.get(kind)
        if fn is None:
            return
        try:
            text = fn(payload)
        except Exception:
            text = None
        if text:
            self._activity(text)

    def _announce_outcome(self, outcome) -> None:
        if outcome.halted_on_objective:
            self._activity(f"✓ Objective captured at frontier '{outcome.frontier}' "
                           f"in {outcome.actions} lead(s).")
        elif outcome.objective_complete:
            self._activity(f"✓ Objective met; continued into breadth "
                           f"(frontier '{outcome.frontier}', {outcome.open_leads} lead(s) left).")
        else:
            self._activity(f"◌ Stopped at frontier '{outcome.frontier}' — "
                           f"{outcome.actions} lead(s) worked, {outcome.open_leads} open.")
