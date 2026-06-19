"""Engagement driver — the methodology state machine.

Replaces the trigger-drained agent queue with an explicit cycle over attack
surfaces:

    initial enumeration → derive surfaces
        for each surface, until exhausted or capped:
            Enumerate (deep) → Plan → Exploit → Validate
            re-derive surfaces; if the cycle produced new intel, cycle again
    → Reporting

Termination is exhaustion-driven (a cycle that adds no new intel marks the
surface done); the cycle/surface caps are backstops against a non-converging
loop, not the normal stop condition.

The driver is UI-agnostic: it calls an already-constructed Orchestrator and
talks to the caller through callbacks, so the TUI worker and the CLI share one
implementation.
"""
from __future__ import annotations

from typing import Callable, Optional

from core.models import EngagementBrief, EngagementRun, Surface


# Phase → agent name. The driver degrades gracefully if an agent is absent.
ENUM_AGENT     = "pentest/enumeration"
PLAN_AGENT     = "pentest/planning"
EXPLOIT_AGENT  = "pentest/exploitation"
AD_AGENT       = "pentest/active-directory"
# The post-foothold owner: local enumeration + privilege escalation, run FROM an
# existing session. The destination once any specialist lands a shell or creds.
POST_EXPLOIT_AGENT = "pentest/post-exploitation"
VALIDATE_AGENT = "pentest/validation"
REPORT_AGENT   = "pentest/report"

# Domain/Active-Directory attack vocabulary. A vuln/escalation lead whose
# technique or description reads like AD belongs to the AD specialist's kill chain
# (kerberoast → crack → PtH → DCSync), NOT generic RCE — even when the surface
# service tag is something generic. Detection complements _SERVICE_SPECIALISTS,
# which only catches AD via the SMB/LDAP/Kerberos service name.
_AD_LEAD_HINTS = (
    "kerberoast", "as-rep", "asrep", "asreproast", "dcsync", "dcsyc",
    "ntlm relay", "ntlm-relay", "ntlmrelay", "smb relay", "pass-the-hash",
    "pass the hash", "pass-the-ticket", "overpass", "silver ticket",
    "golden ticket", "bloodhound", "secretsdump", "ntds.dit", "ntds",
    "constrained delegation", "unconstrained delegation", "rbcd", "spn",
    "domain controller", "active directory", "machine account", "gpp",
    "group policy preferences", "adcs", "certipy", "esc1", "esc8",
    "shadow credentials", "zerologon", "petitpotam", "printerbug", "coerce",
    "ldap", "kerberos", "netntlm",
)


def is_ad_lead(technique: str = "", description: str = "", *extra: str) -> bool:
    """True when the supplied lead/surface text reads like an Active-Directory
    technique. Used to route domain leads to the AD specialist rather than RCE."""
    blob = " ".join(s for s in (technique, description, *extra) if s).lower()
    return any(h in blob for h in _AD_LEAD_HINTS)

# Service/product fingerprint → preferred-tool guidance. Matched (substring, any)
# against "<service> <fingerprint>". First match wins. Keeps the agent from
# hand-rolling a protocol a real client already speaks.
_TOOL_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("minio", "amazons3", "amazon s3", "s3-", " s3", "ceph", "object storage"),
     "This is S3-compatible object storage — enumerate and pull buckets with "
     "`awscli s3 --endpoint-url http://<host>:<port>` (anonymous, or with discovered "
     "access keys). Do NOT poke the S3 API with raw http_request: it requires SigV4 "
     "signing, so manual requests just return 400/403."),
    (("redis",),
     "Use the `redis_query` client (not raw sockets) — check for unauthenticated access, "
     "then INFO/CONFIG GET/KEYS."),
    (("mongo",),
     "Use `mongosh_query` — test for unauthenticated access and enumerate databases/collections."),
    (("mysql", "mariadb"),
     "Use a MySQL client / `impacket_mssql` analogue; test default and discovered creds, never brute first."),
    (("mssql", "ms-sql", "sql server"),
     "Use `impacket_mssql` for auth, queries, and (if sysadmin) xp_cmdshell."),
    (("ldap",),
     "Use `ldapsearch_query` — try an anonymous bind first and dump the naming context."),
    (("smb", "microsoft-ds", "netbios"),
     "Use `netexec smb` / `enum4linux_ng` / `smbclient` — try a null session and guest first, "
     "spray discovered creds, and only brute as a last resort."),
    (("snmp",),
     "Use `snmp_enum` — try community strings `public`/`private` before anything heavier."),
    (("ftp",),
     "Use the `ftp` client — try anonymous login first; list and pull readable files."),
]

# Service → domain specialist for the deep-enumeration slot. When a surface's
# service matches, the specialist's domain methodology runs instead of the
# generic enumerator; otherwise the driver falls back to ENUM_AGENT. The
# specialist must exist in the loaded agent set (else fallback).
_SERVICE_SPECIALISTS = {
    # web
    "http": "pentest/web", "https": "pentest/web", "http-alt": "pentest/web",
    "https-alt": "pentest/web", "http-proxy": "pentest/web", "www": "pentest/web",
    "ssl/http": "pentest/web",
    # active directory / windows
    "active-directory": "pentest/active-directory",   # consolidated DC surface
    "smb": "pentest/active-directory", "microsoft-ds": "pentest/active-directory",
    "netbios-ssn": "pentest/active-directory", "netbios": "pentest/active-directory",
    "ldap": "pentest/active-directory", "ldaps": "pentest/active-directory",
    "ldapssl": "pentest/active-directory", "kerberos": "pentest/active-directory",
    "kerberos-sec": "pentest/active-directory", "kpasswd": "pentest/active-directory",
    "globalcatldap": "pentest/active-directory",
    # databases
    "mysql": "pentest/database", "ms-sql-s": "pentest/database", "mssql": "pentest/database",
    "postgresql": "pentest/database", "postgres": "pentest/database",
    "mongodb": "pentest/database", "mongod": "pentest/database",
    "redis": "pentest/database", "oracle": "pentest/database",
    "elasticsearch": "pentest/database",
    # cloud
    "aws": "pentest/cloud", "gcp": "pentest/cloud",
    # other network services
    "ssh": "pentest/network", "ftp": "pentest/network", "ftps": "pentest/network",
    "smtp": "pentest/network", "snmp": "pentest/network", "telnet": "pentest/network",
    "rdp": "pentest/network", "ms-wbt-server": "pentest/network", "vnc": "pentest/network",
}


class EngagementDriver:
    def __init__(
        self,
        orchestrator,
        agents: dict,
        state,
        brief: EngagementBrief,
        *,
        max_turns: int = 25,
        confirm_exploitation: bool = True,
        max_cycles_per_surface: Optional[int] = 4,
        max_total_cycles: Optional[int] = 40,
        max_surfaces: Optional[int] = 50,
        emit_activity: Optional[Callable[[str], None]] = None,
        confirm_cb: Optional[Callable[[str, list], str]] = None,
        control: Optional[Callable[[], str]] = None,      # → "continue" | "stop" | "end"
        on_run_complete: Optional[Callable[[EngagementRun], None]] = None,
    ):
        self.orch   = orchestrator
        self.agents = agents
        self.state  = state
        self.brief  = brief

        self.max_turns               = max_turns
        self.confirm_exploitation    = confirm_exploitation
        self.max_cycles_per_surface  = max_cycles_per_surface
        self.max_total_cycles        = max_total_cycles
        self.max_surfaces            = max_surfaces

        self._emit_activity  = emit_activity
        self._confirm_cb     = confirm_cb
        self._control        = control
        self._on_run_complete = on_run_complete

        self.runs: list[EngagementRun] = []
        self.all_findings: list = []
        self.total_cycles = 0
        self._exploit_approved_all = False
        self._ended_early = False
        self._stopped = False
        self._capped = False
        self._surface_cap_announced = False
        self._surface_dry_cycles: dict = {}   # surface.id → consecutive no-verified-progress cycles
        # Optional concurrency gate (set by ParallelDriver) — caps simultaneous
        # leaf agent runs. None → serial, no gating.
        self._gate = None

    # ── public ────────────────────────────────────────────────────────────────

    def run(self) -> list[EngagementRun]:
        target = self.brief.primary_target or self.state.target

        if self.brief.exploitation_allowed:
            self._activity("Mode: full engagement — enumerate → plan → exploit → validate per surface.")
        else:
            self._activity(
                "Mode: assessment only — exploitation is NOT enabled, so planning and "
                "exploitation are skipped (enumeration + reporting only). Re-run including "
                "exploitation intent (e.g. 'exploit', 'full pentest') to act on findings."
            )

        # Phase 0 — staged initial enumeration. Rather than one agent trying to
        # "enumerate everything at once" (which front-loads deep probing of
        # services it hasn't even identified yet and burns the turn budget), the
        # picture is grown in two bounded passes, letting each inform the next:
        #   1) Discovery   — find open ports only.            → derive surfaces
        #   2) Service ID  — fingerprint those ports.          → enrich surfaces
        # The per-surface loop below then does the deep dive, now correctly
        # prioritized because services are known before any surface is chosen.
        # Skipped on resume, when surfaces already exist in carried-over state.
        if not self.state.surfaces:
            self._banner(f"Discovery — port sweep of {target}")
            self._run_agent(ENUM_AGENT, target, self._discovery_objective(target),
                            max_turns=self._stage_turns(8))
            self.state.derive_surfaces_from_recon(origin="initial")

            self._banner("Service identification — fingerprinting discovered ports")
            self._run_agent(ENUM_AGENT, target, self._service_id_objective(target),
                            max_turns=self._stage_turns(12))
            # Re-derive: the -sV/-sC pass may have surfaced ports the bare sweep missed.
            self.state.derive_surfaces_from_recon(origin="initial")

            if not self.state.surfaces:
                self.state.add_surface(target, origin="initial")

        # Main surface loop — depth-first per surface until exhausted/capped.
        # Extracted so ParallelDriver can override it with a breadth-first fan-out
        # without re-implementing the surrounding enumeration/flush/report stages.
        self._surface_loop(target)

        # Fold in any still-running background jobs (e.g. hashcat) so their
        # results — cracked credentials, late scan output — are in state before
        # the report is written.
        flush = getattr(self.orch, "flush_jobs", None)
        if callable(flush):
            try:
                flush()
            except Exception:
                pass

        # Reporting — the write-up runs however the engagement ended (paused,
        # ended early, capped, or complete), so the report is always synthesized
        # rather than falling back to raw run data. The only thing that can stop
        # it is a dead LLM (account/auth limit), which raises out before this line
        # and is handled (with a Limitations note) by the caller.
        if self.all_findings:
            self._banner("Reporting — synthesizing the engagement")
            self._run_agent(REPORT_AGENT, target, None)

        return self.runs

    @property
    def termination_reason(self) -> str:
        """Why the engagement stopped — drives the report's Limitations section.
        (account_limit / auth_failed are determined by the caller from the raised
        error; everything else is known here.)"""
        if self._ended_early:
            return "ended_early"
        if self._stopped:
            return "paused"
        if self._capped:
            return "cycle_cap"
        return "completed"

    @property
    def ended_early(self) -> bool:
        return self._ended_early

    @property
    def stopped(self) -> bool:
        return self._stopped

    # ── surface loop ────────────────────────────────────────────────────────────

    def _surface_loop(self, target: str) -> None:
        """Serial, depth-first: pick the highest-value open surface, cycle it,
        repeat until exhausted or a backstop trips. ParallelDriver overrides this
        to work several independent surfaces at once."""
        while True:
            # Objective achieved (root/RCE/flag) — stop opening new work.
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
            surface = self._select_surface()
            if surface is None:
                self._activity("✓ All surfaces exhausted.")
                break
            self._cycle_surface(surface, target)

    # ── one surface cycle ───────────────────────────────────────────────────────

    def _cycle_surface(self, surface: Surface, target: str) -> None:
        surface.status = "active"
        cycle_n = surface.cycles + 1
        sig_before = self.state.intel_signature(self.all_findings)
        findings_before = len(self.all_findings)
        progress_before = self._progress_count()

        # 1) Deep enumeration of this surface — domain specialist if the service
        #    matches one, else the generic enumerator.
        enum_agent = self._enum_agent_for(surface)
        spec = "" if enum_agent == ENUM_AGENT else f"  [{enum_agent.split('/')[-1]}]"
        self._banner(f"Enumeration — {surface.label}  (cycle {cycle_n}){spec}")
        self._run_agent(enum_agent, surface.host, self._enum_objective(surface, target))

        if self._check_control() != "continue":
            surface.cycles += 1
            return

        # 2) Plan → 3) Exploit → 4) Validate. These only run when exploitation is
        # enabled — planning exists to feed exploitation, so producing a plan with
        # no phase to execute it would just strand the work. With exploitation off
        # this is an assessment-only run: enumerate each surface and report.
        if self.brief.exploitation_allowed:
            if PLAN_AGENT in self.agents and self._check_control() == "continue":
                self._banner(f"Planning — {surface.label}")
                self._run_agent(PLAN_AGENT, surface.host, self._plan_objective(surface))

            if self._check_control() == "continue" and self._approve_exploitation(surface):
                self._run_exploit(surface)

        # Close the cycle: re-derive surfaces, then test for new intel.
        surface.cycles += 1
        self.total_cycles += 1
        if not (self.max_surfaces and len(self.state.surfaces) >= self.max_surfaces):
            self.state.derive_surfaces_from_recon(origin="lateral")
        elif not self._surface_cap_announced:
            self._surface_cap_announced = True
            self._activity(
                f"⚠ Surface cap reached ({self.max_surfaces}) — no longer registering "
                "newly discovered surfaces. Raise max_surfaces if the engagement is still productive."
            )
        sig_after = self.state.intel_signature(self.all_findings)

        # Hard rail first: the per-surface cycle cap always stops, no matter who's
        # judging — so an LLM that wants "one more pass" can't run forever.
        if self.max_cycles_per_surface and surface.cycles >= self.max_cycles_per_surface:
            surface.status = "exhausted"
            self._activity(
                f"⚠ {surface.label} hit cycle cap ({self.max_cycles_per_surface}) — "
                "moving on. Raise max_cycles_per_surface to go deeper."
            )
            return

        # Dry-cycle guard: count consecutive cycles that produced NO new *verified*
        # finding. After the cap, stop re-opening this surface regardless of what the
        # LLM judge wants — this kills the "grind a dead surface for hours" loop the
        # intel-signature heuristic misses (minor unverified intel keeps flipping it).
        from core.config import get as _get
        progress_after = self._progress_count()
        dry_cap = _get("max_dry_cycles_per_surface", 2)
        if progress_after > progress_before:
            self._surface_dry_cycles[surface.id] = 0
        else:
            self._surface_dry_cycles[surface.id] = self._surface_dry_cycles.get(surface.id, 0) + 1
            if dry_cap and self._surface_dry_cycles[surface.id] >= dry_cap:
                surface.status = "exhausted"
                self._activity(
                    f"⚠ {surface.label} — {self._surface_dry_cycles[surface.id]} cycle(s) with no new "
                    "verified finding; stopping further passes (a dead end, not new progress)."
                )
                return

        # Otherwise: is this surface worth another pass? The LLM decides, with the
        # signature/low-value heuristic as the fallback.
        new_titles = [f.title for f in self.all_findings[findings_before:]]
        heuristic_exhausted = (sig_after == sig_before) or self._low_value_exhausted(surface)
        if self._judge_exhaustion(surface, new_titles, heuristic_exhausted):
            surface.status = "exhausted"
        else:
            surface.status = "pending"
            self._activity(f"↻ {surface.label} — another pass.")

    def _run_exploit(self, surface: Surface) -> None:
        """The exploit (+ optional validation) phase for one surface — single
        exploitation agent working the vetted plan top-to-bottom. ParallelDriver
        overrides this to fan out bounded prove/refute workers across the plan's
        top hypotheses instead."""
        plan = self.state.get_plan_for(surface.id)
        exploit_agent = self._exploit_agent_for(surface)
        spec = "" if exploit_agent == EXPLOIT_AGENT else f"  [{exploit_agent.split('/')[-1]}]"
        self._banner(f"Exploitation — {surface.label}{spec}")
        self._run_agent(exploit_agent, surface.host,
                        self._exploit_objective(surface, plan))

        from core.config import get
        if (get("validation_enabled", False) and VALIDATE_AGENT in self.agents
                and self._check_control() == "continue"):
            self._banner(f"Validation — {surface.label}")
            self._run_agent(VALIDATE_AGENT, surface.host,
                            self._validate_objective(surface))

    def _progress_count(self) -> int:
        """A surface 'made progress' this cycle if this number went up: verified
        findings + recorded credentials + captured flags. Matches what the agent
        loop counts as banked progress — anything less is a dry, no-progress pass."""
        verified = sum(1 for f in self.all_findings if getattr(f, "verified", False))
        creds = len(getattr(self.state, "credentials", []) or [])
        flags = len(getattr(self.state, "flags", []) or [])
        return verified + creds + flags

    def _low_value_exhausted(self, surface: Surface) -> bool:
        """True if a low-priority service has yielded nothing worth returning for —
        only info/low findings attributable to it and no credentials/lead. Prevents
        burning repeat cycles on a credential-destination service like SSH."""
        from core.engagement_state import service_weight, _finding_on_surface, SEV_ORDER
        if service_weight(surface.service) >= 40:
            return False                       # not a low-value surface — leave it alone
        for f in self.all_findings:
            if _finding_on_surface(f, surface) and \
               SEV_ORDER.get(getattr(f, "severity", "info"), 0) >= SEV_ORDER["medium"]:
                return False                   # has a real lead — keep working it
        return True

    # ── agent invocation ────────────────────────────────────────────────────────

    def _enum_heuristic(self, surface: Surface) -> str:
        """Keyword fallback: pick the deep-enum agent for a surface by its service."""
        specialist = _SERVICE_SPECIALISTS.get((surface.service or "").lower())
        if specialist and specialist in self.agents:
            return specialist
        return ENUM_AGENT

    def _enum_agent_for(self, surface: Surface) -> str:
        """Pick the deep-enumeration agent for a surface. The LLM reasons over the
        service/fingerprint and the candidate specialists; the keyword map is the
        fallback."""
        fallback = self._enum_heuristic(surface)
        if not self._llm_routing():
            return fallback
        # Candidates: every distinct domain specialist that is loaded, plus the
        # generic enumerator. The LLM picks the best fit for this surface.
        cand_names = {ENUM_AGENT, fallback} | {
            v for v in _SERVICE_SPECIALISTS.values() if v in self.agents}
        candidates = [(n, getattr(self.agents[n], "description", "")) for n in cand_names if n in self.agents]
        return self._route("deep enumeration of this surface", surface,
                           self._findings_desc(surface), candidates, fallback)

    def _exploit_agent_for(self, surface: Surface) -> str:
        """Pick the exploitation agent. The generic exploitation agent owns
        code-exec → foothold; an AD/domain surface adds the AD specialist as a
        candidate (kerberoast/AS-REP/DCSync/relay/PtH are its kill chain). The LLM
        picks among the candidates; the heuristic (AD surface, else exploitation)
        is the floor."""
        spec = _SERVICE_SPECIALISTS.get((surface.service or "").lower()) if surface else None
        ad_surface = spec == AD_AGENT and AD_AGENT in self.agents
        fallback = AD_AGENT if ad_surface else EXPLOIT_AGENT
        if not self._llm_routing() or not ad_surface:
            return fallback
        cand_names = {EXPLOIT_AGENT, AD_AGENT}
        candidates = [(n, getattr(self.agents[n], "description", ""))
                      for n in cand_names if n in self.agents]
        return self._route("exploitation of this surface", surface,
                           self._findings_desc(None), candidates, fallback)

    # ── routing helpers ──────────────────────────────────────────────────────────

    def _llm_routing(self) -> bool:
        from core.config import get
        return bool(get("llm_routing", True))

    def _router_model(self) -> str:
        from core.config import get
        return get("router_model", None) or "claude-haiku-4-5-20251001"

    def _surface_desc(self, surface: Surface) -> str:
        bits = [surface.label, f"service={surface.service or 'unknown'}"]
        if surface.fingerprint:
            bits.append(f"fingerprint={surface.fingerprint}")
        if surface.notes:
            bits.append(f"notes={surface.notes}")
        return ", ".join(bits)

    def _findings_desc(self, surface: Optional[Surface]) -> str:
        """Finding titles+types — scoped to a surface for enum routing, or all of
        them for exploit routing (which is about code-exec primitives anywhere)."""
        from core.engagement_state import _finding_on_surface
        out = []
        for f in self.all_findings:
            if surface is not None and not _finding_on_surface(f, surface):
                continue
            out.append(f"- [{getattr(f, 'type', '?')}/{getattr(f, 'severity', '?')}] {f.title}")
        return "\n".join(out[:25])

    def _route(self, slot: str, surface: Surface, findings_desc: str,
               candidates: list, fallback: str) -> str:
        from core.agent_router import choose_agent
        llm = getattr(self.orch, "llm", None)
        if llm is None:
            return fallback
        name, reason, source = choose_agent(
            llm, self._router_model(), slot, self._surface_desc(surface),
            findings_desc, candidates, fallback)
        tag = "LLM" if source == "llm" else "fallback"
        short = slot.split()[0]
        self._activity(f"  [magenta]⇢ route[/magenta] {short} → [bold]{name}[/bold]  [dim]({tag}: {reason})[/dim]")
        return name if name in self.agents else fallback

    def _select_surface(self) -> Optional[Surface]:
        """Pick the next surface to work. The LLM chooses among the open surfaces
        (given the operator's service-tier priors + each surface's leads); the
        `surface_priority` weight table is the fallback."""
        eligible = self.state.eligible_surfaces(self.max_cycles_per_surface)
        if not eligible:
            return None
        heuristic = self.state.next_surface(self.max_cycles_per_surface,
                                            findings=self.all_findings)
        if len(eligible) == 1 or not self._llm_routing():
            return heuristic
        llm = getattr(self.orch, "llm", None)
        if llm is None:
            return heuristic
        from core.agent_router import choose_surface, SURFACE_GUIDANCE
        candidates = [(s.id, self._surface_lead_desc(s)) for s in eligible]
        sid, reason, source = choose_surface(
            llm, self._router_model(), candidates, SURFACE_GUIDANCE,
            heuristic.id if heuristic else eligible[0].id)
        chosen = next((s for s in eligible if s.id == sid), heuristic)
        tag = "LLM" if source == "llm" else "fallback"
        self._activity(f"  [magenta]⇢ next surface[/magenta] → [bold]{chosen.label}[/bold]  [dim]({tag}: {reason})[/dim]")
        return chosen

    def _surface_lead_desc(self, surface: Surface) -> str:
        """Surface one-liner for selection: what it is + any unexploited lead on it."""
        base = self._surface_desc(surface)
        leads = self._findings_desc(surface)
        return f"{base}\n    leads: {leads}" if leads else base

    def _judge_exhaustion(self, surface: Surface, new_titles: list, heuristic: bool) -> bool:
        """Decide whether a surface is exhausted. LLM call with the heuristic as
        fallback; emits the chosen verdict. The cycle cap (a hard rail) is applied
        by the caller before this is reached."""
        if not self._llm_routing():
            self._announce_exhaustion(surface, heuristic, "heuristic")
            return heuristic
        llm = getattr(self.orch, "llm", None)
        if llm is None:
            self._announce_exhaustion(surface, heuristic, "heuristic")
            return heuristic
        from core.agent_router import judge_continue
        summary = ("New findings this cycle: " + "; ".join(new_titles)) if new_titles \
            else "Nothing new this cycle."
        exhausted, reason, source = judge_continue(
            llm, self._router_model(), self._surface_lead_desc(surface), summary, heuristic)
        self._announce_exhaustion(surface, exhausted, "LLM" if source == "llm" else "heuristic", reason)
        return exhausted

    def _announce_exhaustion(self, surface: Surface, exhausted: bool, tag: str, reason: str = "") -> None:
        if exhausted:
            extra = f" [dim]({tag}: {reason})[/dim]" if reason else f" [dim]({tag})[/dim]"
            self._activity(f"✓ {surface.label} exhausted —{extra}")

    def _stage_turns(self, n: int) -> int:
        """A bounded turn budget for an early staged pass. Discovery/service-id
        stay short even when the per-agent default is high or unlimited (0);
        but a deliberately low max_turns config is still respected."""
        if self.max_turns <= 0:
            return n
        return min(n, self.max_turns)

    def _run_agent(self, name: str, target: str, objective: Optional[str],
                   max_turns: Optional[int] = None) -> Optional[EngagementRun]:
        agent_def = self.agents.get(name)
        if agent_def is None:
            self._activity(f"Agent {name!r} not available — skipping.")
            return None
        # In parallel mode the gate caps how many leaf agent loops run at once,
        # across BOTH fan-out layers. Acquired only around the (I/O-bound) run, and
        # never held across a nested fan-out, so it cannot deadlock. Serial → no gate.
        if self._gate is not None:
            with self._gate:
                eng_run = self.orch.run(
                    agent_def, target, objective,
                    max_turns=max_turns or self.max_turns, all_findings=self.all_findings,
                )
        else:
            eng_run = self.orch.run(
                agent_def, target, objective,
                max_turns=max_turns or self.max_turns, all_findings=self.all_findings,
            )
        self.runs.append(eng_run)
        self.all_findings.extend(eng_run.findings)
        self._absorb_followups()
        if self._on_run_complete:
            self._on_run_complete(eng_run)
        return eng_run

    def _absorb_followups(self) -> None:
        """Convert legacy queue_followup requests into surfaces so agents using
        the old mechanism still feed the loop."""
        if not self.state:
            return
        for fu in self.state.drain_followup_queue():
            host = fu.get("target", "")
            if host:
                self.state.add_surface(host=host, origin="lateral",
                                       notes=fu.get("context", "") or "")

    def _approve_exploitation(self, surface: Surface) -> bool:
        if not self.confirm_exploitation or self._exploit_approved_all:
            return True
        if self._confirm_cb is None:
            # Confirmation required but no way to ask — fail safe: do not exploit.
            self._activity("Exploitation requires approval but no prompt is available — skipping.")
            return False
        ans = self._confirm_cb(EXPLOIT_AGENT, self.all_findings)
        if ans == "a":
            self._exploit_approved_all = True
            return True
        return ans == "y"

    # ── objectives (carry the surface + plan focus into each agent) ─────────────

    def _discovery_objective(self, target: str) -> str:
        return (
            f"STAGE 1 of enumeration — DISCOVERY ONLY for {target}. Find what is reachable "
            "and nothing more. Start with a FAST port sweep for quick initial results: call "
            "`nmap_scan` with `fast=true` (top-1000 ports, no version/script detection — returns "
            "in seconds). Then, if warranted, widen by passing a larger `--top-ports N` (e.g. "
            "2000, 5000) or a capped range (e.g. `ports=\"1-45000\"`) rather than a full 1-65535 "
            "scan, which is slow and rarely worth it for an initial pass. Annotate each open port "
            "as a recon finding. "
            "Do NOT fingerprint services in depth, do NOT fuzz directories, do NOT probe "
            "applications, do NOT attempt any access yet — that is the next stage. Keep it to "
            "the port sweep so the picture can be built up deliberately. Finish as soon as the "
            "open ports are mapped."
        )

    def _service_id_objective(self, target: str) -> str:
        return (
            f"STAGE 2 of enumeration — SERVICE IDENTIFICATION for {target}. A staged port sweep "
            "has ALREADY run (a fast top-1000 TCP version scan, with a wider top-45000 TCP and a "
            "top-250 UDP sweep still finishing in the background — their results fold in "
            "automatically). The open ports are already in recon; do NOT kick off your own broad "
            "nmap sweeps to rediscover them. Work each known port in turn:\n"
            "  1. Identify exactly what it is — service, product, and version (a targeted `-sV -sC` "
            "on a SPECIFIC port that lacks a version, a banner grab, or nuclei tech-detection on web "
            "ports). For web, fingerprint the stack: server, framework/CMS, and any vhost/redirect.\n"
            "  2. **Call `record_service` for it** (host, port, service, app, version, tech) — this "
            "is what populates the live target tracker; do it as soon as you identify the service, "
            "for EVERY port, not just web.\n"
            "  3. **Run `searchsploit` on the product+version**, and annotate any public exploit/CVE "
            "match as an UNCONFIRMED finding — `annotate_finding` with `verified=false` and the "
            "CVE/EDB-ID in the evidence. A version match is plausible, not proven, so it stays "
            "verified=false until exploitation actually confirms it — but it MUST be recorded so the "
            "next phase has the lead.\n"
            "Do NOT deep-fuzz, brute-force, or exploit — just build an accurate, recorded service "
            "map. The deep dive into each service happens per-surface next, in priority order."
        )

    def _enum_objective(self, surface: Optional[Surface], target: str) -> str:
        if surface is None:
            return (
                f"Perform the initial broad enumeration of {target}. Map every reachable "
                "host, open port, and service, and annotate each as a recon finding. Work "
                "like a tester: when you find anonymous or default access, extend into that "
                "service immediately and enumerate it deeply rather than moving on. You may "
                "run lightweight verification probes (a quick default-cred check, anonymous "
                "logon, an IDOR or reflected-XSS proof) ONLY to confirm a service's state — "
                "do not exploit further here."
            )
        note = f" Operator note: {surface.notes}." if surface.notes else ""
        hint = self._tool_hint_for(surface)
        hint_line = f" {hint}" if hint else ""
        return (
            f"Deep-enumerate this specific surface: {surface.label} "
            f"(host {surface.host}, service {surface.service or 'unknown'}"
            f"{', ' + surface.fingerprint if surface.fingerprint else ''}, "
            f"port {surface.port or 'n/a'}, surface_id {surface.id}).{note}{hint_line} "
            "Probe it thoroughly and pull everything the service exposes. If anonymous or "
            "default access works, extend into it fully. Call register_surface for any new "
            "host, service, or deeper access you uncover so it gets its own cycle. Verify, "
            "do not exploit — that is the next phase."
        )

    # Service / product fingerprint → the right specialist tool to reach for,
    # so the agent stops hand-rolling a protocol that a real client handles
    # (e.g. poking the S3 API with raw HTTP, which can't do SigV4 signing).
    def _tool_hint_for(self, surface: Surface) -> str:
        fp = f"{surface.service} {surface.fingerprint}".lower()
        for needles, hint in _TOOL_HINTS:
            if any(n in fp for n in needles):
                return hint
        return ""

    def _plan_objective(self, surface: Surface) -> str:
        return (
            f"Produce the test plan for surface_id {surface.id} — {surface.label}. "
            "Reason over exactly what enumeration found for this surface and record an "
            f"ordered, specific plan with record_plan using surface_id={surface.id}. "
            "Order items by likelihood and impact."
        )

    def _exploit_objective(self, surface: Surface, plan) -> str:
        hint = self._tool_hint_for(surface)
        hint_line = f"\n\nTool note: {hint}" if hint else ""
        head = (
            f"Exploit surface {surface.label} (host {surface.host}). 'Exploit' means anything "
            "that lets a tester do something they should not be able to — misconfigurations, "
            "default/reused credentials, anonymous access, IDOR, auth bypass, SSRF, privilege "
            "escalation — not only published CVEs. Demonstrate real impact and annotate "
            "confirmed findings with verified=true and concrete evidence. Call register_surface "
            "for any new access, host, or service you reach."
            "\n\nWork techniques in tiers — exhaust the cheap, high-probability ones before the "
            "noisy, low-probability ones: (1) anonymous / unauthenticated access and "
            "information disclosure; (2) default and already-discovered/reused credentials; "
            "(3) known CVEs and misconfigurations (IDOR, auth bypass, SSRF, injection); "
            "(4) password brute-forcing / spraying — LAST RESORT only, once the above are "
            "genuinely exhausted. Do not open with hydra/brute-force."
            f"{hint_line}"
        )
        if plan and plan.items:
            lines = [head, "", "Work from this vetted plan:"]
            for i, item in enumerate(plan.items, 1):
                lines.append(f"  {i}. [{item.technique or 'test'}] {item.action}")
                if item.rationale:
                    lines.append(f"     ↳ {item.rationale}")
            return "\n".join(lines)
        return head + " No formal plan was produced — use the enumeration findings for this surface to drive exploitation."

    def _validate_objective(self, surface: Surface) -> str:
        return (
            f"Validate every finding associated with {surface.label} (host {surface.host}). "
            "Independently reproduce each claimed exploit with your own tooling in this run. "
            "Mark anything you reproduce verified=true with evidence; mark anything you cannot "
            "reproduce verified=false and say what actually happened. Adjust over-claimed "
            "severities down. Register a new surface if reproduction reveals further access."
        )

    # ── control / budget / emit ─────────────────────────────────────────────────

    def _check_control(self) -> str:
        return self._control() if self._control else "continue"

    def _backstop_tripped(self) -> bool:
        if self.max_total_cycles and self.total_cycles >= self.max_total_cycles:
            self._activity(
                f"⚠ Backstop: hit max_total_cycles ({self.max_total_cycles}). Stopping the loop. "
                "Raise it in config if the engagement was still productive."
            )
            return True
        return False

    def _banner(self, text: str) -> None:
        self._activity(f"── {text} ──", banner=True)

    def _activity(self, text: str, banner: bool = False) -> None:
        if self._emit_activity:
            self._emit_activity(text)
