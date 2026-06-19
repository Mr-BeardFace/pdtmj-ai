"""The strategist — board-level lead supervision, gated on material change.

The old `planning` agent produced a per-surface test plan: a local, one-surface
view. The frontier model needs a *board* view — given everything known and the
objective, what leads exist and which thread is hottest. That is what the
strategist provides.

Two tiers, by cost:

  * Deterministic ingest (`refresh`) runs after every step. It is free (pure data)
    and keeps the board current: new findings/creds/recon become leads via
    `core.ingest`. Its return — how many genuinely new leads landed — is the
    cheap "material change" signal.

  * The LLM consult (`replan`) is expensive, so it runs ONLY on material change
    (new leads, or the frontier advanced). It asks a fast model, given the board
    and objective, for leads the keyword ingest would miss — chained/inferred next
    steps ("you have an SMTP password; the SSH user `ben` reuses it") and a
    re-prioritisation hint. It is strictly additive and fully optional: no LLM, an
    error, or junk output simply leaves the deterministic board untouched.

This is the "consult the strategist only when something changed" cadence the
operator asked for — not every API call, not every turn.
"""
from __future__ import annotations

import json
import re
from typing import Optional

from core.ingest import ingest_all, infer_cost
from core.leads import Lead, LeadStore, Objective

_MAX_TOKENS = 600

_SYSTEM = (
    "You are the lead strategist for a penetration-testing engine. You see the whole board — "
    "the objective, the current kill-chain frontier, banked findings/credentials, and the leads "
    "already queued. Propose ONLY high-value NEXT-STEP leads the engine has not already queued: "
    "concrete, inferred or chained actions that move toward the objective (e.g. reuse a discovered "
    "password against another service, pivot a confirmed RCE into a stable session, chase a "
    "service running as root). Do NOT restate existing leads or generic enumeration. "
    "For each lead give a kill-chain reach (one of: service, vuln, exploited, foothold, user, "
    "privesc, root) — how far it gets IF it works — a prior 0..1, and the single concrete action.\n"
    'Output ONLY JSON: {"leads": [{"description": "...", "technique": "...", "target": "...", '
    '"reach_level": "...", "prior": 0.0}], "focus": "<one sentence on the hottest thread>"}.'
)

_VALID_REACH = {"service", "vuln", "exploited", "foothold", "user", "privesc", "root"}


class Strategist:
    """Keeps a `LeadStore` current and, on material change, consults a fast model
    for board-level leads. `llm`/`model` may be None — then only deterministic
    ingest runs."""

    def __init__(self, llm=None, model: Optional[str] = None, *,
                 on_event=None, enable_llm: bool = True):
        self._llm = llm
        self._model = model or "claude-haiku-4-5-20251001"
        self._on_event = on_event
        self._enable_llm = enable_llm
        self._last_sig: Optional[tuple] = None

    # ── public ────────────────────────────────────────────────────────────────

    def refresh(self, store: LeadStore, state, findings) -> int:
        """Deterministic, free: fold current evidence into the board. Returns the
        count of new leads (the material-change signal)."""
        return ingest_all(store, state, findings)

    def material_change(self, store: LeadStore, state, findings) -> bool:
        """Has the board moved since the last consult? True on first call, on a new
        lead count, or on a frontier advance."""
        sig = self._signature(store, state, findings)
        changed = sig != self._last_sig
        return changed

    def consider(self, store: LeadStore, state, objective: Objective, findings,
                 *, force: bool = False) -> bool:
        """Refresh the board, then — only if something materially changed — consult
        the model for additional leads. Returns True if the LLM was consulted."""
        self.refresh(store, state, findings)
        sig = self._signature(store, state, findings)
        if not force and sig == self._last_sig:
            return False
        consulted = False
        if self._enable_llm and self._llm is not None:
            try:
                added = self._replan(store, state, objective, findings)
                consulted = True
                if added:
                    self._emit("strategist", f"+{added} board lead(s)")
            except Exception:
                consulted = False
        # Recompute AFTER the consult so leads the strategist just added don't read
        # as a fresh "material change" on the next call (they were this change).
        self._last_sig = self._signature(store, state, findings)
        return consulted

    # ── internals ───────────────────────────────────────────────────────────────

    def _signature(self, store: LeadStore, state, findings) -> tuple:
        return (
            len(store.leads),
            store.current_frontier(),
            len(getattr(state, "credentials", []) or []),
            len(getattr(state, "flags", []) or []),
            sum(1 for f in (findings or []) if getattr(f, "verified", False)),
        )

    def _replan(self, store: LeadStore, state, objective: Objective, findings) -> int:
        board = self._board(store, state, objective, findings)
        resp = self._llm.run(model=self._model, system=_SYSTEM,
                             messages=[{"role": "user", "content": board}],
                             tools=[], max_tokens=_MAX_TOKENS)
        text = "".join(getattr(b, "text", "") for b in resp.content
                       if getattr(b, "type", "") == "text").strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        data = json.loads(text)
        added = 0
        for item in (data.get("leads") or [])[:10]:
            lead = self._lead_from(item)
            if lead is None:
                continue
            before = len(store.leads)
            store.add(lead)
            if len(store.leads) > before:
                added += 1
        return added

    def _lead_from(self, item: dict) -> Optional[Lead]:
        desc = (item.get("description") or "").strip()
        if not desc:
            return None
        reach = (item.get("reach_level") or "vuln").strip().lower()
        if reach not in _VALID_REACH:
            reach = "vuln"
        try:
            prior = float(item.get("prior", 0.5))
        except (TypeError, ValueError):
            prior = 0.5
        prior = max(0.05, min(0.95, prior))
        technique = (item.get("technique") or "").strip()
        return Lead(
            kind="escalation" if reach in ("root", "privesc") else "lead",
            description=desc,
            technique=technique,
            target=(item.get("target") or "").strip(),
            reach_level=reach,
            prior=prior,
            cost=infer_cost(desc, technique),
            created_by="strategist",
        )

    def _board(self, store: LeadStore, state, objective: Objective, findings) -> str:
        lines = [f"OBJECTIVE: {objective.description or 'compromise the target'}"]
        goals = ", ".join(f"{g.name}{'✓' if g.met else ''}" for g in objective.goals)
        lines.append(f"Goals: {goals}")
        lines.append(f"Current frontier: {store.frontier_name()}")
        lines.append("")
        creds = getattr(state, "credentials", []) or []
        if creds:
            lines.append("Credentials in hand:")
            for c in creds[:12]:
                lines.append(f"  - {c.cred_type} {c.username or '?'} "
                             f"(found@ {c.location or c.service or '?'})"
                             + ("  ✓verified" if c.verified else ""))
        flags = getattr(state, "flags", []) or []
        if flags:
            lines.append(f"Flags captured: {len(flags)}")
        verified = [f for f in (findings or []) if getattr(f, "verified", False)]
        if verified:
            lines.append("Verified findings:")
            for f in verified[:15]:
                lines.append(f"  - [{getattr(f, 'severity', '?')}] {f.title}")
        unworked = [l for l in store.ranked()[:12]]
        if unworked:
            lines.append("")
            lines.append("Leads already queued (do NOT restate these):")
            for l in unworked:
                lines.append(f"  - [{l.reach_level}] {l.description}")
        lines.append("")
        lines.append("What additional high-value next-step leads exist? JSON only.")
        return "\n".join(lines)

    def _emit(self, kind: str, payload) -> None:
        if self._on_event:
            try:
                self._on_event(kind, payload)
            except Exception:
                pass
