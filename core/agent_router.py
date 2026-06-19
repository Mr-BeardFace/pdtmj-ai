"""LLM-driven engine decisions.

Three methodology judgment calls are made by a fast model rather than fixed
Python heuristics (keyword maps and weight tables):

  - which specialist agent handles a slot   (choose_agent)
  - which attack surface to work next       (choose_surface)
  - whether a surface is exhausted          (judge_continue)

A deterministic fallback is ALWAYS supplied:
if the model is unavailable, errors, or returns something unusable, the
heuristic's answer is used. The LLM decides; the heuristic is the floor — never a
dead end. The model is also given the operator's hard-won priors as guidance, so
it reasons *on top of* experience rather than guessing blind.
"""
from __future__ import annotations

import json
import re

_MAX_TOKENS = 320

# The operator's experience, handed to the model as a prior for surface choice —
# not a hard rule. A concrete lead always overrides the service-tier ordering.
SURFACE_GUIDANCE = (
    "Rule of thumb: services that expose data or functionality WITHOUT credentials are the "
    "higher-yield first targets — web apps, object storage (S3/MinIO), databases, SMB/NFS shares, "
    "FTP, SNMP. Credential-gated services (SSH, RDP, Telnet, WinRM) are usually the DESTINATION "
    "after you have credentials, not the way in — deprioritize them until you have something to "
    "try. A Domain Controller / Active Directory surface is the PRIMARY target on a Windows domain "
    "— it outranks the web ports on that same host (AD enumeration, AS-REP/Kerberoast, and LDAP are "
    "the way in), so pick it early rather than grinding the host's IIS first. "
    "But this is only a prior: a concrete lead wins. A surface with an exposed admin panel, "
    "anonymous access, a known-vulnerable version, or a credential to spray outranks a generic "
    "higher-tier service. Pick the surface most likely to yield the next step."
)


def _ask_json(llm, model: str, system: str, user: str) -> dict | None:
    """Single fast model call returning a parsed JSON object, or None on any failure."""
    try:
        resp = llm.run(model=model, system=system,
                       messages=[{"role": "user", "content": user}],
                       tools=[], max_tokens=_MAX_TOKENS)
        text = "".join(getattr(b, "text", "") for b in resp.content
                       if getattr(b, "type", "") == "text").strip()
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        return json.loads(text)
    except Exception:
        return None


# ── which specialist agent ──────────────────────────────────────────────────────

_AGENT_SYSTEM = (
    "You are the routing component of a penetration-testing engine. Choose the single best-fit "
    "specialist agent from the candidates for the named slot — reason about the service, its "
    "fingerprint, and the findings, the way a lead tester hands work to a specialist. "
    'Output ONLY JSON: {"agent": "<exact candidate name>", "reason": "<one short sentence>"}.'
)


def choose_agent(llm, model: str, slot: str, surface_desc: str,
                 findings_desc: str, candidates: list[tuple[str, str]],
                 fallback: str) -> tuple[str, str, str]:
    """Return (agent_name, reason, source). source is "llm" or "fallback"."""
    names = [c[0] for c in candidates]
    if len(names) <= 1:
        return (fallback, "only one candidate", "fallback")
    cand_block = "\n".join(f"- {n}: {d}" for n, d in candidates)
    user = (f"Slot to fill: {slot}\n\nSurface:\n{surface_desc}\n\n"
            f"Findings so far on this surface:\n{findings_desc or '(none yet)'}\n\n"
            f"Candidate agents:\n{cand_block}\n\nWhich agent should handle this slot? JSON only.")
    data = _ask_json(llm, model, _AGENT_SYSTEM, user)
    if data:
        choice = (data.get("agent") or "").strip()
        if choice in names:
            return (choice, (data.get("reason") or "").strip(), "llm")
    return (fallback, "router unavailable — heuristic fallback", "fallback")


# ── which surface to work next ──────────────────────────────────────────────────

_SURFACE_SYSTEM = (
    "You are the planning component of a penetration-testing engine. Pick which attack surface to "
    "work next from the candidates — the one most likely to advance the engagement toward impact. "
    "Use the guidance as a prior but let concrete leads override it. "
    'Output ONLY JSON: {"surface_id": "<exact candidate id>", "reason": "<one short sentence>"}.'
)


def choose_surface(llm, model: str, candidates: list[tuple[str, str]],
                   guidance: str, fallback_id: str) -> tuple[str, str, str]:
    """candidates: list of (surface_id, description). Returns (surface_id, reason, source)."""
    ids = [c[0] for c in candidates]
    if len(ids) <= 1:
        return (fallback_id, "only one candidate", "fallback")
    cand_block = "\n".join(f"- id={i}: {d}" for i, d in candidates)
    user = (f"Guidance:\n{guidance}\n\nCandidate surfaces (still open):\n{cand_block}\n\n"
            "Which surface should be worked next? JSON only.")
    data = _ask_json(llm, model, _SURFACE_SYSTEM, user)
    if data:
        choice = str(data.get("surface_id") or "").strip()
        if choice in ids:
            return (choice, (data.get("reason") or "").strip(), "llm")
    return (fallback_id, "router unavailable — heuristic fallback", "fallback")


# ── is this surface exhausted? ──────────────────────────────────────────────────

_EXHAUST_SYSTEM = (
    "You are the methodology supervisor for a penetration-testing engine. A surface just finished a "
    "full enumerate/exploit cycle. Decide whether it is worth another pass or is exhausted. Keep "
    "working it ONLY if there is a concrete un-followed lead or a plausible next step; if the last "
    "cycle produced nothing new and no open thread remains, it is exhausted — don't grind. "
    'Output ONLY JSON: {"exhausted": true|false, "reason": "<one short sentence>"}.'
)


def judge_continue(llm, model: str, surface_desc: str, cycle_summary: str,
                   fallback_exhausted: bool) -> tuple[bool, str, str]:
    """Return (exhausted, reason, source). source is "llm" or "fallback"."""
    user = (f"Surface:\n{surface_desc}\n\nWhat the last cycle produced:\n{cycle_summary}\n\n"
            "Is this surface exhausted, or worth another pass? JSON only.")
    data = _ask_json(llm, model, _EXHAUST_SYSTEM, user)
    if data and isinstance(data.get("exhausted"), bool):
        return (data["exhausted"], (data.get("reason") or "").strip(), "llm")
    return (fallback_exhausted, "supervisor unavailable — heuristic fallback", "fallback")
