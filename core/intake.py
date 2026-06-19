"""Free-form engagement intake.

Turns whatever the operator typed — a terse command or a paragraph of background —
into a structured `EngagementBrief` the driver can act on. Hybrid by design:

  - `brief_from_intent` converts the regex fast-path result (ui.intent) with no
    LLM call, for obvious commands like "run pentest/web on X".
  - `classify_brief` sends free-form text to Haiku and extracts targets, scope
    exclusions, credentials, tech context, and focus areas.

The driver/UI tries the fast path first and falls back to `classify_brief`.
"""
from __future__ import annotations

import json
import re

import anthropic

from core.llm_client import _resolve_anthropic_key
from core.models import EngagementBrief

_INTAKE_MODEL = "claude-haiku-4-5-20251001"

_SYSTEM = """You are the intake classifier for a penetration testing platform. The operator
describes an engagement in free-form text — possibly terse, possibly a paragraph with
background, credentials, scope notes, and priorities. Extract everything useful into one JSON object:

- "category": "pentest" | "re" | "code"
- "entry": starting agent. pentest → "pentest/enumeration" (default); re → "re/static"; code → "code/sast".
- "targets": in-scope targets (IPs, domains, URLs, CIDRs, file paths). []
- "out_of_scope": anything the operator says is explicitly off-limits. []
- "objective": one or two clean sentences of intent. Use only what was stated.
- "focus_areas": specific things to prioritize (an endpoint, a parameter, a vuln class). []
- "tech_context": free-text background worth giving every agent (stack, infra, prior knowledge,
  constraints, anything that informs testing). "" if none.
- "credentials": any creds the operator supplied, as objects {"username","secret","service"}.
  service may be "" if unspecified. []
- "allowed_phases": always include "discovery", "assessment", "reporting". Add "exploitation"
  ONLY if the operator asks to exploit, demonstrate impact, pop shells, or run a full pentest.
  Do NOT infer exploitation from recon words ("enumerate", "scan", "map", "check").
- "rationale": one sentence on the classification.

Output only the JSON object. No markdown, no commentary.

Example input:
"full pentest of https://shop.acme.com — it's a Rails app behind Cloudflare. creds: shopper/Spring2024! (web).
they care most about the /api/v2 order endpoints. don't touch billing.acme.com (third party)."
Example output:
{"category":"pentest","entry":"pentest/enumeration","targets":["https://shop.acme.com"],
"out_of_scope":["billing.acme.com"],"objective":"Full penetration test of shop.acme.com including exploitation.",
"focus_areas":["/api/v2 order endpoints"],"tech_context":"Rails app behind Cloudflare.",
"credentials":[{"username":"shopper","secret":"Spring2024!","service":"web"}],
"allowed_phases":["discovery","assessment","exploitation","reporting"],
"rationale":"Full pentest with explicit exploitation requested."}
"""


def resolve_phases(phases) -> list[str]:
    """Normalise allowed_phases and apply the global exploitation toggle.

    discovery/assessment/reporting are always present. Exploitation is governed by
    the `exploitation_enabled` config (default on), so it does not depend on the
    operator using a specific keyword — toggle it with /exploit on|off.
    """
    from core.config import get
    out = [p for p in (phases or []) if p]
    for required in ("discovery", "assessment", "reporting"):
        if required not in out:
            out.append(required)
    if get("exploitation_enabled", True):
        if "exploitation" not in out:
            out.append("exploitation")
    else:
        out = [p for p in out if p != "exploitation"]
    return out


def brief_from_intent(intent: dict, text: str) -> EngagementBrief:
    """Build a brief from a regex-parsed intent dict (no LLM call)."""
    target = intent.get("target", "")
    return EngagementBrief(
        targets=[target] if target else [],
        objective=intent.get("objective", text),
        allowed_phases=resolve_phases(intent.get("allowed_phases")),
        entry=intent.get("entry", "pentest/enumeration"),
        category="pentest",
    )


def classify_brief(text: str) -> EngagementBrief:
    """Parse free-form engagement text into an EngagementBrief using Haiku."""
    client = anthropic.Anthropic(api_key=_resolve_anthropic_key())
    response = client.messages.create(
        model=_INTAKE_MODEL,
        max_tokens=800,
        system=_SYSTEM,
        messages=[{"role": "user", "content": text}],
    )
    raw = response.content[0].text.strip() if response.content else "{}"
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return EngagementBrief(objective=text, rationale="Intake parse failed.")

    return EngagementBrief(
        targets=data.get("targets", []) or [],
        out_of_scope=data.get("out_of_scope", []) or [],
        objective=data.get("objective", "") or text,
        focus_areas=data.get("focus_areas", []) or [],
        tech_context=data.get("tech_context", "") or "",
        credentials=data.get("credentials", []) or [],
        allowed_phases=resolve_phases(data.get("allowed_phases")),
        category=data.get("category", "pentest"),
        entry=data.get("entry", "pentest/enumeration"),
        rationale=data.get("rationale", ""),
    )
