from __future__ import annotations
import re
from typing import Optional

# Matches IPs, domains, and URLs (strips trailing slash)
_TARGET_RE = re.compile(
    r"https?://[^\s]+"                          # full URL
    r"|(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?"       # bare IP (with optional CIDR)
    r"|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/\S*)?",  # domain
    re.IGNORECASE,
)

_AGENT_RE = re.compile(
    r"(?<!\w)"
    r"(pentest/(?:enumeration|web|network|database|active-directory|cloud|exploitation|report)"
    r"|re/(?:static|dynamic|malware)"
    r"|code/(?:sast|secrets|dependencies|report))"
    r"(?!\w)",
    re.IGNORECASE,
)

# \w* suffixes so "assessment", "vulnerabilities", "exploitation", "hacking"
# all match — a bare \b after the stem would reject them.
_ASSESSMENT_KW = re.compile(
    r"\b(assess\w*|test|scan|audit|pentest|recon|exploit\w*|run|check|web|api|application|vulnerabilit\w*|hack\w*)\b",
    re.IGNORECASE,
)

# Explicit exploitation language — gates whether the exploitation phase is
# allowed in the pipeline. Recon-only verbs must NOT match.
_EXPLOIT_KW = re.compile(
    r"\b(exploit\w*|full\s+pentest|pop(?:ping)?\s+(?:a\s+)?shells?"
    r"|get\s+(?:a\s+)?shell|demonstrate\s+impact|hack\w*)\b",
    re.IGNORECASE,
)

_LIST_RE = re.compile(
    r"\b(list|show|history|view)\b.*\b(runs?|scans?|history|engagements?|assessments?)\b"
    r"|\bhistory\b|\blist-?runs?\b|^\s*(runs?|assessments?)\s*$",
    re.IGNORECASE,
)

_LIST_AGENTS_RE = re.compile(
    r"\b(list|show)\b.*\bagents?\b|\bagents?\b$",
    re.IGNORECASE,
)

_LIST_MODELS_RE = re.compile(
    r"\b(list|show)\b.*\bmodels?\b|\bmodels?\b$",
    re.IGNORECASE,
)

_REPORT_RE = re.compile(
    r"(?:generate|create|make|get)?\s*report\s+(?:for\s+)?([a-f0-9]{6,12})",
    re.IGNORECASE,
)


def parse_intent(text: str) -> Optional[dict]:
    """
    Parse natural language input into an action dict.
    Returns None if the intent cannot be determined.

    Recognized actions:
      {"action": "quit"}
      {"action": "help"}
      {"action": "list_runs"}
      {"action": "list_agents"}
      {"action": "list_models"}
      {"action": "report",   "run_id": str}
      {"action": "pipeline", "target": str, "entry": str, "objective": str|None,
       "allowed_phases": list[str]}
      {"action": "run",      "agent": str, "target": str, "objective": str|None}

    The exploitation phase is included in allowed_phases only when the text
    contains explicit exploitation language — recon verbs never enable it.
    """
    stripped = text.strip()
    lower = stripped.lower()

    # ── Quit ──────────────────────────────────────────────────────────────────
    if lower in ("quit", "exit", "q", ":q"):
        return {"action": "quit"}

    # ── Help ──────────────────────────────────────────────────────────────────
    if lower in ("help", "?", "h"):
        return {"action": "help"}

    # ── List runs ─────────────────────────────────────────────────────────────
    if _LIST_RE.search(lower):
        return {"action": "list_runs"}

    # ── List agents ───────────────────────────────────────────────────────────
    if _LIST_AGENTS_RE.search(lower):
        return {"action": "list_agents"}

    # ── List models ───────────────────────────────────────────────────────────
    if _LIST_MODELS_RE.search(lower):
        return {"action": "list_models"}

    # ── Report ────────────────────────────────────────────────────────────────
    m = _REPORT_RE.search(lower)
    if m:
        return {"action": "report", "run_id": m.group(1)}

    # ── Find target ───────────────────────────────────────────────────────────
    target_m = _TARGET_RE.search(stripped)
    if not target_m:
        return None

    target = target_m.group(0).rstrip("/")

    # ── Specific agent named ──────────────────────────────────────────────────
    agent_m = _AGENT_RE.search(lower)
    if agent_m:
        return {
            "action":    "run",
            "agent":     agent_m.group(1).lower(),
            "target":    target,
            "objective": stripped,
        }

    # ── Pipeline (any assessment keyword present) ─────────────────────────────
    if _ASSESSMENT_KW.search(lower):
        allowed = ["discovery", "assessment", "reporting"]
        if _EXPLOIT_KW.search(lower):
            allowed.append("exploitation")
        return {
            "action":         "pipeline",
            "target":         target,
            "entry":          "pentest/enumeration",
            "objective":      stripped,
            "allowed_phases": allowed,
        }

    return None
