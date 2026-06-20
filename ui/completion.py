"""Context-aware command completion.

Pure functions so the completion logic is testable without a Textual runtime.
The app feeds in the live candidate pools (agent names, model ids it has
learned from `/models list`) and these decide what to suggest for the current
input value.
"""
from __future__ import annotations

import re

from ui.commands import COMPLETIONS

_AGENT_SET_MODEL = "/agent set model"


def compute_candidates(value: str, agents: list[str], models: list[str],
                       assessments: list[str] | None = None) -> list[str]:
    """Return the full-line completion candidates for the current input.

    Candidates are whole command lines (prefix + token) so a suggestion can be
    accepted by replacing the input value wholesale.
    """
    low = value.lower()

    # /assessment load <id> — complete saved assessment ids
    if low.startswith("/assessment load"):
        return [f"/assessment load {a}" for a in (assessments or [])]

    # /agent set model <agent|global> <model-id>
    if low.startswith(_AGENT_SET_MODEL):
        rest     = value[len(_AGENT_SET_MODEL):]
        toks     = rest.split()
        trailing = rest.endswith(" ")
        # First argument: the agent name (or "global")
        if len(toks) == 0 or (len(toks) == 1 and not trailing):
            return [f"{_AGENT_SET_MODEL} {a}" for a in (["global"] + list(agents))]
        # Second argument: the model id — keep the chosen agent fixed
        first = toks[0]
        return [f"{_AGENT_SET_MODEL} {first} {m}" for m in models]

    if low.startswith("/models list"):
        return ["/models list anthropic", "/models list openrouter"]

    if low.startswith("/provider set"):
        return ["/provider set anthropic", "/provider set openrouter"]

    return list(COMPLETIONS)


def best_suggestion(value: str, candidates: list[str]) -> str | None:
    """First candidate that extends `value` (case-insensitive prefix match)."""
    if not value:
        return None
    low = value.lower()
    for cand in candidates:
        if cand.lower().startswith(low) and len(cand) > len(value):
            return cand
    return None


def suggest(value: str, agents: list[str], models: list[str],
            assessments: list[str] | None = None) -> str | None:
    return best_suggestion(value, compute_candidates(value, agents, models, assessments))


# ── parsing model ids out of `/models list` output ────────────────────────────

def _looks_like_model_id(tok: str) -> bool:
    # Model ids are lowercase: claude-sonnet-4-6, vendor/model-name:free
    if tok != tok.lower():
        return False
    if "/" in tok:
        return True
    return tok.startswith("claude-") or bool(re.search(r"-\d", tok))


def extract_model_ids(lines: list[str]) -> list[str]:
    """Pull model ids from the formatted output of `/models list`.

    Each result line is "  <id>   <display name> …"; the id is the first token.
    Header and footer lines are filtered by the lowercase/shape heuristic.
    """
    ids: list[str] = []
    for line in lines:
        toks = line.strip().split()
        if toks and _looks_like_model_id(toks[0]):
            ids.append(toks[0])
    return list(dict.fromkeys(ids))   # de-dup, preserve order
