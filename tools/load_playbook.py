"""load_playbook — retrieve domain methodology on demand.

The retrieval counterpart to a domain specialist agent: instead of the driver
routing a surface to a separate `active-directory`/`web`/… agent, the generalist
recognizes the domain from what it has enumerated and pulls the matching playbook
into its own context. Same methodology, no routing, no handoff.

Returned whole (this is an intercepted meta-tool, so it bypasses the result-offload
that would otherwise push a long field to an artifact) — the point is for the
methodology to sit in the agent's context, not behind a read_artifact call.
"""
import re
from core.paths import PLAYBOOKS_DIR


def _available() -> list[str]:
    if not PLAYBOOKS_DIR.exists():
        return []
    return sorted(p.stem for p in PLAYBOOKS_DIR.glob("*.md"))


def _strip_frontmatter(text: str) -> str:
    return re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.DOTALL).strip()


def load_playbook(names) -> dict:
    """Load one or more playbooks by name. `names` may be a list or a single string."""
    if isinstance(names, str):
        names = [n.strip() for n in names.replace(",", " ").split() if n.strip()]
    names = [str(n).strip().lower() for n in (names or []) if str(n).strip()]
    if not names:
        return {"error": "No playbook name given.", "available": _available()}

    base = PLAYBOOKS_DIR.resolve()
    blocks: list[str] = []
    loaded:  list[str] = []
    missing: list[str] = []
    for n in names:
        path = (PLAYBOOKS_DIR / f"{n}.md").resolve()
        # Path guard — never escape the playbooks directory.
        if not str(path).startswith(str(base)) or not path.exists():
            missing.append(n)
            continue
        blocks.append(_strip_frontmatter(path.read_text(encoding="utf-8")))
        loaded.append(n)

    result: dict = {"loaded": loaded}
    if blocks:
        result["playbooks"] = "\n\n---\n\n".join(blocks)
    if missing:
        result["not_found"] = missing
        result["available"] = _available()
    if not blocks:
        result["error"] = (f"No playbook matched {names}. "
                           f"Available: {', '.join(_available()) or '(none)'}")
    return result


TOOL_DEFINITION = {
    "name": "load_playbook",
    "description": (
        "Pull domain-specific methodology into your context on demand. When you've "
        "enumerated a target and recognize a domain — a Windows DC (SMB/LDAP/Kerberos/"
        "WinRM), a web app, a database service — call this with the matching playbook "
        "name(s) to get the attack methodology for it, instead of improvising. You can "
        "load several at once (e.g. a DC that also serves web). Returns the playbook "
        "text directly in the result."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "names": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Playbook name(s) to load, e.g. ['active-directory', 'web'].",
            },
        },
        "required": ["names"],
    },
}
