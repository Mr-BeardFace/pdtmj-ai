import re
from pathlib import Path
from typing import Dict, Any, List

import yaml
from rich.console import Console

_console = Console()


class AgentDefinition:
    def __init__(self, name: str, description: str, scope: List[str],
                 model: str, system_prompt: str, metadata: Dict[str, Any]):
        self.name = name
        self.description = description
        self.scope = scope
        self.model = model        # frontmatter default — overrides applied by Orchestrator
        self.system_prompt = system_prompt
        self.metadata = metadata


def load_agent(agent_name: str, agents_dir: Path) -> AgentDefinition:
    """
    Load agent by name. Supports:
      - flat names:   "web-recon"    → agents/web-recon.md
      - subdirectory: "pentest/web"  → agents/pentest/web.md
    """
    agents_dir = agents_dir.resolve()
    agent_path = (agents_dir / f"{agent_name}.md").resolve()

    # Guard against path traversal (e.g. agent_name = "../../etc/passwd")
    if not str(agent_path).startswith(str(agents_dir)):
        raise FileNotFoundError(f"Agent path escapes agents directory: {agent_name!r}")

    if not agent_path.exists():
        raise FileNotFoundError(f"Agent not found: {agent_path}")

    content = agent_path.read_text(encoding="utf-8")

    match = re.match(r"^---\n(.*?)\n---\n(.*)$", content, re.DOTALL)
    if not match:
        raise ValueError(f"Agent file missing YAML frontmatter: {agent_path}")

    metadata = yaml.safe_load(match.group(1))
    system_prompt = match.group(2).strip()

    # Shared methodology partials. `includes: [foothold, ...]` pulls in
    # agents/_shared/<name>.md and appends it to this agent's prompt, so common
    # methodology lives in one place instead of being duplicated across agents.
    includes = metadata.get("includes") or []
    if includes:
        shared_dir = (agents_dir / "_shared").resolve()
        blocks: List[str] = []
        for inc in includes:
            inc_path = (shared_dir / f"{inc}.md").resolve()
            if not str(inc_path).startswith(str(shared_dir)):
                raise FileNotFoundError(f"Include escapes shared directory: {inc!r}")
            if not inc_path.exists():
                raise FileNotFoundError(f"Shared include not found: {inc_path}")
            blocks.append(inc_path.read_text(encoding="utf-8").strip())
        if blocks:
            system_prompt = system_prompt + "\n\n" + "\n\n".join(blocks)

    return AgentDefinition(
        name=metadata.get("name", agent_name),
        description=metadata.get("description", ""),
        scope=metadata.get("scope", []),
        model=metadata.get("model", "claude-sonnet-4-6"),
        system_prompt=system_prompt,
        metadata=metadata,
    )


def persona_agents(persona_name: str, agents_dir: Path,
                   all_agents: Dict[str, AgentDefinition]) -> Dict[str, AgentDefinition]:
    """Restrict the routable agent set to what the active persona declares.

    A persona's `persona.md` frontmatter may carry an `agents:` allowlist — the agent
    keys that persona dispatches to. When present, `all_agents` is filtered to it, so
    the driver's routing candidate pool (and thus `_*_agent_for` specialist routing)
    only sees those agents. This is how the CTF persona pins exploitation to the
    generalist spine: with the domain specialists absent from the pool, the service-
    specialist branch finds nothing loaded and deterministically falls back to the
    generic agent — no per-surface router call, no specialist fork.

    No allowlist (e.g. the full pentest persona) → unchanged. Agents marked
    `always_last` (the reporter) are always retained so a persona can't drop the
    deliverable."""
    if not persona_name:
        return all_agents
    persona_path = (agents_dir / persona_name / "persona.md").resolve()
    if (not str(persona_path).startswith(str(agents_dir.resolve()))
            or not persona_path.exists()):
        return all_agents
    try:
        m = re.match(r"^---\n(.*?)\n---\n", persona_path.read_text(encoding="utf-8"), re.DOTALL)
        meta = yaml.safe_load(m.group(1)) if m else {}
    except Exception:
        return all_agents
    allow = set(meta.get("agents") or [])
    if not allow:
        return all_agents
    # always_last safety net (keep the reporter) — but only within the persona's own
    # namespace, so a pentest persona doesn't drag in code/re reporters.
    namespaces = {k.split("/")[0] for k in allow}
    return {k: v for k, v in all_agents.items()
            if k in allow or ((v.metadata or {}).get("always_last")
                              and k.split("/")[0] in namespaces)}


def discover_agents(agents_dir: Path) -> Dict[str, AgentDefinition]:
    """
    Return all agents found under agents_dir (recursive).
    Keys are relative paths without .md extension, e.g. "pentest/web".
    base-instructions.md and persona.md are excluded.
    """
    agents: Dict[str, AgentDefinition] = {}
    for path in sorted(agents_dir.rglob("*.md")):
        if path.name in ("base-instructions.md", "persona.md"):
            continue
        # Shared partials (agents/_shared/…) are included into agents, not loaded
        # as standalone agents. Skip any path under a "_"-prefixed directory.
        if any(part.startswith("_") for part in path.relative_to(agents_dir).parts):
            continue
        rel = path.relative_to(agents_dir).with_suffix("")
        name_key = rel.as_posix()
        try:
            a = load_agent(name_key, agents_dir)
            agents[a.name] = a
        except Exception as exc:
            _console.print(f"[yellow]  ⚠ Skipping agent {name_key!r}: {exc}[/yellow]")
    return agents
