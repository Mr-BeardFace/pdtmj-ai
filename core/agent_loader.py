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
