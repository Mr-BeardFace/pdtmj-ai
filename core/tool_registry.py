from typing import Dict, Callable, Any, List


# Named scope groups. An agent scope entry of "@<group>" expands to this tool
# list, so a common toolset (e.g. the exploit/foothold kit shared by the domain
# specialists) is declared once here instead of copied across agent frontmatter.
_SCOPE_GROUPS: Dict[str, List[str]] = {
    # Turning a vuln into a shell and looting from it: OOB/raw channels,
    # connect-in (ssh / winrm), custom payloads, and offline cracking. Pairs with
    # the `includes: [foothold]` methodology block. Only registered tools.
    "foothold": [
        "oob_listener", "web_exec", "nc", "telnet", "ssh_keygen", "ssh_exec",
        "netexec", "port_forward", "run_script", "local_exec",
        "hashcat_crack", "john", "hash_extract",
        "ysoserial", "searchsploit",
    ],
}


def expand_scope(scope: List[str]) -> List[str]:
    """Resolve "@group" tokens in a scope list to their tool names, de-duped and
    order-preserving. Non-group entries pass through unchanged."""
    out: List[str] = []
    seen: set = set()
    for entry in scope or []:
        names = _SCOPE_GROUPS.get(entry[1:], []) if isinstance(entry, str) and entry.startswith("@") else [entry]
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
    return out


class Tool:
    def __init__(self, name: str, description: str, input_schema: dict, func: Callable):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.func = func

    def to_api_format(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def execute(self, **kwargs) -> Any:
        return self.func(**kwargs)


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"Tool not registered: {name}")
        return self._tools[name]

    def get_by_scope(self, scope: List[str]) -> List[Tool]:
        # "*" in scope → every registered tool (an agent that may need anything).
        if scope and "*" in scope:
            return list(self._tools.values())
        return [self._tools[name] for name in expand_scope(scope) if name in self._tools]

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())
