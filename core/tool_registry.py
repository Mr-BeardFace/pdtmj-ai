from typing import Dict, Callable, Any, List


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
        return [self._tools[name] for name in scope if name in self._tools]

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())
