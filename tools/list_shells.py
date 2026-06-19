# list_shells is a meta-tool handled directly by the orchestrator.

TOOL_DEFINITION = {
    "name": "list_shells",
    "description": (
        "List caught reverse-shell sessions (id, source address, alive status). New sessions are "
        "also announced to you automatically when a target connects back, so you usually don't need "
        "to poll — use this to recover a session id or check whether a shell is still alive."
    ),
    "input_schema": {"type": "object", "properties": {}},
}
