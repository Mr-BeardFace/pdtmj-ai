# shell_exec is a meta-tool handled directly by the orchestrator (drives a caught
# reverse-shell session held by the ShellManager).

TOOL_DEFINITION = {
    "name": "shell_exec",
    "description": (
        "Run a command in a caught reverse-shell session and get back clean, framed output "
        "(the manager marks command boundaries for you). Use the session id from list_shells or "
        "from the connect notice. Keep commands non-interactive (no vi/top/su prompts — they hang "
        "the session); for those, run the non-interactive equivalent. Prefer stabilising to "
        "ssh_exec/netexec when you can rather than living in a raw shell."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "session_id": {"type": "string", "description": "Session id of the caught shell."},
            "command": {"type": "string", "description": "Command to run (non-interactive)."},
            "timeout": {"type": "integer", "description": "Seconds to wait for output (default 15)."},
        },
        "required": ["session_id", "command"],
    },
}
