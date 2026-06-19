# start_listener is a meta-tool handled directly by the orchestrator (it owns the
# engagement-scoped ShellManager). Starts a reverse-shell listener and returns
# ready payloads for the agent to trigger via its RCE primitive.

TOOL_DEFINITION = {
    "name": "start_listener",
    "description": (
        "Start a reverse-shell listener on the attacker host and return ready-to-fire payload "
        "one-liners (bash, python, nc, PowerShell, etc.) wired to your IP and the chosen port. "
        "Trigger one of the payloads on the target through your command-execution primitive (web "
        "injection, an existing shell, etc.). When the target connects back, the session appears "
        "automatically and you drive it with shell_exec. Use this when you have command execution "
        "but no clean session and outbound connections are allowed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "description": "Port to listen on (must be reachable from the target). Default 4444."},
            "interface": {"type": "string", "description": "Local interface for the attacker IP (default tun0, falls back to eth0/primary)."},
        },
        "required": [],
    },
}
