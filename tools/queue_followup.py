TOOL_DEFINITION = {
    "name": "queue_followup",
    "description": (
        "Schedule follow-on work for the pipeline. Call this when you discover a new host, "
        "network segment, or attack surface that warrants further investigation by another agent. "
        "The orchestrator will add the requested agent+target to the pipeline queue. "
        "Use this to enable cyclical testing — e.g. discovering 10.10.10.50 via a compromised "
        "host should trigger queue_followup('pentest/enumeration', '10.10.10.50', context)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "agent_name": {
                "type": "string",
                "description": "Agent to run, e.g. 'pentest/enumeration', 'pentest/post-exploitation'",
            },
            "target": {
                "type": "string",
                "description": "Target for the follow-on agent (IP, hostname, URL, file path).",
            },
            "context": {
                "type": "string",
                "description": "Brief context explaining why this follow-up is needed and what was found.",
            },
        },
        "required": ["agent_name", "target"],
    },
}


def queue_followup(agent_name: str, target: str, context: str = "") -> dict:
    # Intercepted by the orchestrator before reaching here.
    # If called directly (e.g. in tests), return a stub response.
    return {
        "queued": True,
        "agent_name": agent_name,
        "target": target,
        "note": "Intercepted by orchestrator — not executed directly.",
    }
