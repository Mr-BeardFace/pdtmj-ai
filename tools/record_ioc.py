# record_ioc is a meta-tool handled directly by the orchestrator.
# Schema only — the handler lives in core/orchestrator.py.

TOOL_DEFINITION = {
    "name": "record_ioc",
    "description": (
        "Record an Indicator of Compromise (IOC) observed during the engagement — "
        "an IP, domain, URL, file hash, C2 endpoint, email address, or other artifact "
        "that should be tracked for OPSEC/attribution/reporting purposes. "
        "Use this when you observe C2 infrastructure, attacker-controlled domains, "
        "malicious hashes, suspicious endpoints, or any indicator worth logging for "
        "post-engagement review."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "ioc_type": {
                "type": "string",
                "enum": ["ip", "domain", "hash", "url", "c2", "email", "other"],
                "description": "The type of indicator.",
            },
            "value": {
                "type": "string",
                "description": "The indicator value (IP address, domain name, SHA256 hash, URL, etc.).",
            },
            "context": {
                "type": "string",
                "description": "Why this indicator is notable — what activity was it associated with.",
            },
            "source": {
                "type": "string",
                "description": "Where it was found — log file path, command output, tool name.",
            },
        },
        "required": ["ioc_type", "value"],
    },
}
