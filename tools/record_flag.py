# record_flag is a meta-tool handled directly by the orchestrator.
# Only injected when the active persona is pentest-ctf — it captures CTF flags.

TOOL_DEFINITION = {
    "name": "record_flag",
    "description": (
        "Record a CTF flag you captured. Call this the moment you recover a flag — paste the "
        "flag value verbatim (e.g. flag{...}, HTB{...}, the exact token) and note where it came "
        "from (which challenge, host, service, or file). The flag is tracked and shown to the "
        "operator for the writeup."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "value": {
                "type": "string",
                "description": "The flag string, verbatim (including any flag{...} wrapper).",
            },
            "location": {
                "type": "string",
                "description": "Where the flag was found — challenge name, host/IP, service, URL, or file path.",
            },
            "verified": {
                "type": "boolean",
                "description": "true if you confirmed it is the real/accepted flag; false if it only looks like one.",
            },
        },
        "required": ["value"],
    },
}
