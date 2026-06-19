# conclude_engagement is a meta-tool handled directly by the orchestrator.
# The agent calls it when the engagement objective is achieved and further
# testing would be wasted effort.

TOOL_DEFINITION = {
    "name": "conclude_engagement",
    "description": (
        "Declare the engagement objective achieved and stop opening new work. Call this when "
        "you have reached the goal and continuing would only add redundant findings: a root/SYSTEM "
        "shell, reliable remote code execution, full domain compromise, or — in a CTF — the final "
        "(root) flag. After you call this, finish your current train of thought; the engagement "
        "stops queuing further surfaces/tests and proceeds straight to reporting. Do NOT call it "
        "for a partial win (a low-priv shell you still intend to escalate, one of several flags) — "
        "only when the objective is genuinely met."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "What was achieved that concludes the engagement (e.g. 'root shell on 10.0.0.5 via sudo misconfig', 'root flag captured', 'Domain Admin obtained').",
            },
        },
        "required": ["reason"],
    },
}
