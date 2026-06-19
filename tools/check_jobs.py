# check_jobs is a meta-tool handled directly by the orchestrator.
# Lets the agent see the status of background jobs (hashcat cracks, large scans).
# Note: completed job results are also delivered to you automatically — you do not
# have to poll. Use this mainly to decide whether to wait on something still running.

TOOL_DEFINITION = {
    "name": "check_jobs",
    "description": (
        "List background jobs and their status (running / done / failed) with runtimes. "
        "Heavy tools like hashcat_crack and background scans run asynchronously; their results "
        "are injected into your context automatically when they finish, so you normally do not "
        "need to call this — use it to check whether something is still running before you decide "
        "to wrap up."
    ),
    "input_schema": {"type": "object", "properties": {}},
}
