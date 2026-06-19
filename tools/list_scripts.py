# list_scripts is a meta-tool handled directly by the orchestrator. It returns the
# ad-hoc scripts written this engagement (via run_script) so the agent can reuse or
# adapt one instead of writing a near-duplicate.

TOOL_DEFINITION = {
    "name": "list_scripts",
    "description": (
        "List the ad-hoc scripts already written this engagement with run_script — each entry's "
        "purpose, language, path, and a content preview, newest first. CHECK THIS BEFORE writing a "
        "new script: if one already does what you need (or is close), reuse or adapt it rather than "
        "re-writing a near-duplicate. Cuts the script sprawl and lets you build on prior work."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Max scripts to return (default 20, newest first).",
            },
        },
    },
}
