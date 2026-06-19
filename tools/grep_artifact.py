# grep_artifact is a meta-tool handled directly by the orchestrator.
# It searches large tool output that was offloaded to an artifact file instead
# of being passed through the LLM in full.

TOOL_DEFINITION = {
    "name": "grep_artifact",
    "description": (
        "Search a large tool-output artifact with a regular expression and get back only "
        "the matching lines. When a tool returns more output than fits in context, the full "
        "output is saved to an artifact and you receive an artifact_id plus a short preview. "
        "Use this to pull exactly the lines you need (e.g. grep for 'password', a status code, "
        "a hostname, a CVE id) instead of guessing from the preview. Supports context lines "
        "around each match."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "description": "ID of the artifact to search."},
            "pattern": {"type": "string", "description": "Regular expression to match (Python regex)."},
            "ignore_case": {"type": "boolean", "description": "Case-insensitive match (default true)."},
            "context": {"type": "integer", "description": "Lines of context to include around each match (default 0)."},
            "max_matches": {"type": "integer", "description": "Cap on matches returned (default 200)."},
            "invert": {"type": "boolean", "description": "Return non-matching lines instead (default false)."},
        },
        "required": ["artifact_id", "pattern"],
    },
}
