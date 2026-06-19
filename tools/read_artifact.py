# read_artifact is a meta-tool handled directly by the orchestrator.
# It returns a slice of a large tool-output artifact by line range.

TOOL_DEFINITION = {
    "name": "read_artifact",
    "description": (
        "Read a window of lines from a large tool-output artifact. When a tool's output is "
        "too large to return in full, it is saved to an artifact and you get an artifact_id "
        "plus a preview. Use read_artifact to page through the full output by line offset, or "
        "grep_artifact to jump straight to matching lines."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "artifact_id": {"type": "string", "description": "ID of the artifact to read."},
            "offset": {"type": "integer", "description": "Zero-based line to start from (default 0)."},
            "limit": {"type": "integer", "description": "Number of lines to return (default 200)."},
        },
        "required": ["artifact_id"],
    },
}
