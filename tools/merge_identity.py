# merge_identity is a meta-tool handled directly by the orchestrator.
# When the agent discovers that an orphan secret (Record B) belongs to a known
# identity (Record A), it merges B into A: target gets source's secret/metadata,
# source is deleted. One tool call, one transaction, one activity log entry.

TOOL_DEFINITION = {
    "name": "merge_identity",
    "description": (
        "Merge two identity records when you discover they represent the same entity. "
        "Typical use: an orphan hash/credential (source) is confirmed to belong to a "
        "known user (target). The target keeps its identity fields; the source's secret, "
        "locations, and metadata backfill any gaps on the target. The source record is "
        "deleted after merge. Use /identity list to find record IDs."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "source_id": {
                "type": "string",
                "description": "ID of the identity to merge FROM (will be deleted after merge).",
            },
            "target_id": {
                "type": "string",
                "description": "ID of the identity to merge INTO (will be preserved and enriched).",
            },
        },
        "required": ["source_id", "target_id"],
    },
}
