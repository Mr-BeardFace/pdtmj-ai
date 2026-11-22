# record_achievement is a meta-tool handled directly by the orchestrator.
# The agent records a proven capability (RCE, DA, forest compromise, etc.)
# without halting the engagement — subsequent agents see what's already proven
# and skip re-executing the same endpoint via a different path.

TOOL_DEFINITION = {
    "name": "record_achievement",
    "description": (
        "Record a proven capability milestone — RCE on a host, Domain Admin, forest compromise, "
        "foothold, privilege escalation, user-level access. This does NOT stop the engagement; it "
        "informs subsequent agents what has already been demonstrated so they can target remaining "
        "gaps instead of re-proving the same endpoint. Call this when you have confirmed a "
        "capability (e.g. executed code as SYSTEM, obtained DA credentials and proved they work, "
        "compromised a trust boundary). The engagement continues to cover remaining attack surface."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "capability": {
                "type": "string",
                "description": "The proven capability: rce, domain_admin, forest_compromise, foothold, privesc, user_access, data_access, or a short custom label.",
            },
            "description": {
                "type": "string",
                "description": "How the capability was achieved, e.g. 'DA via Kerberoasting svc_sql → DCSync', 'RCE via file upload on /api/upload'.",
            },
            "scope": {
                "type": "string",
                "description": "Where this capability applies — hostname, domain name, or surface label (e.g. '10.0.0.5', 'NORTH.sevenkingdoms.local', 'http://10.0.0.5:8080').",
            },
            "finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "IDs of the findings that proved this capability (from annotate_finding responses).",
            },
        },
        "required": ["capability", "description"],
    },
}
