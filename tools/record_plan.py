# record_plan is a meta-tool handled directly by the orchestrator.
# It is not registered in the tool registry — the orchestrator injects its
# schema into planning-phase runs and intercepts calls before dispatch.

TOOL_DEFINITION = {
    "name": "record_plan",
    "description": (
        "Record the test plan for the current attack surface. Call this once you "
        "have reasoned about what to test next. Each item is a concrete action with "
        "the rationale behind it — the exploit phase works only from this vetted list. "
        "Be specific: name the parameter, endpoint, share, account, or misconfiguration "
        "and the exact technique to attempt. Order items by likelihood and impact."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "surface_id": {
                "type": "string",
                "description": "ID of the surface this plan is for (from the engagement state).",
            },
            "items": {
                "type": "array",
                "description": "Ordered list of test actions.",
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "description": "Concrete action to attempt (e.g. 'Test id parameter in /api/v2/users/{id} for IDOR by incrementing id').",
                        },
                        "rationale": {
                            "type": "string",
                            "description": "Why this is worth testing given what enumeration found.",
                        },
                        "technique": {
                            "type": "string",
                            "description": "Short technique label (e.g. 'IDOR', 'default-creds', 'SSRF', 'null-session').",
                        },
                    },
                    "required": ["action"],
                },
            },
            "notes": {
                "type": "string",
                "description": "Optional overall reasoning or sequencing notes for the plan.",
            },
        },
        "required": ["surface_id", "items"],
    },
}
