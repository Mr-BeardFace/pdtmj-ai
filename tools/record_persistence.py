# record_persistence is a meta-tool handled directly by the orchestrator.
# It is the engagement's CHANGE LEDGER: every change made to a target — something
# planted OR an existing thing modified — is recorded here with the original state
# and exact revert steps, so the report carries a complete IOC list and nothing is
# left altered or undocumented.

TOOL_DEFINITION = {
    "name": "record_persistence",
    "description": (
        "Record EVERY change you make to a target — this is the engagement's IOC ledger. Two cases: "
        "(1) something planted — an added SSH key, a new user, an enabled RDP/WinRM, a cron/scheduled "
        "task, a dropped webshell/payload; (2) something modified — a changed password, an edited "
        "ADCS certificate template, an IAM policy / security-group / ACL change, a modified service "
        "binary path or prod script, a flipped config value. Call this the moment you make the change, "
        "with the ORIGINAL state in `before` and the exact `cleanup` (revert/restore) command, so the "
        "operator gets a full record of what changed, where, and when — and can put it back. Leaving "
        "an undocumented or unrevertable change behind is unacceptable; if a change cannot be safely "
        "reverted, do not make it — record the opportunity as a finding instead."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["authorized_key", "user", "reverse_shell", "cron", "scheduled_task",
                         "rdp", "winrm", "service", "webshell",
                         "password_change", "permission_change", "template_change",
                         "config_change", "file_edit", "other"],
                "description": "What was planted or changed.",
            },
            "host": {"type": "string", "description": "Host / resource it was done on (where)."},
            "detail": {"type": "string", "description": "What exactly — key fingerprint, username, the object/policy/template/file changed and the new value."},
            "before": {"type": "string", "description": "The ORIGINAL state before your change (old value/config/permission), so it can be restored. Omit only for purely planted items that had no prior state."},
            "cleanup": {"type": "string", "description": "Exact command/steps to revert or remove the change and restore the original state."},
            "os": {"type": "string", "enum": ["linux", "windows"], "description": "Target OS."},
        },
        "required": ["kind", "host"],
    },
}
