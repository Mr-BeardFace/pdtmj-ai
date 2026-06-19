# register_surface is a meta-tool handled directly by the orchestrator.
# Agents call it when exploitation or enumeration reveals a NEW attack surface
# worth its own Enum→Plan→Exploit→Validate cycle — a new host, a new service, or
# deeper access within the current service (e.g. anonymous FTP that exposes files).

TOOL_DEFINITION = {
    "name": "register_surface",
    "description": (
        "Register a new attack surface for the engagement loop to investigate. Call this "
        "when you discover something that warrants its own focused cycle: a new host reachable "
        "from current access, a new listening service, or deeper access within the current "
        "service that opens further testing (e.g. anonymous login now lets you read a config). "
        "The surface must be within engagement scope. Each surface gets its own enumeration, "
        "planning, exploitation, and validation pass."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Host/IP/domain of the surface. Must be in scope.",
            },
            "service": {
                "type": "string",
                "description": "Service or protocol (e.g. http, smb, ftp, ldap, mssql, ssh).",
            },
            "port": {
                "type": "integer",
                "description": "Port number, if known.",
            },
            "component": {
                "type": "string",
                "description": "Optional narrowing — app path, share name, database, account.",
            },
            "origin": {
                "type": "string",
                "enum": ["lateral", "credential", "deeper"],
                "description": "lateral=new host, credential=reachable via found creds, deeper=expanded access within a service.",
            },
            "notes": {
                "type": "string",
                "description": "Why this surface matters and what to look at.",
            },
        },
        "required": ["host"],
    },
}
