# record_credential is a meta-tool handled directly by the orchestrator.
# The agent reports any credential it discovers or derives in a structured form,
# so credentials are tracked reliably instead of being scraped (error-prone) from
# free-text findings. Recorded credentials become available to every later phase.

TOOL_DEFINITION = {
    "name": "record_credential",
    "description": (
        "Record a credential you discovered or obtained. Call this for: default/guessed "
        "passwords that authenticate, credentials found in exposed config/files/HTTP responses, "
        "password hashes captured (NTLM, NetNTLMv2, Kerberos AS-REP/TGS-REP), API keys, and "
        "tokens. Set 'type' to what it is, put the value verbatim in 'secret' (never mask or "
        "truncate), and give the 'location' where it is used so later phases can reuse it."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": ["password", "hash", "api_key", "token", "key"],
                "description": "What kind of credential this is. Default password.",
            },
            "username": {
                "type": "string",
                "description": "Account/username it belongs to (omit for API keys/tokens with no user).",
            },
            "secret": {
                "type": "string",
                "description": "The credential value, verbatim — the password, hash, API key, token, or private key.",
            },
            "secret_format": {
                "type": "string",
                "description": "For hash/key/token: its format — NTLM, NetNTLMv2, Kerberos-AS-REP, Kerberos-TGS, bcrypt, md5, sha256, JWT, rsa, ed25519, etc.",
            },
            "location": {
                "type": "string",
                "description": "Where this credential applies. On first record this is where it was FOUND. If you later confirm the SAME credential authenticates somewhere else, call record_credential again with the same value, verified=true, and that new location — it is tracked as a 'used' (works-at) location distinct from where it was found.",
            },
            "service": {
                "type": "string",
                "description": "Service/protocol it authenticates to (smb, ssh, http, mssql, ldap, winrm).",
            },
            "port": {
                "type": "integer",
                "description": "Port of the service, if known.",
            },
            "verified": {
                "type": "boolean",
                "description": "true only if you confirmed it authenticates. false = found but unconfirmed.",
            },
        },
        "required": ["secret"],
    },
}
