# record_identity is a meta-tool handled directly by the orchestrator.
# The agent reports any identity or credential it discovers in a structured form.
# Identities range from "found a username" (no secret) to full credentials with
# cleartext passwords or hashes. The realm field scopes the identity to its auth
# domain (AD domain, local host, web app, etc.).

TOOL_DEFINITION = {
    "name": "record_identity",
    "description": (
        "Record a discovered identity — a user account, credential, hash, API key, or token. "
        "Call this whenever you discover: a username (even without a password), default/guessed "
        "passwords, credentials in config/files/responses, password hashes (NTLM, NetNTLMv2, "
        "Kerberos AS-REP/TGS-REP), API keys, tokens, or any authentication material. "
        "Set 'realm' to the authentication scope (AD domain like 'NORTH', hostname for local "
        "accounts, URL for web apps). Set 'service' to the authentication domain (AD, Local, "
        "Web, MSSQL, SSH, etc.) — not the wire protocol. For AD environments, SMB/LDAP/WinRM/"
        "Kerberos creds that authenticate through the domain are all service='AD'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "username": {
                "type": "string",
                "description": "The account/username. Omit only for orphan secrets (API key with no known user).",
            },
            "realm": {
                "type": "string",
                "description": "Authentication scope — the AD domain (NORTH, sevenkingdoms.local), hostname for local accounts, URL for web apps. This determines where the identity is valid.",
            },
            "service": {
                "type": "string",
                "description": "Authentication domain: AD (anything authenticating through Active Directory — SMB, LDAP, WinRM, Kerberos, MSSQL with integrated auth), Local (OS-level), Web (app login/basic auth/JWT), MSSQL (SQL auth), SSH, FTP, etc.",
            },
            "secret": {
                "type": "string",
                "description": "The credential value verbatim — cleartext password, API key, token. Never mask or truncate.",
            },
            "secret_hash": {
                "type": "string",
                "description": "The hash value when the secret is a hash — NTLM hash, NetNTLMv2, AS-REP, TGS-REP. Preserved for pass-the-hash/ticket attacks even after cracking.",
            },
            "secret_type": {
                "type": "string",
                "enum": ["password", "hash", "api_key", "token", "key"],
                "description": "What kind of secret this is. Default password.",
            },
            "secret_format": {
                "type": "string",
                "description": "Format of the hash/key/token: NTLM, NetNTLMv2, Kerberos-AS-REP, Kerberos-TGS, bcrypt, md5, sha256, JWT, rsa, ed25519, etc.",
            },
            "location": {
                "type": "string",
                "description": "Where this identity was found or confirmed working (host:port, service endpoint, config file path).",
            },
            "port": {
                "type": "integer",
                "description": "Port of the service, if known and meaningful (DB port, odd web port). Omit for AD.",
            },
            "verified": {
                "type": "boolean",
                "description": "true only if you confirmed it authenticates successfully. false = discovered but unconfirmed.",
            },
            "notes": {
                "type": "string",
                "description": "Role or context: 'Domain Admin', 'Service Account', 'Standard User', 'SQL sa', etc.",
            },
        },
        "required": [],
    },
}
