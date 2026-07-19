# annotate_finding is a meta-tool handled directly by the orchestrator.
# It is not registered in the tool registry — the orchestrator injects its
# schema into every run and intercepts calls to it before they reach dispatch.
# This file exists only to colocate the schema definition with the other tools.

TOOL_DEFINITION = {
    "name": "annotate_finding",
    "description": (
        "Persist a finding or potential area of interest immediately during the run — "
        "do not wait until the end. Call this as soon as you observe something worth tracking: "
        "reflected input, an exposed interface, an interesting endpoint, a suspicious header, "
        "a parameter that might be injectable, anything that warrants follow-up. "
        "Set verified=false for potential findings you haven't confirmed yet. "
        "Set verified=true when you've confirmed exploitability with evidence. "
        "To enrich or update a finding you already annotated, pass its finding_id. "
        "Use type='dead_end' to BANK A CONFIRMED NEGATIVE — an attempt you actually ran "
        "that provably failed — so it isn't re-tried. Gate: only with verified=true AND the "
        "exact command+output in evidence (a fact you can point at), never an exploitability "
        "guess. Record the FAILED ATTEMPT, not a dead path: 'xp_dirtree to my SMB share "
        "captured nothing as sqlsvc' — NOT 'NTLM capture is impossible'. State the BLOCKER — WHY "
        "it can't work — in the description, because that decides when it reopens: an ACCESS block "
        "(needs creds/higher privilege) reopens on a new foothold, but a FIXED-PROPERTY block (a "
        "cert's Server-Auth-only EKU, a missing feature, a patch level) stays closed until that "
        "property changes — so permuting the identity/target/switches against it is not worth "
        "retrying. A flawed attempt on a valid path is a dead_end for that attempt, not the path."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": (
                    "Generalized vulnerability-class title — spell out acronyms (e.g. "
                    "'Insecure Direct Object Reference', not 'IDOR on /data/{id}'). No specific "
                    "paths, parameters, IDs, or file names in the title (put those in description/"
                    "evidence). NEVER include a credential, password, hash, or token in the title "
                    "or anywhere in the finding — record secrets with record_credential and "
                    "describe only what was exposed."
                ),
            },
            "type": {
                "type": "string",
                "enum": ["recon", "vuln", "config", "exposure", "dead_end"],
                "description": "recon=intelligence, vuln=exploitable weakness, config=misconfiguration, exposure=data/interface exposed, dead_end=a confirmed negative (an attempt that provably failed) — see the gate in the tool description",
            },
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Initial severity estimate — can be revised when confirmed",
            },
            "description": {
                "type": "string",
                "description": "What was observed and why it is interesting. Can be brief at annotation time.",
            },
            "evidence": {
                "type": "object",
                "description": (
                    "Supporting data as key→value. For anything HTTP, prefer the RAW transcript over "
                    "a paraphrase: put the verbatim request in a 'request' key (method, path, headers, "
                    "body — as one multiline string) and the verbatim response in a 'response' key "
                    "(status line, key headers, the relevant body slice). Trim each to the part that "
                    "proves the issue, but keep it raw — do not re-encode as JSON. For non-HTTP "
                    "evidence use 'command' + 'output' (the exact command run and its raw output). "
                    "When a custom script or payload achieved the result, put the version that WORKED "
                    "verbatim in a 'script' key (the final working code, not every failed iteration) so "
                    "the report can show the actual exploit. "
                    "Other useful keys: 'url', 'parameter', 'payload', 'notes'. Never put a credential, "
                    "hash, or token in evidence — record those with record_credential."
                ),
            },
            "verified": {
                "type": "boolean",
                "description": "false = potential, needs follow-up. true = confirmed exploitable with evidence.",
            },
            "finding_id": {
                "type": "string",
                "description": "If provided, updates the existing finding with this ID instead of creating a new one.",
            },
            "impact": {
                "type": "string",
                "description": "Report enrichment (paragraph): what a successful attack breaks, what the attacker achieves, and how likely success is. Set it once the finding is understood — usually at confirmation, not first sighting.",
            },
            "remediation": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Report enrichment: condensed remediation bullets (max 5). Best-practice options, not one specific code snippet.",
            },
            "cvss": {
                "type": "object",
                "description": "Report enrichment: CVSS 3.1 severity. Emit the full vector plus the three resulting scores — do not write out the per-metric table.",
                "properties": {
                    "vector": {"type": "string", "description": "Complete CVSS 3.1 vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C"},
                    "base_score": {"type": "number"},
                    "temporal_score": {"type": "number"},
                    "environmental_score": {"type": "number"},
                },
            },
        },
        "required": ["title", "type", "severity", "description"],
    },
}
