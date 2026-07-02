# record_fact is a meta-tool handled directly by the orchestrator (like
# annotate_finding) — the orchestrator injects its schema into every active run and
# intercepts calls before dispatch. This file only colocates the schema.

TOOL_DEFINITION = {
    "name": "record_fact",
    "description": (
        "Pin a CONFIRMED operational fact so the next turn (or the next agent) acts on it "
        "instead of re-deriving it — or contradicting it. This is scaffolding for the attack, "
        "NOT a reported finding (use annotate_finding for vulns) and NOT a next-step (use "
        "record_plan). Two kinds: "
        "kind='target' — a property of the target that dictates how you exploit it "
        "(e.g. 'UpdateMonitor runs as a .NET AnyCPU process → LoadLibrary needs a 64-bit native DLL'); "
        "kind='channel' — an access/execution channel you established and how it behaves "
        "(e.g. 'command channel = WinRM as msa_health$ via NTLM hash; the DLL reverse shell is BLIND, "
        "stdout not piped — exfil results over the OOB HTTP listener, not the shell'). "
        "Gate: only pin what you CONFIRMED, and put the proof in `evidence` — the exact command and the "
        "observed line (e.g. `file UpdateMonitor.exe → PE32 ... Mono/.Net assembly`). A fact with no "
        "evidence is rejected. If a later observation corrects a fact you pinned, call record_fact again "
        "with the corrected statement and pass `supersedes` = the old fact's id, so the wrong one is "
        "retired on the record instead of silently coexisting."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["target", "channel"],
                "description": "target=a property that dictates how to exploit it; channel=an access/exec channel you established and how it behaves",
            },
            "statement": {
                "type": "string",
                "description": "The fact, one line, stated so the next turn can act on it directly.",
            },
            "evidence": {
                "type": "string",
                "description": "REQUIRED. The command + the observed output line that proves the fact. No evidence → rejected.",
            },
            "scope": {
                "type": "string",
                "description": "Host and/or principal the fact applies to, e.g. '10.129.44.128' or 'msa_health$@logging.htb'.",
            },
            "supersedes": {
                "type": "string",
                "description": "If this fact corrects one you pinned earlier, its id — the old fact is marked invalidated.",
            },
        },
        "required": ["kind", "statement", "evidence"],
    },
}
