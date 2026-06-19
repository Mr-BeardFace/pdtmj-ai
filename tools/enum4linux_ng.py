import json
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def enum4linux_ng(target: str, flags: Optional[str] = None) -> dict:
    binary = shutil.which("enum4linux-ng") or shutil.which("enum4linux_ng")
    if not binary:
        return {"error": "enum4linux-ng not found in PATH. Install: pip install enum4linux-ng"}

    cmd = [binary, "-A", "-oJ", "/dev/stdout", target]
    if flags:
        cmd = [binary] + shlex.split(flags) + ["-oJ", "/dev/stdout", target]

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "enum4linux-ng timed out", "target": target}

    return _parse_output(proc.stdout, proc.stderr, target, " ".join(cmd))


def _parse_output(stdout: str, stderr: str, target: str, command: str) -> dict:
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        # Fall back to raw text parsing
        return {
            "target":     target,
            "raw_output": (stdout + stderr)[:8000],
            "_command":   command,
        }

    def _get(d, *keys, default=None):
        for k in keys:
            if not isinstance(d, dict):
                return default
            d = d.get(k, default)
        return d

    shares = []
    for name, info in (_get(data, "shares", default={}) or {}).items():
        shares.append({
            "name":    name,
            "comment": _get(info, "comment", default=""),
            "access":  _get(info, "access", default=""),
        })

    users = []
    for uid, info in (_get(data, "users", default={}) or {}).items():
        users.append({
            "username": _get(info, "username", default=""),
            "rid":      uid,
            "fullname": _get(info, "fullname", default=""),
        })

    groups = []
    for gid, info in (_get(data, "groups", default={}) or {}).items():
        groups.append({
            "groupname": _get(info, "groupname", default=""),
            "rid":       gid,
            "members":   _get(info, "members", default=[]),
        })

    return {
        "target":        target,
        "workgroup":     _get(data, "workgroup", default=""),
        "domain":        _get(data, "domain", default=""),
        "os":            _get(data, "os", default=""),
        "server":        _get(data, "server", default=""),
        "null_session":  _get(data, "null_session_possible", default=False),
        "rid_cycling":   _get(data, "rid_cycling_possible", default=False),
        "password_policy": _get(data, "password_policy", default={}),
        "shares":        shares,
        "users":         users,
        "groups":        groups,
        "_command":      command,
    }


TOOL_DEFINITION = {
    "name": "enum4linux_ng",
    "description": (
        "Comprehensive Windows/Samba enumeration via enum4linux-ng. "
        "Enumerates: workgroup/domain, OS info, null session availability, "
        "shares and permissions, users (via RID cycling), groups, password policy. "
        "Use on SMB (port 445) or NetBIOS (port 139) hosts after nmap confirms those services."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or hostname running SMB/NetBIOS",
            },
            "flags": {
                "type": "string",
                "description": "Additional flags, e.g. '-u admin -p password' for authenticated enumeration",
            },
        },
        "required": ["target"],
    },
}
