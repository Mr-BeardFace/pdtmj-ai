import json
import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def hydra(target: str, service: str, username: Optional[str] = None,
          password: Optional[str] = None, userlist: Optional[str] = None,
          passlist: Optional[str] = None, flags: Optional[str] = None) -> dict:
    if not shutil.which("hydra"):
        return {"error": "hydra not found in PATH"}

    cmd = ["hydra"]

    if username:
        cmd += ["-l", username]
    elif userlist:
        cmd += ["-L", userlist]
    else:
        return {"error": "username or userlist required"}

    if password:
        cmd += ["-p", password]
    elif passlist:
        cmd += ["-P", passlist]
    else:
        return {"error": "password or passlist required"}

    cmd += ["-o", "/dev/stdout", "-b", "json"]

    if flags:
        cmd += shlex.split(flags)

    cmd.append(f"{service}://{target}")

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "hydra timed out", "target": target}

    result = _parse_output(proc.stdout, proc.stderr, target, service)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(stdout: str, stderr: str, target: str, service: str) -> dict:
    creds: list = []

    # Try JSON output first
    try:
        data = json.loads(stdout)
        for entry in data.get("results", []):
            creds.append({
                "host":     entry.get("host", target),
                "port":     entry.get("port"),
                "service":  entry.get("service", service),
                "login":    entry.get("login", ""),
                "password": entry.get("password", ""),
            })
        return {
            "target":             target,
            "service":            service,
            "found_credentials":  creds,
            "count":              len(creds),
        }
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: parse plain text output
    for line in (stdout + stderr).splitlines():
        m = re.search(r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)", line)
        if m:
            creds.append({
                "host":     m.group(3),
                "port":     int(m.group(1)),
                "service":  m.group(2),
                "login":    m.group(4),
                "password": m.group(5),
            })

    return {
        "target":            target,
        "service":           service,
        "found_credentials": creds,
        "count":             len(creds),
    }


TOOL_DEFINITION = {
    "name": "hydra",
    "description": (
        "Online password brute-force and credential stuffing via Hydra. "
        "Supports SSH, FTP, HTTP-form, SMB, RDP, Telnet, POP3, IMAP, LDAP, and more. "
        "Provide either a single username/password or list files. "
        "Common wordlists on Kali: /usr/share/wordlists/rockyou.txt, "
        "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Target IP or hostname",
            },
            "service": {
                "type": "string",
                "description": "Protocol/service: ssh, ftp, smb, rdp, telnet, http-get, http-post-form, pop3, imap, ldap, mssql, mysql, postgres",
            },
            "username": {
                "type": "string",
                "description": "Single username to test",
            },
            "password": {
                "type": "string",
                "description": "Single password to test",
            },
            "userlist": {
                "type": "string",
                "description": "Path to username list file",
            },
            "passlist": {
                "type": "string",
                "description": "Path to password list file",
            },
            "flags": {
                "type": "string",
                "description": "Additional hydra flags, e.g. '-t 4 -f' (-f stops on first valid credential)",
            },
        },
        "required": ["target", "service"],
    },
}
