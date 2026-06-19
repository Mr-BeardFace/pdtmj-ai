import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def kerbrute(domain: str, dc: str, action: str = "userenum",
             wordlist: Optional[str] = None, users: Optional[str] = None,
             username: Optional[str] = None, password: Optional[str] = None,
             flags: Optional[str] = None) -> dict:
    if not shutil.which("kerbrute"):
        return {"error": "kerbrute not found in PATH"}

    cmd = ["kerbrute", action, "--dc", dc, "-d", domain]

    if action == "userenum":
        target_list = wordlist or users
        if not target_list:
            return {"error": "userenum requires a wordlist path"}
        cmd.append(target_list)
    elif action == "passwordspray":
        if not (wordlist or users) or not password:
            return {"error": "passwordspray requires a userlist and password"}
        cmd += [wordlist or users, password]
    elif action == "bruteuser":
        if not username or not wordlist:
            return {"error": "bruteuser requires username and passlist"}
        cmd += [wordlist, username]
    elif action == "bruteforce":
        if not wordlist:
            return {"error": "bruteforce requires a combo list"}
        cmd.append(wordlist)
    else:
        return {"error": f"Unknown action '{action}'. Use: userenum, passwordspray, bruteuser, bruteforce"}

    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "kerbrute timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, action, domain)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, action: str, domain: str) -> dict:
    valid_users: list = []
    valid_creds: list = []
    invalid_users: list = []

    for line in output.splitlines():
        # VALID USERNAME: user@domain
        vu = re.search(r"VALID USERNAME:\s+(\S+)", line)
        if vu:
            valid_users.append(vu.group(1))

        # VALID LOGIN: user:pass
        vl = re.search(r"VALID LOGIN:\s+(\S+):(\S+)", line)
        if vl:
            valid_creds.append({"username": vl.group(1), "password": vl.group(2)})

        # account does not exist
        inv = re.search(r"(\S+@\S+)\s+does not exist", line, re.IGNORECASE)
        if inv:
            invalid_users.append(inv.group(1))

    return {
        "domain":       domain,
        "action":       action,
        "valid_users":  valid_users,
        "valid_creds":  valid_creds,
        "count":        len(valid_users) + len(valid_creds),
        "raw":          output[:8000],
    }


TOOL_DEFINITION = {
    "name": "kerbrute",
    "description": (
        "Kerberos-based user enumeration and password spraying via kerbrute. "
        "Actions:\n"
        "- 'userenum': validate a list of usernames against the domain KDC (no lockout risk)\n"
        "- 'passwordspray': spray one password across a user list (mind lockout policy)\n"
        "- 'bruteuser': brute-force a single account\n"
        "- 'bruteforce': brute-force using a user:pass combo list\n"
        "Common wordlists: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "domain":   {"type": "string", "description": "Active Directory domain, e.g. 'lab.local'"},
            "dc":       {"type": "string", "description": "Domain controller IP or hostname"},
            "action":   {"type": "string", "description": "'userenum', 'passwordspray', 'bruteuser', 'bruteforce'"},
            "wordlist": {"type": "string", "description": "Path to username list (userenum/passwordspray) or password list (bruteuser) or combo list (bruteforce)"},
            "users":    {"type": "string", "description": "Alias for wordlist — path to user list"},
            "username": {"type": "string", "description": "Target username for bruteuser mode"},
            "password": {"type": "string", "description": "Password for passwordspray mode"},
            "flags":    {"type": "string", "description": "Additional kerbrute flags, e.g. '-v' for verbose"},
        },
        "required": ["domain", "dc"],
    },
}
