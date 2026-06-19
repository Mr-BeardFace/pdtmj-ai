import shlex
import shutil
import subprocess
from core import proc as runner

# Credential-bearing flags whose values must be redacted from logged commands.
import re
_CRED_FLAGS = re.compile(r'(?<= )(-p|-H|--password|--hash)( )(\S+)')


def _validate_nxc_flags(flags: str) -> list[str]:
    # Full passthrough — command execution (-x), modules, exec-methods, and
    # evasion flags are all legitimate in an authorized exploitation phase.
    return shlex.split(flags)


def _not_found_msg() -> str:
    return (
        "netexec/nxc not found. Install it with apt_install('netexec') (Kali "
        "packages it) or `pipx install netexec`, then retry. Do NOT reimplement "
        "netexec with a custom script — provision the tool and use it."
    )


def _broken_install_msg(exe_name: str, detail: str) -> str:
    return (
        f"{exe_name} is present but won't execute — almost certainly a broken "
        f"pipx/venv interpreter (a Python upgrade can orphan the venv): {detail}. "
        f"Repair it with `pipx reinstall netexec` or apt_install('netexec'), then "
        f"retry. Do NOT reimplement netexec with a custom script — fix the tool."
    )


def _redact_command(cmd: list[str]) -> str:
    """Return the command as a printable string with credential values masked."""
    out = []
    skip_next = False
    cred_args = {"-p", "--password", "-H", "--hash"}
    for token in cmd:
        if skip_next:
            out.append("***")
            skip_next = False
        elif token in cred_args:
            out.append(token)
            skip_next = True
        else:
            out.append(token)
    return " ".join(out)


def netexec(
    target: str,
    protocol: str,
    username: str | None = None,
    password: str | None = None,
    hash: str | None = None,
    domain: str | None = None,
    module: str | None = None,
    command: str | None = None,
    flags: str | None = None,
) -> dict:
    """Wrapper for netexec (nxc), the successor to CrackMapExec."""
    exe_name = next((n for n in ("nxc", "netexec", "crackmapexec") if shutil.which(n)), None)
    if exe_name is None:
        return {"error": _not_found_msg()}

    cmd = [exe_name, protocol, target]

    if username:
        cmd += ["-u", username]
    if password:
        cmd += ["-p", password]
    if hash:
        cmd += ["-H", hash]
    if domain:
        cmd += ["-d", domain]
    if module:
        cmd += ["-M", module]
    if command:
        cmd += ["-x", command]
    if flags:
        try:
            cmd += _validate_nxc_flags(flags)
        except ValueError as e:
            return {"error": str(e), "target": target}

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": f"{exe_name} timed out", "target": target}
    except OSError as e:
        # exec failed outright — e.g. the shim's shebang points at a deleted
        # pipx-venv python. which() found the file but the kernel can't run it.
        return {"error": _broken_install_msg(exe_name, str(e)), "target": target}

    output = (proc.stdout + proc.stderr).strip()

    # Some shells surface a broken interpreter as text on stderr (exit, not raise).
    # Detect it and return the repair message instead of an empty/garbled parse
    # that would push the agent toward hand-rolling a script.
    low = output.lower()
    if "bad interpreter" in low or ("no such file or directory" in low and "pipx" in low):
        return {"error": _broken_install_msg(exe_name, output[:300]), "target": target}

    result = _parse_output(output, target, protocol, username, password or hash)
    result["_command"] = _redact_command(cmd)
    return result


def _parse_output(
    output: str,
    target: str,
    protocol: str,
    username: str | None = None,
    credential: str | None = None,
) -> dict:
    lines = output.splitlines()
    hosts: list = []
    shares: list = []
    users: list = []
    authed = False
    pwned  = False

    for line in lines:
        # Host info: [*] 10.10.10.5  SMBv2  (name:DC01) (domain:LAB) ...
        host_m = re.search(
            r"\[\*\]\s+([\d.]+)\s+\S+\s+\(name:(\S+)\)\s+\(domain:(\S+)\)", line
        )
        if host_m:
            hosts.append({
                "ip":     host_m.group(1),
                "name":   host_m.group(2).rstrip(")"),
                "domain": host_m.group(3).rstrip(")"),
            })

        # Share line
        share_m = re.search(
            r"\s+(ADMIN\$|C\$|IPC\$|\S+)\s+(READ|READ,WRITE|NO ACCESS)", line, re.IGNORECASE
        )
        if share_m:
            shares.append({"name": share_m.group(1), "access": share_m.group(2)})

        # User line from --users
        user_m = re.search(
            r"\[\*\]\s+(\S+)\s+badpwdcount.*?status:(\w+)", line, re.IGNORECASE
        )
        if user_m:
            users.append({"username": user_m.group(1), "status": user_m.group(2)})

        # [+] auth success line
        if "[+]" in line:
            authed = True
        if "Pwn3d!" in line:
            pwned = True

    return {
        "target":        target,
        "protocol":      protocol,
        "authenticated": authed,
        "pwned":         pwned,
        # Only expose plaintext credential when auth actually succeeded so the
        # orchestrator can ingest it; credential value travels outside LLM context.
        "username":      username if authed else None,
        "password":      credential if (authed and credential) else None,
        "hosts":         hosts,
        "shares":        shares,
        "users":         users,
        "raw_output":    output[:8000],
    }


TOOL_DEFINITION = {
    "name": "netexec",
    "description": (
        "Network execution and enumeration via netexec/nxc (CrackMapExec successor). "
        "Supports SMB, WinRM, SSH, LDAP, MSSQL, RDP, FTP, VNC. "
        "Use for: SMB enumeration, credential validation, share enumeration, "
        "command execution (with creds), user/group listing, and post-exploitation modules. "
        "Pass module names like 'spider_plus', 'lsassy', 'ntdsutil', 'rdp', 'mimikatz'."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Target IP, hostname, or CIDR range"},
            "protocol": {"type": "string", "description": "Protocol: smb, winrm, ssh, ldap, mssql, rdp, ftp, vnc"},
            "username": {"type": "string", "description": "Username for authentication"},
            "password": {"type": "string", "description": "Password for authentication"},
            "hash":     {"type": "string", "description": "NTLM hash for pass-the-hash (format: LMHASH:NTHASH or just NTHASH)"},
            "domain":   {"type": "string", "description": "Windows domain"},
            "module":   {"type": "string", "description": "Module to run, e.g. 'spider_plus', 'lsassy'"},
            "command":  {"type": "string", "description": "Command to execute remotely via -x"},
            "flags":    {"type": "string", "description": "Additional netexec flags, e.g. '--shares --users --groups --pass-pol --local-auth'"},
        },
        "required": ["target", "protocol"],
    },
}
