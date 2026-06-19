from typing import Optional

TOOL_DEFINITION = {
    "name": "ssh_exec",
    "description": (
        "Execute a command on a remote host via SSH using password or key-based authentication. "
        "Use for post-authentication enumeration, exploitation, and impact demonstration. "
        "Avoid irreversible destructive actions (wiping disks, deleting logs wholesale) "
        "unless explicitly instructed — prefer demonstrating access over destroying evidence."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Target hostname or IP address.",
            },
            "username": {
                "type": "string",
                "description": "SSH username.",
            },
            "command": {
                "type": "string",
                "description": "Command to execute on the remote host.",
            },
            "password": {
                "type": "string",
                "description": "SSH password (omit if using key auth).",
            },
            "key_file": {
                "type": "string",
                "description": "Path to private key file for key-based auth.",
            },
            "port": {
                "type": "integer",
                "description": "SSH port (default: 22).",
                "default": 22,
            },
            "timeout": {
                "type": "integer",
                "description": "Connection timeout in seconds (default: 15).",
                "default": 15,
            },
        },
        "required": ["host", "username", "command"],
    },
}


def ssh_exec(
    host: str,
    username: str,
    command: str,
    password: Optional[str] = None,
    key_file: Optional[str] = None,
    port: int = 22,
    timeout: int = 15,
) -> dict:
    try:
        import paramiko
    except ImportError:
        return {"error": "paramiko not installed — run: pip install paramiko"}

    cmd_display = f"ssh {username}@{host}:{port} '{command}'"

    client = paramiko.SSHClient()
    # AutoAddPolicy: intentional for pentest use — we're connecting to target hosts whose
    # host keys we don't know in advance. MITM protection is not a goal here; if the tool
    # is ever used against trusted infrastructure (jumpboxes, internal relay), switch to
    # RejectPolicy and pre-load the known_hosts file.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if key_file:
            connect_kwargs["key_filename"] = key_file
        elif password:
            connect_kwargs["password"] = password
        else:
            return {"error": "Either password or key_file must be provided."}

        client.connect(**connect_kwargs)

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        client.close()

        return {
            "success":   exit_code == 0,
            "output":    out[:16000],
            "stderr":    err[:4000] if err else None,
            "exit_code": exit_code,
            "host":      host,
            "username":  username,
            "_command":  cmd_display,
        }

    except paramiko.AuthenticationException:
        client.close()
        return {"error": f"Authentication failed for {username}@{host}", "_command": cmd_display}
    except paramiko.SSHException as e:
        client.close()
        return {"error": f"SSH error: {e}", "_command": cmd_display}
    except OSError as e:
        client.close()
        return {"error": f"Connection failed: {e}", "_command": cmd_display}
