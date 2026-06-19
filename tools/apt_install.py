"""Install system package(s) via apt so the engagement can self-provision tools.

When a needed CLI tool isn't on the box (gobuster, seclists, a specific impacket
script, etc.), install it with this. Runs `apt-get install` non-interactively;
uses `sudo -n` when not already root, so it FAILS FAST with a clear message if a
password would be required rather than hanging on a prompt.
"""
import os
import shutil
import subprocess
from core import proc as runner
from core import paths

from core.config import get

OUTPUT_CAP = 8000


def apt_install(packages, timeout: int = 300) -> dict:
    if not get("allow_package_install", True):
        return {"error": "package installation is disabled (allow_package_install=false in config)"}
    if not shutil.which("apt-get"):
        return {"error": "apt-get not found — this is not a Debian/Ubuntu/Kali system"}

    pkgs = [packages] if isinstance(packages, str) else list(packages or [])
    pkgs = [str(p).strip() for p in pkgs if str(p).strip()]
    if not pkgs:
        return {"error": "no packages specified"}
    flags = [p for p in pkgs if p.startswith("-")]
    if flags:
        return {"error": f"refusing package arguments that look like flags: {flags}"}

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    # When not root, preserve TMPDIR/TEMP/TMP across the sudo boundary (sudo's
    # env_reset strips them by default), so apt/debconf's temp + log files land in
    # the assessment scratch, not /tmp.
    prefix = [] if is_root else ["sudo", "-n", "--preserve-env=TMPDIR,TEMP,TMP"]
    cmd = prefix + ["apt-get", "install", "-y", "-q"] + pkgs
    env = paths.scratch_env({**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    display = "apt-get install -y " + " ".join(pkgs)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"error": f"apt-get timed out after {timeout}s — retry with background=true",
                "_command": display}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    err = proc.stderr or ""
    if proc.returncode != 0 and ("password is required" in err.lower()
                                 or "sudo: a password" in err.lower()):
        return {
            "error": ("sudo needs a password (non-interactive). Run PDTMJ-AI as root, enable "
                      "passwordless sudo for apt-get, or install the package manually."),
            "_command": display,
            "stderr":   err[-OUTPUT_CAP:],
        }

    ok = proc.returncode == 0
    return {
        "success":   ok,
        "exit_code": proc.returncode,
        "installed": pkgs if ok else [],
        "stdout":    (proc.stdout or "")[-OUTPUT_CAP:],
        "stderr":    err[-OUTPUT_CAP:],
        "_command":  display,
    }


TOOL_DEFINITION = {
    "name": "apt_install",
    "description": (
        "Install one or more system packages via apt (Debian/Ubuntu/Kali) to self-provision a CLI "
        "tool the engagement needs but the host is missing (e.g. gobuster, seclists, a protocol "
        "client). Runs non-interactively; if it isn't already root it uses `sudo -n`, so it returns "
        "a clear error instead of hanging when sudo would prompt for a password (run as root or set "
        "up passwordless sudo to use it). For a slow install, set background=true."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "packages": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Package names to install, e.g. ['gobuster', 'seclists'].",
            },
            "timeout": {
                "type": "integer",
                "description": "Install timeout seconds (default 300). Use background=true for slow installs.",
            },
        },
        "required": ["packages"],
    },
}
