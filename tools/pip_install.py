"""Install Python package(s) so an ad-hoc script (run_script) can use them.

When an exploit script needs a library that isn't present (pwntools, requests,
paramiko, impacket, …), install it with this instead of shelling out to pip from
inside a script. Packages install into the environment running PDTMJ-AI.
"""
import re
import subprocess
from core import proc as runner
from core import paths
import sys

from core.config import get

OUTPUT_CAP = 8000

# A pip requirement can carry a version/extra spec (e.g. 'requests==2.31.0',
# 'impacket[ldap]'); strip it to the bare dist name for the already-installed check.
_SPEC_SPLIT = re.compile(r"[<>=!~\[ ]")


def _installed_dists(py: str) -> set:
    """Lower-cased set of dist names already installed in the target interpreter."""
    try:
        r = subprocess.run([py, "-m", "pip", "list", "--format=freeze",
                            "--disable-pip-version-check"],
                           capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001
        return set()
    out = set()
    for line in (r.stdout or "").splitlines():
        name = line.split("==", 1)[0].strip().lower()
        if name:
            out.add(name)
    return out


def pip_install(packages, upgrade: bool = False, timeout: int = 300) -> dict:
    if not get("allow_package_install", True):
        return {"error": "package installation is disabled (allow_package_install=false in config)"}
    # Install into THIS interpreter's environment (pentest-ai's venv) so the same
    # interpreter run_script uses can import the package. sys.executable is an
    # absolute path, unaffected by the startup venv-scrub of PATH.
    py = sys.executable

    pkgs = [packages] if isinstance(packages, str) else list(packages or [])
    pkgs = [str(p).strip() for p in pkgs if str(p).strip()]
    if not pkgs:
        return {"error": "no packages specified"}
    # Reject args that look like flags — prevents '--target', '-r', etc. injection.
    flags = [p for p in pkgs if p.startswith("-")]
    if flags:
        return {"error": f"refusing package arguments that look like flags: {flags}"}

    # Skip dists already installed (unless upgrading) so we don't reinstall what the
    # environment already provides (impacket, requests, …). Version-pinned specs are
    # always passed through to pip so it can resolve the exact version.
    present: list = []
    if not upgrade:
        have = _installed_dists(py)
        bare = {p: _SPEC_SPLIT.split(p, 1)[0].strip().lower() for p in pkgs}
        present = [p for p in pkgs if p == bare[p] and bare[p] in have]
        pkgs = [p for p in pkgs if p not in present]
        if not pkgs:
            return {"success": True, "installed": [], "already_present": present,
                    "note": "All requested packages are already installed — nothing to do."}

    cmd = [py, "-m", "pip", "install", "--disable-pip-version-check"]
    if upgrade:
        cmd.append("--upgrade")
    cmd += pkgs
    # Point pip's build/temp dirs (the /tmp/pip-* trees) at the assessment scratch.
    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env=paths.scratch_env())
    except subprocess.TimeoutExpired:
        return {"error": f"pip install timed out after {timeout}s — retry with background=true",
                "_command": f"{py} -m pip install {' '.join(pkgs)}"}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    ok = proc.returncode == 0
    return {
        "success":         ok,
        "exit_code":       proc.returncode,
        "installed":       pkgs if ok else [],
        "already_present": present,
        "stdout":          (proc.stdout or "")[-OUTPUT_CAP:],
        "stderr":          (proc.stderr or "")[-OUTPUT_CAP:],
        "_command":        f"{py} -m pip install {' '.join(pkgs)}",
    }


TOOL_DEFINITION = {
    "name": "pip_install",
    "description": (
        "Install one or more Python packages (pip) into the environment running the engagement. "
        "Use this when a script you want to run with run_script needs a library that isn't "
        "installed (e.g. pwntools, requests, paramiko, impacket, lxml). Provide package names "
        "(optionally with version specifiers like 'requests==2.31.0'). Returns success and pip "
        "output. For a slow install, set background=true."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "packages": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Package names to install, e.g. ['pwntools', 'requests==2.31.0'].",
            },
            "upgrade": {
                "type": "boolean",
                "description": "Pass --upgrade to pip (default false).",
            },
            "timeout": {
                "type": "integer",
                "description": "Install timeout seconds (default 300). Use background=true for slow installs.",
            },
        },
        "required": ["packages"],
    },
}
