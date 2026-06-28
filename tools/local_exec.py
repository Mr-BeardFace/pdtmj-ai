"""Run a shell command on the LOCAL box (the Kali host running PDTMJ-AI) to inspect
downloaded or generated files — strings, cat, grep, ls, file, unzip, xxd, etc."""
import shutil
import subprocess
from core import proc as runner

OUTPUT_CAP = 16000


def local_exec(command: str, timeout: int = 60) -> dict:
    if not command or not command.strip():
        return {"error": "command is required"}
    bash = shutil.which("bash")
    if not bash:
        return {"error": "bash not found in PATH"}
    try:
        proc = runner.run([bash, "-c", command], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"command timed out after {timeout}s — use background=true for slow ops",
                "_command": command}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "_command": command}
    return {
        "exit_code": proc.returncode,
        "stdout":    (proc.stdout or "")[:OUTPUT_CAP],
        "stderr":    (proc.stderr or "")[:OUTPUT_CAP],
        "_command":  command,
    }


TOOL_DEFINITION = {
    "name": "local_exec",
    "description": (
        "Run a shell command on the LOCAL machine running PDTMJ-AI (your Kali box) — NOT the "
        "target. Use it to inspect files you downloaded or generated locally: strings, cat, grep, "
        "ls, file, unzip, head/tail, xxd, sha256sum, etc. Files pulled off a target land in the "
        "downloads dir, which is the working directory, so you can reference them by name "
        "(e.g. \"strings UserInfo.exe | grep -i pass\"). Do NOT use web_exec, ssh_exec, "
        "oob_listener, nc, or http_request to read a local file — those act on the TARGET. For "
        "heavier custom scripting use run_script; for a quick command this is the tool."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to run locally on the Kali box."},
            "timeout": {"type": "integer", "description": "Timeout seconds (default 60). Use background=true for slow ops."},
        },
        "required": ["command"],
    },
}
