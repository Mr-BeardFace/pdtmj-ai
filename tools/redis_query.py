import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def redis_query(target: str, port: int = 6379, command: str = "INFO",
                password: Optional[str] = None, flags: Optional[str] = None) -> dict:
    if not shutil.which("redis-cli"):
        return {"error": "redis-cli not found in PATH"}

    cmd = ["redis-cli", "-h", target, "-p", str(port)]

    if password:
        cmd += ["-a", password, "--no-auth-warning"]

    if flags:
        cmd += shlex.split(flags)

    # Split multi-line commands into individual invocations
    cmd += command.split()

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "redis-cli timed out"}

    output = (proc.stdout + proc.stderr).strip()
    result = _parse_info(output, command)
    result.update({
        "target":   f"{target}:{port}",
        "command":  command,
        "_command": " ".join(cmd),
    })
    return result


def _parse_info(output: str, command: str) -> dict:
    if command.upper().startswith("INFO"):
        parsed: dict = {}
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, _, v = line.partition(":")
                parsed[k] = v
        return {"output": output[:8000], "parsed_info": parsed, "success": bool(output)}

    # CONFIG GET, KEYS, etc.
    lines = [l for l in output.splitlines() if l.strip()]
    return {"output": output[:8000], "lines": lines, "success": bool(output)}


TOOL_DEFINITION = {
    "name": "redis_query",
    "description": (
        "Interact with a Redis server via redis-cli. "
        "Use to: enumerate server info, check auth, read keys, test for unauthenticated access. "
        "Common recon commands: "
        "'INFO' — server/memory/stats; "
        "'CONFIG GET *' — all config (shows bind/requirepass); "
        "'KEYS *' — list all keys (dangerous on large servers); "
        "'DBSIZE' — number of keys; "
        "'GET keyname' — read a value. "
        "No password = unauthenticated access, annotate as critical misconfiguration."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target":   {"type": "string", "description": "Redis server IP or hostname"},
            "port":     {"type": "integer", "description": "Redis port. Default: 6379"},
            "command":  {"type": "string", "description": "Redis command to run. Default: INFO"},
            "password": {"type": "string", "description": "Redis AUTH password"},
            "flags":    {"type": "string", "description": "Additional redis-cli flags"},
        },
        "required": ["target"],
    },
}
