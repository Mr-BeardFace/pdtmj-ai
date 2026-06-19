import re
import shutil
import subprocess
from typing import Optional

from core import proc as runner


def masscan(target: str, ports: str = "1-65535", rate: int = 1000,
            flags: Optional[str] = None) -> dict:
    if not shutil.which("masscan"):
        return {"error": "masscan not found in PATH"}

    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--open-only", "-oJ", "-"]
    if flags:
        import shlex
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "masscan timed out", "target": target}

    result = _parse_json(proc.stdout, target)
    result["_command"] = " ".join(cmd)
    return result


def _parse_json(output: str, target: str) -> dict:
    import json
    open_ports: list = []
    # masscan -oJ outputs a JSON array, but sometimes with trailing comma issues
    # Strip the outer array wrapper and parse individual objects
    lines = output.strip()
    if not lines or lines in ("", "[]", "[\n]"):
        return {"target": target, "open_ports": [], "count": 0}

    # Remove outer brackets and split on record boundaries
    lines = re.sub(r"^\s*\[\s*", "", lines)
    lines = re.sub(r"\s*,?\s*\]\s*$", "", lines)
    records = re.split(r"\}\s*,\s*\{", lines)

    for rec in records:
        rec = rec.strip().strip(",")
        if not rec.startswith("{"):
            rec = "{" + rec
        if not rec.endswith("}"):
            rec = rec + "}"
        try:
            obj = json.loads(rec)
        except json.JSONDecodeError:
            continue
        ip = obj.get("ip", "")
        for port_info in obj.get("ports", []):
            open_ports.append({
                "ip":       ip,
                "port":     port_info.get("port", 0),
                "protocol": port_info.get("proto", "tcp"),
                "status":   port_info.get("status", "open"),
            })

    return {"target": target, "open_ports": open_ports, "count": len(open_ports)}


TOOL_DEFINITION = {
    "name": "masscan",
    "description": (
        "Fast TCP/UDP port scanner using masscan. Significantly faster than nmap for "
        "large ranges or full-port scans. Returns open ports per IP. Use for initial "
        "broad port discovery across a range, then follow up with nmap for service detection."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP address or CIDR range to scan, e.g. '10.10.10.5' or '10.10.10.0/24'",
            },
            "ports": {
                "type": "string",
                "description": "Port range to scan, e.g. '1-65535', '80,443,8080', '22,80,443'. Default: 1-65535",
            },
            "rate": {
                "type": "integer",
                "description": "Packets per second. 1000 is safe; go higher only on local networks. Default: 1000",
            },
            "flags": {
                "type": "string",
                "description": "Additional masscan flags as a string, e.g. '--banners'",
            },
            "background": {
                "type": "boolean",
                "description": "Run as a background job and keep working; results are delivered automatically when it finishes. Use for large CIDR sweeps so it doesn't block.",
            },
        },
        "required": ["target"],
    },
}
