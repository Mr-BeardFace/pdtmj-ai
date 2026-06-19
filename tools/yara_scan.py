import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def yara_scan(rules_path: str, target_path: str, flags: Optional[str] = None) -> dict:
    if not shutil.which("yara"):
        return {"error": "yara not found in PATH. Install: apt install yara"}

    cmd = ["yara", "-r", rules_path, target_path]
    if flags:
        cmd += shlex.split(flags)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "yara timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, rules_path, target_path)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, rules_path: str, target_path: str) -> dict:
    matches: list = []

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("error") or line.startswith("warning"):
            continue
        # YARA output: RuleName /path/to/file
        m = re.match(r"^(\S+)\s+(.+)$", line)
        if m:
            matches.append({
                "rule":  m.group(1),
                "file":  m.group(2),
            })

    errors = [l for l in output.splitlines() if l.startswith("error")]

    return {
        "rules_path":  rules_path,
        "target_path": target_path,
        "matches":     matches,
        "count":       len(matches),
        "errors":      errors[:10],
    }


TOOL_DEFINITION = {
    "name": "yara_scan",
    "description": (
        "Scan files for malware patterns and indicators using YARA rules. "
        "rules_path: path to a .yar/.yara file or directory of rule files. "
        "target_path: file or directory to scan (recursive with -r flag). "
        "Common rule sources: /usr/share/yara-rules/, "
        "github.com/Yara-Rules/rules, github.com/Neo23x0/signature-base. "
        "Use to identify malware families, packer signatures, shellcode, and suspicious code patterns."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "rules_path":  {"type": "string", "description": "Path to YARA rules file or directory"},
            "target_path": {"type": "string", "description": "File or directory to scan"},
            "flags":       {"type": "string", "description": "Additional yara flags, e.g. '-s' to print matching strings"},
        },
        "required": ["rules_path", "target_path"],
    },
}
