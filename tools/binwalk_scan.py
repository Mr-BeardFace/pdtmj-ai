import re
import shlex
import shutil
import subprocess
from core import proc as runner
import tempfile
import os
from typing import Optional


def binwalk_scan(path: str, extract: bool = False, flags: Optional[str] = None) -> dict:
    if not shutil.which("binwalk"):
        return {"error": "binwalk not found in PATH. Install: apt install binwalk"}

    if extract:
        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = ["binwalk", "--extract", "--directory", tmpdir, path]
            if flags:
                cmd += shlex.split(flags)
            try:
                proc = runner.run(cmd, capture_output=True, text=True, timeout=120)
            except subprocess.TimeoutExpired:
                return {"error": "binwalk timed out"}

            output = proc.stdout + proc.stderr
            extracted = []
            for root, dirs, files in os.walk(tmpdir):
                for f in files:
                    fpath = os.path.join(root, f)
                    extracted.append({
                        "path": fpath,
                        "size": os.path.getsize(fpath),
                    })

            result = _parse_output(output, path)
            result["extracted_files"] = extracted[:50]
            result["_command"] = " ".join(cmd)
            return result
    else:
        cmd = ["binwalk", path]
        if flags:
            cmd += shlex.split(flags)
        try:
            proc = runner.run(cmd, capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            return {"error": "binwalk timed out"}

        result = _parse_output(proc.stdout + proc.stderr, path)
        result["_command"] = " ".join(cmd)
        return result


def _parse_output(output: str, path: str) -> dict:
    signatures: list = []

    for line in output.splitlines():
        # Binwalk output: DECIMAL   HEX     DESCRIPTION
        m = re.match(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", line.strip())
        if m:
            signatures.append({
                "offset_decimal": int(m.group(1)),
                "offset_hex":     m.group(2),
                "description":    m.group(3),
            })

    return {
        "path":       path,
        "signatures": signatures,
        "count":      len(signatures),
        "raw":        output[:8000],
    }


TOOL_DEFINITION = {
    "name": "binwalk_scan",
    "description": (
        "Firmware and binary analysis via binwalk. "
        "Scans for embedded file signatures: filesystems (SquashFS, JFFS2, cramfs), "
        "compressed archives (gzip, LZMA, xz), certificates, private keys, "
        "executable code, and boot loaders. "
        "Set extract=true to automatically extract identified components (creates temp directory). "
        "Use on: firmware images, unknown binary blobs, container layers, or any opaque binary."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":    {"type": "string", "description": "Path to the binary/firmware file"},
            "extract": {"type": "boolean", "description": "Extract identified components. Default: false"},
            "flags":   {"type": "string", "description": "Additional binwalk flags, e.g. '-t' for CSV output"},
        },
        "required": ["path"],
    },
}
