import re
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def readelf_analyze(path: str, section: Optional[str] = None,
                    flags: Optional[str] = None) -> dict:
    if not shutil.which("readelf"):
        return {"error": "readelf not found in PATH"}

    if section:
        cmd = ["readelf", f"-{section}", path]
    else:
        # Run with -a for everything, but that's verbose — use targeted flags
        cmd = ["readelf", "-h", "-S", "-l", "-d", "-s", "-r", "-n", "-p", ".comment", path]

    if flags:
        import shlex
        cmd = ["readelf"] + shlex.split(flags) + [path]

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"error": "readelf timed out"}

    output = proc.stdout + proc.stderr
    result = _parse_output(output, path)
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, path: str) -> dict:
    lines = output.splitlines()

    # Extract ELF header fields
    header: dict = {}
    for line in lines:
        for field in ["Class:", "Data:", "Type:", "Machine:", "Entry point:", "OS/ABI:"]:
            if field in line:
                val = line.split(":", 1)[-1].strip()
                header[field.rstrip(":")] = val

    # Extract sections
    sections: list = []
    in_sections = False
    for line in lines:
        if "Section Headers:" in line or "There are" in line and "section headers" in line:
            in_sections = True
            continue
        if in_sections and re.match(r"\s+\[\s*\d+\]", line):
            parts = line.split()
            if len(parts) >= 3:
                sections.append({"name": parts[1] if len(parts) > 1 else "", "type": parts[2] if len(parts) > 2 else ""})
        if in_sections and line.strip() == "":
            in_sections = False

    # Extract dynamic libraries
    libs: list = []
    for line in lines:
        m = re.search(r"\(NEEDED\)\s+Shared library:\s+\[(.+?)\]", line)
        if m:
            libs.append(m.group(1))

    # Look for interesting symbols
    symbols: list = []
    for line in lines:
        if re.search(r"\b(system|exec|popen|dlopen|mmap|socket|connect|recv|send)\b", line):
            symbols.append(line.strip()[:120])

    # Security features: RELRO, canary, NX, PIE
    security_notes: list = []
    output_lower = output.lower()
    if "gnu_relro" in output_lower:
        security_notes.append("RELRO: yes")
    if "stack_chk" in output_lower or "__stack_chk_fail" in output_lower:
        security_notes.append("Stack canary: yes")
    if "gnu_stack" in output_lower:
        if "rw " in output_lower:
            security_notes.append("NX: likely disabled (RW stack)")
        else:
            security_notes.append("NX: likely enabled")

    return {
        "path":            path,
        "elf_header":      header,
        "sections":        sections[:40],
        "shared_libs":     libs,
        "interesting_symbols": list(dict.fromkeys(symbols))[:20],
        "security_notes":  security_notes,
        "raw":             output[:8000],
    }


TOOL_DEFINITION = {
    "name": "readelf_analyze",
    "description": (
        "Analyze an ELF binary using readelf. "
        "Extracts: ELF header (class, architecture, entry point), section headers, "
        "dynamic library dependencies, symbol table, relocations, and notes. "
        "Automatically checks for security features: RELRO, stack canary, NX bit. "
        "Use section='S' for section headers only, 'h' for ELF header, 'd' for dynamic section. "
        "Or omit section for a comprehensive analysis."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":    {"type": "string", "description": "Path to ELF binary"},
            "section": {"type": "string", "description": "Single readelf flag: 'h' (header), 'S' (sections), 'd' (dynamic), 's' (symbols), 'r' (relocations). Omit for comprehensive output."},
            "flags":   {"type": "string", "description": "Full custom readelf flags, e.g. '-a' for all"},
        },
        "required": ["path"],
    },
}
