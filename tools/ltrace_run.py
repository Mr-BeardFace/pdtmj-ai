import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def ltrace_run(binary: str, args: Optional[str] = None,
               functions: Optional[str] = None,
               timeout_seconds: int = 30,
               flags: Optional[str] = None) -> dict:
    if not shutil.which("ltrace"):
        return {"error": "ltrace not found in PATH. Install: apt install ltrace"}

    cmd = ["ltrace", "-s", "256"]

    if functions:
        cmd += ["-e", functions]

    if flags:
        cmd += shlex.split(flags)

    cmd.append(binary)
    if args:
        cmd += shlex.split(args)

    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"error": f"ltrace timed out after {timeout_seconds}s"}

    # ltrace output goes to stderr
    ltrace_output = proc.stderr
    result = _parse_output(ltrace_output, binary)
    result["stdout"] = proc.stdout[:4000]
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, binary: str) -> dict:
    lines = output.splitlines()

    crypto_calls: list = []
    string_ops: list = []
    file_ops: list = []
    auth_ops: list = []

    crypto_funcs = {"EVP_", "RSA_", "AES_", "MD5", "SHA", "hmac", "crypto", "ssl", "tls",
                    "DES_", "BN_", "EC_", "ECDSA"}
    string_funcs  = {"strcmp", "strncmp", "strcasecmp", "memcmp", "strstr", "strcat", "strcpy"}
    file_funcs    = {"fopen", "fread", "fwrite", "fclose", "open", "read", "write"}
    auth_patterns = ["password", "passwd", "auth", "login", "token", "secret", "key", "cred"]

    for line in lines:
        func_m = re.match(r"^(?:\[pid\s+\d+\]\s+)?(\w+)\(", line)
        if func_m:
            name = func_m.group(1)
            if any(c in name for c in crypto_funcs):
                crypto_calls.append(line[:200])
            if name in string_funcs:
                string_ops.append(line[:200])
            if name in file_funcs:
                file_ops.append(line[:200])

        line_lower = line.lower()
        if any(p in line_lower for p in auth_patterns):
            auth_ops.append(line[:200])

    return {
        "binary":          binary,
        "total_calls":     len(lines),
        "crypto_calls":    crypto_calls[:100],
        "string_compare":  string_ops[:100],
        "file_operations": file_ops[:100],
        "auth_related":    auth_ops[:50],
        "raw":             output[:16000],
    }


TOOL_DEFINITION = {
    "name": "ltrace_run",
    "description": (
        "Trace shared library function calls made by a binary using ltrace. "
        "Complements strace — ltrace shows libc/library calls, strace shows kernel calls. "
        "Reveals: string comparisons (for hardcoded credential checks), crypto operations, "
        "file I/O via libc, and auth-related function calls. "
        "functions: comma/wildcard filter like 'strcmp,memcmp' or '*crypt*'. "
        "Particularly useful for finding hardcoded passwords via strcmp() calls."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "binary":          {"type": "string", "description": "Path to binary to execute and trace"},
            "args":            {"type": "string", "description": "Arguments to pass to the binary"},
            "functions":       {"type": "string", "description": "Function filter, e.g. 'strcmp,memcmp' or '*crypt*'"},
            "timeout_seconds": {"type": "integer", "description": "Execution timeout in seconds. Default: 30"},
            "flags":           {"type": "string", "description": "Additional ltrace flags"},
        },
        "required": ["binary"],
    },
}
