import re
import shlex
import shutil
import subprocess
from core import proc as runner
from typing import Optional


def strace_run(binary: str, args: Optional[str] = None, follow_forks: bool = False,
               syscalls: Optional[str] = None, timeout_seconds: int = 30,
               flags: Optional[str] = None) -> dict:
    if not shutil.which("strace"):
        return {"error": "strace not found in PATH"}

    cmd = ["strace", "-s", "256", "-v"]

    if follow_forks:
        cmd.append("-f")
    if syscalls:
        cmd += ["-e", f"trace={syscalls}"]

    if flags:
        cmd += shlex.split(flags)

    cmd.append(binary)
    if args:
        cmd += shlex.split(args)

    try:
        # strace writes to stderr by default
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {"error": f"strace timed out after {timeout_seconds}s (process may still be running)"}

    strace_output = proc.stderr  # strace output goes to stderr
    result = _parse_output(strace_output, binary)
    result["stdout"] = proc.stdout[:4000]
    result["_command"] = " ".join(cmd)
    return result


def _parse_output(output: str, binary: str) -> dict:
    lines = output.splitlines()

    # Categorize syscalls
    network_calls: list = []
    file_ops: list = []
    exec_calls: list = []
    suspicious: list = []

    net_syscalls = {"socket", "connect", "bind", "listen", "accept", "send", "recv",
                    "sendto", "recvfrom", "sendmsg", "recvmsg"}
    file_syscalls = {"open", "openat", "read", "write", "creat", "unlink", "rename",
                     "mkdir", "rmdir", "stat", "fstat", "lstat"}
    exec_syscalls = {"execve", "execveat", "ptrace", "fork", "clone", "mmap", "mprotect"}
    susp_patterns = ["chmod.*777", "shell", "/etc/passwd", "/etc/shadow", "/tmp/",
                     "wget", "curl", "bash", "sh ", "python", "/proc/self"]

    for line in lines:
        syscall_m = re.match(r"^(?:\[pid\s+\d+\]\s+)?(\w+)\(", line)
        if syscall_m:
            name = syscall_m.group(1)
            if name in net_syscalls:
                network_calls.append(line[:200])
            if name in file_syscalls:
                file_ops.append(line[:200])
            if name in exec_syscalls:
                exec_calls.append(line[:200])

        for pat in susp_patterns:
            if re.search(pat, line, re.IGNORECASE):
                suspicious.append(line[:200])
                break

    return {
        "binary":          binary,
        "total_syscalls":  len(lines),
        "network_calls":   network_calls[:200],
        "file_operations": file_ops[:200],
        "exec_calls":      exec_calls[:100],
        "suspicious":      list(dict.fromkeys(suspicious))[:100],
        "raw":             output[:16000],
    }


TOOL_DEFINITION = {
    "name": "strace_run",
    "description": (
        "Trace system calls made by a binary using strace. "
        "Reveals: network connections, file reads/writes, exec calls, memory mappings. "
        "Automatically categorizes network calls, file operations, and exec calls. "
        "Highlights suspicious patterns: /tmp/ writes, shadow file access, shell spawns, etc. "
        "syscalls: comma-separated filter like 'network', 'file', 'execve,connect,open'. "
        "follow_forks=true traces child processes. "
        "Keep timeout_seconds low for interactive programs."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "binary":          {"type": "string", "description": "Path to binary to execute and trace"},
            "args":            {"type": "string", "description": "Arguments to pass to the binary"},
            "follow_forks":    {"type": "boolean", "description": "Follow forked processes (-f). Default: false"},
            "syscalls":        {"type": "string", "description": "Syscall filter, e.g. 'network', 'file', 'execve,connect'"},
            "timeout_seconds": {"type": "integer", "description": "Execution timeout in seconds. Default: 30"},
            "flags":           {"type": "string", "description": "Additional strace flags"},
        },
        "required": ["binary"],
    },
}
