"""Telnet client — socket-based with Telnet IAC option negotiation, optional
login, and a sequence of commands. Avoids the deprecated/removed telnetlib."""
import socket
from typing import Optional

_IAC, _DONT, _DO, _WONT, _WILL = 255, 254, 253, 252, 251
RECV_CAP = 16000


def _read(sock: socket.socket, timeout: int, until: Optional[str] = None,
          max_bytes: int = RECV_CAP) -> bytes:
    """Read from the socket, transparently answering IAC option negotiations
    (refuse everything) and stripping them from the returned data."""
    sock.settimeout(timeout)
    out = bytearray()
    try:
        while len(out) < max_bytes:
            chunk = sock.recv(1024)
            if not chunk:
                break
            i = 0
            while i < len(chunk):
                b = chunk[i]
                if b == _IAC and i + 1 < len(chunk):
                    cmd = chunk[i + 1]
                    if cmd in (_DO, _DONT, _WILL, _WONT) and i + 2 < len(chunk):
                        opt = chunk[i + 2]
                        resp = _WONT if cmd == _DO else (_DONT if cmd == _WILL else None)
                        if resp is not None:
                            try:
                                sock.sendall(bytes([_IAC, resp, opt]))
                            except OSError:
                                pass
                        i += 3
                        continue
                    i += 2
                    continue
                out.append(b)
                i += 1
            if until and until.encode() in bytes(out):
                break
    except socket.timeout:
        pass
    return bytes(out)


def telnet(host: str, port: int = 23, username: Optional[str] = None,
           password: Optional[str] = None, commands: Optional[list] = None,
           timeout: int = 10) -> dict:
    display = f"telnet {host} {port}"
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as e:
        return {"error": f"connection failed: {e}", "host": host, "port": port, "_command": display}

    transcript: list[str] = []
    try:
        transcript.append(_read(sock, timeout, until="login:").decode("utf-8", "replace"))
        if username is not None:
            sock.sendall((username + "\r\n").encode())
            transcript.append(_read(sock, timeout, until="assword").decode("utf-8", "replace"))
            if password is not None:
                sock.sendall((password + "\r\n").encode())
                transcript.append(_read(sock, timeout).decode("utf-8", "replace"))
        for cmd in (commands or []):
            sock.sendall((str(cmd) + "\r\n").encode())
            transcript.append(_read(sock, timeout).decode("utf-8", "replace"))
        sock.close()
    except OSError as e:
        try:
            sock.close()
        except Exception:
            pass
        return {"error": f"telnet error: {e}", "host": host, "_command": display}

    full = "\n".join(t for t in transcript if t)
    return {"host": host, "port": int(port), "connected": True,
            "transcript": full[:RECV_CAP], "truncated": len(full) > RECV_CAP,
            "_command": display}


TOOL_DEFINITION = {
    "name": "telnet",
    "description": (
        "Connect to a Telnet service. Handles Telnet option negotiation, optionally logs in with "
        "username/password, and runs a list of commands, returning the transcript. Use for Telnet "
        "shells and line-based services. For non-negotiated raw TCP use `nc`."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target host or IP."},
            "port": {"type": "integer", "description": "Telnet port (default 23)."},
            "username": {"type": "string", "description": "Login username (sent at the login: prompt)."},
            "password": {"type": "string", "description": "Login password (sent at the password prompt)."},
            "commands": {"type": "array", "items": {"type": "string"},
                         "description": "Commands to run after login, in order."},
            "timeout": {"type": "integer", "description": "Per-read timeout seconds (default 10)."},
        },
        "required": ["host"],
    },
}
