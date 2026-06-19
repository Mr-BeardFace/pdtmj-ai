"""Raw TCP/UDP client (netcat-style) — banner grab, send a payload, read a response."""
import socket
from typing import Optional

RECV_CAP = 16000


def nc(host: str, port: int, data: Optional[str] = None, timeout: int = 10,
       protocol: str = "tcp", read: bool = True) -> dict:
    proto = (protocol or "tcp").lower()
    display = f"nc {'-u ' if proto == 'udp' else ''}{host} {port}"
    try:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            if data is not None:
                s.sendto(data.encode(), (host, int(port)))
            received = b""
            if read:
                try:
                    received, _ = s.recvfrom(RECV_CAP)
                except socket.timeout:
                    pass
            s.close()
        else:
            s = socket.create_connection((host, int(port)), timeout=timeout)
            s.settimeout(timeout)
            if data is not None:
                s.sendall(data.encode())
            received = b""
            if read:
                try:
                    while len(received) < RECV_CAP:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        received += chunk
                except socket.timeout:
                    pass
            s.close()
    except OSError as e:
        return {"error": f"connection failed: {e}", "host": host, "port": port, "_command": display}

    text = received.decode("utf-8", errors="replace")
    return {
        "host": host, "port": int(port), "protocol": proto, "connected": True,
        "bytes": len(received), "received": text[:RECV_CAP],
        "truncated": len(text) > RECV_CAP, "_command": display,
    }


TOOL_DEFINITION = {
    "name": "nc",
    "description": (
        "Raw TCP (or UDP) connection like netcat — open a socket to host:port, optionally send "
        "`data`, and read what comes back. Use for banner grabbing, talking to custom/unknown "
        "services, sending crafted payloads, or probing a port directly. For line-based or "
        "negotiated terminal services prefer the `telnet` tool; for FTP use `ftp`."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "Target host or IP."},
            "port": {"type": "integer", "description": "Target port."},
            "data": {"type": "string", "description": "Optional bytes to send after connecting (e.g. a request or payload). Add \\r\\n yourself if the protocol needs it."},
            "protocol": {"type": "string", "enum": ["tcp", "udp"], "description": "Transport (default tcp)."},
            "read": {"type": "boolean", "description": "Read a response after connecting/sending (default true)."},
            "timeout": {"type": "integer", "description": "Socket timeout seconds (default 10)."},
        },
        "required": ["host", "port"],
    },
}
