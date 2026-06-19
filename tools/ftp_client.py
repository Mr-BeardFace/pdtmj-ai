"""FTP client tool — login, list, retrieve, and upload over FTP (ftplib)."""
from io import BytesIO
from typing import Optional

CONTENT_CAP = 16000


def ftp(host: str, port: int = 21, username: str = "anonymous",
        password: Optional[str] = None, action: str = "list",
        path: str = "", data: Optional[str] = None, timeout: int = 15) -> dict:
    from ftplib import FTP, all_errors

    user = username or "anonymous"
    pw = password if password is not None else ("anonymous@" if user == "anonymous" else "")
    display = f"ftp {user}@{host}:{port} {action} {path}".strip()

    client = FTP()
    try:
        client.connect(host, int(port), timeout=timeout)
        client.login(user, pw)
    except all_errors as e:
        try:
            client.close()
        except Exception:
            pass
        return {"error": f"FTP connect/login failed: {e}", "host": host,
                "username": user, "_command": display}

    result: dict = {"host": host, "port": int(port), "username": user,
                    "action": action, "connected": True, "_command": display}
    try:
        if action == "list":
            listing: list[str] = []
            try:
                client.retrlines("LIST " + (path or ""), listing.append)
            except all_errors:
                pass
            names: list[str] = []
            try:
                names = client.nlst(path or "")
            except all_errors:
                pass
            result["listing"] = listing
            result["files"] = names
            result["count"] = len(names) or len(listing)

        elif action in ("retrieve", "get"):
            if not path:
                return {"error": "path is required for retrieve", "_command": display}
            buf = BytesIO()
            client.retrbinary("RETR " + path, buf.write)
            raw = buf.getvalue()
            text = raw.decode("utf-8", errors="replace")
            result["path"] = path
            result["size_bytes"] = len(raw)
            result["content"] = text[:CONTENT_CAP]
            result["truncated"] = len(text) > CONTENT_CAP

        elif action in ("upload", "put"):
            if not path or data is None:
                return {"error": "path and data are required for upload", "_command": display}
            client.storbinary("STOR " + path, BytesIO(data.encode()))
            result["path"] = path
            result["uploaded_bytes"] = len(data)

        else:
            return {"error": f"unknown action {action!r} (use list | retrieve | upload)",
                    "_command": display}
        return result

    except all_errors as e:
        return {"error": f"FTP {action} failed: {e}", "host": host,
                "action": action, "path": path, "_command": display}
    finally:
        try:
            client.quit()
        except Exception:
            try:
                client.close()
            except Exception:
                pass


TOOL_DEFINITION = {
    "name": "ftp",
    "description": (
        "Connect to an FTP service and list directories, retrieve file contents, or upload a "
        "file. Defaults to anonymous login. Use this to actually authenticate with discovered "
        "credentials and read files (where flags, configs, and secrets often live) rather than "
        "guessing — far more reliable than nmap FTP scripts. action: 'list' (default), "
        "'retrieve' (read a file at path), or 'upload' (write `data` to path)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "FTP host or IP."},
            "port": {"type": "integer", "description": "FTP port (default 21)."},
            "username": {"type": "string", "description": "Username (default 'anonymous')."},
            "password": {"type": "string", "description": "Password (default anonymous mail for anonymous login)."},
            "action": {"type": "string", "enum": ["list", "retrieve", "upload"],
                       "description": "list a directory, retrieve a file, or upload a file. Default list."},
            "path": {"type": "string", "description": "Directory to list, or file path to retrieve/upload."},
            "data": {"type": "string", "description": "Content to write when action=upload."},
            "timeout": {"type": "integer", "description": "Timeout seconds (default 15)."},
        },
        "required": ["host"],
    },
}
