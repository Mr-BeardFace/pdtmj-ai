"""read_file — read a local file for analysis.

Operator-accessible files only. No subprocess execution, no side effects.
Max 256 KB returned per call; use offset/limit for larger files.
"""
from __future__ import annotations

from pathlib import Path

_MAX_BYTES = 256 * 1024


def read_file(
    path: str,
    offset: int = 0,
    limit: int | None = None,
    encoding: str = "utf-8",
) -> dict:
    try:
        p = Path(path).expanduser().resolve()
    except Exception as e:
        return {"error": f"invalid path: {e}"}

    if not p.exists():
        return {"error": f"file not found: {path}"}
    if not p.is_file():
        return {"error": f"not a file: {path}"}

    try:
        size = p.stat().st_size
        max_read = min(_MAX_BYTES, limit if limit is not None else _MAX_BYTES)
        with p.open("rb") as f:
            if offset:
                f.seek(offset)
            raw = f.read(max_read)
        truncated = (offset + len(raw)) < size
        text = raw.decode(encoding, errors="replace")
        result = {"path": str(p), "size": size, "content": text}
        if truncated:
            result["truncated"] = True
            result["next_offset"] = offset + len(raw)
        return result
    except PermissionError:
        return {"error": f"permission denied: {path}"}
    except Exception as e:
        return {"error": str(e)}


TOOL_DEFINITION = {
    "name": "read_file",
    "description": (
        "Read the contents of a local file. Use for reading operator-provided files, "
        "captured loot, configuration files, or any text artifact on disk. "
        "Returns up to 256 KB per call; use offset to page through larger files. "
        "Binary files are decoded as UTF-8 with replacement for unrecognised bytes."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Absolute or home-relative (~) path to the file.",
            },
            "offset": {
                "type": "integer",
                "description": "Byte offset to start reading from (default 0).",
            },
            "limit": {
                "type": "integer",
                "description": "Max bytes to return (default and cap: 262144).",
            },
            "encoding": {
                "type": "string",
                "description": "Text encoding (default utf-8).",
            },
        },
        "required": ["path"],
    },
}
