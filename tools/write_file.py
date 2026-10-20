"""write_file — write a file into the op's ai_workspace/ directory.

SECURITY: path is hard-sandboxed to OPS_DIR/<op>/ai_workspace/.
Any path that resolves outside that directory is rejected — including
../traversal, absolute paths, and symlinks pointing elsewhere.
Operator files are NEVER touched; AI-written files go here only.
"""
from __future__ import annotations

from pathlib import Path

from core.paths import OPS_DIR


def _active_op() -> str | None:
    try:
        return (OPS_DIR / ".active_op").read_text().strip() or None
    except FileNotFoundError:
        return None


def _workspace(op: str) -> Path:
    return OPS_DIR / op / "ai_workspace"


def write_file(path: str, content: str, op: str | None = None) -> dict:
    op_name = op or _active_op()
    if not op_name:
        return {"error": "no active op — cannot determine ai_workspace path"}

    workspace = _workspace(op_name).resolve()

    # Resolve the requested path relative to ai_workspace if not absolute.
    requested = Path(path)
    if not requested.is_absolute():
        target = (workspace / requested).resolve()
    else:
        target = requested.resolve()

    # Hard sandbox check — must be under workspace, no escape
    try:
        target.relative_to(workspace)
    except ValueError:
        return {
            "error": (
                f"path '{path}' resolves outside ai_workspace/ — "
                "AI-written files must stay under the op's ai_workspace/ directory"
            )
        }

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"written": True, "path": str(target)}
    except Exception as e:
        return {"error": str(e)}


TOOL_DEFINITION = {
    "name": "write_file",
    "description": (
        "Write a file into the current op's ai_workspace/ directory. "
        "Use this to save analysis notes, draft reports, IOC lists, wordlists, "
        "or any AI-generated artifact. "
        "Paths are relative to ai_workspace/ by default (e.g. 'notes/recon.md'). "
        "Absolute paths are accepted only if they resolve inside ai_workspace/. "
        "Operator files and directories outside ai_workspace/ cannot be written — "
        "use annotate_finding or record_fact to persist findings instead."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": (
                    "File path, relative to ai_workspace/ (e.g. 'notes.md', "
                    "'recon/hosts.txt'). Subdirectories are created automatically."
                ),
            },
            "content": {
                "type": "string",
                "description": "Text content to write.",
            },
        },
        "required": ["path", "content"],
    },
}
