"""
Git repository operations for code auditing.
Clone repos, inspect history, grep for sensitive patterns, list commits.
"""
import re
import shlex
import shutil
import subprocess
from core import proc as runner
import tempfile
import os
from typing import Optional


def git_ops(path: str, action: str = "log", query: Optional[str] = None,
            depth: Optional[int] = None, flags: Optional[str] = None) -> dict:
    if not shutil.which("git"):
        return {"error": "git not found in PATH"}

    action = action.lower()

    if action == "clone":
        return _clone(path, depth, flags)
    elif action == "log":
        return _log(path, flags)
    elif action == "grep":
        return _grep(path, query, flags)
    elif action == "blame":
        return _blame(path, query, flags)
    elif action == "show":
        return _show(path, query, flags)
    elif action == "ls-files":
        return _ls_files(path, flags)
    elif action == "stash-list":
        return _stash_list(path, flags)
    else:
        return {"error": f"Unknown action '{action}'. Use: clone, log, grep, blame, show, ls-files, stash-list"}


def _run(cmd: list, cwd: Optional[str] = None, timeout: int = 60) -> tuple:
    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "timed out", -1


def _clone(url: str, depth: Optional[int], flags: Optional[str]) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = ["git", "clone"]
        if depth:
            cmd += ["--depth", str(depth)]
        if flags:
            cmd += shlex.split(flags)
        cmd += [url, tmpdir + "/repo"]

        output, rc = _run(cmd, timeout=120)
        repo_path = tmpdir + "/repo"
        exists = os.path.isdir(repo_path + "/.git")

        return {
            "action":    "clone",
            "url":       url,
            "success":   rc == 0 and exists,
            "path":      repo_path if exists else None,
            "output":    output[:1000],
            "_command":  " ".join(cmd),
            "note":      "Repository cloned to temp directory — run further git_ops against the returned path." if exists else "Clone failed.",
        }


def _log(path: str, flags: Optional[str]) -> dict:
    cmd = ["git", "log", "--oneline", "--all", "--no-merges", "-50",
           "--format=%h %ae %ai %s"]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    commits: list = []
    for line in output.splitlines():
        parts = line.split(" ", 3)
        if len(parts) >= 4:
            commits.append({
                "hash":    parts[0],
                "author":  parts[1],
                "date":    parts[2],
                "message": parts[3],
            })

    return {
        "action":   "log",
        "path":     path,
        "commits":  commits,
        "count":    len(commits),
        "_command": " ".join(cmd),
    }


def _grep(path: str, query: Optional[str], flags: Optional[str]) -> dict:
    if not query:
        # Default: search for common sensitive patterns
        query = r"(password|passwd|secret|api_key|access_key|private_key|BEGIN RSA|token|credential)"

    cmd = ["git", "grep", "-i", "-n", "-P", query, "--all-branches"]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    matches: list = []
    for line in output.splitlines()[:200]:
        parts = line.split(":", 2)
        if len(parts) >= 3:
            matches.append({
                "ref":    parts[0],
                "file":   parts[1],
                "line":   parts[2][:200],
            })
        else:
            matches.append({"raw": line[:200]})

    return {
        "action":   "grep",
        "query":    query,
        "path":     path,
        "matches":  matches,
        "count":    len(matches),
        "_command": " ".join(cmd),
    }


def _blame(path: str, file_path: Optional[str], flags: Optional[str]) -> dict:
    if not file_path:
        return {"error": "blame action requires query (file path to blame)"}

    cmd = ["git", "blame", "--porcelain", file_path]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    authors: dict = {}
    for line in output.splitlines():
        author_m = re.match(r"^author (.+)", line)
        if author_m:
            name = author_m.group(1)
            authors[name] = authors.get(name, 0) + 1

    return {
        "action":   "blame",
        "file":     file_path,
        "authors":  [{"name": k, "lines": v} for k, v in sorted(authors.items(), key=lambda x: -x[1])],
        "raw":      output[:8000],
        "_command": " ".join(cmd),
    }


def _show(path: str, commit_ref: Optional[str], flags: Optional[str]) -> dict:
    if not commit_ref:
        commit_ref = "HEAD"

    cmd = ["git", "show", "--stat", commit_ref]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    return {
        "action":    "show",
        "ref":       commit_ref,
        "output":    output[:8000],
        "_command":  " ".join(cmd),
    }


def _ls_files(path: str, flags: Optional[str]) -> dict:
    cmd = ["git", "ls-files"]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    files = [l.strip() for l in output.splitlines() if l.strip()]

    # Flag interesting file types
    sensitive = [f for f in files if re.search(
        r"\.(env|pem|key|pfx|p12|crt|cer|jks|keystore|cfg|conf|config|ini|secret|credentials|htpasswd)$"
        r"|^\.env|Dockerfile|docker-compose|Jenkinsfile|\.travis|\.github/workflows",
        f, re.IGNORECASE
    )]

    return {
        "action":          "ls-files",
        "path":            path,
        "files":           files[:300],
        "total":           len(files),
        "sensitive_files": sensitive,
        "_command":        " ".join(cmd),
    }


def _stash_list(path: str, flags: Optional[str]) -> dict:
    cmd = ["git", "stash", "list"]
    if flags:
        cmd += shlex.split(flags)

    output, rc = _run(cmd, cwd=path)
    stashes = [l.strip() for l in output.splitlines() if l.strip()]

    return {
        "action":   "stash-list",
        "path":     path,
        "stashes":  stashes,
        "count":    len(stashes),
        "_command": " ".join(cmd),
        "note":     "Use 'git stash show stash@{N}' to inspect stash contents — stashes may contain sensitive data." if stashes else "",
    }


TOOL_DEFINITION = {
    "name": "git_ops",
    "description": (
        "Git repository operations for code security auditing.\n"
        "actions:\n"
        "- 'log': show last 50 commits (hash, author, date, message) — reveals contributor emails, sensitive commit messages\n"
        "- 'grep': search all branches for patterns — default searches for password/secret/key patterns\n"
        "- 'ls-files': list all tracked files — highlights sensitive file types (.env, .pem, .key, etc.)\n"
        "- 'stash-list': list git stashes — stashes often contain work-in-progress with sensitive data\n"
        "- 'show': show contents of a specific commit or HEAD\n"
        "- 'blame': show authorship for a specific file\n"
        "- 'clone': clone a remote repository (returns temp path for further analysis)\n\n"
        "path: local repo path, or URL for clone action.\n"
        "query: search term for grep, file path for blame/show, depth for clone."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path":   {"type": "string", "description": "Local repo path, or remote URL for clone action"},
            "action": {"type": "string", "description": "'log', 'grep', 'ls-files', 'stash-list', 'show', 'blame', 'clone'. Default: log"},
            "query":  {"type": "string", "description": "Search pattern (grep), file path (blame/show), or remote URL (clone)"},
            "depth":  {"type": "integer", "description": "Clone depth (for clone action). Omit for full history."},
            "flags":  {"type": "string", "description": "Additional git flags"},
        },
        "required": ["path"],
    },
}
