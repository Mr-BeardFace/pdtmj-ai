"""Extract a crackable hash from a file with John's *2john helpers (zip2john,
ssh2john, keepass2john, …). These ship with Kali's `john` package. Output is the
hash string (the `filename:` prefix stripped) plus a suggested hashcat -m mode, so
it can drop straight into hashcat_crack — or into the `john` tool, which auto-detects.
"""
import os
import shutil
import subprocess

from core import proc as runner

OUTPUT_CAP = 8000

# format -> (*2john binary, suggested hashcat -m mode). Modes marked * vary by the
# file's exact variant — confirm with `hashcat --identify` or just use john.
_EXTRACTORS = {
    "zip":       ("zip2john",       13600),
    "rar":       ("rar2john",       13000),
    "7z":        ("7z2john",        11600),
    "pdf":       ("pdf2john",       10500),   # *10400-10700 / 25400
    "office":    ("office2john",     9600),   # *9400/9500/9600 / 25300
    "ssh":       ("ssh2john",       22911),
    "keepass":   ("keepass2john",   13400),
    "bitlocker": ("bitlocker2john", 22100),
    "gpg":       ("gpg2john",       17010),   # *16700/17010+
}

# Filename hints when the caller doesn't pass a format.
_EXT_FORMAT = {
    ".zip": "zip", ".rar": "rar", ".7z": "7z", ".pdf": "pdf",
    ".docx": "office", ".xlsx": "office", ".pptx": "office",
    ".doc": "office", ".xls": "office", ".ppt": "office",
    ".kdbx": "keepass", ".kdb": "keepass",
    ".pem": "ssh", ".key": "ssh", ".ppk": "ssh",
    ".gpg": "gpg", ".asc": "gpg", ".pgp": "gpg",
    ".vhd": "bitlocker", ".bek": "bitlocker",
}


def _infer_format(path: str) -> str | None:
    base = os.path.basename(path).lower()
    if base.startswith("id_") or base in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"):
        return "ssh"
    _, ext = os.path.splitext(base)
    return _EXT_FORMAT.get(ext)


def _find_extractor(name: str) -> list[str] | None:
    """Resolve a *2john helper to a runnable command — it may be a binary on PATH or
    a python/perl script under the john share dir."""
    for cand in (name, name + ".py", name + ".pl"):
        p = shutil.which(cand)
        if p:
            return [p]
    for base in ("/usr/share/john", "/usr/lib/john", "/opt/john/run"):
        for ext, interp in ((".py", "python3"), (".pl", "perl"), ("", None)):
            fp = os.path.join(base, name + ext)
            if os.path.exists(fp):
                return [interp, fp] if interp else [fp]
    return None


def _strip_to_hash(stdout: str) -> str:
    """*2john prints `filename:$tag$...`; the hash for these formats begins at the
    first `$`, so slice there to drop the filename prefix hashcat won't accept."""
    for line in stdout.splitlines():
        line = line.strip()
        if "$" in line:
            return line[line.index("$"):]
    return stdout.strip()


def hash_extract(file: str, format: str | None = None, timeout: int = 120) -> dict:
    if not file or not os.path.exists(file):
        return {"error": f"file not found: {file}"}
    fmt = (format or _infer_format(file) or "").strip().lower()
    if fmt not in _EXTRACTORS:
        return {"error": f"unknown/undetected format for {os.path.basename(file)} — pass "
                         f"format=", "known_formats": sorted(_EXTRACTORS)}

    extractor, mode = _EXTRACTORS[fmt]
    cmd_prefix = _find_extractor(extractor)
    if not cmd_prefix:
        return {"error": f"{extractor} not found — install John: apt install john"}

    cmd = cmd_prefix + [file]
    try:
        proc = runner.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"{extractor} timed out", "_command": " ".join(cmd)}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "_command": " ".join(cmd)}

    out = (proc.stdout or "")
    h = _strip_to_hash(out)
    if not h or "$" not in h:
        return {"error": f"{extractor} produced no hash (wrong format, or the file isn't "
                         "encrypted/password-protected?)",
                "stderr": (proc.stderr or "")[:OUTPUT_CAP], "_command": " ".join(cmd)}
    return {
        "format":       fmt,
        "extractor":    extractor,
        "hash":         h,
        "hashcat_mode": mode,
        "note": (f"Crack it with hashcat_crack(hash_mode={mode}) or the john tool (john "
                 "auto-detects the format). Some office/pdf/gpg modes vary by variant — "
                 "confirm with `hashcat --identify` or just use john."),
        "_command":     " ".join(cmd),
    }


TOOL_DEFINITION = {
    "name": "hash_extract",
    "description": (
        "Extract a crackable hash from a password-protected/encrypted file using John's *2john "
        "helpers (zip2john, rar2john, 7z2john, pdf2john, office2john, ssh2john, keepass2john, "
        "bitlocker2john, gpg2john). Point it at a file you downloaded (e.g. a protected zip, a "
        "KeePass .kdbx, an encrypted SSH key, an Office doc); it returns the hash with the "
        "filename prefix stripped plus a suggested hashcat -m mode. Then crack it with "
        "hashcat_crack(hash_mode=...) or the john tool. Format is inferred from the extension when "
        "not given."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file":    {"type": "string", "description": "Path to the file (e.g. one in the downloads dir)."},
            "format":  {"type": "string", "description": "zip|rar|7z|pdf|office|ssh|keepass|bitlocker|gpg. Inferred from the extension if omitted."},
            "timeout": {"type": "integer", "description": "Extractor timeout seconds (default 120)."},
        },
        "required": ["file"],
    },
}
