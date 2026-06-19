import os
import shutil
from core import proc as runner


def file_identify(path: str) -> dict:
    result: dict = {"path": path}

    # ── file(1) ──────────────────────────────────────────────────────────────
    if shutil.which("file"):
        try:
            proc = runner.run(["file", "-b", path], capture_output=True, text=True, timeout=10)
            result["file_type"] = proc.stdout.strip()
        except Exception as e:
            result["file_type_error"] = str(e)

    # ── Basic stat info ───────────────────────────────────────────────────────
    try:
        stat = os.stat(path)
        result["size_bytes"] = stat.st_size
        result["size_human"] = _human_size(stat.st_size)
    except OSError as e:
        result["stat_error"] = str(e)

    # ── Magic bytes (first 16 bytes) ──────────────────────────────────────────
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
        result["magic_hex"] = magic.hex()
        result["file_class"] = _classify_magic(magic)
    except Exception as e:
        result["magic_error"] = str(e)

    # ── SHA256 hash ───────────────────────────────────────────────────────────
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        result["sha256"] = h.hexdigest()
    except Exception as e:
        result["hash_error"] = str(e)

    # ── exiftool if available ─────────────────────────────────────────────────
    if shutil.which("exiftool"):
        try:
            proc = runner.run(["exiftool", "-json", path],
                                  capture_output=True, text=True, timeout=15)
            import json
            meta = json.loads(proc.stdout)
            if meta:
                result["exiftool"] = meta[0]
        except Exception:
            pass

    result["_command"] = f"file -b {path}"
    return result


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _classify_magic(magic: bytes) -> str:
    sigs = [
        (b"\x7fELF",                     "ELF binary"),
        (b"MZ",                           "PE/Windows executable"),
        (b"\x50\x4b\x03\x04",            "ZIP archive"),
        (b"\x50\x4b\x05\x06",            "ZIP archive (empty)"),
        (b"\x1f\x8b",                     "gzip archive"),
        (b"\xfd7zXZ\x00",                 "xz/LZMA archive"),
        (b"BZh",                          "bzip2 archive"),
        (b"\x75\x73\x74\x61\x72",        "tar archive"),
        (b"\x89PNG\r\n\x1a\n",           "PNG image"),
        (b"\xff\xd8\xff",                 "JPEG image"),
        (b"GIF87a",                       "GIF image"),
        (b"GIF89a",                       "GIF image"),
        (b"%PDF",                         "PDF document"),
        (b"\xd0\xcf\x11\xe0",            "Microsoft Office (OLE2)"),
        (b"PK\x03\x04",                  "Office Open XML / ZIP"),
        (b"\x52\x61\x72\x21\x1a\x07",   "RAR archive"),
        (b"\x7f\x45\x4c\x46",            "ELF binary"),
        (b"\xca\xfe\xba\xbe",            "Mach-O fat binary"),
        (b"\xce\xfa\xed\xfe",            "Mach-O 32-bit"),
        (b"\xcf\xfa\xed\xfe",            "Mach-O 64-bit"),
        (b"#!/",                          "Script"),
        (b"#!",                           "Script"),
    ]
    for sig, label in sigs:
        if magic.startswith(sig):
            return label
    if all(32 <= b < 127 or b in (9, 10, 13) for b in magic[:8]):
        return "ASCII/text"
    return "unknown"


TOOL_DEFINITION = {
    "name": "file_identify",
    "description": (
        "Identify a file's type, magic bytes, size, and SHA256 hash. "
        "Uses file(1), magic byte analysis, and exiftool (if available) to characterize a file. "
        "Returns: file type string, magic hex, classification (ELF/PE/ZIP/etc), size, and SHA256. "
        "Use as first step before any binary analysis — confirms what you're actually looking at."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the file to identify"},
        },
        "required": ["path"],
    },
}
