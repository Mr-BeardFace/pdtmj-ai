"""John the Ripper offline cracking — runs as a background job (can take a long time).

John auto-detects the hash format from its `$tag$`, so it's the easy path for the
hashes hash_extract produces (zip/ssh/keepass/office/…) and for formats hashcat
lacks a mode for. Passes escalate: a custom wordlist from engagement intel first,
then rockyou. A recovered plaintext is fed back as a credential (same path as
hashcat_crack).
"""
import os
import shutil
import tempfile

from core import proc as runner
from core.config import get


def _parse_show(stdout: str) -> str | None:
    """Pull the plaintext from `john --show` output (login:password:...)."""
    for line in stdout.splitlines():
        line = line.rstrip()
        if not line:
            continue
        low = line.lower()
        if "password hash" in low and ("cracked" in low or "left" in low):
            continue                      # summary line
        parts = line.split(":")
        if len(parts) >= 2 and parts[1]:
            return parts[1]
    return None


def john(hash: str, hash_format: str | None = None,
         username: str | None = None, location: str | None = None,
         custom_words: list | None = None) -> dict:
    binary = get("john_binary", "john")
    if not shutil.which(binary):
        return {"error": f"{binary} not found in PATH — install John: apt install john"}
    if not hash or not hash.strip():
        return {"error": "hash is required (e.g. the output of hash_extract)"}

    wordlist = get("hashcat_wordlist", "/usr/share/wordlists/rockyou.txt")
    if not os.path.exists(wordlist):
        return {"error": f"wordlist not found: {wordlist} (set 'hashcat_wordlist' in config)"}

    fmt_args = [f"--format={hash_format.strip()}"] if hash_format else []

    hash_fd, hash_path = tempfile.mkstemp(prefix="pentest_john_hash_")
    pot_fd,  pot_path  = tempfile.mkstemp(prefix="pentest_john_pot_")
    os.close(pot_fd)
    with os.fdopen(hash_fd, "w", encoding="utf-8") as f:
        f.write(hash.strip() + "\n")

    custom_path = None
    if custom_words:
        words = list(dict.fromkeys(w.strip() for w in custom_words if str(w).strip()))
        if words:
            cw_fd, custom_path = tempfile.mkstemp(prefix="pentest_john_custom_")
            with os.fdopen(cw_fd, "w", encoding="utf-8") as f:
                f.write("\n".join(words) + "\n")

    passes = []
    if custom_path:
        passes.append(("custom", custom_path))
    passes.append(("rockyou", wordlist))

    passes_run: list[str] = []
    last_cmd = ""
    try:
        for name, wl in passes:
            cmd = [binary, f"--wordlist={wl}", f"--pot={pot_path}", *fmt_args, hash_path]
            last_cmd = " ".join(cmd)
            passes_run.append(name)
            try:
                runner.run(cmd, capture_output=True, text=True)   # no timeout — background
            except Exception as e:  # noqa: BLE001
                return {"error": f"john failed: {e}", "_command": last_cmd}

            show = runner.run([binary, "--show", f"--pot={pot_path}", *fmt_args, hash_path],
                              capture_output=True, text=True)
            plaintext = _parse_show(show.stdout or "")
            if plaintext:
                return {
                    "cracked": [{
                        "hash": hash, "plaintext": plaintext,
                        "username": username, "location": location,
                        "hash_format": hash_format or "auto",
                    }],
                    "cracked_count": 1,
                    "cracked_in": name,
                    "passes_run": passes_run,
                    "_command": last_cmd,
                }

        return {
            "cracked": [], "cracked_count": 0, "passes_run": passes_run,
            "note": f"not cracked ({', '.join(passes_run)})",
            "_command": last_cmd,
        }
    finally:
        for p in (hash_path, pot_path, custom_path):
            if not p:
                continue
            try:
                os.unlink(p)
            except Exception:
                pass


TOOL_DEFINITION = {
    "name": "john",
    "description": (
        "Crack a password hash offline with John the Ripper. Runs as a BACKGROUND job — returns "
        "immediately and the result is delivered when cracking finishes. John AUTO-DETECTS the "
        "format from the hash, so it's the easy path for hashes from hash_extract (zip/ssh/keepass/"
        "office/pdf/…) and for formats hashcat has no mode for. Passes stop at the first crack: "
        "(1) your custom_words list, (2) rockyou. Build custom_words from engagement intel for the "
        "best first pass. Pass username/location so a cracked plaintext is recorded against the "
        "right account; a recovered password is added to the credential store automatically. "
        "(For NTLM/Kerberos/standard hashes, hashcat_crack is usually faster — use this for the "
        "file-format hashes and john-only formats.)"
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "hash":        {"type": "string", "description": "The hash to crack (e.g. the 'hash' field from hash_extract). John detects the format."},
            "hash_format": {"type": "string", "description": "Optional John --format (e.g. 'raw-md5', 'krb5tgs'); omit to auto-detect."},
            "username":    {"type": "string", "description": "Account the hash belongs to (so the cracked password is recorded against it)."},
            "location":    {"type": "string", "description": "Where the credential is used (host/service/domain)."},
            "custom_words": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Targeted candidate words from engagement intel (compromised passwords, usernames, hostnames, product names). Tried before rockyou.",
            },
        },
        "required": ["hash"],
    },
}
