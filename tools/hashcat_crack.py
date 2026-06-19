"""hashcat offline cracking — runs as a background job (it can take a long time).

Two passes, escalating: straight rockyou wordlist first, then rockyou + the
OneRule ruleset. No time cap — because it runs in the background, a long crack
never blocks the engagement. A recovered plaintext is fed back as a credential.
"""
import os
import shutil
import tempfile

from core import proc as runner

from core.config import get

# Convenience: map a hash-format label to a hashcat -m mode, so the agent can
# pass the format it already recorded instead of memorising mode numbers.
_FORMAT_MODES = {
    "ntlm": 1000, "nt": 1000,
    "netntlmv2": 5600, "ntlmv2": 5600, "net-ntlmv2": 5600,
    "kerberos-tgs": 13100, "kerberoast": 13100, "tgs-rep": 13100, "tgs": 13100,
    "kerberos-as-rep": 18200, "asrep": 18200, "as-rep": 18200, "asreproast": 18200,
    "md5": 0, "sha1": 100, "sha256": 1400, "sha512": 1700,
    "bcrypt": 3200, "lm": 3000, "mssql": 1731, "mysql": 300, "mysql-sha1": 300,
}


def hashcat_crack(hash: str, hash_mode: int | None = None,
                  hash_format: str | None = None,
                  username: str | None = None,
                  location: str | None = None,
                  custom_words: list | None = None) -> dict:
    binary = get("hashcat_binary", "hashcat")
    if not shutil.which(binary):
        return {"error": f"{binary} not found in PATH"}

    mode = hash_mode
    if mode is None and hash_format:
        mode = _FORMAT_MODES.get(hash_format.strip().lower())
    if mode is None:
        return {"error": "hash_mode (int) or a recognized hash_format is required",
                "known_formats": sorted(_FORMAT_MODES)}

    wordlist = get("hashcat_wordlist", "/usr/share/wordlists/rockyou.txt")
    if not os.path.exists(wordlist):
        return {"error": f"wordlist not found: {wordlist} (set 'hashcat_wordlist' in config)"}
    rules = get("hashcat_rules", "")
    have_rules = bool(rules and os.path.exists(rules))
    rule_args  = ["-r", rules] if have_rules else []

    hash_fd, hash_path = tempfile.mkstemp(prefix="pentest_hc_hash_")
    out_fd,  out_path  = tempfile.mkstemp(prefix="pentest_hc_out_")
    os.close(out_fd)
    with os.fdopen(hash_fd, "w", encoding="utf-8") as f:
        f.write(hash.strip() + "\n")

    # Optional custom wordlist built from engagement intel (enumerated terms,
    # already-compromised passwords, usernames, hostnames, …).
    custom_path = None
    if custom_words:
        words = list(dict.fromkeys(w.strip() for w in custom_words if str(w).strip()))
        if words:
            cw_fd, custom_path = tempfile.mkstemp(prefix="pentest_hc_custom_")
            with os.fdopen(cw_fd, "w", encoding="utf-8") as f:
                f.write("\n".join(words) + "\n")

    # Escalating passes, in order. The custom list (with rules) goes first since
    # targeted candidates are most likely; then rockyou, then rockyou + OneRule.
    # Each pass only runs if the previous one did not crack.
    passes: list[tuple[str, str, list]] = []
    if custom_path:
        passes.append((f"custom{'+OneRule' if have_rules else ''}", custom_path, rule_args))
    passes.append(("rockyou", wordlist, []))
    if have_rules:
        passes.append(("rockyou+OneRule", wordlist, rule_args))

    passes_run: list[str] = []
    last_cmd = ""
    try:
        for name, wl_path, extra in passes:
            open(out_path, "w").close()  # clear outfile between passes
            cmd = [
                binary, "-m", str(mode), "-a", "0",
                "--quiet", "--potfile-disable",
                "--outfile-format", "2",          # plaintext only — trivial to parse
                "-o", out_path,
                hash_path, wl_path, *extra,
            ]
            last_cmd = " ".join(cmd)
            passes_run.append(name)
            try:
                runner.run(cmd, capture_output=True, text=True)  # no timeout by design
            except Exception as e:  # noqa: BLE001
                return {"error": f"hashcat failed: {e}", "_command": last_cmd}

            with open(out_path, encoding="utf-8", errors="replace") as f:
                plains = [ln.strip() for ln in f if ln.strip()]
            if plains:
                plaintext = plains[0]
                return {
                    "cracked": [{
                        "hash": hash, "plaintext": plaintext,
                        "username": username, "location": location,
                        "hash_format": hash_format or "", "mode": mode,
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
        for p in (hash_path, out_path, custom_path):
            if p is None:
                continue
            try:
                os.unlink(p)
            except Exception:
                pass


TOOL_DEFINITION = {
    "name": "hashcat_crack",
    "description": (
        "Crack a password hash offline with hashcat. Runs as a BACKGROUND job — it returns "
        "immediately with a job id and the result is delivered automatically when cracking "
        "finishes, so it never blocks the engagement; continue with other work. Passes run in "
        "order, stopping at the first crack: (1) your custom_words list + the OneRule ruleset "
        "(if you supply candidates), (2) rockyou, (3) rockyou + OneRule. Build custom_words from "
        "engagement intel — already-compromised passwords, usernames, hostnames, app/product "
        "names, and obvious mutations — for the highest-yield first pass. Provide the hash and "
        "either its hashcat mode number or a recognized format label (NTLM, NetNTLMv2, "
        "Kerberos-TGS/Kerberoast, Kerberos-AS-REP, bcrypt, md5, sha256, …). Pass username/location "
        "so a cracked plaintext is recorded against the right account. A recovered password is "
        "added to the credential store automatically."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "The hash to crack, in hashcat's expected format for the mode."},
            "hash_mode": {"type": "integer", "description": "hashcat -m mode number (e.g. 1000 NTLM, 13100 Kerberoast, 18200 AS-REP, 5600 NetNTLMv2, 3200 bcrypt)."},
            "hash_format": {"type": "string", "description": "Alternative to hash_mode: a format label (NTLM, NetNTLMv2, Kerberos-TGS, Kerberos-AS-REP, bcrypt, md5, sha256, …)."},
            "username": {"type": "string", "description": "Account the hash belongs to (so the cracked password is recorded against it)."},
            "location": {"type": "string", "description": "Where the credential is used (host/service/domain)."},
            "custom_words": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Targeted candidate words/passwords built from engagement intel (compromised passwords, usernames, hostnames, product/app names, seasons/years, etc.). Tried first with the OneRule ruleset before rockyou.",
            },
        },
        "required": ["hash"],
    },
}
