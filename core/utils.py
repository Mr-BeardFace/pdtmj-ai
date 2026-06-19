"""Shared utility functions used across core and UI layers."""
from __future__ import annotations

import os
import sys


# ── subprocess environment hygiene ─────────────────────────────────────────────
# PDTMJ-AI runs inside a Python virtualenv. When it shells out to system /
# pipx-installed security tools (impacket, netexec, sqlmap, …), those subprocesses
# inherit the venv's environment and try to run under the venv's Python — which
# lacks their dependencies (e.g. impacket dies with "No module named pkg_resources").
# These helpers hand external tools a venv-free environment so they run against the
# system install they were built for. run_script / pip_install deliberately do NOT
# use this — they pin sys.executable to stay inside the venv.

def system_env(base: dict | None = None) -> dict:
    """Return a copy of the environment with virtualenv contamination removed:
    VIRTUAL_ENV / PYTHONHOME / PYTHONPATH dropped and the venv's bin directory
    stripped from PATH, so `which`/exec resolve system tools and the system
    Python."""
    env = dict(os.environ if base is None else base)
    venv = env.pop("VIRTUAL_ENV", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)

    venv_bins = {os.path.normpath(os.path.dirname(sys.executable))}
    if venv:
        venv_bins.add(os.path.normpath(os.path.join(venv, "bin")))
        venv_bins.add(os.path.normpath(os.path.join(venv, "Scripts")))  # Windows
    path = env.get("PATH", "")
    if path:
        kept = [p for p in path.split(os.pathsep)
                if p and os.path.normpath(p) not in venv_bins]
        env["PATH"] = os.pathsep.join(kept)
    return env


def scrub_process_env() -> None:
    """Apply system_env() to os.environ in place — call once at startup so every
    subprocess inherits a venv-free environment by default. Tools that must stay
    in the venv pin sys.executable, which works regardless of these vars."""
    cleaned = system_env(dict(os.environ))
    for key in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"):
        os.environ.pop(key, None)
    if "PATH" in cleaned:
        os.environ["PATH"] = cleaned["PATH"]


# Realistic browser UA used for all outbound HTTP tool calls.
# Passes basic bot-detection filters without appearing obviously automated.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


# Grammatical/filler words stripped before comparing finding titles, so reworded
# titles for the same issue still match ("Authentication Bypass via Unauthenticated
# Password Reset" ≈ "Unauthenticated Password Reset Allows Account Takeover").
_TITLE_STOPWORDS = frozenset({
    "via", "with", "and", "the", "a", "an", "of", "to", "for", "on", "in", "by",
    "allows", "allow", "allowing", "enables", "enabling", "is", "are", "using",
    "through", "without", "due", "from", "that", "this", "no",
})


def _title_words(title: str) -> frozenset:
    import re
    words = re.sub(r"[^a-z0-9 ]", " ", (title or "").lower()).split()
    return frozenset(w for w in words if w not in _TITLE_STOPWORDS and len(w) > 2)


def title_similarity(a: str, b: str) -> float:
    """0..1 overlap of significant words (intersection / larger set)."""
    if (a or "").strip().lower() == (b or "").strip().lower():
        return 1.0
    wa, wb = _title_words(a), _title_words(b)
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / max(len(wa), len(wb))


def titles_match(a: str, b: str, threshold: float = 0.6) -> bool:
    return title_similarity(a, b) >= threshold


def get_interface_ip(interface: str = "tun0") -> str:
    """Best-effort local IP for an interface — the attacker IP for callbacks/payloads.

    Tries the named interface, then tun0/eth0/wlan0, then a UDP-socket trick that
    yields the primary outbound IP. Returns "" if nothing resolves.
    """
    import re
    import subprocess

    candidates = [interface, "tun0", "eth0", "wlan0", "ens33", "ens160"]
    seen = set()
    for iface in candidates:
        if not iface or iface in seen:
            continue
        seen.add(iface)
        try:
            proc = subprocess.run(["ip", "addr", "show", iface],
                                  capture_output=True, text=True, timeout=5)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", proc.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
    # Fallback: primary outbound IP (no packets actually sent)
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return ""


def mask_secret(secret: str) -> str:
    """Return a partially-masked version of a secret for display.

    Secrets of 4 characters or fewer are fully masked.
    Longer secrets show the first 2 and last 2 characters.
    """
    if not secret:
        return ""
    n = len(secret)
    if n <= 4:
        return "*" * n
    return secret[:2] + "*" * (n - 4) + secret[-2:]
