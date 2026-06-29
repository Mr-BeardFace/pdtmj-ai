"""Run a long-lived offensive daemon on the LOCAL box and read what it captures.

Some tools are meant to run until you stop them — Responder (LLMNR/NBT-NS/mDNS
capture), impacket ntlmrelayx (relay coerced/triggered auth), mitm6. They never
return, so they don't fit local_exec/run_script (which wait for completion) and
can't fold into the JobManager (which waits for a job to finish). This runs them
detached, tees their output to a log you can poll with action='read', and tears
them down at engagement end (or on demand via action='stop').

Typical flow: start a capture/relay daemon → trigger auth (coercer/petitpotam, or
just wait) → read the daemon's log for captured hashes / relayed results → stop.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
import uuid

from core import proc as _proc
from core.paths import scratch_dir

# id -> {popen, name, cmd, logpath, logfile}
_DAEMONS: dict[str, dict] = {}

_LOG_TAIL = 12000   # chars of captured output returned by `read`


def _reap() -> None:
    for did, d in list(_DAEMONS.items()):
        if d["popen"].poll() is not None:
            _close(d)
            _DAEMONS.pop(did, None)


def _tail(path, n_chars: int = _LOG_TAIL) -> str:
    try:
        with open(path, "rb") as f:
            data = f.read()
        return data.decode("utf-8", "replace")[-n_chars:]
    except Exception:
        return ""


def run_daemon(action: str = "start", command: str = "", name: str = "",
               daemon_id: str = "", chars: int = _LOG_TAIL) -> dict:
    action = (action or "start").lower()

    if action == "list":
        _reap()
        live = [{"id": did, "name": d["name"], "command": d["cmd"]}
                for did, d in _DAEMONS.items()]
        return {"action": "list", "daemons": live, "count": len(live)}

    if action == "read":
        d = _DAEMONS.get(daemon_id)
        if not d:
            return {"error": f"no daemon with id {daemon_id} (action='list' to see them)"}
        alive = d["popen"].poll() is None
        return {"action": "read", "id": daemon_id, "name": d["name"], "running": alive,
                "output": _tail(d["logpath"], chars or _LOG_TAIL),
                "note": None if alive else "Daemon has exited — this is its full output."}

    if action == "stop":
        d = _DAEMONS.pop(daemon_id, None)
        if not d:
            return {"error": f"no daemon with id {daemon_id}"}
        _proc._kill(d["popen"])
        out = _tail(d["logpath"])
        _close(d)
        return {"action": "stop", "id": daemon_id, "stopped": 1, "output": out}

    if action in ("stop_all", "stopall"):
        n = 0
        for did, d in list(_DAEMONS.items()):
            _proc._kill(d["popen"])
            _close(d)
            _DAEMONS.pop(did, None)
            n += 1
        return {"action": "stop_all", "stopped": n}

    # ── start ───────────────────────────────────────────────────────────────────
    if not command or not command.strip():
        return {"error": "start requires 'command' (the daemon to run, e.g. "
                         "'sudo responder -I tun0 -wv')"}
    if not shutil.which("bash"):
        return {"error": "bash not found in PATH"}

    label = name or _first_binary(command)
    logpath = scratch_dir() / f"daemon_{label}_{uuid.uuid4().hex[:6]}.log"
    logpath.parent.mkdir(parents=True, exist_ok=True)
    try:
        logfile = open(logpath, "w+b")
        popen = subprocess.Popen(["bash", "-c", command],
                                 stdout=logfile, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL,
                                 start_new_session=(os.name == "posix"))
    except Exception as e:  # noqa: BLE001
        return {"error": f"failed to launch daemon: {e}", "_command": command}

    # Give it a moment; if it dies immediately (bad args, needs root, port in use)
    # report that now rather than leaving a dead handle.
    time.sleep(1.5)
    if popen.poll() is not None:
        tail = _tail(logpath, 1500)
        _close({"logfile": logfile})
        return {"error": "daemon exited immediately — check the command (often needs sudo, "
                         "or the interface/port is wrong/in use).",
                "output": tail, "_command": command}

    did = uuid.uuid4().hex[:8]
    _DAEMONS[did] = {"popen": popen, "name": label, "cmd": command,
                     "logpath": logpath, "logfile": logfile}
    return {"action": "start", "id": did, "name": label, "running": True,
            "note": (f"{label} is running in the background. Poll its capture with "
                     f"run_daemon(action='read', daemon_id='{did}'); stop it with "
                     f"action='stop'. It's torn down automatically at engagement end."),
            "_command": command}


def _first_binary(command: str) -> str:
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    for t in toks:
        if t in ("sudo", "-n") or "=" in t:        # skip sudo + VAR=val prefixes
            continue
        return t.rsplit("/", 1)[-1]
    return "daemon"


def _close(d: dict) -> None:
    try:
        f = d.get("logfile")
        if f:
            f.close()
    except Exception:
        pass


def stop_all() -> dict:
    """Kill every daemon — called by the engagement teardown."""
    return run_daemon(action="stop_all")


TOOL_DEFINITION = {
    "name": "run_daemon",
    "description": (
        "Run a LONG-LIVED offensive daemon on the local box and read what it captures — for tools "
        "that run until stopped: Responder (LLMNR/NBT-NS/mDNS hash capture), impacket ntlmrelayx "
        "(relay coerced/triggered auth), mitm6. These never return, so they don't fit local_exec/"
        "run_script. action='start' (with the full 'command', e.g. 'sudo responder -I tun0 -wv') "
        "launches it detached and returns immediately with an id. action='read' (with daemon_id) "
        "tails its output so you can see captured NetNTLM hashes / relayed results — poll it after "
        "triggering auth (coercer/petitpotam). action='list' shows running daemons; action='stop' "
        "kills one. All are torn down at engagement end. Many need sudo (privileged ports) — include "
        "it in the command. Stay in scope: prefer targeted coercion at your relay over blind "
        "segment-wide poisoning."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action":    {"type": "string", "enum": ["start", "read", "list", "stop"],
                          "description": "start a daemon (default), read its captured output, list running ones, or stop one."},
            "command":   {"type": "string", "description": "Full daemon command for action='start', e.g. 'sudo responder -I tun0 -wv' or 'sudo impacket-ntlmrelayx -t smb://10.0.0.5 -smb2support'."},
            "name":      {"type": "string", "description": "Optional label (defaults to the binary name)."},
            "daemon_id": {"type": "string", "description": "Daemon id (from start/list) for action='read' or 'stop'."},
            "chars":     {"type": "integer", "description": "Max chars of captured output to return on 'read' (default 12000)."},
        },
        "required": ["action"],
    },
}
