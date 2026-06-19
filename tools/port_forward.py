"""Open a port forward / pivot through a foothold to reach internal-only services.

A compromised host often fronts services bound to its loopback or an internal
subnet (a DB on 127.0.0.1, an admin app on an RFC1918 host) that the attack box
cannot reach directly. This opens an SSH tunnel through the foothold so those
services become reachable locally.

It is a LONG-LIVED background process by design: `start` returns as soon as the
local listener is up — it does NOT block the agent — and the tunnel keeps running
so you can hit it with http_request / the protocol clients. Tunnels are tracked
and killed automatically at engagement end (and on demand via action='stop').

Modes:
  - local   (-L): forward 127.0.0.1:<local_port> → <remote_host>:<remote_port> via the pivot.
  - dynamic (-D): a SOCKS5 proxy on <local_port> — reach any host:port the pivot can.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid

from core import proc as _proc
from core.paths import scratch_dir

# id -> {popen, local, spec, errfile}
_TUNNELS: dict[str, dict] = {}


def _port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _redacted(cmd: list[str]) -> list[str]:
    """Mask the sshpass password in the rendered command."""
    out = list(cmd)
    for i, tok in enumerate(out):
        if tok == "-p" and i + 1 < len(out) and out and out[0] == "sshpass":
            out[i + 1] = "***"
    return out


def _build_cmd(pivot, ssh_port, key_file, password, mode, local_port, remote_host, remote_port):
    prefix: list[str] = []
    if password and not key_file:
        if not shutil.which("sshpass"):
            return None, "password auth needs sshpass (`apt_install sshpass`) — or pass key_file"
        prefix = ["sshpass", "-p", password]
    ssh = ["ssh", "-N",
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
           "-o", "BatchMode=" + ("no" if password else "yes")]
    if key_file:
        ssh += ["-i", key_file]
    if ssh_port and int(ssh_port) != 22:
        ssh += ["-p", str(int(ssh_port))]
    if mode == "dynamic":
        ssh += ["-D", f"127.0.0.1:{local_port}"]
    else:
        ssh += ["-L", f"127.0.0.1:{local_port}:{remote_host}:{remote_port}"]
    ssh.append(pivot)
    return prefix + ssh, None


def port_forward(action: str = "start", pivot: str = "", local_port: int = 0,
                 remote_host: str = "", remote_port: int = 0, mode: str = "local",
                 key_file: str = "", password: str = "", ssh_port: int = 22,
                 tunnel_id: str = "") -> dict:
    action = (action or "start").lower()

    if action == "list":
        live = []
        for tid, t in list(_TUNNELS.items()):
            if t["popen"].poll() is not None:
                _TUNNELS.pop(tid, None)                 # reap dead tunnels
            else:
                live.append({"id": tid, "local": t["local"], "spec": t["spec"]})
        return {"action": "list", "tunnels": live, "count": len(live)}

    if action == "stop":
        t = _TUNNELS.pop(tunnel_id, None)
        if not t:
            return {"error": f"no tunnel with id {tunnel_id}"}
        _proc._kill(t["popen"])
        _close(t)
        return {"action": "stop", "id": tunnel_id, "stopped": 1}

    if action in ("stop_all", "stopall"):
        n = 0
        for tid, t in list(_TUNNELS.items()):
            _proc._kill(t["popen"])
            _close(t)
            _TUNNELS.pop(tid, None)
            n += 1
        return {"action": "stop_all", "stopped": n}

    # ── start ─────────────────────────────────────────────────────────────────
    if not shutil.which("ssh"):
        return {"error": "ssh not found in PATH"}
    if not pivot:
        return {"error": "start requires 'pivot' (user@host of the foothold to tunnel through)"}
    if not local_port:
        local_port = int(remote_port) or 1080
    if mode != "dynamic" and (not remote_host or not remote_port):
        return {"error": "local forward requires remote_host and remote_port (the internal service)"}
    if _port_listening(int(local_port)):
        return {"error": f"local port {local_port} is already in use — choose another local_port"}

    cmd, err = _build_cmd(pivot, ssh_port, key_file, password, mode,
                          int(local_port), remote_host, remote_port)
    if err:
        return {"error": err}

    errpath = scratch_dir() / f"tunnel_{local_port}.err"
    errpath.parent.mkdir(parents=True, exist_ok=True)
    try:
        errfile = open(errpath, "w+b")
        popen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errfile,
                                 stdin=subprocess.DEVNULL,
                                 start_new_session=(os.name == "posix"))
    except Exception as e:  # noqa: BLE001
        return {"error": f"failed to launch ssh tunnel: {e}"}

    # Return as soon as the local listener is up — or bail if ssh dies first.
    up = False
    deadline = time.time() + 10
    while time.time() < deadline:
        if popen.poll() is not None:
            break
        if _port_listening(int(local_port)):
            up = True
            break
        time.sleep(0.25)

    rendered = " ".join(_redacted(cmd))
    if not up:
        _proc._kill(popen)
        tail = ""
        try:
            errfile.flush()
            errfile.seek(0)
            tail = errfile.read().decode("utf-8", "replace")[-400:].strip()
        except Exception:
            pass
        with _suppress():
            errfile.close()
        return {"error": "tunnel did not come up (check creds / connectivity / target port)",
                "ssh_stderr": tail, "_command": rendered}

    tid = uuid.uuid4().hex[:8]
    spec = (f"SOCKS5 127.0.0.1:{local_port} via {pivot}" if mode == "dynamic"
            else f"127.0.0.1:{local_port} → {remote_host}:{remote_port} via {pivot}")
    _TUNNELS[tid] = {"popen": popen, "local": f"127.0.0.1:{local_port}",
                     "spec": spec, "errfile": errfile}
    note = (f"SOCKS5 proxy up at 127.0.0.1:{local_port} — point tools at it (proxychains / a "
            "tool's --proxy)." if mode == "dynamic"
            else f"Reach the internal service at 127.0.0.1:{local_port} with http_request or the "
                 "protocol client.")
    return {"action": "start", "id": tid, "mode": mode, "local": f"127.0.0.1:{local_port}",
            "socks": mode == "dynamic", "spec": spec,
            "note": "Tunnel is up and running in the background. " + note,
            "_command": rendered}


def stop_all() -> dict:
    """Kill every tunnel — called by the engagement teardown."""
    return port_forward(action="stop_all")


def _close(t: dict) -> None:
    with _suppress():
        f = t.get("errfile")
        if f:
            f.close()


class _suppress:
    def __enter__(self): return self
    def __exit__(self, *a): return True


TOOL_DEFINITION = {
    "name": "port_forward",
    "description": (
        "Open/close an SSH tunnel through a foothold to reach internal-only services (a DB on the "
        "host's 127.0.0.1, an app on an internal subnet). Runs as a LONG-LIVED background process: "
        "action='start' returns the instant the local listener is up (it does NOT block), the tunnel "
        "stays open so you can hit it, and it is torn down automatically at engagement end. "
        "mode='local' (default) forwards 127.0.0.1:<local_port> → <remote_host>:<remote_port> via the "
        "pivot; mode='dynamic' opens a SOCKS5 proxy on <local_port>. Authenticate with key_file (e.g. "
        "one you made with ssh_keygen) or password. action='list' shows active tunnels; action='stop' "
        "(with tunnel_id) closes one. After 'start', target 127.0.0.1:<local_port> with http_request "
        "or the protocol client."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["start", "list", "stop"],
                       "description": "start a tunnel (default), list active tunnels, or stop one (with tunnel_id)."},
            "pivot": {"type": "string", "description": "Foothold to tunnel through, as user@host (the box you have SSH on)."},
            "mode": {"type": "string", "enum": ["local", "dynamic"],
                     "description": "'local' (-L, one service) or 'dynamic' (-D, SOCKS5 proxy). Default local."},
            "local_port": {"type": "integer", "description": "Local listen port (default: remote_port, or 1080 for SOCKS)."},
            "remote_host": {"type": "string", "description": "Internal host to reach FROM the pivot (e.g. 127.0.0.1 or an internal IP). Required for local mode."},
            "remote_port": {"type": "integer", "description": "Internal service port. Required for local mode."},
            "key_file": {"type": "string", "description": "Path to an SSH private key for the pivot (e.g. from ssh_keygen)."},
            "password": {"type": "string", "description": "SSH password for the pivot (uses sshpass). Prefer key_file."},
            "ssh_port": {"type": "integer", "description": "SSH port on the pivot (default 22)."},
            "tunnel_id": {"type": "string", "description": "Tunnel id to stop (from start/list), with action='stop'."},
        },
        "required": ["action"],
    },
}
