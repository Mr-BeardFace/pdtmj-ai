"""Lightweight session-tracking daemon for pdtmj-ai saddle CLI.

Spawned by `saddle start`. Does NOT run the AI loop — that's the TUI.
Responsibilities:
  - Track shell session PIDs; exit when all are gone
  - Serve Unix socket for: status, badge_update, clear_badge, stop, chat
  - Write / clear OPS_DIR/<op>/.badge for RPROMPT
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from core.paths import OPS_DIR


def _op_dir(op: str) -> Path:
    return OPS_DIR / op


def _socket_path(op: str) -> Path:
    return _op_dir(op) / ".saddle.sock"


def _badge_path(op: str) -> Path:
    return _op_dir(op) / ".badge"


def _sessions_dir(op: str) -> Path:
    return _op_dir(op) / ".sessions"


def _write_badge(op: str, badge: str | None, badge_type: str | None) -> None:
    path = _badge_path(op)
    if badge:
        path.write_text(f"{badge}\n{badge_type or ''}\n")
    else:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass


def _live_pids(op: str) -> set[int]:
    """Return PIDs still alive; prune dead session files."""
    sd = _sessions_dir(op)
    sd.mkdir(parents=True, exist_ok=True)
    alive = set()
    for f in sd.iterdir():
        try:
            pid = int(f.name)
            os.kill(pid, 0)
            alive.add(pid)
        except (ValueError, ProcessLookupError):
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        except PermissionError:
            alive.add(int(f.name))
    return alive


class _Daemon:
    def __init__(self, op: str, persona: str) -> None:
        self._op = op
        self._persona = persona
        self._badge: str | None = None
        self._badge_type: str | None = None
        self._stop_evt = threading.Event()

    def run(self) -> None:
        _write_badge(self._op, None, None)

        sock_path = _socket_path(self._op)
        try:
            sock_path.unlink(missing_ok=True)
        except Exception:
            pass

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(sock_path))
        server.listen(4)
        server.settimeout(1.0)
        threading.Thread(target=self._serve, args=(server,), daemon=True).start()

        # Start log watching + analysis (redteam/pentest only — non-fatal if fails)
        analyst = self._start_log_analyst()

        while not self._stop_evt.is_set():
            time.sleep(30)
            if not _live_pids(self._op):
                break

        if analyst:
            analyst.stop()
        server.close()
        try:
            sock_path.unlink(missing_ok=True)
        except Exception:
            pass
        _write_badge(self._op, None, None)

    def _start_log_analyst(self):
        try:
            from core.engagement_store import EngagementStore
            from core.log_analyst import LogAnalyst
            from core.log_watcher import LogWatcher

            log_dir = _op_dir(self._op) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            store, _, _ = EngagementStore.open_or_create(self._op)
            analyst = LogAnalyst(op=self._op, store=store)
            watcher = LogWatcher(log_dir=log_dir, on_new_content=analyst.feed)

            analyst.start()
            watcher.start()
            return analyst
        except Exception as e:
            print(f"saddle-daemon: log analyst init failed: {e}", file=sys.stderr)
            return None

    def _serve(self, server: socket.socket) -> None:
        while True:
            try:
                conn, _ = server.accept()
            except (socket.timeout, OSError):
                if self._stop_evt.is_set():
                    return
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            data = b""
            while b"\n" not in data:
                if len(data) > 1 << 20:
                    return
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            msg = json.loads(data.split(b"\n")[0])
            t = msg.get("type")

            if t == "status":
                conn.sendall(json.dumps({
                    "type": "status", "running": True,
                    "op": self._op, "persona": self._persona,
                    "badge": self._badge, "badge_type": self._badge_type,
                }).encode() + b"\n")

            elif t == "badge_update":
                self._badge = msg.get("badge")
                self._badge_type = msg.get("badge_type")
                _write_badge(self._op, self._badge, self._badge_type)
                conn.sendall(json.dumps({"type": "ok"}).encode() + b"\n")

            elif t == "clear_badge":
                self._badge = None
                self._badge_type = None
                _write_badge(self._op, None, None)
                conn.sendall(json.dumps({"type": "ok"}).encode() + b"\n")

            elif t == "chat":
                conn.sendall(json.dumps({
                    "type": "error",
                    "message": "AI loop not running — start the TUI first",
                }).encode() + b"\n")

            elif t == "stop":
                conn.sendall(json.dumps({"type": "ok"}).encode() + b"\n")
                self._stop_evt.set()

        except Exception as e:
            print(f"saddle-daemon: handler error: {e}", file=sys.stderr)
        finally:
            try:
                conn.close()
            except Exception:
                pass


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="pdtmj-ai saddle daemon")
    p.add_argument("--op", required=True)
    p.add_argument("--persona", default="pentest")
    args = p.parse_args()
    _Daemon(op=args.op, persona=args.persona).run()


if __name__ == "__main__":
    main()
