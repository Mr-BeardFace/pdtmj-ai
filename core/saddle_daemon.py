"""Lightweight analyst-watcher daemon for pdtmj-ai.

Spawned by `saddle start` or `/op start`. Responsibilities:
  - Watch log files → full analyst → write all findings to DB
  - Poll NightHawk C2 (if configured) → write logs + DB
  - Write .badge file for RPROMPT
  - Write .daemon_pid for `saddle stop`

No socket server. The TUI and saddle CLI read the DB directly.
"""
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

from core.paths import OPS_DIR


def _op_dir(op: str) -> Path:
    return OPS_DIR / op


def _pid_path(op: str) -> Path:
    return _op_dir(op) / ".daemon_pid"


def _badge_path(op: str) -> Path:
    return _op_dir(op) / ".badge"


def _write_pid(op: str) -> None:
    _pid_path(op).write_text(str(os.getpid()))


def _clear_badge(op: str) -> None:
    try:
        _badge_path(op).unlink(missing_ok=True)
    except Exception:
        pass


class _Daemon:
    def __init__(self, op: str, persona: str) -> None:
        self._op             = op
        self._persona        = persona
        self._running        = True
        self._analyst_store  = None

    def run(self) -> None:
        _write_pid(self._op)
        _clear_badge(self._op)

        signal.signal(signal.SIGTERM, self._handle_sig)
        signal.signal(signal.SIGINT,  self._handle_sig)

        analyst, watcher = self._start_analyst()
        c2_backends = self._start_c2(self._analyst_store)

        while self._running:
            time.sleep(5)

        # Clean shutdown
        for backend in c2_backends:
            try:
                backend.stop()
            except Exception:
                pass
        if watcher:
            try:
                watcher.stop()
            except Exception:
                pass
        if analyst:
            analyst.stop()
        _clear_badge(self._op)
        try:
            _pid_path(self._op).unlink(missing_ok=True)
        except Exception:
            pass

    def _handle_sig(self, signum, frame) -> None:
        self._running = False

    def _start_analyst(self):
        """Returns (analyst, watcher). Both may be None on failure or non-ops persona."""
        self._analyst_store = None
        if self._persona not in ("pentest", "redteam"):
            return None, None
        try:
            from core.engagement_store import EngagementStore
            from core.log_analyst import LogAnalyst
            from core.log_watcher import LogWatcher
            from core.config import get as _cfg

            log_dir = _op_dir(self._op) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            store, _, _ = EngagementStore.open_or_create(self._op)
            self._analyst_store = store
            analyst  = LogAnalyst(op=self._op, store=store, persona=self._persona)
            interval = float(_cfg("analyst_interval", 10))
            watcher  = LogWatcher(log_dir=log_dir, on_new_content=analyst.feed,
                                  interval=interval,
                                  on_cursor_update=store.set_log_cursor)
            cursors = store.load_log_cursors()
            analyst.start()
            watcher.start(cursors=cursors)
            return analyst, watcher
        except Exception as e:
            print(f"saddle-daemon: analyst init failed: {e}", file=sys.stderr)
            return None, None

    def _start_c2(self, store=None) -> list:
        try:
            from core.config import get as _cfg
            if not _cfg("c2.enabled", False):
                return []
            if self._persona not in ("pentest", "redteam"):
                return []

            from core.c2.nighthawk import NighthawkC2

            log_dir = _op_dir(self._op) / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            def _on_activity(msg: str) -> None:
                pass  # ponytail: C2 activity goes to logs via _write_log; no socket needed

            backend = NighthawkC2(log_dir=log_dir, on_activity=_on_activity, store=store)
            backend.start()
            return [backend]
        except Exception as e:
            print(f"saddle-daemon: C2 init failed: {e}", file=sys.stderr)
            return []


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description="pdtmj-ai analyst daemon")
    p.add_argument("--op",      required=True)
    p.add_argument("--persona", default="pentest")
    args = p.parse_args()
    _Daemon(op=args.op, persona=args.persona).run()


if __name__ == "__main__":
    main()
