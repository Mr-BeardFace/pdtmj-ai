"""Watches op log files for new content and calls on_new_content(path, bytes).

Sends new data to the analyst on each poll interval; the analyst's own
debounce logic (15s quiet / 60s max wait) handles batching into complete
command+output groups.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable


class LogWatcher:
    _SKIP_NAMES = ("sidesaddle", "debug", "pdtmj")

    def __init__(
        self,
        log_dir: Path,
        on_new_content: Callable[[Path, bytes], None],
        interval: float = 10.0,
        on_cursor_update: Callable[[str, int], None] | None = None,
    ) -> None:
        self._log_dir = log_dir
        self._on_new_content = on_new_content
        self._interval = interval
        self._on_cursor_update = on_cursor_update
        self._cursors: dict[str, int] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, cursors: dict[str, int] | None = None) -> None:
        self._cursors = cursors or {}
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._interval):
            self._poll()

    def _poll(self) -> None:
        if not self._log_dir.exists():
            return
        for path in sorted(self._log_dir.glob("*.log")):
            name_lower = path.name.lower()
            if any(s in name_lower for s in self._SKIP_NAMES):
                continue
            key = str(path)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            cursor = self._cursors.get(key, 0)
            if size <= cursor:
                self._cursors[key] = size
                continue
            try:
                with path.open("rb") as f:
                    f.seek(cursor)
                    data = f.read(size - cursor)
                self._cursors[key] = size
                if not data:
                    continue
                self._on_new_content(path, data)
                if self._on_cursor_update:
                    try:
                        self._on_cursor_update(key, size)
                    except Exception:
                        pass
            except Exception:
                pass
