"""Watches op log files for new content and calls on_new_content(path, bytes).

Buffers incomplete data: a poll that doesn't end with a shell prompt is held
and concatenated with the next poll's data. This ensures the analyst only
sees complete command+output pairs, not fragments split by the poll interval.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Callable

# Prompt patterns that signal "command finished, shell is waiting for input"
_PROMPT_BOUNDARY = re.compile(
    rb"(?:"
    rb"[$#>]\s*$"                       # generic prompt ending
    rb"|Password:\s*$"                  # password prompt (su, sudo, ssh)
    rb"|\$ $"                           # bare dollar prompt
    rb")"
)


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
        self._buffers: dict[str, bytes] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, cursors: dict[str, int] | None = None) -> None:
        self._cursors = cursors or {}
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _read_primary_tty(self) -> str:
        """Read .primary_tty marker — the tty log filename to skip."""
        try:
            return (self._log_dir / ".primary_tty").read_text().strip()
        except (OSError, ValueError):
            return ""

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._interval):
            self._poll()

    def _poll(self) -> None:
        if not self._log_dir.exists():
            return
        primary = self._read_primary_tty()
        for path in sorted(self._log_dir.glob("*.log")):
            name_lower = path.name.lower()
            if any(s in name_lower for s in self._SKIP_NAMES):
                continue
            if primary and path.name == primary:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            key = str(path)
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
                # Prepend any buffered data from previous incomplete polls
                if key in self._buffers:
                    data = self._buffers.pop(key) + data
                # Check if the data ends at a prompt boundary
                tail = data[-200:] if len(data) > 200 else data
                if _PROMPT_BOUNDARY.search(tail):
                    self._on_new_content(path, data)
                    if self._on_cursor_update:
                        try:
                            self._on_cursor_update(key, size)
                        except Exception:
                            pass
                else:
                    # Incomplete — buffer until next poll brings a prompt
                    self._buffers[key] = data
            except OSError:
                pass
