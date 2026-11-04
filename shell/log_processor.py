#!/usr/bin/env python3
"""
Real-time log processor: tails a .raw TTY capture, renders through a terminal
emulator (pyte), writes clean .log with properly reconstructed lines.

Usage:
  # Watch a raw file and write rendered lines to .log:
  python3 log_processor.py --watch /path/to/input.raw --out /path/to/output.log

  # Pipe stdin through and write clean lines to a file (for evil-winrm wrapper):
  command | python3 log_processor.py --stdin /path/to/output.log
"""
from __future__ import annotations
import argparse
import re
import sys
import time
from pathlib import Path

_COLS = 220
_ROWS = 50

_ANSI = re.compile(
    r"\x1b(?:"
    r"\].*?(?:\x07|\x1b\\)"
    r"|\[[0-9;?]*[@-~]"
    r"|[@-Z\\-_]"
    r")"
    r"|\r|\x07|\x08"
)


def _clean(line: str) -> str:
    return _ANSI.sub("", line).rstrip("\r").rstrip()


def _try_import_pyte():
    try:
        import pyte
        return pyte
    except ImportError:
        return None


class TermRenderer:
    """Render raw terminal bytes through pyte and emit complete lines."""

    def __init__(self):
        pyte = _try_import_pyte()
        if pyte is None:
            self._screen = None
            return
        self._screen = pyte.HistoryScreen(_COLS, _ROWS, history=100000)
        self._stream = pyte.Stream(self._screen)

    @property
    def available(self) -> bool:
        return self._screen is not None

    def feed(self, data: str) -> list[str]:
        """Feed raw terminal data, return lines that scrolled off screen."""
        if not self._screen:
            return []
        self._stream.feed(data)
        out: list[str] = []
        while self._screen.history.top:
            hline = self._screen.history.top.popleft()
            text = "".join(hline[col].data for col in sorted(hline)).rstrip()
            if text:
                out.append(text)
        return out

    def flush_remaining(self) -> list[str]:
        """Flush content still visible on screen."""
        if not self._screen:
            return []
        out: list[str] = []
        for row in range(self._screen.lines):
            text = self._screen.display[row].rstrip()
            if text:
                out.append(text)
        return out


def watch_file(input_path: Path, output_path: Path) -> None:
    """Watch a raw TTY file and write rendered lines to output."""
    renderer = TermRenderer()
    cursor = 0
    with open(output_path, "a") as out:
        while True:
            try:
                size = input_path.stat().st_size
                if size > cursor:
                    with open(input_path, "rb") as f:
                        f.seek(cursor)
                        raw = f.read().decode("utf-8", errors="replace")
                    if renderer.available:
                        for line in renderer.feed(raw):
                            out.write(line + "\n")
                    else:
                        for line in raw.splitlines():
                            clean = _clean(line)
                            if clean:
                                out.write(clean + "\n")
                    out.flush()
                    cursor = size
            except FileNotFoundError:
                pass
            time.sleep(0.5)


def process_stdin(output_path: Path) -> None:
    """Read stdin line by line, pass through to terminal, write clean lines to output."""
    with open(output_path, "a") as out:
        for line in sys.stdin:
            print(line, end="")
            sys.stdout.flush()
            clean = _clean(line)
            if clean:
                out.write(clean + "\n")
                out.flush()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", type=Path, help="Input file to watch")
    parser.add_argument("--stdin", type=Path, help="Output file when reading from stdin")
    parser.add_argument("--out", type=Path, help="Output file for --watch mode")
    args = parser.parse_args()

    if args.stdin:
        process_stdin(args.stdin)
    elif args.watch and args.out:
        watch_file(args.watch, args.out)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
