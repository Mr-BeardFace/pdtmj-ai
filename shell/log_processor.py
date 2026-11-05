#!/usr/bin/env python3
"""
Real-time log processor: tails a .raw TTY capture, replays cursor movement
to reconstruct clean lines, writes .log.

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


# ── CSI sequence parser ──────────────────────────────────────────────────────
# Matches: ESC [ <params> <final byte>
_CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z@-~])")
# Matches: OSC (ESC ] ... BEL/ST)
_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)")
# Matches: single-byte ESC sequences (excludes ] to avoid short-matching OSC), BEL
_OTHER_ESC = re.compile(r"\x1b[@-Z\\^_]|\x07")

# ANSI stripping for the stdin passthrough path (no cursor emulation needed)
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


class LineBuffer:
    """Single-line cursor emulator. Handles cursor moves, overwrites, erases."""

    def __init__(self):
        self._buf: list[str] = []
        self._cur = 0

    def _ensure(self, pos: int) -> None:
        """Extend buffer with spaces if cursor is past end."""
        if pos >= len(self._buf):
            self._buf.extend(" " for _ in range(pos - len(self._buf) + 1))

    def putchar(self, ch: str) -> None:
        self._ensure(self._cur)
        self._buf[self._cur] = ch
        self._cur += 1

    def move_to(self, col: int) -> None:
        self._cur = max(0, col)

    def move_rel(self, delta: int) -> None:
        self._cur = max(0, self._cur + delta)

    def erase_to_end(self) -> None:
        self._buf = self._buf[:self._cur]

    def erase_to_start(self) -> None:
        end = min(self._cur, len(self._buf))
        for i in range(end):
            self._buf[i] = " "

    def erase_line(self) -> None:
        self._buf.clear()
        self._cur = 0

    def cr(self) -> None:
        self._cur = 0

    def bs(self) -> None:
        self._cur = max(0, self._cur - 1)

    def flush(self) -> str:
        line = "".join(self._buf).rstrip()
        self._buf.clear()
        self._cur = 0
        return line


class CursorRenderer:
    """Stateful renderer: feed raw chunks over time, get completed lines back."""

    def __init__(self):
        self._buf = LineBuffer()
        self._residual = ""

    def feed(self, data: str) -> list[str]:
        """Feed a chunk of raw terminal data, return lines completed by \\n."""
        data = self._residual + data
        self._residual = ""
        # Hold back any incomplete ESC sequence at the tail
        esc_pos = data.rfind("\x1b", max(0, len(data) - 32))
        if esc_pos >= 0:
            tail = data[esc_pos:]
            if not _CSI.match(tail) and not _OSC.match(tail) and not _OTHER_ESC.match(tail):
                self._residual = tail
                data = data[:esc_pos]

        out: list[str] = []
        i = 0
        n = len(data)

        while i < n:
            ch = data[i]

            if ch == "\x1b":
                if i + 1 >= n:
                    self._residual = data[i:]
                    break
                m = _CSI.match(data, i)
                if m:
                    params, final = m.group(1), m.group(2)
                    _handle_csi(self._buf, params, final)
                    i = m.end()
                    continue
                m = _OSC.match(data, i)
                if m:
                    i = m.end()
                    continue
                m = _OTHER_ESC.match(data, i)
                if m:
                    i = m.end()
                    continue
                nxt = data[i + 1]
                if nxt == "[" or nxt == "]":
                    self._residual = data[i:]
                    break
                i += 2
                continue

            if ch == "\n":
                out.append(self._buf.flush())
                i += 1
                continue

            if ch == "\r":
                self._buf.cr()
                i += 1
                continue

            if ch == "\x08":
                self._buf.bs()
                i += 1
                continue

            if ch == "\x07":
                i += 1
                continue

            if ch >= " " or ch == "\t":
                if ch == "\t":
                    target = (self._buf._cur + 8) & ~7
                    while self._buf._cur < target:
                        self._buf.putchar(" ")
                else:
                    self._buf.putchar(ch)
            i += 1

        return out

    def flush(self) -> str:
        """Flush any incomplete line (call at end of stream)."""
        return self._buf.flush()


def render_raw(data: str) -> list[str]:
    """One-shot convenience: render a full raw capture into lines."""
    r = CursorRenderer()
    out = r.feed(data)
    remainder = r.flush()
    if remainder:
        out.append(remainder)
    return out


def _handle_csi(buf: LineBuffer, params: str, final: str) -> None:
    """Handle a CSI escape sequence."""
    # Parse first param (default 1 for most, 0 for G/H/d)
    parts = params.split(";") if params else []

    def p(idx: int = 0, default: int = 1) -> int:
        try:
            return int(parts[idx]) if parts[idx] else default
        except (IndexError, ValueError):
            return default

    if final == "C":       # Cursor forward
        buf.move_rel(p())
    elif final == "D":     # Cursor back
        buf.move_rel(-p())
    elif final == "G":     # Cursor to absolute column (1-based)
        buf.move_to(p(default=1) - 1)
    elif final == "H" or final == "f":
        # Cursor position — in our single-line model, just handle column
        # CSI row;col H — we only care about col
        buf.move_to(p(1, default=1) - 1)
    elif final == "d":     # Cursor to absolute row — ignore (single line)
        pass
    elif final == "K":     # Erase in line
        mode = p(default=0)
        if mode == 0:
            buf.erase_to_end()
        elif mode == 1:
            buf.erase_to_start()
        elif mode == 2:
            buf.erase_line()
    elif final == "J":     # Erase in display — treat as erase line
        mode = p(default=0)
        if mode == 2 or mode == 3:
            buf.erase_line()
        elif mode == 0:
            buf.erase_to_end()
    elif final == "A":     # Cursor up — emit current line and reset
        line = buf.flush()
        # Don't append — cursor-up means the shell is redrawing
        pass
    elif final == "B":     # Cursor down — ignore
        pass
    elif final == "P":     # Delete characters at cursor
        count = p()
        pos = buf._cur
        buf._buf = buf._buf[:pos] + buf._buf[pos + count:]
    elif final == "@":     # Insert blank characters at cursor
        count = p()
        pos = buf._cur
        buf._buf = buf._buf[:pos] + [" "] * count + buf._buf[pos:]
    # All other CSI sequences (colors, modes, etc.) — ignore


def watch_file(input_path: Path, output_path: Path) -> None:
    """Watch a raw TTY file and write rendered lines to output."""
    renderer = CursorRenderer()
    cursor = 0
    with open(output_path, "a") as out:
        while True:
            try:
                size = input_path.stat().st_size
                if size > cursor:
                    with open(input_path, "rb") as f:
                        f.seek(cursor)
                        raw = f.read().decode("utf-8", errors="replace")
                    cursor = size
                    for line in renderer.feed(raw):
                        if line:
                            out.write(line + "\n")
                    out.flush()
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
