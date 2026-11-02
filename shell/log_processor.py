#!/usr/bin/env python3
"""
Real-time log processor: tails a .raw TTY capture, strips ANSI, writes clean .log.

Usage:
  # Watch a raw file and write ANSI-stripped lines to .log:
  python3 log_processor.py --watch /path/to/input.raw --out /path/to/output.log

  # Pipe stdin through and write clean lines to a file (for evil-winrm wrapper):
  command | python3 log_processor.py --stdin /path/to/output.log
"""
from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path


_ANSI = __import__("re").compile(
    r"\x1b(?:"
    r"\].*?(?:\x07|\x1b\\)"   # OSC: ESC ] ... BEL | ESC \
    r"|\[[0-9;?]*[@-~]"        # CSI: ESC [ ... final
    r"|[@-Z\\-_]"              # Fe: ESC single-byte
    r")"
    r"|\r|\x07|\x08"           # bare CR, BEL, and BS
)


def _clean(line: str) -> str:
    return _ANSI.sub("", line).rstrip("\r").rstrip()


def watch_file(input_path: Path, output_path: Path) -> None:
    """Watch a raw TTY file and write ANSI-stripped lines to output.

    Lines are written without timestamps so the preprocessor treats the whole
    file as unstructured output content (one chunk via fallback), rather than
    treating each line as a separate command.  The cmd_*.log written by the
    preexec hook provides the command timeline; this file provides the output.
    """
    cursor = 0
    with open(output_path, "a") as out:
        while True:
            try:
                size = input_path.stat().st_size
                if size > cursor:
                    with open(input_path, "rb") as f:
                        f.seek(cursor)
                        raw = f.read().decode("utf-8", errors="replace")
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
