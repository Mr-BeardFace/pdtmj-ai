from __future__ import annotations
import re
from pathlib import Path
from datetime import datetime, timezone

_MAX_OUTPUT_LINES = 200

# ── ANSI / OSC stripping ──────────────────────────────────────────────────────
_ANSI = re.compile(
    r"\x1b(?:"
    r"\].*?(?:\x07|\x1b\\)"   # OSC: ESC ] ... BEL | ESC \
    r"|\[[0-9;?]*[@-~]"        # CSI: ESC [ ... final
    r"|[@-Z\\-_]"              # Fe: ESC single-byte
    r")"
    r"|\r|\x07|\x08"           # bare CR, BEL, and BS
)

def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


# ── prompt patterns ───────────────────────────────────────────────────────────

# cmd_YYYYMMDD.log format from preexec hook: "[2024-10-22 20:12:38] nmap -sC ..."
_CMD_LOG_LINE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.+)$"
)

_LOCAL_PROMPT = re.compile(
    r"^(?:\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\])?"
    r"\[([^\]]+)\]:([^\$\n]*)\$"
)

# ponytail: heuristic — extend when a new shell format is seen
_REMOTE_PROMPT = re.compile(
    r"^"
    r"(?:[0-9];[^\[]*)?+"
    r"(?:"
    r"\[[\w\-\.]+@[\w\-\.][^\]]*\]"
    r"|[\w\-\.]+@[\w\-\.]+[:/~]"
    r"|[\w\-\.]+:[/~]"
    r")"
    r"[^\n]{0,60}"
    r"[$#>]\s*$"
)

_SHELL_IDLE_OSC = re.compile(
    r"^2;[\w\-\.]+@[\w\-\.]+[:/]"
)

def _parse_osc_title(line: str) -> tuple[str | None, str]:
    if not line.startswith("2;"):
        return None, ""
    if _SHELL_IDLE_OSC.match(line):
        return None, ""
    if "7;file://" in line:
        return None, ""

    content = line[2:]
    trailing = ""

    if "1;" in content:
        cmd_part = content[:content.index("1;")].strip()
        rest = content[content.index("1;") + 2:]
        short = cmd_part.split()[0] if cmd_part else ""
        if short and rest.startswith(short):
            trailing = rest[len(short):]
        cmd = cmd_part
    else:
        cmd = content.strip()

    return (cmd if cmd else None), trailing


# ── assembled-command detection ───────────────────────────────────────────────

def _reconstruct_from_echo(lines: list[str]) -> tuple[str, list[str]]:
    concat = ""
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        s_nows = re.sub(r"\s+", "", s)
        concat_nows = re.sub(r"\s+", "", concat)
        if concat_nows and s_nows == concat_nows:
            return s, [l for l in lines[i + 1:] if l.strip()]
        if (concat_nows and len(s_nows) > len(concat_nows)
                and s_nows.startswith(concat_nows)):
            return s, [l for l in lines[i + 1:] if l.strip()]
        concat += s
    return "", [l for l in lines if l.strip()]


# ponytail: threshold=5; was 4 but 4-char PHP/output lines were being swallowed
_PTY_ECHO_THRESHOLD = 5

def _reconstruct_pty_echo(lines: list[str]) -> tuple[str, list[str]]:
    cmd_parts: list[str] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        if len(s) <= _PTY_ECHO_THRESHOLD:
            cmd_parts.append(s)
        else:
            return "".join(cmd_parts), [l for l in lines[i:] if l.strip()]
    return "".join(cmd_parts), []


_PROMPT_ID = re.compile(r"([\w\-\.]+)@([\w\-\.]+).*?([$#])\s*$")

def _prompt_identity(prompt: str) -> tuple[str, str, str] | None:
    m = _PROMPT_ID.search(prompt)
    return (m.group(1), m.group(2), m.group(3)) if m else None

def _make_session_event(old: tuple[str, str, str], new: tuple[str, str, str]) -> dict:
    ou, oh, op = old
    nu, nh, np = new
    if oh != nh:
        sig = f"lateral movement → {nh}"
    elif op == "$" and np == "#":
        sig = "privilege escalation → root"
    elif ou != nu:
        sig = f"user changed: {ou} → {nu}"
    else:
        sig = "prompt changed"
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "command": f"(session event: {sig})",
        "output": f"{ou}@{oh}{op} → {nu}@{nh}{np}",
        "context": "session-event",
    }


def _is_assembled_echo(garbled: str, candidate: str) -> bool:
    # ponytail: subsequence + prefix + ratio — cheap and specific enough
    g = re.sub(r"\s+", "", garbled)
    c = re.sub(r"\s+", "", candidate)
    if not c or len(c) < 3 or len(c) < len(g) * 0.7:
        return False
    pfx = min(3, len(c), len(g))
    if g[:pfx] != c[:pfx]:
        return False
    it = iter(g)
    return all(ch in it for ch in c)


# ── block ─────────────────────────────────────────────────────────────────────

_NOISE_LINES = re.compile(r"^[=>%\s]*$")
_OSC_REMNANT = re.compile(r"^[0-9];")


class _Block:
    def __init__(self, timestamp: str | None, context: str,
                 identity: tuple[str, str, str] | None = None):
        self.timestamp = timestamp
        self.context = context
        self.identity = identity
        self.command_title: str | None = None
        self.lines: list[str] = []
        self.extra_output: list[str] = []
        self._title_at: int = -1

    def _tag(self, chunk: dict) -> dict:
        if self.identity:
            chunk["remote_user"], chunk["remote_host"], chunk["remote_privs"] = self.identity
        return chunk

    def add(self, line: str) -> None:
        s = line.strip()
        if s and not _NOISE_LINES.match(s):
            self.lines.append(s)

    def set_title(self, cmd: str, trailing: str = "") -> None:
        if not self.command_title:
            self.command_title = cmd
            self._title_at = len(self.lines)
            if trailing.strip():
                self.extra_output.append(trailing.strip())

    def finalize(self) -> dict | None:
        content = [l for l in self.lines if l.strip() and not _OSC_REMNANT.match(l)]
        if not content and not self.command_title and not self.extra_output:
            return None

        ts = self.timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        if self.command_title:
            if self._title_at >= 0:
                post = [l for l in self.lines[self._title_at:]
                        if l.strip() and not _OSC_REMNANT.match(l)]
            else:
                post = content
            output_lines = self.extra_output + post
            return self._tag({
                "timestamp": ts,
                "command": self.command_title,
                "output": "\n".join(output_lines[:_MAX_OUTPUT_LINES]).strip(),
                "context": self.context,
            })

        if not content:
            return None

        if self.context == "local":
            return {
                "timestamp": ts,
                "command": content[0],
                "output": "\n".join(content[1:_MAX_OUTPUT_LINES]).strip(),
                "context": self.context,
            }

        cmd, output = _reconstruct_from_echo(content)
        if cmd:
            return self._tag({
                "timestamp": ts,
                "command": cmd,
                "output": "\n".join(output[:_MAX_OUTPUT_LINES]).strip(),
                "context": "remote-nc",
            })

        cmd, output = _reconstruct_pty_echo(content)
        if cmd:
            if output and _is_assembled_echo(cmd, output[0]):
                cmd, output, ctx = output[0], output[1:], "remote-nc"
            else:
                ctx = "remote-pty"
            return self._tag({
                "timestamp": ts,
                "command": cmd,
                "output": "\n".join(output[:_MAX_OUTPUT_LINES]).strip(),
                "context": ctx,
            })

        return self._tag({
            "timestamp": ts,
            "command": "(remote session)",
            "output": "\n".join(content[:_MAX_OUTPUT_LINES]).strip(),
            "context": "remote-raw",
        })


# ── cmd log fast path ────────────────────────────────────────────────────────

def _parse_cmd_log(lines: list[str]) -> list[dict]:
    """Parse preexec cmd log lines: '[YYYY-MM-DD HH:MM:SS] command'."""
    chunks: list[dict] = []
    for line in lines:
        m = _CMD_LOG_LINE.match(line)
        if m:
            chunks.append({
                "timestamp": m.group(1),
                "command": m.group(2),
                "output": "",
                "context": "local",
            })
    return chunks


# ── main entry points ─────────────────────────────────────────────────────────

def parse_chunks(raw: bytes) -> list[dict]:
    """Parse raw script/tty log bytes into [{timestamp, command, output, context}]."""
    text = strip_ansi(raw.decode("utf-8", errors="replace"))
    lines = text.splitlines()

    # Fast path: detect cmd_YYYYMMDD.log format (every non-blank line matches _CMD_LOG_LINE)
    non_blank = [l.strip() for l in lines if l.strip()]
    if non_blank and all(_CMD_LOG_LINE.match(l) for l in non_blank):
        return _parse_cmd_log(non_blank)

    chunks: list[dict] = []
    current: _Block | None = None
    learned_prompt: str | None = None
    learned_id: tuple[str, str, str] | None = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("Script started") or stripped.startswith("Script done"):
            continue

        if stripped.startswith("2;"):
            cmd, trailing = _parse_osc_title(stripped)
            if cmd and current is not None:
                current.set_title(cmd, trailing)
            continue

        if _OSC_REMNANT.match(stripped) and not re.search(r"[$#]", stripped):
            continue

        # cmd log line embedded in mixed content (e.g. tty log with timestamps)
        cm = _CMD_LOG_LINE.match(stripped)
        if cm:
            if current is not None:
                chunk = current.finalize()
                if chunk:
                    chunks.append(chunk)
            current = _Block(timestamp=cm.group(1), context="local")
            current.add(cm.group(2))
            continue

        m = _LOCAL_PROMPT.match(stripped)
        if m:
            if current is not None:
                chunk = current.finalize()
                if chunk:
                    chunks.append(chunk)
            current = _Block(timestamp=m.group(1), context="local")
            continue

        is_remote = stripped == learned_prompt
        if not is_remote and _REMOTE_PROMPT.match(stripped):
            is_remote = True
            new_id = _prompt_identity(stripped)
            if learned_prompt is None:
                learned_prompt, learned_id = stripped, new_id
            elif new_id and learned_id and new_id != learned_id:
                if current is not None:
                    chunk = current.finalize()
                    if chunk:
                        chunks.append(chunk)
                    current = None
                chunks.append(_make_session_event(learned_id, new_id))
                learned_prompt, learned_id = stripped, new_id

        if is_remote:
            if current is not None:
                chunk = current.finalize()
                if chunk:
                    chunks.append(chunk)
            current = _Block(timestamp=None, context="remote", identity=learned_id)
            continue

        if current is not None:
            current.add(stripped)

    if current is not None:
        chunk = current.finalize()
        if chunk:
            chunks.append(chunk)

    if not chunks:
        clean_lines = [l for l in lines if l.strip()]
        if clean_lines:
            chunks = [{
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "command": "(raw session — format unrecognised)",
                "output": "\n".join(clean_lines[:_MAX_OUTPUT_LINES]),
                "context": "raw",
            }]

    return chunks


def chunks_to_text(chunks: list[dict]) -> str:
    """Format parsed chunks into a clean LLM-readable string.

    All target-sourced content is wrapped in <TARGET_OUTPUT> so the analyst
    system prompt can treat it as untrusted data, not instructions.
    """
    parts = []
    for c in chunks:
        if c.get("context") == "session-event":
            parts.append(f"[{c['timestamp']}] *** {c['command']} ***\n{c.get('output', '')}")
            continue
        ctx = f"[{c.get('context', '?')}] " if c.get("context") else ""
        incomplete = c.get("context") == "remote-raw"
        block = f"[{c['timestamp']}] {ctx}$ {c['command']}"
        if incomplete:
            block += "  [NOTE: output structure unrecognised — content may be partial or misaligned]"
        if c.get("output"):
            out_lines = c["output"].splitlines()
            if len(out_lines) > 100:
                block += "\n" + "\n".join(out_lines[:100])
                block += f"\n... ({len(out_lines) - 100} more lines truncated)"
            else:
                block += "\n" + c["output"]
        parts.append(block)
    return "<TARGET_OUTPUT>\n" + "\n\n".join(parts) + "\n</TARGET_OUTPUT>"
