"""Persistent session logging for engagements.

Every orchestrator event is written to two files that share a base path:

  - <name>.log    human-readable, timestamped — reasoning, commands, output,
                  annotations, operator actions. This is the file you read.
  - <name>.jsonl  one JSON object per event with full (untruncated) data —
                  for tooling, replay, or grepping raw output.

The logger is deliberately defensive: a logging failure must never interrupt
an engagement, so every write is wrapped and swallowed.
"""
from __future__ import annotations

import json
from core.timeutil import now_local
from pathlib import Path
from typing import Any

# Events that are pure UI/accounting noise — kept in the jsonl stream but never
# written to the human-readable log.
_TEXT_SKIP = {"token_update", "state_update"}

# How much tool output to inline in the .log file (full output is always in jsonl).
_OUTPUT_CAP = 2000


class SessionLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.path.with_suffix(".jsonl")

    # ── public API ────────────────────────────────────────────────────────────

    def header(self, target: str, objective: str | None = None,
               persona: str = "", mode: str = "pipeline") -> None:
        ts = self._stamp()
        lines = [
            "=" * 78,
            "  PDTMJ-AI engagement log",
            f"  started : {ts}",
            f"  target  : {target}",
            f"  mode    : {mode}",
        ]
        if persona:
            lines.append(f"  persona : {persona}")
        if objective:
            lines.append(f"  objective: {objective}")
        lines.append("=" * 78)
        self._write_text("\n".join(lines) + "\n")
        self._write_json("session_start", {
            "target": target, "objective": objective,
            "persona": persona, "mode": mode,
        })

    def log(self, event_type: str, data: dict[str, Any]) -> None:
        """Record one event. Safe to call from any thread; never raises."""
        try:
            self._write_json(event_type, data)
        except Exception:
            pass
        if event_type in _TEXT_SKIP:
            return
        try:
            text = self._format(event_type, data)
            if text:
                self._write_text(f"{self._stamp()}  {text}\n")
        except Exception:
            pass

    # ── formatting ────────────────────────────────────────────────────────────

    def _format(self, t: str, d: dict[str, Any]) -> str:
        if t == "agent_start":
            return (f"\n{'─' * 60}\n"
                    f"AGENT  {d.get('agent', '?')} → {d.get('target', '?')}"
                    f"  (run {d.get('run_id', '?')})")

        if t == "agent_reasoning":
            text = (d.get("text") or "").strip()
            if not text:
                return ""
            body = "\n".join(f"        {ln}" for ln in text.splitlines() if ln.strip())
            return "reasoning:\n" + body

        if t == "tool_start":
            inputs = d.get("inputs", {})
            return f"→ {d.get('name', '?')}  {self._compact(inputs)}"

        if t == "tool_done":
            parts = []
            if d.get("command_str"):
                parts.append(f"$ {d['command_str']}")
            if d.get("summary"):
                parts.append(f"  ✓ {d['summary']}")
            out = d.get("output")
            if out is not None:
                rendered = out if isinstance(out, str) else self._compact(out, cap=_OUTPUT_CAP)
                if len(rendered) > _OUTPUT_CAP:
                    rendered = rendered[:_OUTPUT_CAP] + " …[truncated — see .jsonl]"
                parts.append(f"  output: {rendered}")
            return "\n".join(parts)

        if t == "tool_cached":
            return f"↩ {d.get('name', '?')}  cache hit — {d.get('summary', '')}"

        if t == "tool_error":
            return f"✗ {d.get('name', '?')}: {d.get('error', '')}"

        if t == "annotation":
            state = "verified" if d.get("verified") else "potential"
            sev   = str(d.get("severity", "info")).upper()
            line  = f"[{sev}] {d.get('title', '')}  ({state})"
            desc  = (d.get("description") or "").strip()
            if desc:
                line += f"\n        {desc}"
            return line

        if t == "followup_queued":
            return f"→ followup queued: {d.get('agent_name', '?')} on {d.get('target', '?')}"

        if t == "followup_rejected":
            return f"✗ followup rejected (out of scope): {d.get('agent_name', '?')} on {d.get('target', '?')}"

        if t == "operator_interrupt":
            return f"⚡ operator: {d.get('message', '')}"

        if t == "operator_command":
            return f"» {d.get('text', '')}"

        if t == "agent_done":
            return (f"■ {d.get('agent', '?')} complete — "
                    f"{d.get('findings_count', 0)} finding(s)  ${d.get('cost', 0):.4f}")

        if t == "api_retry":
            return f"⟳ {d.get('reason', '')} — retry {d.get('attempt', '?')}/5 in {d.get('wait', 0):.0f}s"

        if t == "note":
            return d.get("text", "")

        return ""

    @staticmethod
    def _compact(value: Any, cap: int = 400) -> str:
        try:
            s = json.dumps(value, default=str, ensure_ascii=False)
        except Exception:
            s = str(value)
        return s if len(s) <= cap else s[:cap] + "…"

    # ── io ────────────────────────────────────────────────────────────────────

    @staticmethod
    def _stamp() -> str:
        return now_local().strftime("%Y-%m-%d %H:%M:%S")

    def _write_text(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(text)

    def _write_json(self, event_type: str, data: dict[str, Any]) -> None:
        rec = {"ts": now_local().isoformat(),
               "type": event_type, **data}
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str, ensure_ascii=False) + "\n")
