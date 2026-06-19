"""Artifact store for large tool output.

Tool output that would be wasteful or impossible to pass through the LLM is
written to a file here; the model receives a small preview plus an
`artifact_id` and can then `grep_artifact` / `read_artifact` to pull exactly
the lines it needs. This keeps full fidelity (nothing is silently truncated
away) while keeping the context window small.

Stores are engagement-scoped: one per Orchestrator, so every agent in an
engagement can read artifacts produced by earlier agents.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path


class ArtifactStore:
    def __init__(self, base_dir: Path):
        self.dir = Path(base_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        # Lightweight in-memory index so any agent can be SHOWN what raw captures
        # exist this engagement (and read them on demand). Shared across agents via
        # the single per-engagement store.
        self._index: list[dict] = []

    # ── write ─────────────────────────────────────────────────────────────────

    def store(self, content: str, *, label: str = "output", ext: str = "txt") -> dict:
        """Persist content and return a reference dict."""
        if not isinstance(content, str):
            content = str(content)
        aid  = uuid.uuid4().hex[:10]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:40] or "output"
        path = self.dir / f"{aid}_{safe}.{ext}"
        path.write_text(content, encoding="utf-8")
        lines = content.count("\n") + 1
        self._index.append({"artifact_id": aid, "label": safe, "lines": lines,
                            "bytes": len(content)})
        return {
            "artifact_id": aid,
            "path": str(path),
            "bytes": len(content),
            "lines": lines,
        }

    def recent(self, n: int = 12) -> list[dict]:
        """The most-recently stored artifacts (newest first) for the context index."""
        return list(reversed(self._index[-n:]))

    # ── read ──────────────────────────────────────────────────────────────────

    def _resolve(self, artifact_id: str) -> Path | None:
        aid = re.sub(r"[^A-Za-z0-9]", "", artifact_id or "")
        if not aid:
            return None
        matches = list(self.dir.glob(f"{aid}_*"))
        return matches[0] if matches else None

    def read(self, artifact_id: str, offset: int = 0, limit: int = 200) -> dict:
        """Return a slice of lines [offset, offset+limit)."""
        path = self._resolve(artifact_id)
        if path is None:
            return {"error": f"artifact {artifact_id!r} not found"}
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        offset = max(0, offset)
        window = lines[offset:offset + max(1, limit)]
        return {
            "artifact_id": artifact_id,
            "total_lines": len(lines),
            "offset": offset,
            "returned": len(window),
            "content": "\n".join(window),
        }

    def grep(self, artifact_id: str, pattern: str, *, ignore_case: bool = True,
             context: int = 0, max_matches: int = 200, invert: bool = False) -> dict:
        """Return lines matching a regex, optionally with surrounding context."""
        path = self._resolve(artifact_id)
        if path is None:
            return {"error": f"artifact {artifact_id!r} not found"}
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as e:
            return {"error": f"invalid pattern: {e}"}

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        ctx = max(0, context)
        hits: list[int] = [i for i, ln in enumerate(lines) if bool(rx.search(ln)) != invert]
        total = len(hits)
        hits = hits[:max_matches]

        if ctx == 0:
            out = [f"{i + 1}: {lines[i]}" for i in hits]
        else:
            shown: set[int] = set()
            out = []
            for i in hits:
                for j in range(max(0, i - ctx), min(len(lines), i + ctx + 1)):
                    if j not in shown:
                        shown.add(j)
                        marker = ":" if j == i else "-"
                        out.append(f"{j + 1}{marker} {lines[j]}")
        return {
            "artifact_id": artifact_id,
            "pattern": pattern,
            "total_matches": total,
            "returned_matches": len(hits),
            "truncated": total > len(hits),
            "content": "\n".join(out),
        }
