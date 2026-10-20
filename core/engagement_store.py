"""SQLite persistence for pentest/redteam engagements.

pentest-ctf uses JSON/in-memory (unchanged — this module is not loaded for CTF).

Each op lives at OPS_DIR/<op_name>/engagement.db.  The store is opened once per
session and closed on shutdown.  All writes use WAL mode and a 5-second busy
timeout so concurrent TUI + daemon access degrades gracefully.

Op lifecycle:
  - open_or_create(name, target, persona) → (EngagementStore, is_new, review_mode)
  - review_mode=True when the engagement was previously ended; callers treat it
    as read-only and do not start new runs.
  - end_engagement() marks status="ended" — next open is review_mode.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.paths import OPS_DIR


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _op_db_path(op_name: str) -> Path:
    d = OPS_DIR / op_name
    d.mkdir(parents=True, exist_ok=True)
    return d / "engagement.db"


class EngagementStore:
    def __init__(self, db_path: Path, engagement_id: str) -> None:
        self._db_path = db_path
        self.engagement_id = engagement_id
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.row_factory = sqlite3.Row

    # ── Schema ────────────────────────────────────────────────────────────────

    @staticmethod
    def _init_schema(conn: sqlite3.Connection) -> None:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS engagements (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                target      TEXT NOT NULL DEFAULT '',
                persona     TEXT NOT NULL DEFAULT 'pentest',
                status      TEXT NOT NULL DEFAULT 'running',
                objective   TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL,
                ended_at    TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS surfaces (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leads (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                agent           TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'running',
                summary         TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                ended_at        TEXT
            );
            CREATE TABLE IF NOT EXISTS token_usage (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                run_id          TEXT NOT NULL DEFAULT '',
                input_tokens    INTEGER NOT NULL DEFAULT 0,
                output_tokens   INTEGER NOT NULL DEFAULT 0,
                cache_read      INTEGER NOT NULL DEFAULT 0,
                cache_write     INTEGER NOT NULL DEFAULT 0,
                cost_usd        REAL NOT NULL DEFAULT 0.0,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analyst_cycles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                run_id          TEXT NOT NULL DEFAULT '',
                notes           TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL
            );
        """)
        conn.commit()

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def open_or_create(
        cls,
        op_name: str,
        target: str = "",
        persona: str = "pentest",
        objective: str = "",
    ) -> tuple["EngagementStore", bool, bool]:
        """Open or create an engagement DB for op_name.

        Returns (store, is_new, review_mode).
        review_mode=True when the engagement was previously ended.
        """
        db_path = _op_db_path(op_name)
        is_new = not db_path.exists()

        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        cls._init_schema(conn)

        row = conn.execute(
            "SELECT id, status FROM engagements WHERE name = ? ORDER BY created_at DESC LIMIT 1",
            (op_name,),
        ).fetchone()

        if row is None:
            engagement_id = str(uuid.uuid4())[:12]
            conn.execute(
                "INSERT INTO engagements (id, name, target, persona, status, objective, created_at)"
                " VALUES (?, ?, ?, ?, 'running', ?, ?)",
                (engagement_id, op_name, target, persona, objective, _now()),
            )
            conn.commit()
            review_mode = False
            is_new = True
        else:
            engagement_id = row["id"]
            review_mode = row["status"] == "ended"
            is_new = False

        store = cls.__new__(cls)
        store._db_path = db_path
        store.engagement_id = engagement_id
        store._conn = conn
        return store, is_new, review_mode

    # ── Writes ────────────────────────────────────────────────────────────────

    def upsert_finding(self, finding) -> None:
        """Insert or replace a Finding (by id)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO findings (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (finding.id, self.engagement_id, finding.model_dump_json(), _now()),
        )
        self._conn.commit()

    def upsert_credential(self, cred) -> None:
        """Insert or replace a Credential (by id). Masked secret only."""
        self._conn.execute(
            "INSERT OR REPLACE INTO credentials (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (cred.id, self.engagement_id, cred.model_dump_json(), _now()),
        )
        self._conn.commit()

    def upsert_surface(self, surface) -> None:
        """Insert or replace a Surface (by id)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO surfaces (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (surface.id, self.engagement_id, surface.model_dump_json(), _now()),
        )
        self._conn.commit()

    def upsert_fact(self, fact) -> None:
        """Insert or replace an OperationalFact (by id)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO facts (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (fact.id, self.engagement_id, fact.model_dump_json(), _now()),
        )
        self._conn.commit()

    def add_token_usage(
        self,
        run_id: str,
        input_tokens: int,
        output_tokens: int,
        cache_read: int = 0,
        cache_write: int = 0,
        cost_usd: float = 0.0,
    ) -> None:
        self._conn.execute(
            "INSERT INTO token_usage"
            " (engagement_id, run_id, input_tokens, output_tokens, cache_read, cache_write, cost_usd, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (self.engagement_id, run_id, input_tokens, output_tokens,
             cache_read, cache_write, cost_usd, _now()),
        )
        self._conn.commit()

    def upsert_run(self, run_id: str, agent: str, status: str, summary: str = "") -> None:
        """Create or update a run record."""
        existing = self._conn.execute(
            "SELECT id FROM runs WHERE id = ?", (run_id,)
        ).fetchone()
        if existing is None:
            self._conn.execute(
                "INSERT INTO runs (id, engagement_id, agent, status, summary, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, self.engagement_id, agent, status, summary, _now()),
            )
        else:
            ended_at = _now() if status in ("complete", "failed") else None
            self._conn.execute(
                "UPDATE runs SET status = ?, summary = ?, ended_at = ? WHERE id = ?",
                (status, summary, ended_at, run_id),
            )
        self._conn.commit()

    def end_engagement(self) -> None:
        """Mark the engagement ended — next open will be review_mode."""
        self._conn.execute(
            "UPDATE engagements SET status = 'ended', ended_at = ? WHERE id = ?",
            (_now(), self.engagement_id),
        )
        self._conn.commit()

    # ── Reads ─────────────────────────────────────────────────────────────────

    def load_engagement_meta(self) -> dict:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (self.engagement_id,)
        ).fetchone()
        return dict(row) if row else {}

    def load_findings(self) -> list:
        from core.models import Finding
        rows = self._conn.execute(
            "SELECT json FROM findings WHERE engagement_id = ? ORDER BY created_at",
            (self.engagement_id,),
        ).fetchall()
        return [Finding.model_validate_json(r["json"]) for r in rows]

    def load_credentials(self) -> list:
        from core.engagement_state import Credential
        rows = self._conn.execute(
            "SELECT json FROM credentials WHERE engagement_id = ? ORDER BY created_at",
            (self.engagement_id,),
        ).fetchall()
        return [Credential.model_validate_json(r["json"]) for r in rows]

    def load_surfaces(self) -> list:
        from core.models import Surface
        rows = self._conn.execute(
            "SELECT json FROM surfaces WHERE engagement_id = ? ORDER BY created_at",
            (self.engagement_id,),
        ).fetchall()
        return [Surface.model_validate_json(r["json"]) for r in rows]

    def load_facts(self) -> list:
        from core.models import OperationalFact
        rows = self._conn.execute(
            "SELECT json FROM facts WHERE engagement_id = ? ORDER BY created_at",
            (self.engagement_id,),
        ).fetchall()
        return [OperationalFact.model_validate_json(r["json"]) for r in rows]

    def token_usage_totals(self) -> dict:
        row = self._conn.execute(
            "SELECT SUM(input_tokens) as inp, SUM(output_tokens) as out,"
            "       SUM(cache_read) as cr, SUM(cache_write) as cw, SUM(cost_usd) as cost"
            " FROM token_usage WHERE engagement_id = ?",
            (self.engagement_id,),
        ).fetchone()
        if not row or row["inp"] is None:
            return {"input_tokens": 0, "output_tokens": 0, "cache_read": 0,
                    "cache_write": 0, "cost_usd": 0.0}
        return {
            "input_tokens": row["inp"], "output_tokens": row["out"],
            "cache_read": row["cr"], "cache_write": row["cw"],
            "cost_usd": row["cost"],
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
