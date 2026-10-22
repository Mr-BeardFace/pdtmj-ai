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

# Migration columns: (table, col_name, col_def) — added if missing on open
_MIGRATIONS: list[tuple[str, str, str]] = [
    ("analyst_cycles", "frontier_level", "TEXT NOT NULL DEFAULT ''"),
    ("analyst_cycles", "summary",        "TEXT NOT NULL DEFAULT ''"),
    ("analyst_cycles", "hypothesis",     "TEXT NOT NULL DEFAULT ''"),
    ("analyst_cycles", "next_steps_json","TEXT NOT NULL DEFAULT '[]'"),
    ("analyst_cycles", "op_picture",     "TEXT NOT NULL DEFAULT ''"),
    ("analyst_cycles", "advisory",       "TEXT NOT NULL DEFAULT ''"),
]


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
                frontier_level  TEXT NOT NULL DEFAULT '',
                summary         TEXT NOT NULL DEFAULT '',
                hypothesis      TEXT NOT NULL DEFAULT '',
                next_steps_json TEXT NOT NULL DEFAULT '[]',
                op_picture      TEXT NOT NULL DEFAULT '',
                advisory        TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id              TEXT PRIMARY KEY,
                engagement_id   TEXT NOT NULL,
                json            TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                ts              TEXT NOT NULL,
                message         TEXT NOT NULL,
                notable         INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hosts (
                ip              TEXT NOT NULL,
                engagement_id   TEXT NOT NULL,
                hostname        TEXT NOT NULL DEFAULT '',
                os              TEXT NOT NULL DEFAULT '',
                open_ports_json TEXT NOT NULL DEFAULT '[]',
                notes           TEXT NOT NULL DEFAULT '',
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (ip, engagement_id)
            );
            CREATE TABLE IF NOT EXISTS beacons (
                beacon_id       TEXT NOT NULL,
                engagement_id   TEXT NOT NULL,
                host            TEXT NOT NULL DEFAULT '',
                ip              TEXT NOT NULL DEFAULT '',
                user_ctx        TEXT NOT NULL DEFAULT '',
                arch            TEXT NOT NULL DEFAULT '',
                os              TEXT NOT NULL DEFAULT '',
                c2_type         TEXT NOT NULL DEFAULT 'unknown',
                notes           TEXT NOT NULL DEFAULT '',
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                PRIMARY KEY (beacon_id, engagement_id)
            );
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                service         TEXT NOT NULL DEFAULT '',
                host            TEXT NOT NULL DEFAULT '',
                port            INTEGER,
                username        TEXT NOT NULL DEFAULT '',
                secret_masked   TEXT NOT NULL DEFAULT '',
                result          TEXT NOT NULL DEFAULT 'fail',
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activity_records (
                activity_id     TEXT NOT NULL,
                engagement_id   TEXT NOT NULL,
                beacon_id       TEXT NOT NULL DEFAULT '',
                timestamp       TEXT NOT NULL DEFAULT '',
                ioc_type        TEXT NOT NULL DEFAULT 'unknown',
                execution_context TEXT NOT NULL DEFAULT '',
                execution_host  TEXT NOT NULL DEFAULT '',
                user_context    TEXT NOT NULL DEFAULT '',
                command_action  TEXT NOT NULL DEFAULT '',
                result          TEXT NOT NULL DEFAULT '',
                observable_artifacts TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL,
                PRIMARY KEY (activity_id, engagement_id)
            );
            CREATE TABLE IF NOT EXISTS log_cursors (
                file_path       TEXT NOT NULL,
                engagement_id   TEXT NOT NULL,
                byte_offset     INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (file_path, engagement_id)
            );
            CREATE TABLE IF NOT EXISTS analyst_state (
                engagement_id   TEXT PRIMARY KEY,
                frontier        TEXT NOT NULL DEFAULT 'recon',
                op_picture      TEXT NOT NULL DEFAULT '',
                advisory        TEXT NOT NULL DEFAULT '',
                opsec_level     TEXT NOT NULL DEFAULT 'low',
                updated_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                role            TEXT NOT NULL,
                content         TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS c2_state (
                engagement_id   TEXT NOT NULL,
                backend         TEXT NOT NULL,
                session_id      TEXT NOT NULL DEFAULT '',
                agent_index_json TEXT NOT NULL DEFAULT '{}',
                agent_done_json TEXT NOT NULL DEFAULT '[]',
                updated_at      TEXT NOT NULL,
                PRIMARY KEY (engagement_id, backend)
            );
            CREATE TABLE IF NOT EXISTS persistence (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id   TEXT NOT NULL,
                kind            TEXT NOT NULL DEFAULT 'other',
                host            TEXT NOT NULL DEFAULT '',
                detail          TEXT NOT NULL DEFAULT '',
                cleanup         TEXT NOT NULL DEFAULT '',
                created_at      TEXT NOT NULL
            );
        """)
        conn.commit()

    @staticmethod
    def _migrate_schema(conn: sqlite3.Connection) -> None:
        """Add new columns to existing tables without breaking existing DBs."""
        existing: dict[str, set[str]] = {}
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            tbl = row[0]
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({tbl})").fetchall()}
            existing[tbl] = cols
        for table, col, col_def in _MIGRATIONS:
            if table in existing and col not in existing[table]:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
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
        cls._migrate_schema(conn)

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

    def upsert_ioc(self, ioc) -> None:
        """Insert or replace an IOC (by id)."""
        self._conn.execute(
            "INSERT OR REPLACE INTO iocs (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (ioc.id, self.engagement_id, ioc.model_dump_json(), _now()),
        )
        self._conn.commit()

    def load_iocs(self) -> list:
        from core.models import IOC
        rows = self._conn.execute(
            "SELECT json FROM iocs WHERE engagement_id = ? ORDER BY created_at",
            (self.engagement_id,),
        ).fetchall()
        return [IOC.model_validate_json(r["json"]) for r in rows]

    def add_activity(self, ts: str, message: str, notable: bool = False) -> None:
        self._conn.execute(
            "INSERT INTO activity_log (engagement_id, ts, message, notable, created_at) VALUES (?, ?, ?, ?, ?)",
            (self.engagement_id, ts, message, int(notable), _now()),
        )
        self._conn.commit()

    def get_activity_log(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ts, message, notable FROM activity_log WHERE engagement_id = ? ORDER BY id",
            (self.engagement_id,),
        ).fetchall()
        return [{"ts": r["ts"], "message": r["message"], "notable": bool(r["notable"])} for r in rows]

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

    # ── Analyst helpers (flat-kwarg shortcuts for analyst DB writes) ──────────

    def add_finding_from_analyst(
        self, severity: str, title: str, description: str,
        target: str = "", evidence: str = "", technique: str = "",
    ) -> None:
        from core.models import Finding
        f = Finding(
            type="vuln",
            severity=severity,
            title=title,
            description=description,
            target=target,
            evidence={"raw": evidence} if evidence else {},
        )
        if technique:
            f.type = technique
        self.upsert_finding(f)

    def add_credential_from_analyst(
        self, username: str = "", secret: str = "",
        cred_type: str = "password", cred_format: str = "",
        location: str = "", service: str = "",
        source_host: str = "", added_by: str = "analyst",
    ) -> None:
        from core.engagement_state import Credential
        c = Credential(
            cred_type=cred_type,
            username=username or None,
            secret=secret,
            secret_format=cred_format,
            location=location,
            service=service,
            source_agent=added_by,
        )
        self.upsert_credential(c)

    def add_lead_from_analyst(
        self, description: str, reach_level: str = "vuln",
        prior: float = 0.5, cost: str = "medium",
        target: str = "", technique: str = "",
        command: str = "", opsec: str = "medium",
        insight: str = "routine", notes: str = "",
    ) -> None:
        from core.leads import Lead
        lead = Lead(
            kind=technique or "vuln",
            description=description,
            technique=technique,
            target=target,
            reach_level=reach_level,
            prior=prior,
            cost=cost,
            status="open",
            created_by="analyst",
            notes=(f"opsec:{opsec} insight:{insight} command:{command}" +
                   (f"\n{notes}" if notes else "")),
            detection_risk=opsec,
        )
        self._conn.execute(
            "INSERT OR IGNORE INTO leads (id, engagement_id, json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (lead.id, self.engagement_id, lead.model_dump_json(), _now()),
        )
        self._conn.commit()

    def add_fact(self, statement: str, evidence: str = "", scope: str = "") -> None:
        from core.models import OperationalFact
        self.upsert_fact(OperationalFact(kind="target", statement=statement,
                                         evidence=evidence, scope=scope))

    def add_analyst_cycle(
        self, frontier_level: str = "", summary: str = "",
        hypothesis: str = "", next_steps: list | None = None,
        op_picture: str = "", advisory: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO analyst_cycles"
            " (engagement_id, frontier_level, summary, hypothesis, next_steps_json,"
            "  op_picture, advisory, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (self.engagement_id, frontier_level, summary, hypothesis,
             json.dumps(next_steps or []), op_picture, advisory, _now()),
        )
        self._conn.commit()

    # ── Hosts ──────────────────────────────────────────────────────────────────

    def upsert_host(
        self, ip: str, hostname: str = "", os: str = "",
        notes: str = "", open_ports: list | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO hosts (ip, engagement_id, hostname, os, open_ports_json, notes, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(ip, engagement_id) DO UPDATE SET"
            "  hostname = excluded.hostname, os = excluded.os,"
            "  open_ports_json = excluded.open_ports_json,"
            "  notes = excluded.notes, updated_at = excluded.updated_at",
            (ip, self.engagement_id, hostname, os,
             json.dumps(open_ports or []), notes, _now()),
        )
        self._conn.commit()

    def load_hosts(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ip, hostname, os, open_ports_json, notes FROM hosts"
            " WHERE engagement_id = ? ORDER BY updated_at",
            (self.engagement_id,),
        ).fetchall()
        return [{
            "ip": r["ip"], "hostname": r["hostname"], "os": r["os"],
            "open_ports": json.loads(r["open_ports_json"] or "[]"),
            "notes": r["notes"],
        } for r in rows]

    # ── Beacons ────────────────────────────────────────────────────────────────

    def upsert_beacon(
        self, beacon_id: str, host: str = "", ip: str = "",
        user: str = "", arch: str = "", os: str = "",
        c2_type: str = "unknown", notes: str = "",
    ) -> None:
        now = _now()
        self._conn.execute(
            "INSERT INTO beacons"
            " (beacon_id, engagement_id, host, ip, user_ctx, arch, os, c2_type, notes, first_seen, last_seen)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(beacon_id, engagement_id) DO UPDATE SET"
            "  host=excluded.host, ip=excluded.ip, user_ctx=excluded.user_ctx,"
            "  arch=excluded.arch, os=excluded.os, c2_type=excluded.c2_type,"
            "  notes=excluded.notes, last_seen=excluded.last_seen",
            (beacon_id, self.engagement_id, host, ip, user, arch, os, c2_type, notes, now, now),
        )
        self._conn.commit()

    def load_beacons(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT beacon_id, host, ip, user_ctx, arch, os, c2_type, notes, first_seen, last_seen"
            " FROM beacons WHERE engagement_id = ? ORDER BY first_seen",
            (self.engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Auth attempts ──────────────────────────────────────────────────────────

    def add_auth_attempt(
        self, service: str, host: str, result: str,
        port: int | None = None, username: str = "", secret_masked: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO auth_attempts"
            " (engagement_id, service, host, port, username, secret_masked, result, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (self.engagement_id, service, host, port, username, secret_masked, result, _now()),
        )
        self._conn.commit()

    def load_auth_attempts(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT service, host, port, username, secret_masked, result, created_at"
            " FROM auth_attempts WHERE engagement_id = ? ORDER BY id",
            (self.engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Activity records (analyst-extracted) ──────────────────────────────────

    def add_activity_record(
        self, activity_id: str, beacon_id: str = "",
        timestamp: str = "", ioc_type: str = "unknown",
        execution_context: str = "", execution_host: str = "",
        user_context: str = "", command_action: str = "",
        result: str = "", observable_artifacts: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO activity_records"
            " (activity_id, engagement_id, beacon_id, timestamp, ioc_type,"
            "  execution_context, execution_host, user_context, command_action,"
            "  result, observable_artifacts, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (activity_id, self.engagement_id, beacon_id, timestamp, ioc_type,
             execution_context, execution_host, user_context, command_action,
             result, observable_artifacts, _now()),
        )
        self._conn.commit()

    def load_activity_records(self, limit: int = 200) -> list[dict]:
        rows = self._conn.execute(
            "SELECT activity_id, beacon_id, timestamp, ioc_type, execution_context,"
            "       execution_host, user_context, command_action, result, observable_artifacts"
            " FROM activity_records WHERE engagement_id = ? ORDER BY created_at DESC LIMIT ?",
            (self.engagement_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Log cursors ────────────────────────────────────────────────────────────

    def get_log_cursor(self, file_path: str) -> int:
        row = self._conn.execute(
            "SELECT byte_offset FROM log_cursors WHERE file_path = ? AND engagement_id = ?",
            (file_path, self.engagement_id),
        ).fetchone()
        return row["byte_offset"] if row else 0

    def set_log_cursor(self, file_path: str, offset: int) -> None:
        self._conn.execute(
            "INSERT INTO log_cursors (file_path, engagement_id, byte_offset, updated_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(file_path, engagement_id) DO UPDATE SET"
            "  byte_offset=excluded.byte_offset, updated_at=excluded.updated_at",
            (file_path, self.engagement_id, offset, _now()),
        )
        self._conn.commit()

    def load_log_cursors(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT file_path, byte_offset FROM log_cursors WHERE engagement_id = ?",
            (self.engagement_id,),
        ).fetchall()
        return {r["file_path"]: r["byte_offset"] for r in rows}

    # ── Analyst state ──────────────────────────────────────────────────────────

    def upsert_analyst_state(
        self, frontier: str = "recon", op_picture: str = "",
        advisory: str = "", opsec_level: str = "low",
    ) -> None:
        self._conn.execute(
            "INSERT INTO analyst_state (engagement_id, frontier, op_picture, advisory, opsec_level, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(engagement_id) DO UPDATE SET"
            "  frontier=excluded.frontier, op_picture=excluded.op_picture,"
            "  advisory=excluded.advisory, opsec_level=excluded.opsec_level,"
            "  updated_at=excluded.updated_at",
            (self.engagement_id, frontier, op_picture, advisory, opsec_level, _now()),
        )
        self._conn.commit()

    def get_analyst_state(self) -> dict | None:
        row = self._conn.execute(
            "SELECT frontier, op_picture, advisory, opsec_level, updated_at"
            " FROM analyst_state WHERE engagement_id = ?",
            (self.engagement_id,),
        ).fetchone()
        return dict(row) if row else None

    # ── Chat history ───────────────────────────────────────────────────────────

    def add_chat_message(self, role: str, content: str) -> None:
        self._conn.execute(
            "INSERT INTO chat_history (engagement_id, role, content, created_at)"
            " VALUES (?, ?, ?, ?)",
            (self.engagement_id, role, content, _now()),
        )
        self._conn.commit()

    def load_chat_history(self, limit: int = 20) -> list[dict]:
        rows = self._conn.execute(
            "SELECT role, content FROM chat_history WHERE engagement_id = ?"
            " ORDER BY id DESC LIMIT ?",
            (self.engagement_id, limit),
        ).fetchall()
        return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]

    def clear_chat_history(self) -> None:
        self._conn.execute(
            "DELETE FROM chat_history WHERE engagement_id = ?", (self.engagement_id,)
        )
        self._conn.commit()

    # ── C2 state ───────────────────────────────────────────────────────────────

    def upsert_c2_state(
        self, backend: str, session_id: str = "",
        agent_index: dict | None = None, agent_done: list | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO c2_state"
            " (engagement_id, backend, session_id, agent_index_json, agent_done_json, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(engagement_id, backend) DO UPDATE SET"
            "  session_id=excluded.session_id, agent_index_json=excluded.agent_index_json,"
            "  agent_done_json=excluded.agent_done_json, updated_at=excluded.updated_at",
            (self.engagement_id, backend, session_id,
             json.dumps(agent_index or {}), json.dumps(agent_done or []), _now()),
        )
        self._conn.commit()

    def get_c2_state(self, backend: str) -> dict | None:
        row = self._conn.execute(
            "SELECT session_id, agent_index_json, agent_done_json FROM c2_state"
            " WHERE engagement_id = ? AND backend = ?",
            (self.engagement_id, backend),
        ).fetchone()
        if not row:
            return None
        return {
            "session_id": row["session_id"],
            "agent_index": json.loads(row["agent_index_json"] or "{}"),
            "agent_done": json.loads(row["agent_done_json"] or "[]"),
        }

    # ── Persistence ────────────────────────────────────────────────────────────

    def add_persistence(
        self, kind: str = "other", host: str = "",
        detail: str = "", cleanup: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO persistence (engagement_id, kind, host, detail, cleanup, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (self.engagement_id, kind, host, detail, cleanup, _now()),
        )
        self._conn.commit()

    def load_persistence(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT kind, host, detail, cleanup, created_at FROM persistence"
            " WHERE engagement_id = ? ORDER BY id",
            (self.engagement_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Token totals summary ───────────────────────────────────────────────────

    def get_token_summary(self) -> dict:
        """Quick token totals + cost across all analyst cycles for this engagement."""
        row = self._conn.execute(
            "SELECT SUM(input_tokens) as inp, SUM(output_tokens) as out, SUM(cost_usd) as cost"
            " FROM token_usage WHERE engagement_id = ?",
            (self.engagement_id,),
        ).fetchone()
        if not row or row["inp"] is None:
            return {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
        return {"input_tokens": int(row["inp"]), "output_tokens": int(row["out"]),
                "cost_usd": float(row["cost"] or 0.0)}

    # ── Notable leads count (for badge) ───────────────────────────────────────

    def count_notable_open_leads(self) -> int:
        """Count open leads with insight=notable (for RPROMPT badge)."""
        rows = self._conn.execute(
            "SELECT json FROM leads WHERE engagement_id = ?", (self.engagement_id,)
        ).fetchall()
        count = 0
        for r in rows:
            try:
                d = json.loads(r["json"])
                # leads store insight in notes field as "opsec:X insight:Y command:Z"
                notes = d.get("notes", "")
                status = d.get("status", "open")
                if status in ("open", "active", "advancing") and "insight:notable" in notes:
                    count += 1
            except Exception:
                pass
        return count

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
