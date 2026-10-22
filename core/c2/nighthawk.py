"""Nighthawk C2 backend — polls NightHawk API and writes logs to op log dir.

Auth flow: POST /api/v1.0/User/login → sessionId → X-NHAPI-SESSION header.
Content-Type must be text/json; application/json returns HTTP 415.
State (session_id, agent_index cursors) is stored in engagement DB, not a JSON file.
"""
from __future__ import annotations

import json
import ssl
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from core import config
from core.c2.base import C2Backend

_POLL_COUNT = 100


class NighthawkC2(C2Backend):

    def __init__(
        self,
        log_dir: Path,
        on_activity: Callable[[str], None],
        store=None,
    ) -> None:
        super().__init__(log_dir, on_activity)
        self._url        = config.get("c2.nighthawk.url", "").rstrip("/")
        self._username   = config.get("c2.nighthawk.username", "")
        self._password   = self._get_password()
        self._verify_tls = config.get("c2.nighthawk.verify_tls", False)
        self._poll_secs  = int(config.get("c2.nighthawk.poll_interval", 30))
        self._store      = store

        self._session_id:    str | None      = None
        self._agent_index:   dict[str, int]  = {}
        self._agent_done:    set[str]        = set()
        self._agent_names:   dict[str, str]  = {}
        self._agent_announced: set[str]      = set()

        self._stop   = threading.Event()
        self._thread: threading.Thread | None = None
        self._load_state()

    @staticmethod
    def _get_password() -> str:
        try:
            import keyring
            return keyring.get_password("pentest-ai", "nighthawk") or ""
        except Exception:
            return ""

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        if not self._url:
            self._on_activity("[yellow]C2:[/yellow] Nighthawk URL not configured — use /c2 url <url>")
            return
        if not self._username or not self._password:
            self._on_activity("[yellow]C2:[/yellow] Credentials not set — use /c2 auth <user> <pass>")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="nh-poller")
        self._thread.start()
        self._on_activity(f"[green]C2:[/green] Nighthawk polling {self._url}")

    def stop(self) -> None:
        self._stop.set()
        self._save_state()
        if self._session_id:
            try:
                self._request("GET", f"/api/v1.0/User/logout/{self._session_id}")
            except Exception:
                pass
            self._session_id = None
        self._on_activity("[yellow]C2:[/yellow] Nighthawk polling stopped")

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _login(self) -> None:
        body = json.dumps({"username": self._username, "password": self._password}).encode()
        resp = self._request("POST", "/api/v1.0/User/login", body=body)
        sid = resp.get("sessionId") or resp.get("session_id") or resp.get("id")
        if not sid:
            raise ValueError(f"NH login: no sessionId in response — keys: {list(resp.keys())}")
        self._session_id = sid
        self._save_state()

    def _ensure_session(self) -> None:
        if not self._session_id:
            self._login()

    # ── State persistence (DB) ────────────────────────────────────────────────

    def _save_state(self) -> None:
        if not self._store:
            return
        try:
            self._store.upsert_c2_state(
                backend="nighthawk",
                session_id=self._session_id or "",
                agent_index=self._agent_index,
                agent_done=list(self._agent_done),
            )
        except Exception:
            pass

    def _load_state(self) -> None:
        if not self._store:
            return
        try:
            state = self._store.get_c2_state("nighthawk")
            if state:
                self._session_id  = state["session_id"] or None
                self._agent_index = state["agent_index"] or {}
                self._agent_done  = set(state["agent_done"] or [])
        except Exception:
            pass

    # ── Poll loop ─────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._poll_once()
            except RuntimeError as e:
                msg = str(e)
                if "401" in msg or "403" in msg or "session" in msg.lower():
                    self._session_id = None
                    self._save_state()
                else:
                    self._on_activity(f"[red]C2 error:[/red] {e}")
            except Exception as e:
                self._on_activity(f"[red]C2 error:[/red] {e}")
            self._stop.wait(self._poll_secs)

    def _poll_once(self) -> None:
        self._ensure_session()
        result = self._request("GET", "/api/v1.0/Agent/list?includeDisconnected=true")
        agents: list[dict] = (
            result.get("innerResult") or result.get("result") or []
            if isinstance(result, dict) else result
        )
        if not agents:
            return

        for agent in agents:
            cid = agent.get("clientId", "")
            if not cid:
                continue
            self._agent_names[cid] = self._display_name(agent)
            connected = bool(agent.get("connected", True))

            if cid not in self._agent_announced:
                block = self._beacon_block(agent)
                if block:
                    self._write_log(f"c2_nh_{cid[:8]}.log", block)
                    self._on_activity(
                        f"[green]C2:[/green] New beacon: {cid[:8]} @ {self._display_name(agent)}"
                    )
                    if self._store:
                        mi = agent.get("detailedMachineInfo") or {}
                        self._store.upsert_beacon(
                            beacon_id=cid[:16],
                            host=mi.get("machineName") or agent.get("externalIP", ""),
                            ip=agent.get("externalIP", ""),
                            user=mi.get("userName", ""),
                            os=mi.get("osVersion", ""),
                            c2_type="nighthawk",
                        )
                self._agent_announced.add(cid)

            if cid in self._agent_done:
                continue

            idx  = self._agent_index.get(cid, 0)
            body = json.dumps([cid]).encode()
            result2 = self._request(
                "POST", f"/api/v1.0/Console/list/first/{_POLL_COUNT}/{idx}", body=body
            )
            updates: list[dict] = (
                result2.get("innerResult") or result2.get("result") or []
                if isinstance(result2, dict) else result2 if isinstance(result2, list) else []
            )
            if updates:
                text = self._updates_to_log(updates, agent)
                if text.strip():
                    self._write_log(f"c2_nh_{cid[:8]}.log", text)
                self._agent_index[cid] = idx + len(updates)

            if not connected and len(updates) < _POLL_COUNT:
                self._agent_done.add(cid)

        self._save_state()

    # ── Conversion ────────────────────────────────────────────────────────────

    def _updates_to_log(self, updates: list[dict], agent: dict) -> str:
        host  = self._display_name(agent)
        lines: list[str] = []
        for u in updates:
            ts  = self._parse_ts(u.get("updateTime", ""))
            inp = u.get("inputUpdate") or {}
            if inp.get("inputText"):
                operator = inp.get("userName", "operator")
                cmd      = inp.get("inputText", "").strip()
                lines.append(f"[{ts}] $ {cmd}  [C2:NH/{operator} {host}]")
            txt = u.get("textUpdate") or {}
            if txt.get("consoleText"):
                lines.append(txt["consoleText"].rstrip())
            cr = (u.get("commandResponseUpdate") or {}).get("commandResponse") or {}
            if cr.get("output"):
                lines.append(str(cr["output"]).rstrip())
        return "\n".join(lines)

    @staticmethod
    def _display_name(agent: dict) -> str:
        if agent.get("agentName"):
            return agent["agentName"]
        mi   = agent.get("detailedMachineInfo") or {}
        host = mi.get("machineName") or agent.get("externalIP", "")
        user = mi.get("userName") or ""
        return f"{host}\\{user}" if user else host or (agent.get("clientId") or "")[:8]

    def _beacon_block(self, agent: dict) -> str:
        mi      = agent.get("detailedMachineInfo") or {}
        ts      = self._parse_ts(agent.get("firstSeen", ""))
        ips_raw = mi.get("ipAddresses") or []
        ips     = ", ".join(str(i) for i in ips_raw) if isinstance(ips_raw, list) else str(ips_raw)
        cid     = (agent.get("clientId") or "")[:8]
        lines = [
            f"[{ts}] # BEACON {cid}",
            f"  hostname={mi.get('machineName', '?')}",
            f"  user={mi.get('userName', '?')}",
            f"  external_ip={agent.get('externalIP', '?')}",
            f"  internal_ips={ips}",
            f"  process={mi.get('processName', '')} PID {mi.get('processId', '')}",
            f"  listener={agent.get('listenerName', '?')}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _parse_ts(raw: str) -> str:
        if not raw:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return raw[:19].replace("T", " ")

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, body: bytes | None = None) -> dict | list:
        headers = {"Content-Type": "text/json", "Accept": "text/json"}
        if self._session_id:
            headers["X-NHAPI-SESSION"] = self._session_id
        ctx = None
        if not self._verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        req = urllib.request.Request(
            self._url + path, data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"NH {method} {path} → HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"NH unreachable: {e.reason}") from e
