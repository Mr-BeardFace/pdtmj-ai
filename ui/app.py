from __future__ import annotations

import json
import queue
import re
import threading
from datetime import datetime
from core.timeutil import now_local
from typing import Optional

from rich.markup import escape as markup_escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Input, RichLog, Static, ListView, ListItem, Label,
    TextArea, TabbedContent, TabPane, DataTable,
)
from textual import events, work
from textual.message import Message
from textual.suggester import Suggester

from ui.commands import (
    dispatch as cmd_dispatch,
    handle_cred_add,
)
from core.utils import mask_secret
from core.paths import (RESULTS_DIR, AGENTS_DIR, LOGS_DIR, ASSESSMENTS_DIR,
                        set_assessment_dir, use_assessment_scratch)
from core.artifacts import ArtifactStore
from core.registry import build_registry, load_all_agents
from core.agent_loader import load_agent
from core.llm_client import LLMClient, APIAccountLimitError, APIAuthError
from core.orchestrator import Orchestrator
from core.engagement_state import EngagementState
from core.session_log import SessionLogger
from core.models import Assessment

_MARKUP_RE = re.compile(r"\[/?[^\]]*\]")

# Seeded model ids — extended at runtime when the user runs `/models list`.
_DEFAULT_MODEL_IDS = [
    "claude-opus-4-7",
    "claude-sonnet-4-6",
    "claude-haiku-4-5-20251001",
]


class DynamicSuggester(Suggester):
    """Input ghost-text suggester driven by the app's live candidate pools."""

    def __init__(self, app: "PentestApp") -> None:
        super().__init__(use_cache=False, case_sensitive=False)
        self._app = app

    async def get_suggestion(self, value: str) -> str | None:
        return self._app._current_suggestion(value)

_SEV_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "dim",
}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_CSS = """
Screen {
    background: #0d1117;
    color: #e6edf3;
    layout: vertical;
}

#status-bar {
    height: 1;
    background: #161b22;
    color: #58a6ff;
    padding: 0 1;
    text-style: bold;
}

#main-panes {
    height: 1fr;
}

/* ── Left pane ─────────────────────────────────── */

#left-pane {
    width: 33%;
    border-right: solid #30363d;
    layout: vertical;
}

#findings-list {
    height: 1fr;
    min-height: 5;
    background: #0d1117;
    scrollbar-color: #30363d #0d1117;
}

#findings-list > ListItem {
    background: #0d1117;
    padding: 0 1;
}

#findings-list > ListItem:hover {
    background: #161b22;
}

#findings-list > ListItem.--highlight {
    background: #1c2128;
}

#info-tabs {
    height: 1fr;
    border-top: solid #30363d;
}

.host-os {
    height: 1;
    background: #161b22;
    color: #8b949e;
    padding: 0 1;
    display: none;
}

TabbedContent {
    background: #0d1117;
}

TabPane {
    background: #0d1117;
    padding: 0;
}

DataTable {
    background: #0d1117;
    height: 1fr;
}

DataTable > .datatable--header {
    background: #161b22;
    color: #3fb950;
}

DataTable > .datatable--cursor {
    background: #1c2128;
}

/* ── Right pane ────────────────────────────────── */

#right-pane {
    width: 1fr;
    layout: vertical;
}

#activity-log {
    height: 7fr;
    background: #0d1117;
    scrollbar-color: #30363d #0d1117;
    padding: 0 1;
}

#cmd-dialogue {
    height: 3fr;
    border-top: dashed #30363d;
    layout: vertical;
    display: none;
}

#cmd-log {
    height: 1fr;
    background: #0d1117;
    scrollbar-color: #30363d #0d1117;
    padding: 0 1;
}

/* ── Shared ────────────────────────────────────── */

.pane-header {
    background: #161b22;
    color: #3fb950;
    text-style: bold;
    padding: 0 1;
    height: 1;
}

.pane-header-toggle {
    background: #161b22;
    color: #3fb950;
    text-style: bold;
    padding: 0 1;
    height: 1;
}

.pane-header-toggle:hover {
    background: #1c2128;
    color: #58a6ff;
}

Input {
    height: 3;
    background: #0d1117;
    border: tall #30363d;
    border-top: tall #58a6ff;
    color: #e6edf3;
    padding: 0 1;
}

Input:focus {
    border: tall #58a6ff;
}

/* ── Modals ────────────────────────────────────── */

FindingDetailModal, ActivityLogModal {
    align: center middle;
}

#modal-outer {
    width: 82%;
    height: 82%;
    background: #161b22;
    border: solid #58a6ff;
    padding: 1 2;
    layout: vertical;
}

#modal-title {
    color: #58a6ff;
    text-style: bold;
    height: 1;
    margin-bottom: 1;
}

#modal-body {
    height: 1fr;
    background: #0d1117;
    color: #e6edf3;
}

#modal-hint {
    height: 1;
    color: #484f58;
    margin-top: 1;
}
"""


# ── Modals ────────────────────────────────────────────────────────────────────

class FindingDetailModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, finding: dict) -> None:
        super().__init__()
        self._finding = finding

    def compose(self) -> ComposeResult:
        f   = self._finding
        sev = f.get("severity", "info").upper()
        col = _SEV_COLOR.get(f.get("severity", "info"), "white")

        lines = [
            f"[{col}][{sev}][/{col}]  {f.get('title', '')}",
            f"Type: {f.get('type', '')}   Verified: {'Yes' if f.get('verified') else 'No'}",
            f"Target: {f.get('target', '')}",
            "",
        ]
        for section, key in [
            ("Description", "description"),
            ("Impact",       "impact"),
        ]:
            if f.get(key):
                lines += [f"── {section} ──", f[key], ""]

        if f.get("remediation"):
            rem = f["remediation"]
            if isinstance(rem, list):
                rem = "\n".join(f"  • {r}" for r in rem)
            lines += ["── Remediation ──", rem, ""]

        if f.get("cvss") and f["cvss"].get("vector"):
            c = f["cvss"]
            lines += [
                "── CVSS 3.1 ──",
                f"  {c.get('vector', '')}",
                f"  Base {c.get('base_score', '')}  "
                f"Temporal {c.get('temporal_score', '')}  "
                f"Environmental {c.get('environmental_score', '')}",
                "",
            ]

        if f.get("evidence"):
            ev = f["evidence"]
            if isinstance(ev, dict):
                ev = json.dumps(ev, indent=2)
            lines += ["── Evidence ──", str(ev), ""]

        with Vertical(id="modal-outer"):
            yield Static("  Finding Detail", id="modal-title")
            yield TextArea("\n".join(lines), id="modal-body", read_only=True)
            yield Static("  [dim]Esc / q — close[/dim]", id="modal-hint")


class ActivityLogModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-outer"):
            yield Static("  Activity Log", id="modal-title")
            yield TextArea(self._text, id="modal-body", read_only=True)
            yield Static(
                "  [dim]Esc / q — close  ·  select + Ctrl+C to copy[/dim]",
                id="modal-hint",
            )


class CmdLogModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, text: str) -> None:
        super().__init__()
        self._text = text

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-outer"):
            yield Static("  Command Log", id="modal-title")
            yield TextArea(self._text, id="modal-body", read_only=True)
            yield Static(
                "  [dim]Esc / q — close  ·  select + Ctrl+C to copy[/dim]",
                id="modal-hint",
            )


class ConfirmQuitModal(ModalScreen):
    """Quit-while-running confirmation."""
    BINDINGS = [("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-outer"):
            yield Static("  Quit while agent is running?", id="modal-title")
            yield Static(
                "  An agent is still running. Quitting now will abandon the current run.\n"
                "  Any findings collected so far have been saved.",
                id="modal-body",
            )
            yield Input(placeholder="y to confirm, Esc to cancel", id="key-input")
            yield Static("  [dim]y — quit  |  Esc — continue[/dim]", id="modal-hint")

    def on_mount(self) -> None:
        self.query_one("#key-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.value.strip().lower() == "y":
            self.dismiss(True)
        else:
            self.dismiss(False)


class KeySetModal(ModalScreen):
    """Modal for securely entering the API key (masked input)."""
    BINDINGS = [("escape", "dismiss", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-outer"):
            yield Static("  Set Anthropic API Key", id="modal-title")
            yield Static(
                "  Key will be stored in your system keychain — not written to disk.\n"
                "  Press Enter to save, Esc to cancel.",
                id="modal-body",
            )
            yield Input(placeholder="sk-ant-...", password=True, id="key-input")
            yield Static("  [dim]Esc — cancel[/dim]", id="modal-hint")

    def on_mount(self) -> None:
        self.query_one("#key-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        key = event.value.strip()
        if key:
            self.dismiss(key)
        else:
            self.dismiss(None)


class ExploitConfirmModal(ModalScreen):
    """Approve / deny an exploitation-phase agent before it runs."""
    BINDINGS = [("escape", "deny", "Deny")]

    def __init__(self, agent_name: str, findings: list[dict]) -> None:
        super().__init__()
        self._agent_name = agent_name
        self._findings   = findings

    def compose(self) -> ComposeResult:
        lines = [
            f"  The pipeline wants to run [bold]{self._agent_name}[/bold] (exploitation phase).",
            "",
        ]
        if self._findings:
            lines.append("  Findings that triggered it:")
            for f in self._findings[:8]:
                sev = f.get("severity", "info")
                col = _SEV_COLOR.get(sev, "white")
                lines.append(f"    [{col}][{sev.upper()}][/{col}] {markup_escape(f.get('title', ''))}")
            if len(self._findings) > 8:
                lines.append(f"    … and {len(self._findings) - 8} more")
        with Vertical(id="modal-outer"):
            yield Static("  ⚠ Approve exploitation?", id="modal-title")
            yield Static("\n".join(lines), id="modal-body")
            yield Input(placeholder="y = yes  /  n = no  /  a = yes to all", id="key-input")
            yield Static("  [dim]y — approve  |  n / Esc — skip  |  a — approve all[/dim]", id="modal-hint")

    def on_mount(self) -> None:
        # Steal focus to the modal's own input. Without this the main command input
        # keeps focus (it's live during a run for operator interrupts), so the y/n/a
        # keystrokes — and the Enter — get sent to the LLM instead of answering here.
        self.query_one("#key-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        ans = event.value.strip().lower()
        self.dismiss(ans if ans in ("y", "a") else "n")

    def action_deny(self) -> None:
        self.dismiss("n")


# ── Main App ──────────────────────────────────────────────────────────────────

class PentestApp(App):
    TITLE = "PDTMJ-AI"
    CSS = _CSS
    BINDINGS = [
        Binding("ctrl+c",      "request_quit",        "Quit"),
        Binding("ctrl+l",      "show_activity_log",   "Full Log",    show=False),
        Binding("ctrl+y",      "copy_activity_log",   "Copy Log",    show=False),
        Binding("ctrl+d",      "toggle_cmd_dialogue", "Commands",    show=False),
        Binding("up",          "history_prev",        "History ↑",   show=False),
        Binding("down",        "history_next",        "History ↓",   show=False),
        # Tab accepts the current completion; falls back to focus nav when none.
        Binding("tab",         "accept_completion",   "Complete",    show=False, priority=True),
        # Pane resize — priority so they fire even when Input has focus
        Binding("ctrl+left",   "pane_shrink_left",    "Narrow left", show=False, priority=True),
        Binding("ctrl+right",  "pane_grow_left",      "Widen left",  show=False, priority=True),
        Binding("ctrl+up",     "pane_grow_right",    "Grow log",    show=False, priority=True),
        Binding("ctrl+down",   "pane_shrink_right",  "Shrink log",  show=False, priority=True),
    ]

    # ── Internal messages (posted from worker threads via post_message) ──────────

    class Activity(Message):
        def __init__(self, text: str) -> None:
            self.text = text; super().__init__()

    class Running(Message):
        def __init__(self, active: bool) -> None:
            self.active = active; super().__init__()

    class Finding(Message):
        def __init__(self, finding: dict) -> None:
            self.finding = finding; super().__init__()

    class Port(Message):
        def __init__(self, ip: str, entry: dict) -> None:
            self.ip = ip; self.entry = entry; super().__init__()

    class OsInfo(Message):
        def __init__(self, ip: str, os_str: str) -> None:
            self.ip = ip; self.os_str = os_str; super().__init__()

    class Cred(Message):
        def __init__(self, cred_type: str, username: str, secret: str,
                     secret_masked: str, secret_format: str, location: str,
                     verified: bool, used_at: list | None = None) -> None:
            self.cred_type = cred_type; self.username = username
            self.secret = secret; self.secret_masked = secret_masked
            self.secret_format = secret_format; self.location = location
            self.used_at = used_at or []
            self.verified = verified; super().__init__()

    class Flag(Message):
        def __init__(self, value: str, location: str, verified: bool) -> None:
            self.value = value; self.location = location
            self.verified = verified; super().__init__()

    class Service(Message):
        def __init__(self, host: str, port, service: str, app: str,
                     version: str, tech: str, os: str, hostname: str = "") -> None:
            self.host = host; self.port = port; self.service = service
            self.app = app; self.version = version; self.tech = tech; self.os = os
            self.hostname = hostname
            super().__init__()

    class PipelineEvent(Message):
        def __init__(self, ev: dict) -> None:
            self.ev = ev; super().__init__()

    # ─────────────────────────────────────────────────────────────────────────

    def __init__(self) -> None:
        super().__init__()
        self._is_running      = False
        self._interrupt_queue: queue.Queue = queue.Queue()
        self._control_queue: queue.Queue = queue.Queue()   # mid-agent /abort·/continue·/skip
        self._stop_flag = threading.Event()
        self._end_flag  = threading.Event()
        self._orchestrator = None   # live Orchestrator while an engagement runs (for /job)
        self._agent_held = False    # True while an agent is parked by /abort

        # Total engagement cost accumulator
        self._total_tokens: dict = {"input": 0, "output": 0, "cache_read": 0}
        self._total_cost: float  = 0.0

        # Assessment clock — accumulated *working* time (survives /pause; the gap
        # while paused is not counted). Reset when a fresh assessment starts.
        self._run_start: float | None = None   # monotonic, set while running
        self._run_accum: float = 0.0           # seconds banked from prior run stretches

        self._current_agent  = ""
        self._current_target = ""
        self._active_persona = "pentest"

        # Command history
        self._cmd_history: list[str] = []
        self._hist_idx: int = -1

        # Findings store (list of full finding dicts)
        self._findings: list[dict] = []

        # Activity log text for Ctrl+L modal / Ctrl+Y copy
        self._activity_lines: list[str] = []
        # True while re-rendering a loaded assessment's saved event stream — suppresses
        # state-mutating side effects in _handle_event (render-only).
        self._replaying: bool = False
        # Command log text for COMMANDS header-click modal
        self._cmd_lines: list[str] = []

        # Manual credentials (pre-loaded via /cred add)
        self._manual_creds: list[dict] = []

        # Cred reveal map {masked → plaintext}
        self._cred_reveal: dict[str, str] = {}

        # Static Hosts table — row keys (host:port/proto) already present
        self._host_rows: set[str] = set()
        # row_key → Textual RowKey, so updates are O(1) instead of scanning every
        # row each time (the Hosts table is touched on every state change).
        self._host_rowkeys: dict[str, object] = {}
        # Host-level facts keyed by IP, backfilled across that host's port rows
        self._host_os:   dict[str, str] = {}
        self._host_name: dict[str, str] = {}
        # Precedence: cells the agent authoritatively set (via record_service) must
        # not be overwritten by the raw nmap baseline, which re-posts every cycle.
        # row_key → set of agent-owned columns; plus IPs whose OS the agent owns.
        self._agent_cols:   dict[str, set[str]] = {}
        self._agent_os_ips: set[str] = set()

        # Pane sizes (adjusted with Ctrl+arrows)
        self._left_width:    int = 33   # percent, left pane horizontal share (right gets the rest)
        self._right_act_fr:  int = 7    # activity-log fraction (out of 10 shared with cmd-dialogue)

        # O(1) finding dedup: normalized_title → finding dict (same ref as in _findings)
        self._findings_title_map: dict[str, dict] = {}

        # Lock protecting pipeline state mutated from worker threads
        self._pipeline_lock = threading.Lock()

        # Current/last assessment — the single session artifact
        self._current_assessment: Optional[Assessment] = None
        self._current_assessment_path: Optional[object] = None  # Path
        self._current_assessment_dir: Optional[object] = None   # Path — per-assessment folder

        # Kept for backward compat with _cmd_report fallback
        self._last_pipeline_runs:   list = []
        self._last_pipeline_target: str  = ""

        # Saved state when pipeline halts on account limit — available for /continue
        self._pipeline_resume: Optional[dict] = None

        # Live engagement state of the running pipeline — used by /scope commands
        self._current_state: Optional[EngagementState] = None

        # Session logger for the running engagement (None when idle)
        self._session_logger: Optional[SessionLogger] = None

        # Tab-completion candidate sources
        self._known_models: list[str] = []
        self._known_agents: list[str] = []

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Static("", id="status-bar")
        with Horizontal(id="main-panes"):
            # ── Left ──────────────────────────────────────────────────────────
            with Vertical(id="left-pane"):
                yield Static("● FINDINGS", classes="pane-header")
                yield ListView(id="findings-list")
                with TabbedContent(id="info-tabs"):
                    with TabPane("Hosts", id="tab-hosts"):
                        yield DataTable(id="hosts-table", cursor_type="row")
                    with TabPane("Creds", id="tab-creds"):
                        yield DataTable(id="creds-table", cursor_type="row")
                    # Flags tab is always built but hidden unless the CTF persona is active.
                    with TabPane("Flags", id="tab-flags"):
                        yield DataTable(id="flags-table", cursor_type="row")
            # ── Right ─────────────────────────────────────────────────────────
            with Vertical(id="right-pane"):
                yield Static("● AGENT WORKING  [dim](Ctrl+L view · Ctrl+Y copy)[/dim]", classes="pane-header")
                yield RichLog(id="activity-log", markup=True, highlight=False, auto_scroll=True, wrap=True)
                with Vertical(id="cmd-dialogue"):
                    yield Static(
                        "● COMMANDS  [dim](Ctrl+D hide · click to copy)[/dim]",
                        classes="pane-header-toggle",
                        id="cmd-header",
                    )
                    yield RichLog(id="cmd-log", markup=True, highlight=False, auto_scroll=True)
        yield Input(
            placeholder="PDTMJ-AI ›  (/ for commands · Tab to complete)",
            id="cmd-input",
            suggester=DynamicSuggester(self),
        )

    def on_mount(self) -> None:
        # Set up creds table columns — explicit keys, because add_columns()
        # auto-generates keys and string lookups like get_cell(row, "Secret")
        # would raise CellDoesNotExist.
        ct = self.query_one("#creds-table", DataTable)
        for label in ("Type", "Username", "Secret", "Format", "Location", "✓"):
            ct.add_column(label, key=label)

        # Hosts table — the single target tracker. Populated as recon discovers
        # hosts/ports/services. One row per host:port; host-level columns
        # (Hostname/OS) repeat down a host's rows so each line stands alone.
        ht = self.query_one("#hosts-table", DataTable)
        for label in ("IP", "Hostname", "OS", "Port", "Service", "Fingerprint", "Tech"):
            ht.add_column(label, key=label)

        # Flags table (CTF) — columns set up; tab shown only for the CTF persona
        ft = self.query_one("#flags-table", DataTable)
        for label in ("Flag", "Where", "✓"):
            ft.add_column(label, key=label)

        # Load active persona from config
        try:
            from core.config import get
            self._active_persona = get("active_persona", "pentest")
        except Exception:
            pass

        self._sync_flags_tab()

        # Preload completion candidate pools
        self._known_models = list(_DEFAULT_MODEL_IDS)
        try:
            self._known_agents = sorted(load_all_agents().keys())
        except Exception:
            self._known_agents = []

        self._update_status()
        self.set_interval(1.0, self._tick_clock)   # live assessment clock
        self._welcome()

    # ── completion ────────────────────────────────────────────────────────────

    def _current_suggestion(self, value: str) -> Optional[str]:
        from ui.completion import suggest
        # Refresh the saved-assessment ids only when the user is actually completing
        # an /assessment load — cheap dir scan, kept off the hot path otherwise.
        assessments = (self._known_assessment_ids()
                       if value.lower().startswith("/assessment load") else None)
        return suggest(value, self._known_agents, self._known_models, assessments)

    def _known_assessment_ids(self) -> list[str]:
        """Saved assessment ids (newest first), parsed from the assessment folder/file
        names — for /assessment load <id> tab-completion."""
        ids: list[str] = []
        for f in self._assessment_files():
            name = f.parent.name if f.parent.name.startswith("assessment_") else f.stem
            parts = name.split("_")
            if len(parts) >= 2 and parts[0] == "assessment":
                ids.append(parts[1])
        return list(dict.fromkeys(ids))

    def action_accept_completion(self) -> None:
        try:
            inp = self.query_one("#cmd-input", Input)
        except Exception:
            inp = None
        if inp is not None and self.focused is inp:
            sugg = self._current_suggestion(inp.value)
            if sugg and sugg != inp.value:
                inp.value = sugg
                inp.cursor_position = len(inp.value)
                return
        # No suggestion (or input not focused) — preserve default Tab navigation
        try:
            self.screen.focus_next()
        except Exception:
            pass

    def _capture_models(self, lines: list[str]) -> None:
        """Learn model ids from `/models list` output for tab-completion."""
        from ui.completion import extract_model_ids
        ids = extract_model_ids(lines)
        if ids:
            self._known_models = list(dict.fromkeys(ids + self._known_models))
            self._activity(
                f"[dim]{len(ids)} model id(s) now available — Tab-complete after "
                f"/agent set model <agent>[/dim]"
            )

    # ── Input handling ────────────────────────────────────────────────────────

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        self._hist_idx = -1
        if not text:
            return
        # Keep secrets out of ↑-recallable history
        lower = text.lower()
        sensitive = lower.startswith("/key set ") or lower.startswith("/cred add ")
        if not sensitive and not (self._cmd_history and self._cmd_history[-1] == text):
            self._cmd_history.append(text)

        # / commands ALWAYS go to command handler regardless of running state
        if text.startswith("/"):
            self._log_session("operator_command", {"text": text})
            self._handle_slash(text)
        elif self._is_running:
            self._interrupt_queue.put(text)
            self._log_session("operator_command", {"text": text})
            self._activity(f"[magenta]⚡ sent to agent:[/magenta] {text}")
        else:
            self._dispatch(text)

    def _log_session(self, event_type: str, data: dict) -> None:
        """Write to the active engagement log, if one is running."""
        logger = self._session_logger
        if logger is not None:
            try:
                logger.log(event_type, data)
            except Exception:
                pass

    def action_history_prev(self) -> None:
        if not self._cmd_history:
            return
        inp = self.query_one("#cmd-input", Input)
        if self._hist_idx == -1:
            self._hist_idx = len(self._cmd_history) - 1
        elif self._hist_idx > 0:
            self._hist_idx -= 1
        inp.value = self._cmd_history[self._hist_idx]
        inp.cursor_position = len(inp.value)

    def action_history_next(self) -> None:
        if not self._cmd_history or self._hist_idx == -1:
            return
        inp = self.query_one("#cmd-input", Input)
        if self._hist_idx < len(self._cmd_history) - 1:
            self._hist_idx += 1
            inp.value = self._cmd_history[self._hist_idx]
        else:
            self._hist_idx = -1
            inp.value = ""
        inp.cursor_position = len(inp.value)

    def action_request_quit(self) -> None:
        # Ctrl+C copies the current text selection (Textual convention) when there
        # is one; it only falls through to quitting when nothing is selected.
        try:
            selected = self.screen.get_selected_text()
        except Exception:
            selected = None
        if selected:
            if self._copy_to_clipboard(selected):
                self._flash_status(f"Copied {len(selected)} chars")
            try:
                self.screen.clear_selection()
            except Exception:
                pass
            return

        if self._is_running:
            def _on_confirm(confirmed: bool | None) -> None:
                if confirmed:
                    self.exit()
            self.push_screen(ConfirmQuitModal(), callback=_on_confirm)
        else:
            self.exit()

    def _flash_status(self, msg: str) -> None:
        try:
            self.query_one("#status-bar", Static).update(f"[green]{msg}[/green]")
            self.set_timer(2.0, self._update_status)
        except Exception:
            pass

    def action_show_activity_log(self) -> None:
        self.push_screen(ActivityLogModal("\n".join(self._activity_lines)))

    def action_copy_activity_log(self) -> None:
        text = "\n".join(self._activity_lines)
        if self._copy_to_clipboard(text):
            n = len(self._activity_lines)
            self.query_one("#status-bar", Static).update(
                f"[green]Copied {n} lines to clipboard[/green]"
            )
            self.set_timer(2.0, self._update_status)
        else:
            self.query_one("#status-bar", Static).update(
                "[yellow]Clipboard unavailable[/yellow]"
            )
            self.set_timer(2.0, self._update_status)

    def action_toggle_cmd_dialogue(self) -> None:
        dlg = self.query_one("#cmd-dialogue")
        dlg.display = not dlg.display

    def on_click(self, event: events.Click) -> None:
        widget = getattr(event, 'widget', None)
        if widget is not None and getattr(widget, 'id', None) == 'cmd-header':
            self.push_screen(CmdLogModal("\n".join(self._cmd_lines)))

    def _os_clipboard_copy(self, text: str) -> bool:
        """Push text to the real OS clipboard via a local CLI tool.

        Returns True only when a tool actually accepted it. This is what makes
        copy work on a Kali desktop, where Textual's OSC 52 sequence frequently
        never reaches the X/Wayland clipboard. Order: Wayland → X11 → platform
        native.
        """
        import os
        import shutil
        import subprocess
        import sys

        if sys.platform == "win32":
            candidates = [["clip"]]
        elif sys.platform == "darwin":
            candidates = [["pbcopy"]]
        else:
            candidates = []
            if os.environ.get("WAYLAND_DISPLAY"):
                candidates.append(["wl-copy"])
            candidates += [
                ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"],
                ["wl-copy"],
            ]

        for cmd in candidates:
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = subprocess.run(
                    cmd, input=text.encode("utf-8"),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                )
                if proc.returncode == 0:
                    return True
            except Exception:
                continue
        return False

    def copy_to_clipboard(self, text: str) -> None:
        """Override Textual's clipboard so EVERY native copy path — app text
        selection (Ctrl+C), the TextArea log modals, and row-click copy — reaches
        the desktop clipboard, not just OSC 52. Push to a local clipboard tool
        first, then still emit OSC 52 for terminals/SSH sessions that support it.
        """
        self._os_clipboard_copy(text)
        try:
            super().copy_to_clipboard(text)
        except Exception:
            pass

    def _copy_to_clipboard(self, text: str) -> bool:
        """Best-effort copy for the explicit copy actions' status flash. Reports
        True when a local tool verifiably took it; otherwise falls back to OSC 52
        (unverifiable — reported as best-effort success)."""
        if self._os_clipboard_copy(text):
            return True
        try:
            super().copy_to_clipboard(text)
            return True
        except Exception:
            return False

    # ── Pane resize ───────────────────────────────────────────────────────────

    def action_pane_shrink_left(self) -> None:
        self._left_width = max(15, self._left_width - 3)
        self.query_one("#left-pane").styles.width = f"{self._left_width}%"

    def action_pane_grow_left(self) -> None:
        self._left_width = min(75, self._left_width + 3)
        self.query_one("#left-pane").styles.width = f"{self._left_width}%"

    def action_pane_grow_right(self) -> None:
        """Ctrl+Up — grow activity log, shrink cmd-dialogue."""
        self._right_act_fr = min(9, self._right_act_fr + 1)
        self.query_one("#activity-log").styles.height = f"{self._right_act_fr}fr"
        dlg = self.query_one("#cmd-dialogue")
        if dlg.display:
            dlg.styles.height = f"{10 - self._right_act_fr}fr"

    def action_pane_shrink_right(self) -> None:
        """Ctrl+Down — shrink activity log, grow cmd-dialogue (shows it if hidden)."""
        self._right_act_fr = max(2, self._right_act_fr - 1)
        self.query_one("#activity-log").styles.height = f"{self._right_act_fr}fr"
        dlg = self.query_one("#cmd-dialogue")
        if not dlg.display:
            dlg.display = True
        dlg.styles.height = f"{10 - self._right_act_fr}fr"

    # ── Findings list click ───────────────────────────────────────────────────

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index
        if idx is not None and 0 <= idx < len(self._findings):
            self.push_screen(FindingDetailModal(self._findings[idx]))

    # ── Creds table click (reveal) ────────────────────────────────────────────

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        # DataTables don't support text-selection, so a row click copies the row
        # (and for creds, reveals + copies the secret).
        tid = event.data_table.id
        dt  = event.data_table

        if tid == "creds-table":
            row_key = str(event.row_key.value)
            plain = self._cred_reveal.get(row_key)
            if plain is None:
                return
            current = str(dt.get_cell(event.row_key, "Secret"))
            if "*" in current:
                dt.update_cell(event.row_key, "Secret", plain, update_width=True)
            else:
                dt.update_cell(event.row_key, "Secret", mask_secret(plain), update_width=True)
            if self._copy_to_clipboard(plain):
                self._flash_status("Secret copied to clipboard")

        elif tid == "flags-table":
            flag = str(event.row_key.value)
            if self._copy_to_clipboard(flag):
                self._flash_status("Flag copied to clipboard")

        elif tid == "hosts-table":
            try:
                row = dt.get_row(event.row_key)
            except Exception:
                return
            text = "  ".join(str(c) for c in row if str(c))
            if text and self._copy_to_clipboard(text):
                self._flash_status("Host row copied to clipboard")

    # ── Slash command handler ─────────────────────────────────────────────────

    def _handle_slash(self, text: str) -> None:
        # Special case: /key set with no args → open masked modal
        if text.strip().lower() == "/key set":
            self._open_key_set_modal()
            return

        # Special case: /cred add — handled by app to update creds table
        from ui.commands import parse
        parsed = parse(text)
        if parsed and parsed[0] == "/cred add":
            lines, success, cred = handle_cred_add(parsed[1])
            if success and cred:
                self._manual_creds.append(cred)
                self._show_cred_in_table(cred, source="manual")
            self._show_cmd_output(lines, success)
            return

        # /cred list — number every credential on the board (operator + agent)
        if parsed and parsed[0] == "/cred list":
            self._show_cmd_output(self._cred_list_lines(), True)
            return

        # /cred remove <n> — pull ANY credential, including an agent-recorded one
        if parsed and parsed[0] == "/cred remove":
            self._cred_remove(parsed[1])
            return

        # /cred clear
        if parsed and parsed[0] == "/cred clear":
            self._manual_creds.clear()
            if self._current_state is not None:
                self._current_state.credentials.clear()
            self._refresh_creds_table()
            self._show_cmd_output(["Credentials cleared."], True)
            return

        # /scope add — approve a target for agent followups (running engagement)
        if parsed and parsed[0] == "/scope add":
            if not parsed[1]:
                self._show_cmd_output(["Usage: /scope add <target>"], False)
            elif self._current_state is None:
                self._show_cmd_output(
                    ["No engagement running. Scope is seeded from the target when a run starts."],
                    False,
                )
            else:
                for t in parsed[1]:
                    self._current_state.add_scope(t)
                self._show_cmd_output(
                    [f"Scope expanded: {', '.join(parsed[1])}",
                     "Agents may now queue followups against it."],
                    True,
                )
            return

        # /scope remove — take a target out of scope (and keep it out)
        if parsed and parsed[0] == "/scope remove":
            if not parsed[1]:
                self._show_cmd_output(["Usage: /scope remove <target>"], False)
            elif self._current_state is None:
                self._show_cmd_output(["No engagement running."], False)
            else:
                removed, missing = [], []
                for t in parsed[1]:
                    (removed if self._current_state.remove_scope(t) else missing).append(t)
                lines = []
                if removed:
                    lines.append(f"Removed from scope: {', '.join(removed)}")
                    lines.append("Agents will no longer act against it; it is now excluded.")
                if missing:
                    lines.append(f"Not in scope (now excluded anyway): {', '.join(missing)}")
                self._show_cmd_output(lines, bool(removed))
            return

        # /scope list
        if parsed and parsed[0] == "/scope list":
            if self._current_state is None:
                self._show_cmd_output(["No engagement running."], False)
            else:
                lines = ["Approved scope:", ""] + [
                    f"  {t}" for t in self._current_state.scope_targets
                ]
                if self._current_state.out_of_scope:
                    lines += ["", "Excluded (out of scope):", ""] + [
                        f"  {t}" for t in self._current_state.out_of_scope
                    ]
                self._show_cmd_output(lines, True)
            return

        # /job [list] | /job kill <id> — inspect / terminate background jobs.
        # parsed[0] may be "/job", "/job list", or "/job kill" (subcommands are
        # registered paths); fold the sub back in with the trailing args.
        if parsed and parsed[0].split()[0] == "/job":
            sub_tokens = parsed[0].split()[1:]
            self._handle_job_command(sub_tokens + list(parsed[1]))
            return

        # /abort — hard-stop the current agent: kill every in-flight process and
        # park the agent for guidance (then /continue this agent or /skip to next).
        if parsed and parsed[0] == "/abort":
            if not self._is_running or self._orchestrator is None:
                self._show_cmd_output(["No engagement running."], False)
            elif self._agent_held:
                self._show_cmd_output(["Agent already held — type guidance, then "
                                       "/continue or /skip."], False)
            else:
                from core.config import get as _cfg_get
                exempt = _cfg_get("kill_exempt_tools", []) or []
                res = self._orchestrator._procs.kill_all(exempt=exempt)
                killed, skipped = res["killed"], res["skipped"]
                self._control_queue.put("abort")
                self._agent_held = True
                skip_note = f"; left {', '.join(skipped)} running (exempt)" if skipped else ""
                self._activity(f"  [red]■ /abort — {killed} process(es) killed{skip_note}; agent held[/red]")
                lines = [f"Aborted: {killed} in-flight process(es) terminated."]
                if skipped:
                    lines.append(f"Left running (kill-exempt): {', '.join(skipped)} — "
                                 f"use /job kill <id> to stop one explicitly.")
                lines += ["Agent is held. Type your correction, then:",
                          "  [cyan]/continue[/cyan] — resume THIS agent with your guidance",
                          "  [cyan]/skip[/cyan]     — abandon it and move to the next agent"]
                self._show_cmd_output(lines, True)
            return

        # /skip — abandon a held agent and advance the pipeline to the next one
        if parsed and parsed[0] == "/skip":
            if not self._agent_held:
                self._show_cmd_output(["Nothing to skip — no agent is held (/abort first)."], False)
            else:
                self._control_queue.put("skip")
                self._agent_held = False
                self._show_cmd_output(["Skipping agent — advancing to the next."], True)
            return

        # /pause — temporarily pause the engagement; resume with /continue
        if parsed and parsed[0] == "/pause":
            if not self._is_running:
                self._show_cmd_output(["No engagement running."], False)
            else:
                self._stop_flag.set()
                self._interrupt_queue.put("/pause — finish your current action then pause.")
                self._show_cmd_output(
                    ["Engagement will pause after the current agent finishes.",
                     "Type [bold cyan]/continue[/bold cyan] to resume where it left off."],
                    True,
                )
            return

        # /end — stop pipeline, run always_last, generate report
        if parsed and parsed[0] == "/end":
            if not self._is_running:
                self._show_cmd_output(["No pipeline running."], False)
            else:
                self._end_flag.set()
                self._interrupt_queue.put("/end — wrap up your current action. The engagement is ending.")
                self._show_cmd_output(
                    ["Pipeline will stop after the current agent.",
                     "Reporting agents will run and a report will be generated."],
                    True,
                )
            return

        # /continue — release a held agent (after /abort), else resume a paused
        # pipeline / one halted by an account limit.
        if parsed and parsed[0] == "/continue":
            if self._agent_held:
                self._control_queue.put("resume")
                self._agent_held = False
                self._activity("[green]▶ Resuming agent with your guidance.[/green]")
                self._show_cmd_output(["Resuming the held agent with your guidance."], True)
            elif self._is_running:
                self._show_cmd_output(["Pipeline is already running."], False)
            else:
                with self._pipeline_lock:
                    r = self._pipeline_resume
                    self._pipeline_resume = None
                if r:
                    self._show_cmd_output(["Resuming engagement…"], True)
                    self._activity("[cyan]↺ Resuming engagement after account limit.[/cyan]")
                    self._run_pipeline(r["brief"], _resume_from=r)
                else:
                    self._show_cmd_output(["Nothing to resume. Start a new run instead."], False)
            return

        # /report — bare: generate HTML now; on|off: toggle auto-reporting at end
        if parsed and parsed[0] == "/report":
            arg = (parsed[1][0].lower() if parsed[1] else "")
            if arg in ("on", "off", "true", "false", "enable", "disable",
                       "enabled", "disabled", "yes", "no", "0", "1"):
                from ui.commands import handle_report
                lines, ok = handle_report(parsed[1])
                self._show_cmd_output(lines, ok)
            elif arg in ("regen", "resynth", "resynthesize", "synth", "new"):
                # Re-run the report AGENT (LLM) against a loaded assessment's findings
                # and write a fresh narrative report — recovers a full write-up from a
                # saved assessment without re-running the engagement.
                if self._is_running:
                    self._show_cmd_output(["An engagement is running — finish it first."], False)
                elif not (self._current_assessment and self._current_assessment.runs
                          and self._current_assessment.merged_findings()):
                    self._show_cmd_output(
                        ["No loaded assessment with findings to re-synthesize.",
                         "Run [cyan]/assessment load <id>[/cyan] first, then /report regen."], False)
                else:
                    self._resynthesize_report()
            else:
                self._cmd_report()
            return

        # /clear — wipe the current assessment's panels (keeps saved results/logs)
        if parsed and parsed[0] == "/clear":
            if self._is_running:
                self._show_cmd_output(["An engagement is running — /pause or /end it first."], False)
            else:
                self._reset_assessment_view(full=True)
                self._show_cmd_output(["Board cleared. Run a new target to start a fresh assessment."], True)
            return

        # /assessment list|load|new — manage saved assessments
        if parsed and parsed[0] in ("/assessment list", "/assessment load", "/assessment new"):
            sub = parsed[0].split()[1]
            if sub == "list":
                self._list_runs()
            elif sub == "load":
                if not parsed[1]:
                    self._show_cmd_output(
                        ["Usage: /assessment load <assessment-id>",
                         "Run [cyan]/assessment list[/cyan] to see saved assessments."], False)
                else:
                    self._cmd_load(parsed[1][0])
            elif sub == "new":
                if self._is_running:
                    self._show_cmd_output(["An engagement is running — /pause or /end it first."], False)
                else:
                    self._reset_assessment_view(full=True)
                    self._show_cmd_output(["Board cleared. Run a target to start a fresh assessment."], True)
            return

        # /exit and /quit
        if parsed and parsed[0] in ("/exit", "/quit"):
            self.action_request_quit()
            return

        result = cmd_dispatch(text)
        if result is None:
            self._show_cmd_output([f"Not a command: {text!r}"], False)
            return
        lines, success = result[0], result[1]
        self._show_cmd_output(lines, success)

        # Sync app state for commands that change it
        if success and parsed:
            if parsed[0] == "/persona set" and parsed[1]:
                self._active_persona = parsed[1][0].lower()
                self._sync_flags_tab()
                self._update_status()
            elif parsed[0] == "/provider set":
                self._update_status()
            elif parsed[0] == "/models list":
                self._capture_models(lines)

    def _open_key_set_modal(self) -> None:
        def on_dismiss(key: str | None) -> None:
            if key:
                from ui.commands import handle_key_set
                # split so the modal also accepts "<provider> <key>" (e.g. local)
                lines, success = handle_key_set(key.split())
                self._show_cmd_output(lines, success)
            else:
                self._show_cmd_output(["Key entry cancelled."], False)
        self.push_screen(KeySetModal(), callback=on_dismiss)

    def _show_cmd_output(self, lines: list[str], success: bool) -> None:
        """Show command output in the command dialogue pane."""
        dlg = self.query_one("#cmd-dialogue")
        dlg.display = True
        log = self.query_one("#cmd-log", RichLog)
        ts  = datetime.now().strftime("%H:%M:%S")
        color = "green" if success else "yellow"
        icon  = "✓" if success else "!"
        log.write(f"[dim]{ts}[/dim]  [{color}]{icon}[/{color}]")
        self._cmd_lines.append(f"{ts}  {icon}")
        for line in lines:
            log.write(f"  {line}")
            self._cmd_lines.append(f"  {line}")
        log.write("")
        self._cmd_lines.append("")

    # ── /job — inspect / kill background jobs ─────────────────────────────────

    _JOB_STATUS_STYLE = {
        "running": "[cyan]● running[/cyan]",
        "done":    "[green]✓ done[/green]",
        "failed":  "[yellow]✗ failed[/yellow]",
        "killed":  "[red]✖ killed[/red]",
    }

    def _handle_job_command(self, args: list[str]) -> None:
        orch = self._orchestrator
        if orch is None:
            self._show_cmd_output(["No engagement running — no jobs."], False)
            return
        sub = (args[0].lower() if args else "list")

        if sub == "kill":
            if len(args) < 2:
                self._show_cmd_output(["Usage: /job kill <id>   (or /job kill all)"], False)
                return
            if args[1].lower() == "all":
                res = orch._jobs.kill_all()
                self._activity(
                    f"  [red]✖ killed all jobs:[/red] {res.get('jobs', 0)} job(s), "
                    f"{res.get('processes', 0)} process(es) terminated")
                self._show_cmd_output(
                    [f"Killed all running jobs — {res.get('jobs', 0)} job(s), "
                     f"{res.get('processes', 0)} process(es) terminated."], True)
                return
            job_id = args[1]
            res = orch._jobs.kill(job_id)
            if res.get("ok"):
                self._activity(
                    f"  [red]✖ job killed:[/red] {markup_escape(res.get('label', ''))} "
                    f"[dim](job {job_id}, {res.get('processes', 0)} process(es) terminated)[/dim]"
                )
                self._show_cmd_output(
                    [f"Killed job {job_id} ({res.get('label', '')}) — "
                     f"{res.get('processes', 0)} process(es) terminated."], True)
            else:
                self._show_cmd_output([res.get("error", "kill failed")], False)
            return

        # default: list running jobs + the last few finished ones
        jobs = orch._jobs.list_active(finished_tail=3)
        if not jobs:
            self._show_cmd_output(["No background jobs running."], True)
            return
        lines = []
        for j in jobs:
            status = self._JOB_STATUS_STYLE.get(j["status"], j["status"])
            info = markup_escape(j.get("info", ""))
            row = (f"[bold]{j['id']}[/bold]  {markup_escape(j['label'])}  {status}  "
                   f"[dim]{j['runtime_s']:.0f}s[/dim]")
            if info:
                row += f"  [dim]{info}[/dim]"
            if j["status"] == "failed" and j.get("error"):
                row += f"  [yellow]{markup_escape(str(j['error']))[:60]}[/yellow]"
            lines.append(row)
        running = sum(1 for j in jobs if j["status"] == "running")
        lines.append("")
        lines.append(f"[dim]{running} running · kill one with [/dim][cyan]/job kill <id>[/cyan]")
        self._show_cmd_output(lines, True)

    # ── Command dispatch (non-slash) ──────────────────────────────────────────

    def _dispatch(self, text: str) -> None:
        from ui.intent import parse_intent
        intent = parse_intent(text)
        if intent is None:
            # The regex parser only understands network targets. Fall back to
            # the Haiku router for everything else (file paths, RE/code audits,
            # free-form phrasing) — it runs in a worker so the UI never blocks.
            if len(text.split()) >= 2:
                self._activity("[dim]Classifying request…[/dim]")
                self._classify_and_run(text)
            else:
                self._activity(f"[red]Unrecognized:[/red] {text!r}  [dim](/ for commands, help for usage)[/dim]")
            return

        action = intent["action"]

        if action == "quit":
            self.exit()
        elif action == "help":
            self._show_help()
        elif action == "list_runs":
            self._list_runs()
        elif action == "list_agents":
            self._show_cmd_output(*self._cmd_agent_list())
        elif action == "list_models":
            lines, ok = self._cmd_model_list()
            self._show_cmd_output(lines, ok)
            if ok:
                self._capture_models(lines)
        elif action == "report":
            self._make_report(intent["run_id"])
        elif action in ("pipeline", "run"):
            if self._is_running:
                self._activity("[yellow]Already running. Type without / to send instructions to the agent.[/yellow]")
                return
            target = intent["target"]
            obj    = intent.get("objective")
            if action == "pipeline":
                from core.intake import brief_from_intent
                brief  = brief_from_intent(intent, text)
                phases = brief.allowed_phases
                self._activity(
                    f"[cyan]Engagement →[/cyan] {target}"
                    + (f"  [dim]phases: {', '.join(phases)}[/dim]")
                    + (f"  [dim]persona: {self._active_persona}[/dim]" if self._active_persona != "pentest" else "")
                )
                self._run_pipeline(brief)
            else:
                agent = intent["agent"]
                self._activity(f"[cyan]Run →[/cyan] {agent} on {target}")
                self._run_single(target, agent, obj)

    @work(thread=True)
    def _classify_and_run(self, text: str) -> None:
        """LLM intake for free-form requests the regex parser can't handle.

        Extracts a full engagement brief — targets, scope exclusions, creds,
        tech context, focus areas — then starts the engagement.
        """
        try:
            from core.intake import classify_brief
            brief = classify_brief(text)
        except Exception as e:
            self.post_message(PentestApp.Activity(
                f"[red]Could not classify request:[/red] {e}  [dim](/ for commands, help for usage)[/dim]"
            ))
            return

        if not brief.primary_target:
            self.post_message(PentestApp.Activity(
                f"[yellow]No target found in request.[/yellow] {brief.rationale}"
            ))
            return

        extras = []
        if brief.out_of_scope:
            extras.append(f"excl: {', '.join(brief.out_of_scope)}")
        if brief.credentials:
            extras.append(f"{len(brief.credentials)} cred(s)")
        if brief.focus_areas:
            extras.append(f"focus: {', '.join(brief.focus_areas)}")
        extra_str = f"  [dim]{' · '.join(extras)}[/dim]" if extras else ""

        self.post_message(PentestApp.Activity(
            f"[cyan]Engagement →[/cyan] {brief.primary_target}  "
            f"[dim]{brief.category} · phases: {', '.join(brief.allowed_phases)}[/dim]{extra_str}"
        ))

        def _start() -> None:
            if self._is_running:
                self._activity("[yellow]Already running — request ignored.[/yellow]")
                return
            self._run_pipeline(brief)

        self.call_from_thread(_start)

    def _cmd_agent_list(self) -> tuple[list[str], bool]:
        from ui.commands import handle_agent_list
        return handle_agent_list()

    def _cmd_model_list(self) -> tuple[list[str], bool]:
        from ui.commands import handle_models_list
        return handle_models_list("anthropic")

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _activity(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._activity_lines.append(f"{ts}  {_strip_markup(msg)}")
        self.query_one("#activity-log", RichLog).write(f"[dim]{ts}[/dim]  {msg}")

    def _update_status(self) -> None:
        persona_str = f"  [dim]persona: {self._active_persona}[/dim]" if self._active_persona else ""

        # Assessment clock, shown inline in the status bar.
        elapsed = self._elapsed_seconds()
        # Plain single-width marker — the stopwatch emoji (⏱) is double-width and
        # clips in many terminals.
        clock_str = (f"  [yellow]▸ {self._fmt_elapsed(elapsed)}[/yellow]"
                     if (self._is_running or elapsed > 0) else "")

        # Token + cost — compact, inline on the left right after the timer.
        tok = self._total_tokens
        if tok["input"] or tok["output"]:
            from core.config import get as _cfg_get
            free_api = _cfg_get("active_provider", "anthropic") == "openrouter"
            cost_label = (
                f"~${self._total_cost:.4f} (free api)"
                if free_api else
                f"~${self._total_cost:.4f}"
            )
            tokens_str = (
                f"  [dim]{self._kfmt(tok['input'])}↑ {self._kfmt(tok['output'])}↓"
                + (f" {self._kfmt(tok['cache_read'])}⟳" if tok["cache_read"] else "")
                + f"  [bold]{cost_label}[/bold][/dim]"
            )
        else:
            tokens_str = ""

        # Agent shown without the redundant "pentest/" namespace (persona already shows it).
        agent_disp = self._current_agent.split("/")[-1] if self._current_agent else ""

        def _build(tgt: str) -> str:
            if self._is_running:
                st = (f"[green]▶ {agent_disp}[/green] [dim]→ {tgt}[/dim]" if tgt
                      else f"[green]▶ {agent_disp}[/green]")
            else:
                st = "[dim]idle[/dim]"
            return (f"[bold cyan]PDTMJ-AI[/bold cyan]{persona_str}  "
                    f"{st}{clock_str}{tokens_str}")

        width = max(self.size.width - 2, 20)   # -2 for the bar's padding

        target = self._current_target
        left = _build(target)
        lw = len(_strip_markup(left))
        # If the breadcrumb would overflow, trim the target (not the timer/tokens).
        if lw > width and target:
            over = lw - width
            keep = max(0, len(target) - over - 1)
            target = (target[:keep] + "…") if keep > 0 else "…"
            left = _build(target)

        bar = self.query_one("#status-bar", Static)
        bar.update(left)

    def _elapsed_seconds(self) -> float:
        import time
        live = (time.monotonic() - self._run_start) if self._run_start is not None else 0.0
        return self._run_accum + live

    @staticmethod
    def _kfmt(n: int) -> str:
        """Compact token count: 512934 → 513k, 1294044 → 1.3M."""
        if n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n // 1000}k"
        return str(n)

    @staticmethod
    def _fmt_elapsed(secs: float) -> str:
        s = int(secs)
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        if h:
            return f"{h}h {m:02d}m"
        if m:
            return f"{m}m {sec:02d}s"
        return f"{sec}s"

    def _tick_clock(self) -> None:
        # Refresh the status bar once a second while running so the clock ticks.
        if self._is_running:
            self._update_status()

    def _set_running(self, value: bool) -> None:
        import time
        if value and self._run_start is None:
            self._run_start = time.monotonic()
        elif not value and self._run_start is not None:
            self._run_accum += time.monotonic() - self._run_start
            self._run_start = None
        self._is_running = value
        inp = self.query_one("#cmd-input", Input)
        inp.placeholder = (
            "⚡ send instruction to agent  (/ still works)" if value
            else "PDTMJ-AI ›  (/ for commands)"
        )
        self._update_status()

    def _welcome(self) -> None:
        act = self.query_one("#activity-log", RichLog)
        act.write("[bold cyan]PDTMJ-AI[/bold cyan] [dim]— Please Don't Take My Job, AI[/dim]")
        act.write("[dim]  agentic penetration testing[/dim]")
        act.write("")
        act.write("[dim]  run a full assessment against 10.10.10.1[/dim]")
        act.write("[dim]  run pentest/web against 10.10.10.1[/dim]")
        act.write("[dim]  /persona set pentest-ctf  |  /cred add admin P@ss smb  |  /models list[/dim]")
        act.write("[dim]  /provider set openrouter  |  /key set sk-or-...  |  /models list openrouter[/dim]")
        act.write("[dim]  /info — show all current settings  |  /help — commands[/dim]")
        act.write("[dim]  Ctrl+L — full log  |  Ctrl+D — toggle command pane  |  ↑↓ history[/dim]")
        act.write("[dim]  copy: Ctrl+L opens the log in a selectable view  ·  Ctrl+Y copies the whole log[/dim]")
        act.write("[dim]  click a Hosts/Creds/Flags row to copy it  ·  Shift+drag for native terminal select[/dim]")
        act.write("")

    def _show_help(self) -> None:
        from ui.commands import handle_help
        lines, _ = handle_help()
        self._show_cmd_output(lines, True)

    @staticmethod
    def _assessment_files() -> list:
        """All assessment.json files, newest first — the new per-assessment folders
        (assessments/*/assessment.json) plus any legacy results/assessment_*.json."""
        files = list(ASSESSMENTS_DIR.glob("*/assessment.json"))
        files += [f for f in RESULTS_DIR.glob("assessment_*.json")
                  if not f.name.endswith(".state.json")]
        return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)

    @staticmethod
    def _fmt_date(d: dict, f) -> str:
        """Local 'YYYY-MM-DD HH:MM' from the record's start_time, else file mtime."""
        from datetime import datetime
        raw = d.get("start_time")
        try:
            if raw:
                return datetime.fromisoformat(raw).astimezone().strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
        return datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")

    def _list_runs(self) -> None:
        assessment_files = self._assessment_files()
        single_files = sorted(
            [f for f in RESULTS_DIR.glob("*.json")
             if not f.name.startswith("assessment_") and not f.name.startswith("pipeline_")],
            key=lambda f: f.stat().st_mtime, reverse=True,
        )
        if not assessment_files and not single_files:
            self._activity("[dim]No runs found.[/dim]")
            return
        lines = []
        if assessment_files:
            lines.append("Assessments:")
            lines.append("")
            for f in assessment_files[:15]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    aid     = d.get("id", "?")
                    target  = d.get("target", "?")
                    status  = d.get("status", "?")
                    runs    = d.get("runs", [])
                    agents  = ", ".join(r.get("agent", "?") for r in runs)
                    n       = sum(len(r.get("findings", [])) for r in runs)
                    cost    = sum(r.get("estimated_cost_usd", 0) for r in runs)
                    date    = self._fmt_date(d, f)
                    sc      = "green" if status == "complete" else ("yellow" if status == "running" else "red")
                    lines.append(
                        f"  [dim]{date}[/dim]  [cyan]{aid}[/cyan]  [dim]{target}[/dim]"
                        f"  [{sc}]{status}[/{sc}]  {len(runs)} agent(s)  {n} finding(s)"
                        + (f"  [dim]${cost:.4f}[/dim]" if cost else "")
                    )
                    if agents:
                        lines.append(f"    [dim]{agents}[/dim]")
                except Exception:
                    pass
            lines.append("")
            lines.append("[dim]Load one with: [/dim][cyan]/assessment load <id>[/cyan]")
        if single_files:
            lines.append("")
            lines.append("Single-agent runs:")
            lines.append("")
            for f in single_files[:10]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    run_id = d.get("id", "?")
                    agent  = d.get("agent", "?")
                    target = d.get("target", "?")
                    status = d.get("status", "?")
                    n      = len(d.get("findings", []))
                    cost   = d.get("estimated_cost_usd", 0)
                    sc     = "green" if status == "complete" else "red"
                    lines.append(
                        f"  [cyan]{run_id}[/cyan]  {agent}  [dim]{target}[/dim]"
                        f"  [{sc}]{status}[/{sc}]  {n} finding(s)"
                        + (f"  [dim]${cost:.4f}[/dim]" if cost else "")
                    )
                except Exception:
                    pass
        self._show_cmd_output(lines, True)

    def _replay_engagement(self, jsonl_path) -> None:
        """Re-render a saved assessment's activity log from its structured event
        stream, through the live `_handle_event` renderer (with `_replaying` set so it
        renders only — no state mutation). This restores the exact colours and the
        expanded multi-line tool output the live view shows; the flat engagement.log
        can't, since it stores compact JSON with escaped newlines."""
        self._replaying = True
        try:
            for ln in jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    ev = json.loads(ln)
                except Exception:
                    continue
                try:
                    self._handle_event(ev)
                except Exception:
                    continue   # one malformed/unknown event must not abort the replay
        finally:
            self._replaying = False

    def _cmd_load(self, assessment_id: str) -> None:
        """Load a saved assessment back into the TUI panels by id (or id prefix)."""
        if self._is_running:
            self._show_cmd_output(["An engagement is running — /pause or /end it first."], False)
            return
        aid = assessment_id.strip()
        # New layout: assessments/<dir>/assessment.json whose folder/record carries
        # the id; legacy: results/assessment_<id>_<target>.json. Match either.
        matches = [m for m in self._assessment_files()
                   if aid in m.parent.name or aid in m.name]
        if not matches:
            self._show_cmd_output(
                [f"No assessment found for id '{aid}'.",
                 "Run [cyan]/assessment list[/cyan] to see saved assessments."], False)
            return
        path = sorted(matches, key=lambda m: m.stat().st_mtime, reverse=True)[0]
        try:
            assessment = Assessment(**json.loads(path.read_text(encoding="utf-8")))
        except Exception as e:
            self._show_cmd_output([f"Failed to load {path.name}: {e}"], False)
            return

        # Clean board and wipe the live log — we repopulate it from the saved log.
        self._reset_assessment_view(clear_log=True)
        self._current_assessment      = assessment
        self._current_assessment_path = path
        self._current_assessment_dir  = path.parent if path.parent != RESULTS_DIR else None

        # Logs window ← rebuild it from the saved structured event stream
        # (engagement.jsonl), replayed through the SAME renderer the live view uses,
        # so colours and multi-line output come back exactly as they ran. The plain
        # engagement.log is only a fallback for assessments saved before the jsonl
        # existed (it's compact JSON, so its tool output shows literal "\n").
        jsonl_path = path.parent / "engagement.jsonl"
        if jsonl_path.exists():
            self._replay_engagement(jsonl_path)
        else:
            log_path = path.parent / "engagement.log"
            if not log_path.exists():
                log_path = LOGS_DIR / f"{path.stem}.log"
            if log_path.exists():
                try:
                    act = self.query_one("#activity-log", RichLog)
                    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        self._activity_lines.append(line)
                        act.write(line)
                except Exception:
                    pass

        # Findings ← every run's findings.
        n_find = 0
        for run in assessment.runs:
            for f in run.findings:
                self._add_finding(f.model_dump())
                n_find += 1

        # Hosts / Creds / Flags ← the masked state snapshot, if it exists.
        n_host = n_cred = n_flag = 0
        snap_path = path.with_suffix(".state.json")
        if snap_path.exists():
            try:
                snap = json.loads(snap_path.read_text(encoding="utf-8"))
            except Exception:
                snap = {}
            recon = snap.get("recon", {}) or {}
            for ip, os_str in (recon.get("os_info", {}) or {}).items():
                self._host_os[ip] = os_str; self._agent_os_ips.add(ip)
            for ip, name in (recon.get("host_names", {}) or {}).items():
                self._host_name.setdefault(ip, name)
            for s in snap.get("services", []):
                host = s.get("host", "")
                if s.get("os"):
                    self._host_os[host] = s["os"]; self._agent_os_ips.add(host)
                fp = f"{s.get('app','')} {s.get('version','')}".strip() if s.get("app") \
                    else (s.get("version", "") or "")
                if s.get("port"):
                    self._add_host_row(host, {
                        "port": s.get("port"), "protocol": "tcp",
                        "service": s.get("service", ""), "version": fp,
                        "tech": s.get("tech", ""), "hostname": self._host_name.get(host, ""),
                    }, authoritative=True)
                    n_host += 1
            for c in snap.get("credentials", []):
                self._show_cred_in_table({
                    "cred_type":     c.get("cred_type"),
                    "username":      c.get("username"),
                    "secret":        c.get("secret_masked", ""),   # masked-only, never cleartext
                    "secret_format": c.get("secret_format", ""),
                    "location":      c.get("location") or c.get("service", ""),
                    "used_at":       c.get("used_at", []),
                    "verified":      c.get("verified"),
                }, source="loaded")
                n_cred += 1
            for fl in snap.get("flags", []):
                self._add_flag_row(fl.get("value", ""), fl.get("location", ""),
                                   bool(fl.get("verified")))
                n_flag += 1
            self._sync_flags_tab()

        note = "" if snap_path.exists() else "  [yellow](no saved panel snapshot — findings only)[/yellow]"
        self._show_cmd_output(
            [f"Loaded assessment {assessment.id}  ({assessment.target}, {assessment.status})",
             f"  {n_find} finding(s) · {n_host} host(s) · {n_cred} cred(s) · {n_flag} flag(s){note}",
             "  /report to regenerate the HTML report for this assessment."], True)

    def _cmd_report(self) -> None:
        """Handle /report — generate HTML from last assessment, or most recent runs."""
        from reporting.formatter import generate_merged_report
        self._show_cmd_output(["Generating HTML report…"], True)
        if self._current_assessment and self._current_assessment.runs:
            try:
                path = generate_merged_report(
                    self._current_assessment.runs, RESULTS_DIR,
                    fmt="html", target=self._current_assessment.target,
                )
                self._show_cmd_output([f"Report saved: {path}"], True)
                self._activity(f"[green]HTML Report:[/green] {path}")
            except Exception as e:
                self._show_cmd_output([f"Report failed: {e}"], False)
        else:
            # Fallback: load most recent assessment JSON from disk
            assessment_files = sorted(
                RESULTS_DIR.glob("assessment_*.json"),
                key=lambda f: f.stat().st_mtime, reverse=True,
            )
            if not assessment_files:
                # Last resort: single-agent run files for same target
                files = sorted(
                    [f for f in RESULTS_DIR.glob("*.json") if not f.name.startswith("assessment_")],
                    key=lambda f: f.stat().st_mtime, reverse=True,
                )
                if not files:
                    self._show_cmd_output(["No runs found. Run an assessment first."], False)
                    return
                from core.models import EngagementRun
                try:
                    first_target = json.loads(files[0].read_text(encoding="utf-8")).get("target", "")
                    runs = []
                    for f in files:
                        d = json.loads(f.read_text(encoding="utf-8"))
                        if d.get("target") == first_target:
                            runs.append(EngagementRun(**d))
                    runs.sort(key=lambda r: r.start_time)
                    path = generate_merged_report(runs, RESULTS_DIR, fmt="html", target=first_target)
                    self._show_cmd_output([f"Report saved: {path}"], True)
                    self._activity(f"[green]HTML Report:[/green] {path}")
                except Exception as e:
                    self._show_cmd_output([f"Report failed: {e}"], False)
                return
            try:
                d = json.loads(assessment_files[0].read_text(encoding="utf-8"))
                assessment = Assessment(**d)
                path = generate_merged_report(
                    assessment.runs, RESULTS_DIR,
                    fmt="html", target=assessment.target,
                )
                self._show_cmd_output([f"Report saved: {path}"], True)
                self._activity(f"[green]HTML Report:[/green] {path}")
            except Exception as e:
                self._show_cmd_output([f"Report failed: {e}"], False)

    def _make_report(self, run_id: str) -> None:
        from core.models import EngagementRun
        from reporting.formatter import generate_report
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", run_id)
        matches = list(RESULTS_DIR.glob(f"{safe_id}*.json"))
        if not matches:
            self._activity(f"[red]No run found matching: {run_id}[/red]")
            return
        try:
            data = json.loads(matches[0].read_text(encoding="utf-8"))
            run  = EngagementRun(**data)
            path = generate_report(run, RESULTS_DIR)
            self._activity(f"[green]Report:[/green] {path}")
        except Exception as e:
            self._activity(f"[red]Report failed: {e}[/red]")

    # ── Findings pane ─────────────────────────────────────────────────────────

    def _reset_assessment_view(self, clear_log: bool = False, full: bool = False) -> None:
        """Clear the in-memory TUI panels (Hosts / Findings / Creds / Flags and
        their tracking) so a new or loaded assessment starts on a clean board.
        Touches only UI state — never deletes saved results or on-disk session
        logs. Operator `/cred` entries are kept (they seed the next run) and
        re-rendered. By default the activity/Logs scrollback is preserved (a
        separator is written); pass clear_log=True to wipe it (used by /load,
        which then repopulates it from the loaded assessment's log).

        Pass full=True for a blank-slate reset (used by /clear): also wipes the
        activity log, the token/cost meter, the agent/target breadcrumb, and the
        operator's manual credentials — i.e. the window as if just opened. Only
        the command I/O area is left untouched."""
        self.query_one("#hosts-table", DataTable).clear()
        self._host_rows.clear(); self._host_rowkeys.clear()
        self._host_os.clear(); self._host_name.clear()
        self._agent_cols.clear(); self._agent_os_ips.clear()

        self.query_one("#findings-list", ListView).clear()
        self._findings.clear(); self._findings_title_map.clear()

        if full:
            self._manual_creds.clear()                     # blank slate → drop operator creds too
        self.query_one("#creds-table", DataTable).clear()
        self._cred_reveal.clear()
        for c in self._manual_creds:                       # operator creds persist (none if full)
            self._show_cred_in_table(c, source="manual")

        self.query_one("#flags-table", DataTable).clear()

        self._current_assessment      = None
        self._current_assessment_path = None
        self._current_state           = None
        self._run_accum               = 0.0   # fresh assessment → clock from zero
        self._run_start               = None

        if full:
            self._total_tokens = {"input": 0, "output": 0, "cache_read": 0}
            self._total_cost   = 0.0
            self._current_agent  = ""
            self._current_target = ""

        if clear_log or full:
            self.query_one("#activity-log", RichLog).clear()
            self._activity_lines.clear()
        else:
            self._activity("[dim]── board cleared ──[/dim]")

        if full:
            self._update_status()   # repaint the bar as idle with a zeroed meter

    def _add_finding(self, f: dict) -> None:
        key = f.get("title", "").lower()
        if key in self._findings_title_map:
            self._findings_title_map[key].update({k: v for k, v in f.items() if v})
        else:
            self._findings.append(f)
            self._findings_title_map[key] = f
        # Re-sort on update too — an update can raise a finding's severity
        self._findings.sort(
            key=lambda x: _SEV_ORDER.get(x.get("severity", "info"), 0),
            reverse=True,
        )
        self._refresh_findings_list()

    def _refresh_findings_list(self) -> None:
        lv = self.query_one("#findings-list", ListView)
        lv.clear()
        for f in self._findings:
            sev = f.get("severity", "info")
            if sev == "info":
                continue  # INFO entries live in the host tabs, not the findings list
            col   = _SEV_COLOR.get(sev, "white")
            mark  = "✓" if f.get("verified") else "◈"
            label = Label(
                f"[{col}]{mark} {sev[:4].upper()}[/{col}] {f.get('title', '')}"
            )
            lv.append(ListItem(label))

    # ── Creds table ───────────────────────────────────────────────────────────

    def _show_cred_in_table(self, c: dict, source: str = "agent") -> None:
        """Add or update a credential row: Type | Username | Secret | Format | Location | ✓."""
        dt        = self.query_one("#creds-table", DataTable)
        cred_type = c.get("cred_type") or "password"
        username  = c.get("username") or c.get("user") or ""
        secret    = c.get("secret") or c.get("password") or ""
        fmt       = c.get("secret_format", "") or ""
        location_base = c.get("location") or c.get("service") or ""
        used_at   = c.get("used_at") or []
        location  = location_base
        if used_at:
            location = (location_base + "  ·works@ " + ", ".join(used_at)).strip(" ·")
        verified  = "✓" if c.get("verified") else ""
        masked    = mask_secret(secret)

        # Key on the STABLE identity (base location, not the works@-augmented one)
        # so a later update — verified / used_at added — refreshes the row in place
        # instead of inserting a duplicate.
        row_key = f"{cred_type}|{username}|{location_base}|{secret[:8]}"
        self._cred_reveal[row_key] = secret

        if dt.row_count > 0 and row_key in [str(k.value) for k in dt.rows]:
            rk = next(k for k in dt.rows if str(k.value) == row_key)
            dt.update_cell(rk, "Secret",   masked,   update_width=True)
            dt.update_cell(rk, "Format",   fmt,      update_width=True)
            dt.update_cell(rk, "Location", location, update_width=True)
            dt.update_cell(rk, "✓",        verified, update_width=True)
        else:
            dt.add_row(cred_type, username, masked, fmt, location, verified, key=row_key)

    def _refresh_creds_table(self) -> None:
        """Rebuild the Creds tab from the authoritative source — live engagement
        state when a run exists (operator + agent creds), else the operator pre-load
        list. Called after a /cred remove or /cred clear."""
        dt = self.query_one("#creds-table", DataTable)
        dt.clear()
        self._cred_reveal.clear()
        if self._current_state is not None and self._current_state.credentials:
            for c in self._current_state.credentials:
                self._show_cred_in_table(c.model_dump(), source="agent")
        else:
            for c in self._manual_creds:
                self._show_cred_in_table(c, source="manual")

    def _cred_list_lines(self) -> list:
        """Numbered list of every credential on the board so the operator can pull
        one by number. Uses the live engagement state when present (this is where
        agent-discovered creds live), else the operator pre-load list."""
        from core.utils import mask_secret
        if self._current_state is not None and self._current_state.credentials:
            lines = [f"  {'#':<3}{'Type':<9}{'Username':<18}{'Secret':<18}{'Location':<18}✓", ""]
            for i, c in enumerate(self._current_state.credentials, 1):
                lines.append(
                    f"  {i:<3}{c.cred_type:<9}{(c.username or ''):<18}"
                    f"{mask_secret(c.secret):<18}{(c.location or c.service or ''):<18}"
                    f"{'✓' if c.verified else ''}")
            lines += ["", "Remove any one (incl. agent-found) with: /cred remove <#>"]
            return lines
        if not self._manual_creds:
            return ["No credentials.  /cred add <user> <pass> [service], or run an engagement."]
        lines = [f"  {'#':<3}{'Username':<18}{'Secret':<18}Service", ""]
        for i, c in enumerate(self._manual_creds, 1):
            lines.append(f"  {i:<3}{c.get('username', ''):<18}"
                         f"{mask_secret(c.get('secret', '')):<18}{c.get('service', '')}")
        lines += ["", "Remove one with: /cred remove <#>"]
        return lines

    def _cred_remove(self, args: list) -> None:
        from core.utils import mask_secret
        if not args:
            self._show_cmd_output(["Usage: /cred remove <#>   (number from /cred list)"], False)
            return
        try:
            n = int(args[0])
        except (ValueError, TypeError):
            self._show_cmd_output([f"'{args[0]}' is not a number. Usage: /cred remove <#>"], False)
            return

        # Live engagement state is authoritative when present — this is what removes
        # an agent-discovered cred so it stops showing up in the agent's context.
        if self._current_state is not None and self._current_state.credentials:
            removed = self._current_state.remove_credential(n - 1)
            if removed is None:
                self._show_cmd_output([f"No credential #{n}. Use /cred list."], False)
                return
            # Drop a matching operator pre-load entry too, so a later reset won't re-seed it.
            self._manual_creds = [m for m in self._manual_creds
                                  if not (m.get("secret") == removed.secret
                                          and (m.get("username") or None) == removed.username)]
            self._refresh_creds_table()
            who = f"{removed.username}:" if removed.username else ""
            self._show_cmd_output(
                [f"Removed #{n}  {who}{mask_secret(removed.secret)}  "
                 f"({removed.location or removed.service or removed.cred_type}).",
                 "The agent will no longer see it in its context."], True)
            return

        # No live state → operate on the operator pre-load list.
        if 1 <= n <= len(self._manual_creds):
            removed = self._manual_creds.pop(n - 1)
            self._refresh_creds_table()
            self._show_cmd_output(
                [f"Removed #{n}  {removed.get('username', '')}:"
                 f"{mask_secret(removed.get('secret', ''))}."], True)
        else:
            self._show_cmd_output([f"No credential #{n}. Use /cred list."], False)

    # ── Flags table (CTF) ───────────────────────────────────────────────────────

    def _sync_flags_tab(self) -> None:
        """Show the Flags tab only when the CTF persona is active."""
        try:
            tabs = self.query_one("#info-tabs", TabbedContent)
            if self._active_persona == "pentest-ctf":
                tabs.show_tab("tab-flags")
            else:
                tabs.hide_tab("tab-flags")
        except Exception:
            pass

    def _add_flag_row(self, value: str, location: str, verified: bool) -> None:
        dt = self.query_one("#flags-table", DataTable)
        row_key = value
        if dt.row_count > 0 and row_key in [str(k.value) for k in dt.rows]:
            rk = next(k for k in dt.rows if str(k.value) == row_key)
            dt.update_cell(rk, "Where", location, update_width=True)
            dt.update_cell(rk, "✓", "✓" if verified else "", update_width=True)
            return
        dt.add_row(value, location, "✓" if verified else "", key=row_key)

    # ── Hosts table (static) ────────────────────────────────────────────────────

    def _add_host_row(self, ip: str, port_entry: dict, authoritative: bool = False) -> None:
        """Add or update one row in the single target tracker.

        One row per host:port. Columns: IP | Hostname | OS | Port | Service |
        Fingerprint | Tech. `authoritative` distinguishes the agent's own
        interpretation (record_service — wins, and locks the cell) from the raw
        nmap baseline (only fills blanks, never clobbers an agent-set cell). This
        stops the scan baseline re-posting every cycle from reverting the LLM's
        "Camaleon CMS" back to "nginx 1.26.3".
        """
        dt       = self.query_one("#hosts-table", DataTable)
        port     = str(port_entry.get("port", ""))
        proto    = port_entry.get("protocol", "tcp")
        service  = port_entry.get("service", "") or ""
        fingerprint = port_entry.get("version", "") or port_entry.get("product", "") or ""
        tech     = port_entry.get("tech", "") or ""
        if port_entry.get("hostname"):
            self._host_name.setdefault(ip, port_entry["hostname"])
        hostname = self._host_name.get(ip, "")
        os_str   = self._host_os.get(ip, "")
        row_key  = f"{ip}:{port}/{proto}"
        owned    = self._agent_cols.setdefault(row_key, set())

        def _set(rk, col: str, val: str) -> None:
            if not val:
                return
            if authoritative:
                dt.update_cell(rk, col, val, update_width=True)
                owned.add(col)
            elif col not in owned:                  # baseline: don't clobber the agent
                dt.update_cell(rk, col, val, update_width=True)

        if row_key in self._host_rows:
            rk = self._host_rowkeys.get(row_key)
            if rk is None:
                return
            _set(rk, "Service", service)
            _set(rk, "Fingerprint", fingerprint)
            _set(rk, "Tech", tech)
            _set(rk, "Hostname", hostname)
            _set(rk, "OS", os_str)
            return

        self._host_rows.add(row_key)
        self._host_rowkeys[row_key] = dt.add_row(
            ip, hostname, os_str, port, service, fingerprint, tech, key=row_key)
        if authoritative:
            for col, val in (("Service", service), ("Fingerprint", fingerprint),
                             ("Tech", tech), ("Hostname", hostname), ("OS", os_str)):
                if val:
                    owned.add(col)
        self._sort_hosts(dt)

    @staticmethod
    def _host_sort_key(values: tuple) -> tuple:
        """Order rows by IP (numeric octet order), then port (numeric). IPv4
        addresses sort ahead of any non-IPv4 host label; the leading group flag
        keeps int- and str-keyed rows from being compared against each other."""
        ip_val, port_val = values
        try:
            port_key = int(port_val)
        except (ValueError, TypeError):
            port_key = 0
        parts = str(ip_val).split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return (0, tuple(int(p) for p in parts), port_key)
        return (1, str(ip_val), port_key)

    def _sort_hosts(self, dt: "DataTable | None" = None) -> None:
        dt = dt or self.query_one("#hosts-table", DataTable)
        dt.sort("IP", "Port", key=self._host_sort_key)

    def _update_host_field(self, ip: str, column: str, value: str) -> None:
        """Backfill a host-level column (OS/Hostname) across every row for an IP."""
        if not value:
            return
        dt = self.query_one("#hosts-table", DataTable)
        prefix = f"{ip}:"
        for k in list(dt.rows):
            if str(k.value).startswith(prefix):
                try:
                    dt.update_cell(k, column, value, update_width=True)
                except Exception:
                    pass

    # ── Event handler ─────────────────────────────────────────────────────────

    # ── Message handlers (run on the event loop — safe to await) ─────────────

    def on_pentest_app_activity(self, ev: Activity) -> None:
        self._activity(ev.text)

    def on_pentest_app_running(self, ev: Running) -> None:
        self._set_running(ev.active)

    def on_pentest_app_finding(self, ev: Finding) -> None:
        self._add_finding(ev.finding)

    def on_pentest_app_port(self, ev: Port) -> None:
        if ev.ip:
            self._add_host_row(ev.ip, ev.entry)

    def on_pentest_app_os_info(self, ev: OsInfo) -> None:
        # nmap OS guess (baseline) — store and backfill, but never overwrite an OS
        # the agent already set via record_service.
        if ev.ip and ev.os_str and ev.ip not in self._agent_os_ips:
            self._host_os[ev.ip] = ev.os_str
            self._update_host_field(ev.ip, "OS", ev.os_str)

    def on_pentest_app_service(self, ev: Service) -> None:
        # Agent-annotated service detail — the LLM's interpretation of the raw
        # scan. AUTHORITATIVE: it wins over the nmap baseline and locks the cells.
        if ev.os and ev.host:
            self._host_os[ev.host] = ev.os
            self._agent_os_ips.add(ev.host)
            self._update_host_field(ev.host, "OS", ev.os)
        if ev.hostname and ev.host:
            self._host_name[ev.host] = ev.hostname
            self._update_host_field(ev.host, "Hostname", ev.hostname)
        if ev.port:
            fingerprint = (f"{ev.app} {ev.version}".strip()) if ev.app else ""
            self._add_host_row(ev.host, {
                "port": ev.port, "protocol": "tcp", "service": ev.service,
                "version": fingerprint, "tech": ev.tech,
            }, authoritative=True)

    def on_pentest_app_cred(self, ev: Cred) -> None:
        if not ev.secret:
            return
        self._show_cred_in_table({
            "cred_type":     ev.cred_type,
            "username":      ev.username,
            "secret":        ev.secret,          # real value; table masks for display
            "secret_format": ev.secret_format,
            "location":      ev.location,
            "used_at":       ev.used_at,
            "verified":      ev.verified,
        }, source="agent")

    def on_pentest_app_flag(self, ev: Flag) -> None:
        self._add_flag_row(ev.value, ev.location, ev.verified)

    async def on_pentest_app_pipeline_event(self, ev: PipelineEvent) -> None:
        self._handle_event(ev.ev)

    # ── Pipeline event dispatcher (non-state events only) ─────────────────────

    # Output fields worth showing inline, in priority order (the "most important
    # pieces"); structured-only results fall back to a compact JSON line.
    _SNIPPET_TEXT_KEYS = ("stdout", "output", "text", "body", "raw", "result",
                          "response", "content", "data")
    _SNIPPET_MAX_LINES = 8
    _SNIPPET_MAX_WIDTH = 160

    def _output_snippet(self, output) -> list[str]:
        """A few lines of the ACTUAL tool output for the activity log. Full output
        stays in the artifact store / Ctrl+L log; this is the at-a-glance preview."""
        if isinstance(output, dict):
            text = ""
            for k in self._SNIPPET_TEXT_KEYS:
                v = output.get(k)
                if isinstance(v, str) and v.strip():
                    text = v
                    break
            if not text:                              # structured-only (nmap hosts, ffuf, …)
                slim = {k: v for k, v in output.items()
                        if k != "_command" and v not in (None, "", [], {})
                        and not (isinstance(v, str) and not v.strip())}
                text = json.dumps(slim, default=str) if slim else ""
        else:
            text = str(output or "")

        lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            return []
        shown = lines[:self._SNIPPET_MAX_LINES]
        out = [ln[:self._SNIPPET_MAX_WIDTH] + ("…" if len(ln) > self._SNIPPET_MAX_WIDTH else "")
               for ln in shown]
        extra = len(lines) - len(shown)
        if extra > 0:
            out.append(f"… +{extra} more line(s) — Ctrl+L / read_artifact for full output")
        return out

    def _handle_event(self, event: dict) -> None:
        # `_replaying` is set while re-rendering a loaded assessment's saved event
        # stream: render every activity line exactly as live, but suppress the state
        # mutations (findings, status, token counters, hold flags) — the panels are
        # repopulated separately from the saved snapshot, and counters must not move.
        t = event.get("type")

        if t == "agent_reasoning":
            text = event.get("text", "").strip()
            if text:
                for line in text.splitlines():
                    if line.strip():
                        self._activity(f"  [dim]│[/dim] [italic]{markup_escape(line)}[/italic]")

        elif t == "tool_start":
            name   = event["name"]
            inputs = event.get("inputs", {})
            self.query_one("#activity-log", RichLog).write("")
            if name == "run_script":
                # Don't dump the script blob — show its purpose so the operator
                # can follow what an ad-hoc script is actually doing.
                purpose = str(inputs.get("purpose", "")).strip() or "(no purpose given)"
                lang    = inputs.get("language", "")
                self._activity(f"[cyan]▶ run_script[/cyan] [dim]({markup_escape(str(lang))})[/dim]  {markup_escape(purpose)}")
            else:
                brief = ", ".join(
                    f"{markup_escape(str(k))}={markup_escape(repr(str(v)[:40]))}"
                    for k, v in list(inputs.items())[:2]
                )
                self._activity(f"[cyan]▶ {name}[/cyan]  [dim]{brief}[/dim]")

        elif t == "tool_done":
            if event.get("command_str"):
                self._activity(f"  [dim]$ {markup_escape(event['command_str'])}[/dim]")
            if event.get("summary"):
                self._activity(f"  [green]✓[/green] {markup_escape(event['summary'])}")
            for ln in self._output_snippet(event.get("output")):
                self._activity(f"  [dim]┃ {markup_escape(ln)}[/dim]")
            out = event.get("output")
            if isinstance(out, dict) and out.get("script_file"):
                self._activity(f"  [dim]↳ script saved: {markup_escape(str(out['script_file']))}[/dim]")

        elif t == "tool_cached":
            self._activity(
                f"  [dim]↩ {event['name']}  (cache hit — {markup_escape(event.get('summary', ''))})[/dim]"
            )

        elif t == "tool_error":
            self._activity(f"  [red]✗ {event['name']}: {markup_escape(str(event['error']))}[/red]")

        elif t == "annotation":
            sev      = event["severity"]
            title    = event["title"]
            verified = event.get("verified", False)
            col      = _SEV_COLOR.get(sev, "white")
            tag      = "CONFIRMED" if verified else "potential"
            self._activity(f"  [{col}][{tag}][/{col}] [{sev.upper()}] {title}")
            if not self._replaying:        # findings come from the saved runs on load
                self._add_finding({
                    "id":          event.get("finding_id", ""),
                    "title":       title,
                    "severity":    sev,
                    "verified":    verified,
                    "type":        event.get("ftype", ""),
                    "description": event.get("description", ""),
                    "target":      event.get("target", ""),
                    "evidence":    event.get("evidence", {}),
                })

        elif t == "agent_start":
            if not self._replaying:
                self._current_agent  = event["agent"]
                self._current_target = event["target"]
                self._update_status()
            self._activity(
                f"\n[bold cyan]── {event['agent']} ──[/bold cyan]  {event['target']}"
            )

        elif t == "agent_done":
            agent  = event["agent"]
            n      = event["findings_count"]
            cost   = event.get("cost", 0)
            status = event.get("status", "complete")
            tail   = f"{n} finding(s)  [dim]${cost:.4f}[/dim]"
            if status == "max_turns":
                # Forced stop — agent ran out of turns before finishing. This is
                # NOT a clean completion; flag it so a truncated run is obvious.
                limit = event.get("max_turns")
                cap   = f" ({limit})" if limit else ""
                self._activity(
                    f"[yellow]⚠ {agent} hit max turns{cap} — stopped before finishing "
                    f"(may be truncated)[/yellow]  {tail}"
                )
            elif status == "concluded":
                self._activity(f"[green]■ {agent} concluded — objective met[/green]  {tail}")
            else:
                self._activity(f"[green]■ {agent} complete[/green]  {tail}")

        elif t == "token_update":
            if not self._replaying:        # don't move live counters when replaying
                self._total_tokens["input"]      += event.get("input_delta", 0)
                self._total_tokens["output"]     += event.get("output_delta", 0)
                self._total_tokens["cache_read"] += event.get("cache_read_delta", 0)
                self._total_cost                 += event.get("cost_delta", 0.0)
                self._update_status()

        elif t == "api_retry":
            self._activity(
                f"[yellow]⟳ {event['reason']} — retrying in {event['wait']:.0f}s "
                f"(attempt {event['attempt']}/5)[/yellow]"
            )

        elif t == "loop_nudge":
            self._activity(
                f"  [yellow]↻ nudge[/yellow] [dim]repeated call(s): {markup_escape(event.get('detail', ''))} "
                f"— agent told to change approach[/dim]"
            )

        elif t == "operator_interrupt":
            self._activity(f"[magenta]⚡ Operator:[/magenta] {event.get('message', '')}")

        elif t == "followup_queued":
            self._activity(
                f"  [magenta]→ followup:[/magenta] {event.get('agent_name')} on {event.get('target')}"
            )

        elif t == "followup_rejected":
            self._activity(
                f"  [yellow]✗ followup rejected — out of scope:[/yellow] "
                f"{event.get('agent_name')} on {event.get('target')}"
                f"  [dim]/scope add {event.get('target')} to approve[/dim]"
            )

        elif t == "plan_recorded":
            label = event.get("surface_label", "") or event.get("surface_id", "")
            self._activity(
                f"  [magenta]▣ plan:[/magenta] {event.get('item_count', 0)} item(s) for {markup_escape(str(label))}"
            )
            for item in event.get("items", [])[:8]:
                tech = item.get("technique", "")
                tag  = f"[{markup_escape(tech)}] " if tech else ""
                self._activity(f"    [dim]·[/dim] {tag}{markup_escape(item.get('action', ''))}")

        elif t == "surface_registered":
            self._activity(
                f"  [magenta]◆ surface:[/magenta] {markup_escape(event.get('label', ''))}"
                f"  [dim]({event.get('origin', '')})[/dim]"
            )

        elif t == "surface_rejected":
            self._activity(
                f"  [yellow]✗ surface rejected — out of scope:[/yellow] {markup_escape(event.get('host', ''))}"
            )

        elif t == "artifact_stored":
            field = event.get("field")
            what  = f"{event.get('tool', '')}.{field}" if field else event.get("tool", "")
            self._activity(
                f"  [dim]⛁ {markup_escape(str(what))} → artifact {event.get('artifact_id', '')} "
                f"({event.get('lines', 0)} lines) — agent can grep/read it[/dim]"
            )

        elif t == "agent_held":
            if not self._replaying:
                self._agent_held = True
            self._activity("  [yellow]⏸ agent held — type guidance, then /continue or /skip[/yellow]")

        elif t == "agent_resumed":
            if not self._replaying:
                self._agent_held = False
            self._activity("  [green]▶ agent resumed with operator guidance[/green]")

        elif t == "agent_skipped":
            if not self._replaying:
                self._agent_held = False
            self._activity("  [yellow]⏭ agent skipped — advancing to next[/yellow]")

        elif t == "job_started":
            info = _compact_inputs(event.get("inputs"))
            line = (f"  [magenta]▸[/magenta] {markup_escape(event.get('name', ''))} "
                    f"[dim]({event.get('job_id', '')})[/dim]")
            if info:
                line += f"  [dim]{markup_escape(info)}[/dim]"
            self._activity(line)

        elif t == "job_done":
            if event.get("status") == "failed":
                self._activity(
                    f"  [yellow]⏗ job {markup_escape(event.get('name', ''))} failed:[/yellow] "
                    f"{markup_escape(str(event.get('error', '')))}"
                )
            else:
                self._activity(
                    f"  [magenta]⏗ job done:[/magenta] {markup_escape(event.get('name', ''))} "
                    f"[dim]({event.get('runtime', 0):.0f}s)[/dim]  [green]✓[/green] "
                    f"{markup_escape(event.get('summary', ''))}"
                )

        elif t == "jobs_flushing":
            self._activity(
                f"[dim]Waiting on {event.get('count', 0)} background job(s) before reporting…[/dim]"
            )

    # ── Background workers ────────────────────────────────────────────────────

    def _confirm_exploitation_from_worker(self, agent_name: str, findings: list) -> str:
        """Block the worker thread on an operator y/n/a decision.

        Pushes ExploitConfirmModal on the UI thread and waits for its callback.
        Returns "y", "n", or "a".
        """
        answer: dict = {}
        done = threading.Event()
        relevant = [
            {"severity": f.severity, "title": f.title}
            for f in findings
            if f.severity in ("medium", "high", "critical")
        ]

        def _show() -> None:
            def _cb(ans: str | None) -> None:
                answer["v"] = ans or "n"
                done.set()
            self.push_screen(ExploitConfirmModal(agent_name, relevant), callback=_cb)

        self.call_from_thread(_show)
        done.wait()
        return answer.get("v", "n")

    def _drain_stale_interrupts(self) -> None:
        """Discard instructions typed after the previous run ended — they must
        not leak into a new engagement."""
        while True:
            try:
                self._interrupt_queue.get_nowait()
            except queue.Empty:
                break

    def _make_log_cb(self):
        """Build the orchestrator log callback that fans events out to the UI."""
        _prev_tokens: dict[str, dict] = {}

        def log_cb(ev: dict) -> None:
            t = ev.get("type")
            if t == "token_update":
                run_id = ev.get("run_id", "_")
                prev   = _prev_tokens.get(run_id, {"input": 0, "output": 0, "cache_read": 0, "cost": 0.0})
                delta  = {
                    "type":             "token_update",
                    "input_delta":      max(0, ev.get("input", 0)      - prev["input"]),
                    "output_delta":     max(0, ev.get("output", 0)     - prev["output"]),
                    "cache_read_delta": max(0, ev.get("cache_read", 0) - prev["cache_read"]),
                    "cost_delta":       max(0.0, ev.get("cost", 0.0)   - prev["cost"]),
                }
                _prev_tokens[run_id] = {
                    "input": ev.get("input", 0), "output": ev.get("output", 0),
                    "cache_read": ev.get("cache_read", 0), "cost": ev.get("cost", 0.0),
                }
                self.post_message(PentestApp.PipelineEvent(delta))
            elif t == "state_update":
                recon = ev.get("recon", {})
                creds = ev.get("credentials", [])
                host_names = recon.get("host_names", {})
                # The Service/App/Tech detail comes from the agent via record_service
                # (the "service" event below); nmap only seeds IP/port/service/banner
                # + hostname here.
                for p in recon.get("open_ports", []):
                    if p.get("host"):
                        entry = dict(p)
                        entry["hostname"] = host_names.get(p["host"], "")
                        self.post_message(PentestApp.Port(p["host"], entry))
                # Surfaces with a concrete port also feed the Hosts table (so a
                # service the agent registered shows up even if nmap missed it).
                # Portless surfaces (e.g. the bare target) are skipped — they'd
                # only add an empty Host row with no port/service.
                for s in ev.get("surfaces", []):
                    if s.get("host") and s.get("port"):
                        self.post_message(PentestApp.Port(s["host"], {
                            "host":     s["host"],
                            "port":     s.get("port"),
                            "protocol": "tcp",
                            "service":  s.get("service", ""),
                            "version":  "",
                        }))
                for host_ip, os_str in recon.get("os_info", {}).items():
                    if os_str:
                        self.post_message(PentestApp.OsInfo(host_ip, os_str))
                for c in creds:
                    self.post_message(PentestApp.Cred(
                        cred_type=c.get("cred_type", "password"),
                        username=c.get("username", "") or "",
                        secret=c.get("secret", ""),
                        secret_masked=c.get("secret_masked", ""),
                        secret_format=c.get("secret_format", ""),
                        location=c.get("location", "") or c.get("service", ""),
                        used_at=c.get("used_at", []),
                        verified=c.get("verified", False),
                    ))
            elif t == "credential":
                # record_credential fired — update the Creds tab immediately
                self.post_message(PentestApp.Cred(
                    cred_type=ev.get("cred_type", "password"),
                    username=ev.get("username", "") or "",
                    secret=ev.get("secret", ""),
                    secret_masked=ev.get("secret_masked", ""),
                    secret_format=ev.get("secret_format", ""),
                    location=ev.get("location", ""),
                    used_at=ev.get("used_at", []),
                    verified=ev.get("verified", False),
                ))
                _u = ev.get("username", "")
                _tag = "✓" if ev.get("verified") else "?"
                self.post_message(PentestApp.Activity(
                    f"  [magenta]🔑 cred[/magenta] [{ev.get('cred_type', 'password')}] "
                    f"{(_u + ':') if _u else ''}{ev.get('secret_masked', '')} {_tag}"
                    + (f"  [dim]@ {ev.get('location')}[/dim]" if ev.get("location") else "")
                ))
            elif t == "service":
                self.post_message(PentestApp.Service(
                    host=ev.get("host", ""), port=ev.get("port"),
                    service=ev.get("service", ""), app=ev.get("app", ""),
                    version=ev.get("version", ""), tech=ev.get("tech", ""),
                    os=ev.get("os", ""), hostname=ev.get("hostname", ""),
                ))
                fp = (f"{ev.get('app','')} {ev.get('version','')}".strip()) if ev.get("app") else ""
                bits = [x for x in (ev.get("service"), fp, ev.get("tech"), ev.get("os")) if x]
                where = f"{ev.get('host','')}" + (f":{ev.get('port')}" if ev.get("port") else "")
                self.post_message(PentestApp.Activity(
                    f"  [cyan]⊙ service[/cyan] {where}  [dim]{' · '.join(bits)}[/dim]"
                ))
            elif t == "flag":
                self.post_message(PentestApp.Flag(
                    value=ev.get("value", ""),
                    location=ev.get("location", ""),
                    verified=ev.get("verified", False),
                ))
                self.post_message(PentestApp.Activity(
                    f"  [bold green]🚩 FLAG[/bold green] {ev.get('value', '')}"
                    + (f"  [dim]@ {ev.get('location')}[/dim]" if ev.get("location") else "")
                ))
            else:
                self.post_message(PentestApp.PipelineEvent(ev))

        return log_cb

    @work(thread=True)
    def _run_pipeline(self, brief, _resume_from: Optional[dict] = None) -> None:
        """Drive a full engagement through the Enum→Plan→Exploit→Validate loop."""
        from core.config import get as cfg_get

        self._stop_flag.clear()
        self._end_flag.clear()
        self._drain_stale_interrupts()
        # Fresh engagement → wipe the previous assessment's board (not on resume).
        if not _resume_from:
            self.call_from_thread(self._reset_assessment_view)
        self.post_message(PentestApp.Running(True))

        target = brief.primary_target or ""
        try:
            max_turns            = int(cfg_get("max_turns_default", 20))
            confirm_exploitation = bool(cfg_get("confirm_exploitation", True))

            # ── state: fresh or resumed ──────────────────────────────────────
            if _resume_from:
                state      = _resume_from["state"]
                assessment = _resume_from["assessment"]
                prior_runs = list(_resume_from.get("runs", []))
            else:
                state = EngagementState(target=target)
                state.scope_targets = list(dict.fromkeys([target] + brief.targets))
                state.out_of_scope  = list(brief.out_of_scope)
                state.tech_context  = brief.tech_context
                state.focus_areas   = list(brief.focus_areas)
                # Seed credentials from the brief and any manual /cred adds
                for c in list(brief.credentials) + list(self._manual_creds):
                    if c.get("secret"):
                        state.add_credential(
                            cred_type=c.get("cred_type", "password"),
                            username=c.get("username"),
                            secret=c["secret"], service=c.get("service", ""),
                            location=c.get("location", "") or c.get("service", ""),
                            source_agent="brief", verified=False,
                        )
                assessment = Assessment(target=target, objective=brief.objective)
                prior_runs = []

            self._current_state = state

            # Everything this assessment produces lives under ONE folder:
            # assessments/assessment_<id>_<target>/ — json, state, logs, report,
            # scripts/, artifacts/, scratch/. set_assessment_dir also points tool
            # tempfiles + run_script + the artifact store inside it.
            adir            = set_assessment_dir(assessment.id, target)
            assessment_path = adir / "assessment.json"
            state_path      = adir / "state.json"
            self._current_assessment_dir = adir

            def _save_state_snapshot() -> None:
                # Masked panel snapshot (hosts/creds/flags/ledger) so /load can
                # rebuild the TUI later. Never blocks or breaks the engagement.
                try:
                    state_path.write_text(
                        json.dumps(state.state_snapshot(), indent=2), encoding="utf-8")
                except Exception:
                    pass
            logger = SessionLogger(adir / "engagement.log")
            self._session_logger = logger
            if _resume_from:
                logger.log("note", {"text": "── resumed after account limit ──"})
            else:
                logger.header(target, brief.objective, persona=self._active_persona, mode="pipeline")
                if brief.out_of_scope:
                    logger.log("note", {"text": f"out of scope: {', '.join(brief.out_of_scope)}"})
            self.post_message(PentestApp.Activity(f"[dim]Log: {logger.path}[/dim]"))

            def _on_retry(attempt: int, wait: float, reason: str) -> None:
                self.post_message(PentestApp.PipelineEvent({
                    "type": "api_retry", "attempt": attempt, "wait": wait, "reason": reason,
                }))

            llm          = LLMClient(on_retry=_on_retry)
            registry     = build_registry()
            orchestrator = Orchestrator(
                llm, registry, RESULTS_DIR,
                log_callback=self._make_log_cb(), quiet=True,
                engagement_state=state,
                interrupt_queue=self._interrupt_queue,
                control_queue=self._control_queue,
                active_persona=self._active_persona,
                save_individual_runs=False,
                session_logger=logger,
                artifact_store=ArtifactStore(adir / "artifacts"),
            )
            self._orchestrator = orchestrator   # for /job list|kill from the UI

            # The active persona may pin the routable agent set (CTF → generalist
            # spine only), so specialist routing can't fork work off the generalist.
            from core.agent_loader import persona_agents
            all_agents = persona_agents(self._active_persona, AGENTS_DIR, load_all_agents())

            # ── driver callbacks ─────────────────────────────────────────────
            def emit_activity(text: str) -> None:
                self.post_message(PentestApp.Activity(f"[bold cyan]{text}[/bold cyan]"
                                                      if text.startswith("──") else text))

            def control() -> str:
                if self._stop_flag.is_set():
                    return "stop"
                if self._end_flag.is_set():
                    return "end"
                return "continue"

            def on_run_complete(eng_run) -> None:
                assessment.runs.append(eng_run)
                try:
                    assessment_path.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
                except Exception:
                    pass
                _save_state_snapshot()
                for f in eng_run.findings:
                    self.post_message(PentestApp.Finding(f.model_dump()))

            driver_kwargs = dict(
                max_turns=max_turns,
                confirm_exploitation=confirm_exploitation,
                max_cycles_per_surface=cfg_get("max_cycles_per_surface", 4),
                max_total_cycles=cfg_get("max_total_cycles", 40),
                max_surfaces=cfg_get("max_surfaces", 50),
                emit_activity=emit_activity,
                confirm_cb=self._confirm_exploitation_from_worker,
                control=control,
                on_run_complete=on_run_complete,
            )
            # FrontierDriver works the single hottest lead toward the objective —
            # confirm→advance the frontier, dead end→release, objective→halt (ctf)
            # or carry into breadth (pentest). parallel_enabled only sets the
            # fan-out WIDTH (off → serial focus, one lead at a time).
            from core.frontier_driver import FrontierDriver
            parallel = cfg_get("parallel_enabled", False)
            if parallel:
                emit_activity(
                    f"◎ Frontier engagement — hottest lead to the objective; fan-out "
                    f"×{cfg_get('surface_fanout', 3)}, ≤{cfg_get('max_parallel_agents', 3)} "
                    "agents at once.")
            else:
                emit_activity(
                    "◎ Frontier engagement — driving the hottest lead to the objective "
                    "(serial focus). Confirm→advance, dead end→release, objective→halt.")
            driver = FrontierDriver(
                orchestrator, all_agents, state, brief,
                frontier_max_actions=cfg_get("frontier_max_actions", None),
                attempts_cap=cfg_get("frontier_attempts_cap", 3),
                surface_fanout=cfg_get("surface_fanout", 3) if parallel else 1,
                hypothesis_fanout=cfg_get("hypothesis_fanout", 3) if parallel else 1,
                hypothesis_worker_turns=cfg_get("hypothesis_worker_turns", 12),
                **driver_kwargs,
            )
            # On resume, seed the driver with findings already gathered so cross-run
            # dedup and the final report account for them.
            driver.all_findings = [f for r in prior_runs for f in r.findings]
            driver.runs = []

            interrupted = False
            termination = None      # report Limitations reason; None → ask the driver
            try:
                driver.run()
            except APIAccountLimitError as e:
                with self._pipeline_lock:
                    self._pipeline_resume = {
                        "brief": brief, "state": state, "assessment": assessment,
                        "runs": prior_runs + driver.runs,
                    }
                interrupted = True
                termination = "account_limit"
                self.post_message(PentestApp.Activity(
                    f"[red]⛔ {e}[/red]\n  Top up and type [bold cyan]/continue[/bold cyan] to resume."
                ))
            except APIAuthError as e:
                interrupted = True
                termination = "auth_failed"
                self.post_message(PentestApp.Activity(f"[red]⛔ {e}[/red]"))

            if termination is None:
                termination = driver.termination_reason   # paused / ended_early / cycle_cap / completed
            completed_runs = prior_runs + driver.runs

            # A /pause saves the same resume state as an account-limit halt, so
            # /continue re-enters the surface loop where it left off (surfaces,
            # cycle counts, and findings intact).
            if driver.stopped and not interrupted:
                with self._pipeline_lock:
                    self._pipeline_resume = {
                        "brief": brief, "state": state, "assessment": assessment,
                        "runs": completed_runs,
                    }
                self.post_message(PentestApp.Activity(
                    "[cyan]⏸ Paused.[/cyan]  Type [bold cyan]/continue[/bold cyan] to resume where it left off."))

            # ── finalise ─────────────────────────────────────────────────────
            assessment.end_time = now_local()
            assessment.status = "interrupted" if (interrupted or driver.stopped) else "complete"
            try:
                assessment_path.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
            except Exception:
                pass
            _save_state_snapshot()

            with self._pipeline_lock:
                self._current_assessment      = assessment
                self._current_assessment_path = assessment_path
                self._last_pipeline_runs      = list(completed_runs)
                self._last_pipeline_target    = target

            all_findings = assessment.merged_findings()
            if not interrupted and not driver.stopped:
                summary = (f"{len(all_findings)} finding(s)  "
                           f"[dim]surfaces: {len(state.surfaces)}  cycles: {driver.total_cycles}  "
                           f"creds: {len(state.credentials)}[/dim]")
                label = "■ Engagement ended (/end)" if driver.ended_early else "■ Engagement complete"
                mode_note = ("" if brief.exploitation_allowed else
                             "  [yellow](assessment only — exploitation was not enabled)[/yellow]")
                self.post_message(PentestApp.Activity(f"\n[bold green]{label}[/bold green]  {summary}{mode_note}"))

            # Produce the report file however the engagement ended — EXCEPT on a pure
            # /pause, which is a temporary halt resumed with /continue. The write-up
            # is generated when the engagement actually finishes or is /end-ed; an
            # account/auth limit still reports (with a Limitations note). The in-
            # pipeline report agent is skipped on pause too, so this stays consistent.
            paused = driver.stopped and not interrupted
            from core.config import get as _cfg_get
            if all_findings and not paused and _cfg_get("reporting_enabled", True):
                self._generate_pipeline_report(
                    target, completed_runs,
                    persistence=[p.model_dump() for p in state.persistence],
                    termination=termination)
            elif all_findings and not paused:
                self.post_message(PentestApp.Activity(
                    "[dim]Reporting is OFF (/report on to re-enable) — no report generated. "
                    "Run /report to make one on demand.[/dim]"))

        except Exception as e:
            self.post_message(PentestApp.Activity(f"[red]Error: {e}[/red]"))
        finally:
            # Teardown on a TERMINAL end (complete / /end / error) — but NOT on a
            # resumable halt (/pause or account-limit), which keeps its jobs and
            # local changes for /continue. Kill outstanding background work and
            # revert local machine changes (the /etc/hosts vhost entries we added).
            orch = self._orchestrator
            with self._pipeline_lock:
                resumable = self._pipeline_resume is not None
            if orch is not None and not resumable:
                self._cleanup_engagement(orch)
            self._stop_flag.clear()
            self._end_flag.clear()
            self._current_state = None
            self._session_logger = None
            self._orchestrator = None
            self._agent_held = False
            self.post_message(PentestApp.Running(False))

    def _cleanup_engagement(self, orch) -> None:
        """Terminal-end teardown: stop every outstanding background job/process and
        revert local machine changes. Target-side changes (planted keys/users) are
        listed in the report's Cleanup Required section for the operator — not
        auto-reverted here, since reverting on a remote host can fail or hang."""
        try:
            res = orch._jobs.kill_all()
            if res.get("jobs"):
                self.post_message(PentestApp.Activity(
                    f"[dim]  teardown — killed {res['jobs']} background job(s), "
                    f"{res.get('processes', 0)} process(es).[/dim]"))
        except Exception:
            pass
        try:
            orch._procs.kill_all()          # backstop: any lingering registered proc
        except Exception:
            pass
        try:
            from tools.port_forward import stop_all as _stop_tunnels
            res = _stop_tunnels()           # close any SSH pivots/port forwards still open
            if res.get("stopped"):
                self.post_message(PentestApp.Activity(
                    f"[dim]  teardown — closed {res['stopped']} port forward(s).[/dim]"))
        except Exception:
            pass
        try:
            from tools.hosts_entry import hosts_entry
            out = hosts_entry("remove")     # drop every PDTMJ-AI-managed /etc/hosts line
            removed = out.get("removed") if isinstance(out, dict) else None
            if removed:
                self.post_message(PentestApp.Activity(
                    f"[dim]  teardown — reverted {len(removed)} /etc/hosts entr(ies).[/dim]"))
        except Exception:
            pass

    def _generate_pipeline_report(self, target: str, completed_runs: list,
                                  persistence: list | None = None,
                                  termination: str = "completed") -> None:
        """Merge all pipeline runs and write a single HTML report into the
        assessment folder (falls back to results/ if no assessment dir is set)."""
        try:
            from reporting.formatter import generate_merged_report
            out_dir = self._current_assessment_dir or RESULTS_DIR
            path = generate_merged_report(completed_runs, out_dir, fmt="html",
                                          target=target, persistence=persistence,
                                          termination=termination)
            self.post_message(PentestApp.Activity(f"[green]HTML Report:[/green] {path}"))
        except Exception as e:
            self.post_message(PentestApp.Activity(f"[red]Report failed: {e}[/red]"))

    @staticmethod
    def _rehydrate_report_state(state, assessment) -> None:
        """Regen loads only the masked state.json (no tool_log, no handoffs). Rebuild
        both from the full assessment runs so `build_context_block` can surface the real
        command history and each agent's own technical narrative to the report writer —
        the difference between re-narrating finding titles and re-synthesizing from the
        actual engagement. The runs were secret-redacted when stored, so this is safe."""
        from core.engagement_state import ToolLogEntry
        from core.pipeline import REPORT_AGENT
        for run in assessment.runs:
            for tc in run.tool_calls:
                out = tc.output
                out_s = ("" if out is None
                         else out if isinstance(out, str)
                         else json.dumps(out, default=str))
                state.tool_log.append(ToolLogEntry(
                    agent=run.agent,
                    tool_name=tc.tool_name,
                    command=tc.command_str or tc.tool_name,
                    summary=(out_s[:160].replace("\n", " ") if out_s
                             else (tc.error or "")[:160]),
                    truncated_output=out_s[:800],
                    timestamp=tc.timestamp,
                ))
            # Each agent's own close-out narrative is the richest "what happened" signal —
            # far more than the bare findings. Feed the report writer all of them (the
            # report agent's own prior narration is skipped to avoid echoing itself).
            if run.agent != REPORT_AGENT:
                state.add_handoff(
                    run.agent, run.technical_overview or run.summary
                    or run.executive_summary or "")

    @work(thread=True)
    def _resynthesize_report(self) -> None:
        """Re-run the report agent (LLM) against a loaded assessment's saved findings
        and write a fresh narrative report. Recovers a full write-up from a saved
        assessment without re-running the engagement. Guards are checked by the
        caller; this assumes a loaded assessment with findings exists."""
        self.post_message(PentestApp.Running(True))
        try:
            from core.pipeline import REPORT_AGENT
            assessment = self._current_assessment
            target     = assessment.target
            adir       = self._current_assessment_dir
            findings   = assessment.merged_findings()

            # Review-only state from the masked snapshot (creds masked, no tool_log).
            snap: dict = {}
            if adir and (adir / "state.json").exists():
                try:
                    snap = json.loads((adir / "state.json").read_text(encoding="utf-8"))
                except Exception:
                    snap = {}
            state = EngagementState.from_snapshot(snap) if snap else EngagementState(target=target)
            if not state.target:
                state.target = target
            # The masked state.json carries no tool_log/handoffs, so a bare regen would
            # write from findings alone — the same shallow report. Rebuild the evidence
            # trail and each agent's narrative from the full (already-redacted) runs so
            # the report agent re-synthesizes from the real engagement, not just titles.
            self._rehydrate_report_state(state, assessment)
            self._current_state = state

            ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
            logger = SessionLogger(LOGS_DIR / f"resynth_report_{ts}.log")
            self._session_logger = logger
            self.post_message(PentestApp.Activity(
                f"[cyan]Re-synthesizing report from {len(findings)} saved finding(s)…[/cyan]"))

            llm       = LLMClient()
            registry  = build_registry()
            art_store = ArtifactStore(adir / "artifacts") if adir else None
            orchestrator = Orchestrator(
                llm, registry, RESULTS_DIR, log_callback=self._make_log_cb(), quiet=True,
                engagement_state=state, active_persona=self._active_persona,
                session_logger=logger, artifact_store=art_store,
            )
            self._orchestrator = orchestrator
            report_def = load_agent(REPORT_AGENT, AGENTS_DIR)
            eng_run = orchestrator.run(report_def, target, None, max_turns=20,
                                       all_findings=findings)

            # Keep a single report run, persist the assessment, render fresh HTML.
            assessment.runs = [r for r in assessment.runs if r.agent != REPORT_AGENT] + [eng_run]
            if self._current_assessment_path:
                try:
                    self._current_assessment_path.write_text(
                        assessment.model_dump_json(indent=2), encoding="utf-8")
                except Exception:
                    pass
            self._generate_pipeline_report(
                target, assessment.runs, persistence=snap.get("persistence", []))
        except Exception as e:
            self.post_message(PentestApp.Activity(f"[red]Re-synthesis failed: {e}[/red]"))
        finally:
            self._orchestrator   = None
            self._current_state  = None
            self._session_logger = None
            self.post_message(PentestApp.Running(False))

    @work(thread=True)
    def _run_single(
        self, target: str, agent_name: str, objective: Optional[str] = None
    ) -> None:
        self._drain_stale_interrupts()
        self.post_message(PentestApp.Running(True))
        try:
            from core.config import get as cfg_get
            from core.orchestrator import _safe_filename_part
            max_turns = int(cfg_get("max_turns_default", 20))
            state = EngagementState(target=target)
            self._current_state = state

            ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_a    = _safe_filename_part(agent_name)
            safe_t    = _safe_filename_part(target)
            logger    = SessionLogger(LOGS_DIR / f"run_{safe_a}_{safe_t}_{ts}.log")
            self._session_logger = logger
            # Keep transient tool tempfiles in a per-run working dir, not /tmp.
            use_assessment_scratch(f"{safe_a}_{safe_t}_{ts}")
            logger.header(target, objective, persona=self._active_persona,
                          mode=f"single:{agent_name}")
            self.post_message(PentestApp.Activity(f"[dim]Log: {logger.path}[/dim]"))
            for c in self._manual_creds:
                state.add_credential(
                    cred_type=c.get("cred_type", "password"), username=c.get("username"),
                    secret=c["secret"], service=c.get("service", ""),
                    location=c.get("service", ""),
                    source_agent="manual", verified=False,
                )

            llm       = LLMClient()
            registry  = build_registry()
            orchestrator = Orchestrator(
                llm, registry, RESULTS_DIR,
                log_callback=self._make_log_cb(), quiet=True,
                engagement_state=state,
                interrupt_queue=self._interrupt_queue,
                control_queue=self._control_queue,
                active_persona=self._active_persona,
                session_logger=logger,
            )
            self._orchestrator = orchestrator   # for /job list|kill from the UI
            agent_def = load_agent(agent_name, AGENTS_DIR)
            eng_run   = orchestrator.run(agent_def, target, objective, max_turns=max_turns)
            with self._pipeline_lock:
                self._last_pipeline_runs   = [eng_run]
                self._last_pipeline_target = target
            for f in eng_run.findings:
                self.post_message(PentestApp.Finding(f.model_dump()))
            self.post_message(PentestApp.Activity(
                f"\n[bold green]■ {agent_name} complete[/bold green]  {len(eng_run.findings)} finding(s)"
            ))
        except Exception as e:
            self.post_message(PentestApp.Activity(f"[red]Error: {e}[/red]"))
        finally:
            self._current_state = None
            self._session_logger = None
            self._orchestrator = None
            self._agent_held = False
            self.post_message(PentestApp.Running(False))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_markup(text: str) -> str:
    return _MARKUP_RE.sub("", text)


def _compact_inputs(inputs) -> str:
    """One-line `key=val` summary of a tool's inputs for the job log/list view."""
    if not isinstance(inputs, dict):
        return ""
    parts = []
    for k, v in inputs.items():
        if k == "background" or v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        s = str(v)
        if len(s) > 40:
            s = s[:37] + "…"
        parts.append(f"{k}={s}")
        if len(parts) >= 4:
            break
    return " ".join(parts)


def run_app() -> None:
    PentestApp().run()
