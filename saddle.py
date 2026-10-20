#!/usr/bin/env python3
"""saddle — pdtmj-ai shell-native CLI.

Manages pentest/redteam ops without the TUI.  pentest-ctf is JSON/in-memory
and is not covered here.

Usage:
  saddle start --op <name> [--persona pentest|redteam] [--target <t>]
  saddle stop  [--op <name>]
  saddle status [--op <name>]
  saddle end   [--op <name>]
  saddle findings/creds/surfaces/facts [--op <name>]
  saddle ops
  saddle ai <message...>  (requires TUI running)
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich import box
from rich.table import Table

_console = Console()
_PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(_PROJECT_DIR))

from core.paths import OPS_DIR  # noqa: E402

_ACTIVE_OP_FILE = OPS_DIR / ".active_op"
_ACTIVE_PERSONA_FILE = OPS_DIR.parent / ".active_persona"
_PERSONAS = ("pentest", "redteam")
_SEV_COLOR = {"info": "dim", "low": "green", "medium": "yellow",
              "high": "red", "critical": "bold red"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _active_op() -> str | None:
    try:
        return _ACTIVE_OP_FILE.read_text().strip() or None
    except FileNotFoundError:
        return None


def _set_active_op(op: str, persona: str = "") -> None:
    OPS_DIR.mkdir(parents=True, exist_ok=True)
    _ACTIVE_OP_FILE.write_text(op)
    if persona:
        _ACTIVE_PERSONA_FILE.write_text(persona)


def _clear_active_op() -> None:
    try:
        _ACTIVE_OP_FILE.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    try:
        _ACTIVE_PERSONA_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _socket_path(op: str) -> Path:
    return OPS_DIR / op / ".saddle.sock"


def _sessions_dir(op: str) -> Path:
    return OPS_DIR / op / ".sessions"


def _daemon_running(op: str) -> bool:
    sock = _socket_path(op)
    if not sock.exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(str(sock))
        s.close()
        return True
    except Exception:
        return False


def _socket_request(op: str, msg: dict, timeout: float = 10.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(_socket_path(op)))
    s.sendall(json.dumps(msg).encode() + b"\n")
    data = b""
    while b"\n" not in data:
        if len(data) > 1 << 20:
            s.close()
            raise RuntimeError("socket response too large")
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return json.loads(data.split(b"\n")[0])


def _register_pid(op: str, pid: int) -> None:
    sd = _sessions_dir(op)
    sd.mkdir(parents=True, exist_ok=True)
    (sd / str(pid)).touch()


def _unregister_pid(op: str, pid: int) -> None:
    try:
        (_sessions_dir(op) / str(pid)).unlink(missing_ok=True)
    except Exception:
        pass


def _open_store(op: str | None = None):
    """Return (EngagementStore, op_name). Fails if op has no DB."""
    from core.engagement_store import EngagementStore

    op_name = op or _active_op()
    if not op_name:
        raise click.ClickException("no active op — run: saddle start --op <name>")

    db_path = OPS_DIR / op_name / "engagement.db"
    if not db_path.exists():
        raise click.ClickException(
            f"no engagement DB for '{op_name}' — run: saddle start --op {op_name}"
        )
    store, _, _ = EngagementStore.open_or_create(op_name)
    return store, op_name


def _resolve_op(op: str | None) -> str:
    name = op or _active_op()
    if not name:
        raise click.ClickException("no active op — use --op <name> or: saddle start --op <name>")
    return name


# ── Root group ────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """saddle — pdtmj-ai shell CLI for pentest/redteam ops."""


# ── Daemon lifecycle ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", required=True, help="Op name")
@click.option("--persona", default="pentest", type=click.Choice(_PERSONAS),
              show_default=True, help="Persona for this op")
@click.option("--target", default="", help="Primary target (IP, CIDR, hostname)")
@click.option("--objective", default="", help="Engagement objective")
def start(op: str, persona: str, target: str, objective: str) -> None:
    """Create or resume an op and start the session daemon."""
    from core.engagement_store import EngagementStore

    store, is_new, review_mode = EngagementStore.open_or_create(
        op, target=target, persona=persona, objective=objective
    )
    store.close()

    if review_mode:
        _console.print(
            f"[yellow]saddle: op '{op}' was ended — loaded in review mode.[/yellow]\n"
            "Use [bold]saddle end --reopen[/bold] to reactivate it (not yet implemented)."
        )
        return

    if _daemon_running(op):
        _register_pid(op, os.getppid())
        _set_active_op(op, persona)
        _console.print(f"saddle: daemon already running for [bold]{op}[/bold]")
        return

    _register_pid(op, os.getppid())
    _set_active_op(op, persona)

    env = {**os.environ, "PYTHONPATH": str(_PROJECT_DIR)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "core.saddle_daemon", "--op", op, "--persona", persona],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=str(_PROJECT_DIR),
    )

    for _ in range(30):
        if _daemon_running(op):
            label = "[dim](new)[/dim]" if is_new else "[dim](resumed)[/dim]"
            _console.print(f"saddle: started op [bold]{op}[/bold]  persona=[cyan]{persona}[/cyan]  {label}")
            return
        time.sleep(0.2)

    _console.print("saddle: daemon started but socket not yet ready", style="yellow")


@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
def stop(op: str | None) -> None:
    """Stop the daemon and deregister this shell."""
    op_name = _resolve_op(op)
    _unregister_pid(op_name, os.getppid())
    if _daemon_running(op_name):
        try:
            _socket_request(op_name, {"type": "stop"}, timeout=5.0)
        except Exception:
            pass
    if _active_op() == op_name:
        _clear_active_op()
    _console.print(f"saddle: stopped [bold]{op_name}[/bold]")


@cli.command(hidden=True)
@click.argument("pid", type=int)
@click.option("--op", default=None)
def register(pid: int, op: str | None) -> None:
    """Register a shell PID with the active op (called by shell hooks)."""
    op_name = _resolve_op(op)
    _register_pid(op_name, pid)


@cli.command(hidden=True)
@click.argument("pid", type=int)
@click.option("--op", default=None)
def unregister(pid: int, op: str | None) -> None:
    """Unregister a shell PID (called by shell EXIT trap)."""
    op_name = op or _active_op()
    if op_name:
        _unregister_pid(op_name, pid)


# ── Op status ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
@click.option("--clear", "clear_badge", is_flag=True, default=False)
def status(op: str | None, clear_badge: bool) -> None:
    """Show op summary (frontier, counts, badge)."""
    op_name = _resolve_op(op)

    if _daemon_running(op_name):
        try:
            resp = _socket_request(op_name, {"type": "status"}, timeout=5.0)
            _console.print(f"op:       [bold]{resp.get('op', op_name)}[/bold]")
            _console.print(f"persona:  [cyan]{resp.get('persona', '?')}[/cyan]")
            badge = resp.get("badge")
            if badge:
                _console.print(f"badge:    [yellow][{badge}][/yellow]  ({resp.get('badge_type', '?')})")
            if clear_badge:
                _socket_request(op_name, {"type": "clear_badge"}, timeout=5.0)
        except Exception as e:
            _console.print(f"[yellow]daemon error: {e}[/yellow]")
        return

    # Fall back to DB
    store, _ = _open_store(op_name)
    try:
        meta = store.load_engagement_meta()
        totals = store.token_usage_totals()
        _console.print(f"op:       [bold]{op_name}[/bold]")
        _console.print(f"persona:  [cyan]{meta.get('persona', '?')}[/cyan]")
        _console.print(f"target:   {meta.get('target', '—')}")
        _console.print(f"status:   {meta.get('status', '?')}")
        findings = store.load_findings()
        creds = store.load_credentials()
        surfaces = store.load_surfaces()
        _console.print(f"findings: {len(findings)}")
        _console.print(f"creds:    {len(creds)}")
        _console.print(f"surfaces: {len(surfaces)}")
        if totals["cost_usd"]:
            _console.print(f"cost:     ${totals['cost_usd']:.2f}")
    finally:
        store.close()


@cli.command()
@click.option("--op", default=None)
def end(op: str | None) -> None:
    """Mark an engagement as ended (puts it in review mode on next open)."""
    store, op_name = _open_store(op)
    try:
        store.end_engagement()
    finally:
        store.close()
    if _active_op() == op_name:
        _clear_active_op()
    _console.print(f"[green]saddle:[/green] op [bold]{op_name}[/bold] marked ended")


# ── Data views ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None)
@click.option("--severity", default=None,
              type=click.Choice(("info", "low", "medium", "high", "critical")))
def findings(op: str | None, severity: str | None) -> None:
    """List findings."""
    store, _ = _open_store(op)
    try:
        rows = store.load_findings()
    finally:
        store.close()

    if severity:
        rows = [r for r in rows if r.severity == severity]
    if not rows:
        _console.print("[dim]no findings[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("ID", width=8)
    t.add_column("Sev", width=8)
    t.add_column("Title")
    t.add_column("Target")
    t.add_column("V", width=1)

    for r in rows:
        color = _SEV_COLOR.get(r.severity, "white")
        t.add_row(
            r.id,
            f"[{color}]{r.severity.upper()}[/{color}]",
            r.title,
            r.target,
            "[green]✓[/green]" if r.verified else "",
        )
    _console.print(t)
    _console.print(f"[dim]{len(rows)} finding(s)[/dim]")


@cli.command()
@click.option("--op", default=None)
@click.option("--reveal", is_flag=True, default=False, help="Show full secrets")
def creds(op: str | None, reveal: bool) -> None:
    """List credentials."""
    store, _ = _open_store(op)
    try:
        rows = store.load_credentials()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no credentials[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Type", width=10)
    t.add_column("Username")
    t.add_column("Secret")
    t.add_column("Format", width=14)
    t.add_column("Location")
    t.add_column("Service", width=8)

    for r in rows:
        secret = r.secret or ""
        if reveal:
            display = secret or "(none)"
        else:
            display = r.secret_masked or (
                (secret[:2] + "…" + secret[-2:]) if len(secret) > 6 else secret
            )
        t.add_row(
            r.cred_type,
            r.username or "",
            display,
            r.secret_format or "",
            r.location or "",
            r.service or "",
        )
    _console.print(t)
    _console.print(f"[dim]{len(rows)} credential(s)[/dim]")


@cli.command()
@click.option("--op", default=None)
def surfaces(op: str | None) -> None:
    """List attack surfaces."""
    store, _ = _open_store(op)
    try:
        rows = store.load_surfaces()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no surfaces[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Host")
    t.add_column("Service", width=10)
    t.add_column("Port", width=6)
    t.add_column("Label")
    t.add_column("Status", width=10)
    t.add_column("Cycles", width=6)

    for r in rows:
        t.add_row(
            r.host,
            r.service or "",
            str(r.port or ""),
            r.label or "",
            r.status,
            str(r.cycles),
        )
    _console.print(t)
    _console.print(f"[dim]{len(rows)} surface(s)[/dim]")


@cli.command()
@click.option("--op", default=None)
def facts(op: str | None) -> None:
    """List confirmed operational facts."""
    store, _ = _open_store(op)
    try:
        rows = store.load_facts()
    finally:
        store.close()

    if not rows:
        _console.print("[dim]no facts[/dim]")
        return

    for r in rows:
        scope = f"  [dim][{r.scope}][/dim]" if r.scope else ""
        _console.print(f"  ({r.kind}) {r.statement}{scope}")
        if r.evidence:
            _console.print(f"    [dim]{r.evidence[:100]}[/dim]")


# ── Op management ─────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op", default=None)
@click.option("--type", "ioc_type", default=None,
              type=click.Choice(("ip", "domain", "hash", "url", "c2", "email", "other")))
def iocs(op: str | None, ioc_type: str | None) -> None:
    """List tracked IOCs."""
    store, _ = _open_store(op)
    try:
        rows = store.load_iocs()
    finally:
        store.close()

    if ioc_type:
        rows = [r for r in rows if r.ioc_type == ioc_type]
    if not rows:
        _console.print("[dim]no IOCs[/dim]")
        return

    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Type", width=8)
    t.add_column("Value")
    t.add_column("Context")
    t.add_column("Source")

    for r in rows:
        t.add_row(r.ioc_type, r.value, r.context or "", r.source or "")
    _console.print(t)
    _console.print(f"[dim]{len(rows)} IOC(s)[/dim]")


@cli.command("ops")
def list_ops() -> None:
    """List all saved ops."""
    if not OPS_DIR.exists():
        _console.print("[dim]no saved ops[/dim]")
        return
    ops = sorted(
        p.name for p in OPS_DIR.iterdir()
        if p.is_dir() and (p / "engagement.db").exists()
    )
    if not ops:
        _console.print("[dim]no saved ops[/dim]")
        return
    active = _active_op()
    for name in ops:
        running = "  [green]● daemon[/green]" if _daemon_running(name) else ""
        marker = "  [yellow]← active[/yellow]" if name == active else ""
        _console.print(f"  {name}{running}{marker}")


# ── Config ───────────────────────────────────────────────────────────────────

@cli.command("config")
@click.argument("args", nargs=-1)
def config_cmd(args: tuple[str, ...]) -> None:
    """View or change settings.

    \b
    saddle config               — list all settings for active persona
    saddle config <group>       — list one group
    saddle config <key>         — show detail for a key
    saddle config <key> <value> — change a setting
    """
    from ui.commands import handle_config
    lines, _ok = handle_config(list(args))
    for line in lines:
        _console.print(line)


# ── AI chat (requires TUI running) ───────────────────────────────────────────

@cli.command()
@click.argument("message", nargs=-1, required=True)
@click.option("--op", default=None)
def ai(message: tuple[str, ...], op: str | None) -> None:
    """Chat with the AI (requires TUI running with this op active)."""
    op_name = _resolve_op(op)
    if not _daemon_running(op_name):
        raise click.ClickException(
            f"daemon not running for '{op_name}' — run: saddle start --op {op_name}"
        )
    try:
        resp = _socket_request(op_name, {"type": "chat", "message": " ".join(message)},
                               timeout=120.0)
        if resp.get("type") == "error":
            raise click.ClickException(resp.get("message", "unknown error"))
        _console.print(resp.get("text", ""))
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(str(e))


if __name__ == "__main__":
    cli()
