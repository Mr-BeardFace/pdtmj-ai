#!/usr/bin/env python3
"""saddle — pdtmj-ai shell-native CLI.

Manages pentest/redteam ops without the TUI.

Usage:
  saddle start --op <name> [--persona pentest|redteam] [--target <t>] [--objective <o>]
  saddle stop  [--op <name>]
  saddle end   [--op <name>]
  saddle op    list | status | findings | creds | surfaces | facts | iocs |
               leads | advisory | hosts | activity
  saddle c2    status | url | auth | connect | disconnect
  saddle config [key] [value]
  saddle ai <message...>
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich import box
from rich.table import Table

_console     = Console()
_PROJECT_DIR = Path(__file__).parent
sys.path.insert(0, str(_PROJECT_DIR))

from core.paths import OPS_DIR  # noqa: E402

_ACTIVE_OP_FILE      = OPS_DIR / ".active_op"
_ACTIVE_PERSONA_FILE = OPS_DIR.parent / ".active_persona"
_PERSONAS   = ("pentest", "redteam")
_SEV_COLOR  = {"info": "dim", "low": "green", "medium": "yellow",
               "high": "red", "critical": "bold red"}


# ── Internal helpers ──────────────────────────────────────────────────────────

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
        try:
            from core.config import set_value as _cfg_set
            _cfg_set("active_persona", persona)
        except Exception:
            pass


def _clear_active_op() -> None:
    try:
        _ACTIVE_OP_FILE.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    try:
        _ACTIVE_PERSONA_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def _pid_path(op: str) -> Path:
    return OPS_DIR / op / ".daemon_pid"


def _daemon_running(op: str) -> bool:
    """Check if daemon is alive by reading .daemon_pid."""
    try:
        pid = int(_pid_path(op).read_text().strip())
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _stop_daemon(op: str) -> None:
    """Send SIGTERM to daemon process."""
    try:
        pid = int(_pid_path(op).read_text().strip())
        os.kill(pid, signal.SIGTERM)
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


# ── Root ──────────────────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """saddle — pdtmj-ai shell CLI for pentest/redteam ops."""


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--op",        required=True, help="Op name")
@click.option("--persona",   default="pentest", type=click.Choice(_PERSONAS), show_default=True)
@click.option("--target",    default="", help="Primary target (IP, CIDR, hostname)")
@click.option("--objective", default="", help="Engagement objective")
def start(op: str, persona: str, target: str, objective: str) -> None:
    """Create or resume an op and start the analyst daemon."""
    from core.engagement_store import EngagementStore

    store, is_new, review_mode = EngagementStore.open_or_create(
        op, target=target, persona=persona, objective=objective
    )
    store.close()

    if review_mode:
        _console.print(
            f"[yellow]saddle: op '{op}' was ended — loaded in review mode.[/yellow]\n"
            "Use [bold]saddle end --reopen[/bold] to reactivate it."
        )
        return

    if _daemon_running(op):
        _set_active_op(op, persona)
        _console.print(f"saddle: daemon already running for [bold]{op}[/bold]")
        return

    _set_active_op(op, persona)

    env = {**os.environ, "PYTHONPATH": str(_PROJECT_DIR)}
    subprocess.Popen(
        [sys.executable, "-m", "core.saddle_daemon", "--op", op, "--persona", persona],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=str(_PROJECT_DIR),
    )

    # Wait briefly for daemon to write PID file
    for _ in range(20):
        if _pid_path(op).exists():
            label = "[dim](new)[/dim]" if is_new else "[dim](resumed)[/dim]"
            _console.print(
                f"saddle: started op [bold]{op}[/bold]  persona=[cyan]{persona}[/cyan]  {label}"
            )
            return
        time.sleep(0.2)

    _console.print("saddle: daemon spawned (PID file pending)", style="yellow")


@cli.command()
@click.option("--op", default=None, help="Op name (default: active op)")
def stop(op: str | None) -> None:
    """Stop the analyst daemon."""
    op_name = _resolve_op(op)
    if _daemon_running(op_name):
        _stop_daemon(op_name)
        time.sleep(0.5)
    if _active_op() == op_name:
        _clear_active_op()
    _console.print(f"saddle: stopped [bold]{op_name}[/bold]")


@cli.command()
@click.option("--op", default=None)
def end(op: str | None) -> None:
    """Mark an op as ended (review-only on next open)."""
    store, op_name = _open_store(op)
    try:
        store.end_engagement()
    finally:
        store.close()
    if _active_op() == op_name:
        _clear_active_op()
    _console.print(f"[green]saddle:[/green] op [bold]{op_name}[/bold] marked ended")


# ── Op subcommands ────────────────────────────────────────────────────────────

@cli.group()
def op() -> None:
    """Op data views: list, status, findings, creds, surfaces, facts, iocs,
    leads, advisory, hosts, activity."""


@op.command("list")
def op_list() -> None:
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
        marker  = "  [yellow]← active[/yellow]" if name == active else ""
        _console.print(f"  {name}{running}{marker}")


@op.command("status")
@click.option("--op", default=None)
def op_status(op: str | None) -> None:
    """Show op summary (frontier, counts, token cost)."""
    store, op_name = _open_store(op)
    try:
        meta    = store.load_engagement_meta()
        totals  = store.token_usage_totals()
        st      = store.get_analyst_state()
        n_leads = store.count_notable_open_leads()
        _console.print(f"op:        [bold]{op_name}[/bold]  {'[green]● daemon[/green]' if _daemon_running(op_name) else ''}")
        _console.print(f"persona:   [cyan]{meta.get('persona', '?')}[/cyan]")
        _console.print(f"target:    {meta.get('target', '—')}")
        _console.print(f"status:    {meta.get('status', '?')}")
        if st:
            _console.print(f"frontier:  [bold]{st.get('frontier', '?')}[/bold]")
            opsec = st.get("opsec_level", "low")
            opsec_col = {"low": "green", "medium": "yellow",
                         "high": "red", "critical": "bold red"}.get(opsec, "white")
            _console.print(f"opsec:     [{opsec_col}]{opsec}[/{opsec_col}]")
        _console.print(f"findings:  {len(store.load_findings())}")
        _console.print(f"leads:     {n_leads} notable open")
        _console.print(f"creds:     {len(store.load_credentials())}")
        _console.print(f"surfaces:  {len(store.load_surfaces())}")
        _console.print(f"hosts:     {len(store.load_hosts())}")
        _console.print(f"beacons:   {len(store.load_beacons())}")
        if totals["cost_usd"]:
            _console.print(f"cost:      [dim]↑{totals['input_tokens']} ↓{totals['output_tokens']} ${totals['cost_usd']:.2f}[/dim]")
    finally:
        store.close()


@op.command("findings")
@click.option("--op", default=None)
@click.option("--severity", default=None,
              type=click.Choice(("info", "low", "medium", "high", "critical")))
def op_findings(op: str | None, severity: str | None) -> None:
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
    t.add_column("ID",  width=8)
    t.add_column("Sev", width=8)
    t.add_column("Title")
    t.add_column("Target")
    for r in rows:
        c = _SEV_COLOR.get(r.severity, "white")
        t.add_row(r.id, f"[{c}]{r.severity.upper()}[/{c}]", r.title, r.target)
    _console.print(t)
    _console.print(f"[dim]{len(rows)} finding(s)[/dim]")


@op.command("creds")
@click.option("--op", default=None)
@click.option("--reveal", is_flag=True, default=False)
def op_creds(op: str | None, reveal: bool) -> None:
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
    t.add_column("Type",    width=10)
    t.add_column("Username")
    t.add_column("Secret")
    t.add_column("Service", width=8)
    t.add_column("Source",  width=14)
    for r in rows:
        secret  = r.secret or ""
        display = secret if reveal else (secret[:2] + "***" if len(secret) > 3 else secret)
        t.add_row(r.cred_type, r.username or "", display, r.service or "", r.location or "")
    _console.print(t)
    _console.print(f"[dim]{len(rows)} credential(s)[/dim]")


@op.command("surfaces")
@click.option("--op", default=None)
def op_surfaces(op: str | None) -> None:
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
    t.add_column("Port",    width=6)
    t.add_column("Status",  width=10)
    for r in rows:
        t.add_row(r.host, r.service or "", str(r.port or ""), r.status)
    _console.print(t)


@op.command("facts")
@click.option("--op", default=None)
def op_facts(op: str | None) -> None:
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
        _console.print(f"  {r.statement}{scope}")
        if r.evidence:
            _console.print(f"    [dim]{r.evidence[:120]}[/dim]")


@op.command("iocs")
@click.option("--op", default=None)
@click.option("--type", "ioc_type", default=None,
              type=click.Choice(("ip", "domain", "hash", "url", "c2", "email", "other")))
def op_iocs(op: str | None, ioc_type: str | None) -> None:
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
    t.add_column("Type",   width=8)
    t.add_column("Value")
    t.add_column("Context")
    for r in rows:
        t.add_row(r.ioc_type, r.value, r.context or "")
    _console.print(t)


@op.command("leads")
@click.option("--op", default=None)
@click.option("--all", "show_all", is_flag=True, default=False,
              help="Show all leads, not just notable open ones")
def op_leads(op: str | None, show_all: bool) -> None:
    """Show notable open leads from analyst."""
    store, _ = _open_store(op)
    try:
        st = store.get_analyst_state()
        frontier = st.get("frontier", "recon") if st else "recon"
        rows = store._conn.execute(
            "SELECT json FROM leads WHERE engagement_id = ? ORDER BY created_at DESC",
            (store.engagement_id,),
        ).fetchall()
    finally:
        store.close()

    leads = [json.loads(r["json"]) for r in rows]
    if not show_all:
        leads = [l for l in leads
                 if l.get("status", "open") in ("open", "active", "advancing")
                 and "insight:notable" in l.get("notes", "")]
    if not leads:
        msg = "no notable open leads" if not show_all else "no leads"
        _console.print(f"[dim]{msg}[/dim]")
        return

    _console.print(f"[dim]Frontier: {frontier}[/dim]\n")
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Reach",  width=10)
    t.add_column("OPSEC",  width=8)
    t.add_column("Description")
    t.add_column("Command")
    for l in leads:
        notes   = l.get("notes", "")
        # Extract opsec from notes field ("opsec:medium insight:notable command:...")
        opsec   = "?"
        command = ""
        for part in notes.split():
            if part.startswith("opsec:"):
                opsec = part[6:]
            elif part.startswith("command:"):
                command = part[8:]
        oc = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(opsec, "white")
        t.add_row(l.get("reach_level", "?"), f"[{oc}]{opsec}[/{oc}]",
                  l.get("description", ""), command[:60])
    _console.print(t)
    _console.print(f"[dim]{len(leads)} lead(s)[/dim]")


@op.command("advisory")
@click.option("--op", default=None)
def op_advisory(op: str | None) -> None:
    """Show current analyst advisory and op picture."""
    store, _ = _open_store(op)
    try:
        st = store.get_analyst_state()
    finally:
        store.close()

    if not st:
        _console.print("[dim]no analyst data yet[/dim]")
        return

    _console.print(f"[bold]Frontier:[/bold] {st.get('frontier', '?')}")
    opsec = st.get("opsec_level", "low")
    oc = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(opsec, "white")
    _console.print(f"[bold]OPSEC:[/bold]    [{oc}]{opsec}[/{oc}]")
    _console.print()
    op_pic = st.get("op_picture", "").strip()
    if op_pic:
        _console.print("[bold]Op Picture:[/bold]")
        _console.print(op_pic)
        _console.print()
    adv = st.get("advisory", "").strip()
    if adv:
        _console.print("[bold]Advisory:[/bold]")
        for line in adv.splitlines():
            s = line.strip()
            if s.startswith("|_ OPSEC"):
                _console.print(f"  [dim]{s}[/dim]")
            elif s:
                _console.print(f"  {s}")


@op.command("hosts")
@click.option("--op", default=None)
def op_hosts(op: str | None) -> None:
    """List discovered hosts."""
    store, _ = _open_store(op)
    try:
        rows = store.load_hosts()
    finally:
        store.close()
    if not rows:
        _console.print("[dim]no hosts[/dim]")
        return
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("IP")
    t.add_column("Hostname")
    t.add_column("OS")
    t.add_column("Open Ports")
    t.add_column("Notes")
    for h in rows:
        t.add_row(h["ip"], h["hostname"], h["os"],
                  ", ".join(h["open_ports"][:8]), h["notes"][:40])
    _console.print(t)
    _console.print(f"[dim]{len(rows)} host(s)[/dim]")


@op.command("activity")
@click.option("--op", default=None)
@click.option("--limit", default=20, show_default=True)
def op_activity(op: str | None, limit: int) -> None:
    """Show recent activity log entries."""
    store, _ = _open_store(op)
    try:
        rows = store.get_activity_log()[-limit:]
    finally:
        store.close()
    if not rows:
        _console.print("[dim]no activity[/dim]")
        return
    for r in rows:
        _console.print(f"[dim]{r['ts']}[/dim]  {r['message']}")


# ── AI chat (direct LLM call with DB context) ─────────────────────────────────

@cli.command()
@click.argument("message", nargs=-1, required=True)
@click.option("--op", default=None)
def ai(message: tuple[str, ...], op: str | None) -> None:
    """Chat with the AI using current engagement context."""
    store, op_name = _open_store(op)
    try:
        meta    = store.load_engagement_meta()
        st      = store.get_analyst_state()
        history = store.load_chat_history(limit=10)
        frontier = st.get("frontier", "recon") if st else "recon"
        op_pic   = st.get("op_picture", "") if st else ""
        persona  = meta.get("persona", "pentest")

        system = (
            f"You are a {persona} advisor embedded in a live engagement. "
            f"Op: {op_name}  Frontier: {frontier}\n"
            f"Op picture: {op_pic or 'Not yet established'}\n\n"
            "Answer concisely and tactically. "
            "Never use web_search with target IPs, hostnames, or discovered credentials."
        )
        msgs = history + [{"role": "user", "content": " ".join(message)}]
        from core.llm_client import LLMClient
        from core.config import get as _cfg
        model = _cfg("global_model") or _cfg("analyst_model") or "claude-sonnet-4-5"
        resp  = LLMClient().run(
            model=model, system=system, messages=msgs, tools=[], max_tokens=2048,
        )
        reply = ""
        for block in (resp.content or []):
            if getattr(block, "type", None) == "text":
                reply += block.text
        reply = reply.strip()
        if reply:
            store.add_chat_message("user", " ".join(message))
            store.add_chat_message("assistant", reply)
            _console.print(reply)
        else:
            _console.print("[dim]No response[/dim]")
    except Exception as e:
        raise click.ClickException(str(e))
    finally:
        store.close()


# ── C2 commands ───────────────────────────────────────────────────────────────

@cli.group()
def c2() -> None:
    """C2 backend configuration and status (pentest/redteam only)."""


@c2.command("status")
@click.option("--op", default=None)
def c2_status(op: str | None) -> None:
    """Show C2 backend status."""
    from core.config import get as _cfg
    enabled = _cfg("c2.enabled", False)
    url     = _cfg("c2.nighthawk.url", "")
    user    = _cfg("c2.nighthawk.username", "")
    _console.print(f"c2.enabled:  {'[green]yes[/green]' if enabled else '[dim]no[/dim]'}")
    _console.print(f"nighthawk:   {url or '[dim](not set)[/dim]'}")
    _console.print(f"username:    {user or '[dim](not set)[/dim]'}")
    store, _ = _open_store(op)
    try:
        state   = store.get_c2_state("nighthawk")
        beacons = store.load_beacons()
    finally:
        store.close()
    if state:
        sid      = state.get("session_id", "")
        n_agents = len(state.get("agent_index", {}))
        _console.print(f"session:     {(sid[:12] + '…') if sid else '[dim]none[/dim]'}")
        _console.print(f"polled:      {n_agents} agent(s)")
    if beacons:
        _console.print(f"\n[bold]Beacons ({len(beacons)}):[/bold]")
        for b in beacons:
            _console.print(f"  {b['beacon_id'][:8]}  host={b['host']}  ip={b['ip']}  user={b['user_ctx']}")


@c2.command("url")
@click.argument("url")
def c2_url(url: str) -> None:
    """Set NightHawk C2 server URL."""
    from core.config import set_value as _cfg_set
    _cfg_set("c2.nighthawk.url", url.rstrip("/"))
    _cfg_set("c2.enabled", True)
    _console.print(f"[green]c2:[/green] NightHawk URL set to {url}")


@c2.command("auth")
@click.argument("username")
def c2_auth(username: str) -> None:
    """Set NightHawk username and password (stored in keychain)."""
    from core.config import set_value as _cfg_set
    password = click.prompt("NightHawk password", hide_input=True)
    _cfg_set("c2.nighthawk.username", username)
    try:
        import keyring
        keyring.set_password("pentest-ai", "nighthawk", password)
    except Exception as e:
        raise click.ClickException(f"keyring error: {e}")
    _console.print(f"[green]c2:[/green] NightHawk credentials saved for {username}")


@c2.command("connect")
@click.option("--op", default=None)
def c2_connect(op: str | None) -> None:
    """Start NightHawk polling (daemon must be running)."""
    op_name = _resolve_op(op)
    if not _daemon_running(op_name):
        raise click.ClickException(
            f"daemon not running — run: saddle start --op {op_name}"
        )
    _console.print("[dim]Daemon is running; NightHawk polling starts automatically when c2.enabled=true.[/dim]")
    _console.print("Restart the daemon to pick up new C2 settings:")
    _console.print(f"  saddle stop --op {op_name} && saddle start --op {op_name}")


@c2.command("disconnect")
@click.option("--op", default=None)
def c2_disconnect(op: str | None) -> None:
    """Clear NightHawk session from DB."""
    store, _ = _open_store(op)
    try:
        store.upsert_c2_state("nighthawk", session_id="", agent_index={}, agent_done=[])
    finally:
        store.close()
    _console.print("[green]c2:[/green] NightHawk session cleared from DB")


# ── Config ────────────────────────────────────────────────────────────────────

@cli.command("config")
@click.argument("args", nargs=-1)
def config_cmd(args: tuple[str, ...]) -> None:
    """View or change settings.

    \b
    saddle config               — list all settings
    saddle config <group>       — list one group
    saddle config <key>         — show key detail
    saddle config <key> <value> — change a setting
    """
    from ui.commands import handle_config
    lines, _ok = handle_config(list(args))
    for line in lines:
        _console.print(line)


# ── Provider / key / models ──────────────────────────────────────────────────

def _tui(text: str) -> None:
    from ui.commands import dispatch
    result = dispatch(text)
    if result:
        lines, _ = result
        for line in lines:
            _console.print(line)


@cli.group()
def provider() -> None:
    """Switch the active LLM provider."""


@provider.command("list")
def provider_list() -> None:
    _tui("/provider list")


@provider.command("set")
@click.argument("name")
def provider_set(name: str) -> None:
    _tui(f"/provider set {name}")


@cli.group()
def key() -> None:
    """Manage API keys (stored in system keychain)."""


@key.command("list")
def key_list() -> None:
    _tui("/key list")


@key.command("set")
@click.argument("provider_name")
def key_set(provider_name: str) -> None:
    api_key = click.prompt("API key", hide_input=True)
    _tui(f"/key set {provider_name} {api_key}")


@key.command("clear")
@click.argument("provider_name", default="")
def key_clear(provider_name: str) -> None:
    _tui(f"/key clear {provider_name}".strip())


@cli.group()
def models() -> None:
    """List models for a provider."""


@models.command("list")
@click.argument("provider_name", default="")
@click.argument("bedrock_provider", default="")
def models_list(provider_name: str, bedrock_provider: str) -> None:
    parts = [p for p in (provider_name, bedrock_provider) if p]
    _tui(f"/models list {' '.join(parts)}".strip())


@models.command("providers")
def models_providers() -> None:
    _tui("/models providers")


if __name__ == "__main__":
    cli()
