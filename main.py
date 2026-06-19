#!/usr/bin/env python3
import json
from typing import TYPE_CHECKING

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

load_dotenv()

from core.paths import AGENTS_DIR, RESULTS_DIR, LOGS_DIR  # noqa: E402 — after load_dotenv

if TYPE_CHECKING:                       # forward-ref only; runtime import is in-function
    from core.models import EngagementRun

# Ensure results directory exists at startup so list-runs never crashes on a fresh install
RESULTS_DIR.mkdir(exist_ok=True)

console = Console()

# Keep local aliases so existing internal references in this file continue to work
BASE_DIR = AGENTS_DIR.parent


def _build_registry():
    from core.registry import build_registry
    return build_registry()


def _load_all_agents() -> dict:
    from core.registry import load_all_agents
    return load_all_agents()


def _load_run(run_id: str) -> "EngagementRun":
    from core.models import EngagementRun

    matches = list(RESULTS_DIR.glob(f"{run_id}*.json"))
    if not matches:
        console.print(f"[red]No run found matching ID: {run_id}[/red]")
        raise SystemExit(1)
    data = json.loads(matches[0].read_text(encoding="utf-8"))
    return EngagementRun(**data)


def _format_run_block(run: "EngagementRun", *, brief: bool = False) -> list[str]:
    """Render one run as a list of lines for handoff context."""
    lines = [
        f"### {run.agent} — {run.target}  (run id: {run.id}  status: {run.status})",
        "",
    ]
    if run.technical_overview and not brief:
        excerpt = run.technical_overview[:600]
        if len(run.technical_overview) > 600:
            excerpt += "..."
        lines += [excerpt, ""]

    confirmed = [f for f in run.findings if f.verified]
    potential = [f for f in run.findings if not f.verified]

    if confirmed:
        lines.append("**Confirmed findings:**")
        for f in confirmed:
            cvss_str = f"  CVSS {f.cvss.base_score}" if (f.cvss and f.cvss.base_score) else ""
            lines.append(f"- [{f.severity.upper()}] {f.title} (id={f.id}){cvss_str}")
            if not brief:
                lines.append(f"  {f.description[:300]}{'...' if len(f.description) > 300 else ''}")
                if f.evidence:
                    lines.append(f"  Evidence: {json.dumps(f.evidence)[:200]}")
        lines.append("")

    if potential:
        lines.append("**Potential findings (unverified — investigate these):**")
        for f in potential:
            lines.append(f"- [{f.severity.upper()}] {f.title} (id={f.id})")
            if not brief:
                lines.append(f"  {f.description[:200]}{'...' if len(f.description) > 200 else ''}")
        lines.append("")

    return lines


def _format_handoff(run: "EngagementRun") -> str:
    lines = ["## Prior run context", ""]
    lines += _format_run_block(run)
    lines.append(
        "Use this context to guide your work. Prioritize confirmed findings, then "
        "investigate potential ones. All findings must be verified through active "
        "tooling in this run."
    )
    return "\n".join(lines)


def _format_multi_handoff(runs: list) -> str:
    lines = [f"## Prior engagement context ({len(runs)} run(s))", ""]
    for run in runs:
        lines += _format_run_block(run, brief=len(runs) > 2)
    lines.append(
        "Use this cumulative context to guide your work. Prioritize confirmed "
        "findings, then investigate potential ones. All findings must be verified "
        "through active tooling in this run."
    )
    return "\n".join(lines)


@click.group()
def cli():
    """PDTMJ-AI  —  Agentic penetration testing platform"""
    # Strip the virtualenv from the environment so external security tools spawned
    # as subprocesses (impacket, netexec, …) run against the system Python they
    # were installed against, not pentest-ai's venv (which lacks their deps).
    from core.utils import scrub_process_env
    scrub_process_env()


@cli.command()
@click.option("--agent", required=True, help="Agent name (e.g. pentest/web or web-recon)")
@click.option("--target", required=True, help="Target domain, IP, or path")
@click.option("--objective", default=None, help="Override the default objective prompt")
@click.option("--from-run", "from_run", default=None, help="Load prior run (ID prefix) as recon context")
@click.option("--report", is_flag=True, default=False, help="Auto-generate report on completion")
@click.option("--max-turns", default=None, type=int, show_default=True, help="Max agentic loop iterations")
def run(agent, target, objective, from_run, report, max_turns):
    """Run a single agent against a target."""
    from core.agent_loader import load_agent
    from core.config import get
    from core.llm_client import LLMClient
    from core.orchestrator import Orchestrator

    max_turns = max_turns or get("max_turns_default", 20)

    handoff_context = None
    if from_run:
        prior_run = _load_run(from_run)
        handoff_context = _format_handoff(prior_run)
        console.print(f"[dim]Loaded recon context from run {prior_run.id} "
                      f"({len(prior_run.findings)} findings)[/dim]")

    agent_def = load_agent(agent, AGENTS_DIR)
    llm = LLMClient()
    registry = _build_registry()

    from core.session_log import SessionLogger
    from core.orchestrator import _safe_filename_part
    from datetime import datetime as _dt
    _ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    logger = SessionLogger(
        LOGS_DIR / f"run_{_safe_filename_part(agent)}_{_safe_filename_part(target)}_{_ts}.log"
    )
    logger.header(target, objective, mode=f"single:{agent}")
    console.print(f"[dim]Log: {logger.path}[/dim]")

    orchestrator = Orchestrator(llm, registry, RESULTS_DIR, session_logger=logger)

    if handoff_context and objective:
        objective = f"{handoff_context}\n\n---\n\n{objective}"
    elif handoff_context:
        objective = handoff_context

    engagement_run = orchestrator.run(agent_def, target, objective, max_turns=max_turns)

    if report:
        from reporting.formatter import generate_report
        report_path = generate_report(engagement_run, RESULTS_DIR)
        console.print(f"\n[bold]Report:[/bold] {report_path}")


@cli.command()
@click.argument("run_id")
@click.option("--format", "fmt", default="markdown", show_default=True)
def report(run_id, fmt):
    """Generate a report from a saved run."""
    from reporting.formatter import generate_report
    from core.models import EngagementRun

    matches = list(RESULTS_DIR.glob(f"{run_id}*.json"))
    if not matches:
        console.print(f"[red]No run found matching ID: {run_id}[/red]")
        raise SystemExit(1)

    data = json.loads(matches[0].read_text(encoding="utf-8"))
    engagement_run = EngagementRun(**data)
    path = generate_report(engagement_run, RESULTS_DIR, fmt)
    console.print(f"Report: {path}")


@cli.command("list-runs")
def list_runs():
    """List saved engagement runs."""
    files = sorted(RESULTS_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not files:
        console.print("No runs found.")
        return

    table = Table(title="Engagement Runs")
    table.add_column("ID", style="cyan")
    table.add_column("Agent")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Start")

    for f in files[:25]:
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            table.add_row(
                d.get("id", "?"),
                d.get("agent", "?"),
                d.get("target", "?"),
                d.get("status", "?"),
                str(len(d.get("findings", []))),
                d.get("start_time", "")[:16],
            )
        except Exception:
            pass

    console.print(table)


@cli.command("list-agents")
def list_agents():
    """List available agents."""
    import re
    import yaml

    table = Table(title="Available Agents")
    table.add_column("Name", style="cyan")
    table.add_column("Category")
    table.add_column("Phase")
    table.add_column("Description")
    table.add_column("Model")

    for af in sorted(AGENTS_DIR.rglob("*.md")):
        if af.name == "base-instructions.md":
            continue
        content = af.read_text(encoding="utf-8")
        m = re.match(r"^---\n(.*?)\n---", content, re.DOTALL)
        if m:
            meta = yaml.safe_load(m.group(1))
            rel = af.relative_to(AGENTS_DIR).with_suffix("")
            category = rel.parent.as_posix() if rel.parent.as_posix() != "." else "legacy"
            table.add_row(
                meta.get("name", af.stem),
                category,
                meta.get("phase", ""),
                meta.get("description", ""),
                meta.get("model", ""),
            )

    console.print(table)


@cli.command()
@click.option("--target", required=True, help="Target domain, IP, or path")
@click.option("--entry", default="pentest/enumeration", show_default=True, help="Entry agent")
@click.option("--objective", default=None, help="Free-form objective/background for the engagement")
@click.option("--report", is_flag=True, default=False, help="Generate final report after the engagement")
@click.option("--max-turns", default=None, type=int, show_default=True, help="Max turns per agent")
@click.option("--allowed-phases", default=None, help="Comma-separated allowed phases, e.g. 'discovery,assessment,exploitation'")
@click.option("--no-confirm", is_flag=True, default=False, help="Skip exploitation confirmation prompt")
def pipeline(target, entry, objective, report, max_turns, allowed_phases, no_confirm):
    """Run a full engagement: the Enum→Plan→Exploit→Validate loop over each
    attack surface until exhaustion, then a synthesized report.
    """
    from core.config import get
    from core.llm_client import LLMClient
    from core.orchestrator import Orchestrator, _safe_filename_part
    from core.engagement_state import EngagementState
    from core.session_log import SessionLogger
    from core.pipeline import EngagementDriver
    from core.models import EngagementBrief, Assessment

    max_turns = max_turns or get("max_turns_default", 20)
    confirm_exploitation = (not no_confirm) and get("confirm_exploitation", True)

    from core.intake import resolve_phases
    raw_phases = [p.strip().lower() for p in allowed_phases.split(",")] if allowed_phases else []
    phases = resolve_phases(raw_phases)

    brief = EngagementBrief(
        targets=[target], objective=objective or f"Engagement against {target}.",
        allowed_phases=phases, entry=entry,
    )

    state = EngagementState(target=target)
    llm = LLMClient()
    registry = _build_registry()

    logger = SessionLogger(LOGS_DIR / f"pipeline_{_safe_filename_part(target)}.log")
    logger.header(target, objective, mode=f"pipeline:{entry}")
    console.print(f"[dim]Log: {logger.path}[/dim]")

    orchestrator = Orchestrator(
        llm, registry, RESULTS_DIR,
        engagement_state=state,
        session_logger=logger,
    )

    all_agents = _load_all_agents()
    assessment = Assessment(target=target, objective=brief.objective)

    def console_confirm(agent_name: str, findings: list) -> str:
        console.print(f"\n[bold yellow]⚠ Exploitation phase: {agent_name}[/bold yellow]")
        for f in findings:
            if f.severity in ("medium", "high", "critical"):
                console.print(f"  [{f.severity.upper()}] {f.title}")
        answer = ""
        while answer.lower() not in ("y", "n", "a"):
            answer = input("\nApprove exploitation? [Y]es / [N]o / [A]ll: ").strip() or "n"
        return answer.lower()

    def on_run_complete(eng_run) -> None:
        assessment.runs.append(eng_run)

    driver = EngagementDriver(
        orchestrator, all_agents, state, brief,
        max_turns=max_turns,
        confirm_exploitation=confirm_exploitation,
        max_cycles_per_surface=get("max_cycles_per_surface", 4),
        max_total_cycles=get("max_total_cycles", 40),
        max_surfaces=get("max_surfaces", 50),
        emit_activity=lambda text: console.print(
            f"[bold cyan]{text}[/bold cyan]" if text.startswith("──") else f"[dim]{text}[/dim]"
        ),
        confirm_cb=console_confirm if confirm_exploitation else None,
        on_run_complete=on_run_complete,
    )
    completed_runs = driver.run()

    if completed_runs:
        safe_target = _safe_filename_part(target)
        assessment.status = "complete"
        assessment_path = RESULTS_DIR / f"assessment_{assessment.id}_{safe_target}.json"
        assessment_path.write_text(assessment.model_dump_json(indent=2), encoding="utf-8")
        console.print(
            f"\n[dim]Assessment: {assessment_path}  "
            f"surfaces: {len(state.surfaces)}  cycles: {driver.total_cycles}  "
            f"creds: {len(state.credentials)}[/dim]"
        )

    if report and completed_runs:
        from reporting.formatter import generate_report, merge_runs
        merged = merge_runs(completed_runs, agent_name="pipeline", target=target)
        report_path = generate_report(merged, RESULTS_DIR)
        console.print(f"[bold]Report:[/bold] {report_path}")


@cli.command("list-models")
def list_models():
    """List available Claude models with descriptions."""
    table = Table(title="Claude Models")
    table.add_column("Model ID", style="cyan")
    table.add_column("Name")
    table.add_column("Notes")

    models = [
        ("claude-opus-4-7",           "Opus 4.7",   "Most capable — exploitation, post-exploitation, complex reasoning"),
        ("claude-sonnet-4-6",         "Sonnet 4.6", "Balanced capability/speed — default for most agents"),
        ("claude-haiku-4-5-20251001", "Haiku 4.5",  "Fast and lightweight — enumeration, recon"),
    ]
    for model_id, name, notes in models:
        table.add_row(model_id, name, notes)
    console.print(table)


@cli.command("app")
def launch_app():
    """Launch the interactive terminal UI."""
    from ui.app import run_app
    run_app()


@cli.command("config")
@click.argument("key", required=False)
@click.argument("value", required=False)
def config_cmd(key, value):
    """View or set config values. Usage: config [key] [value]"""
    from core.config import load_config, set_value

    if key and value:
        # Parse value type
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        elif value.isdigit():
            value = int(value)
        elif value.lower() == "null":
            value = None
        set_value(key, value)
        console.print(f"[green]Set {key} = {value!r}[/green]")
    else:
        cfg = load_config()
        if key:
            console.print(f"{key} = {cfg.get(key)!r}")
        else:
            table = Table(title="Configuration")
            table.add_column("Key", style="cyan")
            table.add_column("Value")
            for k, v in cfg.items():
                table.add_row(k, str(v))
            console.print(table)


if __name__ == "__main__":
    import sys
    # Default to launching the TUI when no subcommand is given
    if len(sys.argv) == 1:
        from core.utils import scrub_process_env
        scrub_process_env()          # same venv scrub the cli() group applies
        from ui.app import run_app
        run_app()
    else:
        cli()
