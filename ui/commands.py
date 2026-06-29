"""Slash command system for the PDTMJ-AI TUI.

All / commands are routed here regardless of whether an agent is running.
Each handler returns (output_lines: list[str], success: bool).
"""
from __future__ import annotations

import os

from core.llm_client import (
    PROVIDERS, get_provider, resolve_provider_key, provider_for_key,
    auth_headers, _KEYRING_SERVICE,
)

# Provider names, derived from the llm_client registry — used for command
# completions and validation so a new provider needs no edits here.
_PROVIDER_NAMES = tuple(PROVIDERS)

# /config completions — every setting key plus the group names, derived from the
# settings registry so a new setting is tab-completable with no edits here.
from core.settings import all_keys as _setting_keys, GROUPS as _setting_groups
_CONFIG_COMPLETIONS = _setting_keys() + tuple(g.lower() for g in _setting_groups)

# ── Command registry ──────────────────────────────────────────────────────────
# Single source of truth. Parsing, tab-completion, the grouped /help overview,
# and per-command help (/help <cmd>) are all derived from this — so adding or
# renaming a command means editing one place, not four lists that drift apart.
#
# A command is either a GROUP (several subcommands: /key set|list|clear) or a
# LEAF (stands alone, optionally with args: /turns <n|off>). A leaf is modelled
# as a single Sub with an empty name.

from dataclasses import dataclass


@dataclass(frozen=True)
class Sub:
    name: str                          # subcommand word ("set"); "" for a leaf
    desc: str                          # one-line description
    args: str = ""                     # arg hint shown after the path, e.g. "<api-key>"
    complete: tuple[str, ...] = ()     # extra completion suffixes (arg values)


@dataclass(frozen=True)
class Command:
    name: str                          # "/key"
    summary: str                       # family one-liner (grouped overview)
    subs: tuple[Sub, ...]              # subcommands; a lone Sub(name="") = leaf
    detail: tuple[str, ...] = ()       # extra lines for per-command help

    @property
    def is_leaf(self) -> bool:
        return len(self.subs) == 1 and self.subs[0].name == ""


COMMANDS: list[Command] = [
    Command("/info", "Snapshot: anchors, anything off-default, and your keys",
            (Sub("", "Snapshot of the active config — anchors + changed-from-default + keys"),)),
    Command("/config", "View or change any setting (the single place to configure)",
            (Sub("", "List all (grouped), /config <group>, /config <key>, or /config <key> <value>",
                 "[key|group] [value]", _CONFIG_COMPLETIONS),)),
    Command("/key", "Manage API keys (stored in the system keychain)", (
        Sub("set",   "Store a key (provider auto-detected, or name it explicitly)", "[provider] <api-key>"),
        Sub("list",  "Show API key status for all providers"),
        Sub("clear", "Remove key(s) from the keychain",
            f"[{'|'.join(_PROVIDER_NAMES)}]", _PROVIDER_NAMES),
    )),
    Command("/models", "List available models for a provider", (
        Sub("list", "List models (free-only for OpenRouter)",
            f"[{'|'.join(_PROVIDER_NAMES)}]", _PROVIDER_NAMES),
    )),
    Command("/agent", "Inspect and override per-agent models and temperatures", (
        Sub("set model", "Override the model for one agent (or 'global')",
            "<name|global> <model-id>", ("global",)),
        Sub("set temp", "Override the sampling temperature for one agent (or 'global')",
            "<name|global> <0.0-1.0|default>", ("global",)),
        Sub("list", "List all agents with their current model and temperature"),
    )),
    Command("/cred", "Pre-load or manage engagement credentials", (
        Sub("add",    "Pre-load a credential", "<user> <secret> [service]"),
        Sub("list",   "List credentials (operator + agent-discovered), numbered"),
        Sub("remove", "Remove a credential by its number from /cred list", "<n>"),
        Sub("clear",  "Remove all manually added credentials"),
    )),
    Command("/persona", "Switch the engagement persona", (
        Sub("set",  "Set the engagement persona", "<persona-name>"),
        Sub("list", "List available personas"),
    )),
    Command("/provider", "Switch the active LLM provider", (
        Sub("set",  "Switch active provider (local also takes a base URL)",
            f"<{'|'.join(_PROVIDER_NAMES)}> [baseURL]", _PROVIDER_NAMES),
        Sub("list", "Show current provider and key status"),
        Sub("login", "Authenticate a provider that uses a login flow",
            "<provider> [code]", _PROVIDER_NAMES),
    )),
    Command("/scope", "Manage the engagement's in-scope targets", (
        Sub("add",    "Approve a target for agent followups", "<target>"),
        Sub("remove", "Take a host/IP/CIDR out of scope (and keep it out)", "<target>"),
        Sub("list",   "Show approved (and excluded) scope targets"),
    )),
    Command("/job", "List running background jobs (and recent finished) or kill one by id",
            (Sub("list", "List running jobs plus the last few finished"),
             Sub("kill", "Terminate a running job and its process by id (or 'all')", "<id|all>",
                 ("all",)))),
    Command("/abort", "Hard-stop the current agent: kill every in-flight process and hold it for guidance",
            (Sub("", "Kill all in-flight processes and hold the agent — then /continue or /skip"),)),
    Command("/skip", "Abandon a held agent (after /abort) and advance to the next agent",
            (Sub("", "Abandon a held agent (after /abort) and advance to the next agent"),)),
    Command("/pause", "Temporarily pause the engagement after the current agent — resume with /continue",
            (Sub("", "Temporarily pause the engagement after the current agent — resume with /continue"),)),
    Command("/end", "Stop the pipeline, run always-last agents, generate the report",
            (Sub("", "Stop the pipeline, run always-last agents, generate the report"),)),
    Command("/continue", "Resume a held agent (after /abort), a paused engagement, or one halted by an account limit",
            (Sub("", "Resume a held agent (after /abort) with your guidance, or resume a paused/halted engagement"),)),
    Command("/assessment", "List, load, or start a fresh assessment", (
        Sub("list", "List saved assessments (id, date, target, status)"),
        Sub("load", "Reload a saved assessment into the panels by id", "<assessment-id>"),
        Sub("new",  "Clear the board to start a fresh assessment"),
    )),
    Command("/report", "Generate a report now, or regen to re-synthesize a loaded assessment",
            (Sub("", "No arg re-renders the report now; regen re-runs the report agent on a "
                 "loaded assessment. (Toggle auto-reporting with /config reporting_enabled.)",
                 "[regen]", ("regen",)),)),
    Command("/clear", "Reset to a blank window — panels, agent log, and token meter (saved files on disk are kept)",
            (Sub("", "Reset to a blank window — panels, agent log, and token meter (saved files on disk are kept)"),)),
    Command("/help", "Show this help — '/help <command>' for one command in detail",
            (Sub("", "Show this help — '/help <command>' for one command in detail",
                 "[command]"),)),
    Command("/exit", "Exit PDTMJ-AI", (Sub("", "Exit PDTMJ-AI"),)),
    Command("/quit", "Exit PDTMJ-AI", (Sub("", "Exit PDTMJ-AI"),)),
]

_BY_NAME: dict[str, Command] = {c.name: c for c in COMMANDS}
GROUP_NAMES: frozenset[str] = frozenset(c.name for c in COMMANDS if not c.is_leaf)


def _sub_path(cmd: Command, sub: Sub) -> str:
    return f"{cmd.name} {sub.name}".rstrip()


def _sub_sig(cmd: Command, sub: Sub) -> str:
    path = _sub_path(cmd, sub)
    return f"{path} {sub.args}".rstrip()


def _build_paths() -> list[str]:
    """Every recognizable command path. Group base names are included so a bare
    '/key' parses (and routes to that group's help)."""
    paths: list[str] = []
    for c in COMMANDS:
        paths.append(c.name)
        for s in c.subs:
            if s.name:
                paths.append(_sub_path(c, s))
    return paths


def _build_completions() -> list[str]:
    out: list[str] = []
    for c in COMMANDS:
        for s in c.subs:
            path = _sub_path(c, s)          # leaf → "/turns", group sub → "/key set"
            out.append(path)
            for x in s.complete:
                out.append(f"{path} {x}")
    return out


# Derived views (kept for backward-compat with parse()/usage() and completion.py)
COMMAND_PATHS: list[str] = _build_paths()
COMPLETIONS: list[str] = _build_completions()
COMMAND_HELP: dict[str, str] = {
    _sub_path(c, s): s.desc for c in COMMANDS for s in c.subs
}


# ── Parser ────────────────────────────────────────────────────────────────────

def parse(text: str) -> tuple[str, list[str]] | None:
    """Parse a slash command string.

    Returns (command_path, args_list) for a recognized command prefix,
    or (raw_word, []) for an unknown /command so the caller can show help.
    Returns None if text doesn't start with /.
    """
    text = text.strip()
    if not text.startswith("/"):
        return None

    lower = text.lower()
    for path in sorted(COMMAND_PATHS, key=len, reverse=True):
        if lower.startswith(path + " ") or lower == path:
            rest = text[len(path):].strip()
            args = rest.split() if rest else []
            return path, args

    # Unknown / command — return the first word
    return text.split()[0], []


def usage(cmd_path: str) -> str:
    return COMMAND_HELP.get(cmd_path, f"Unknown command: {cmd_path}")


# ── Help rendering ────────────────────────────────────────────────────────────

# Command families for the grouped /help overview. Every command name MUST appear
# in exactly one group (a startup check in _overview_lines guards against drift).
_HELP_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Setup & config",        ("/info", "/config", "/key", "/models", "/agent", "/persona", "/provider")),
    ("Engagement setup",      ("/scope", "/cred")),
    ("Control (while running)", ("/abort", "/skip", "/pause", "/continue", "/end", "/job")),
    ("Assessments & reports", ("/assessment", "/report")),
    ("Session",               ("/clear", "/help", "/exit", "/quit")),
)


def _overview_lines() -> list[str]:
    """Grouped overview: commands organised by family. Group commands show their
    subcommands in parens; leaf args are omitted here (they live in /help <cmd>)
    so every summary aligns in one clean column regardless of arg length."""
    lines = ["Slash commands (work anytime, even while an agent is running):", ""]

    # Forms: group → "/name (sub | sub)", leaf → just "/name" (args go to /help).
    def _form(c: Command) -> str:
        if c.is_leaf:
            return c.name
        return f"{c.name} ({' | '.join(s.name for s in c.subs)})"

    width = max(len(_form(c)) for c in COMMANDS) + 2
    for title, names in _HELP_GROUPS:
        lines.append(f"[bold]{title}[/bold]")
        for name in names:
            c = _BY_NAME.get(name)
            if c is None:                       # group references a missing command
                continue
            lines.append(f"  [cyan]{_form(c):<{width}}[/cyan] {c.summary}")
        lines.append("")
    lines += [
        "[dim]/help <command>[/dim]  — detail + arguments for one command  (e.g. /help config)",
        "While an agent runs, anything without / is sent to the agent as an instruction.",
        "",
        "Keyboard shortcuts:",
        "  Ctrl+L          Full activity log modal",
        "  Ctrl+D          Toggle command pane",
        "  Ctrl+←/→        Resize left/right pane split",
        "  Ctrl+↑/↓        Resize findings/info-tabs split",
        "  ↑/↓             Command history",
    ]
    return lines


def _command_help(arg: str) -> list[str] | None:
    """Detailed help for one command. Accepts 'scope', '/scope', etc."""
    word = arg.lstrip("/").lower().split()
    cmd = _BY_NAME.get("/" + word[0]) if word else None
    if cmd is None:
        return None
    if cmd.is_leaf:
        sub = cmd.subs[0]
        head = f"{cmd.name} {sub.args}".rstrip()
        lines = [f"[cyan]{head}[/cyan] — {cmd.summary}"]
    else:
        lines = [f"[cyan]{cmd.name}[/cyan] — {cmd.summary}", ""]
        width = max(len(_sub_sig(cmd, s)) for s in cmd.subs) + 2
        for s in cmd.subs:
            lines.append(f"  [cyan]{_sub_sig(cmd, s):<{width}}[/cyan] {s.desc}")
    if cmd.detail:
        lines += [""] + [f"  {d}" for d in cmd.detail]
    return lines


# ── API key helpers ───────────────────────────────────────────────────────────
# NOTE: the keyring service name "pentest-ai" below is kept literal through the
# PDTMJ-AI rebrand on purpose — it is the lookup key for already-stored API keys,
# so renaming it would orphan the operator's saved credentials. Leave it as-is.

def get_api_key() -> str | None:
    """Resolve the Anthropic API key (keychain → env). Kept as a named helper for
    the common case; other providers resolve via resolve_provider_key(spec)."""
    return resolve_provider_key(PROVIDERS["anthropic"])


# ── Handlers ─────────────────────────────────────────────────────────────────

def _masked_key_source(spec) -> str:
    """'keychain (sk-...123)' / 'env var (...)' / 'not set' for one provider."""
    try:
        import keyring
        stored = keyring.get_password(_KEYRING_SERVICE, spec.keyring_key)
    except Exception:
        stored = None
    if stored:
        return f"keychain  ({stored[:8]}...{stored[-4:]})"
    env = os.environ.get(spec.env_var)
    if env:
        return f"env var   ({env[:8]}...{env[-4:]})"
    return "not set"


def handle_key_list() -> tuple[list[str], bool]:
    from core.config import get
    lines = ["API key status:", ""]
    for spec in PROVIDERS.values():
        lines.append(f"  {spec.label:<12} {_masked_key_source(spec)}")
    lines += ["", f"  Active provider: {get('active_provider', 'anthropic')}"]
    return lines, True


def handle_key_clear(args: list[str]) -> tuple[list[str], bool]:
    """Remove API key(s) from keychain. Target: a provider name, or all if omitted."""
    target = args[0].lower() if args else "all"
    if target != "all" and target not in PROVIDERS:
        return [f"Unknown provider: {target!r}",
                f"  Supported: {', '.join(_PROVIDER_NAMES)}, all"], False
    results: list[str] = []
    try:
        import keyring
        for spec in PROVIDERS.values():
            if target in (spec.name, "all"):
                try:
                    keyring.delete_password(_KEYRING_SERVICE, spec.keyring_key)
                    results.append(f"{spec.label} key removed.")
                except Exception:
                    results.append(f"{spec.label} key not found in keychain.")
        return results, True
    except Exception as e:
        return [f"Keychain error: {e}"], False


def handle_key_set(args: list[str]) -> tuple[list[str], bool]:
    """Store a new API key.

      /key set <api-key>             provider auto-detected from the key prefix
      /key set <provider> <api-key>  explicit provider (for keys with no standard
                                     prefix, e.g. a local server)
    """
    if not args:
        return ["Usage: /key set [provider] <api-key>"], False

    # Two tokens → explicit provider; one token → auto-detect by prefix.
    if len(args) >= 2 and args[0].lower() in PROVIDERS:
        spec    = PROVIDERS[args[0].lower()]
        new_key = args[1]
    else:
        new_key = args[0]
        spec    = provider_for_key(new_key)
        if spec is None:
            lines = ["Unknown key format — say which provider: /key set <provider> <api-key>",
                     f"  Providers: {', '.join(_PROVIDER_NAMES)}"]
            for s in PROVIDERS.values():
                if s.key_prefixes:
                    lines.append(f"  {s.label} keys start with  {s.key_prefixes[0]}")
            return lines, False
    try:
        import keyring
        keyring.set_password(_KEYRING_SERVICE, spec.keyring_key, new_key)
        masked = (new_key[:8] + "..." + new_key[-4:]) if len(new_key) > 12 else "***"
        return [f"{spec.label} API key stored in system keychain  ({masked})"], True
    except Exception as e:
        return [f"Keychain error: {e}"], False


def _fetch_models_raw(provider: str = "") -> tuple[list[dict], str]:
    """Fetch the raw model dicts for a provider (active one if ''). Returns
    (models, error_message); error is "" on success. The single source of truth for
    both the displayed list AND tab-completion — registry-driven (endpoint/auth/
    free-only all come from the ProviderSpec)."""
    from core.config import get
    from core.llm_client import models_url_for
    provider = (provider or get("active_provider", "anthropic")).lower()
    spec = PROVIDERS.get(provider)
    if spec is None:
        return [], f"Unknown provider: {provider!r}  (supported: {', '.join(_PROVIDER_NAMES)})"
    models_url = models_url_for(spec)
    if not models_url:
        if spec.base_url_config:
            return [], f"{spec.label}: no base URL set — run /provider set {provider} <url> first."
        return [], f"{spec.label} does not expose a model list."
    key = resolve_provider_key(spec)
    if not key and not spec.key_optional:
        pfx = spec.key_prefixes[0] if spec.key_prefixes else ""
        return [], f"No {spec.label} API key set. Run: /key set {pfx}..."
    try:
        import httpx
        r = httpx.get(models_url, headers=auth_headers(spec, key or ""), timeout=10)
        r.raise_for_status()
        models = r.json().get("data", [])
    except Exception as e:
        return [], f"API error: {e}"
    if spec.free_only:
        # Free models: both prompt and completion cost must be "0".
        models = [
            m for m in models
            if str(m.get("pricing", {}).get("prompt", "1"))      == "0"
            and str(m.get("pricing", {}).get("completion", "1")) == "0"
        ]
    return models, ""


def fetch_model_ids(provider: str = "") -> list[str]:
    """Raw model ids for tab-completion — straight from the provider API, NOT re-parsed
    from display text. So local/Ollama names (llama3.1:8b, mistral) work, where the
    display-text heuristic dropped them."""
    models, _ = _fetch_models_raw(provider)
    return [m["id"] for m in models if m.get("id")]


def handle_models_list(provider: str = "") -> tuple[list[str], bool]:
    """List available models for a provider (defaults to the active one)."""
    from core.config import get
    provider = (provider or get("active_provider", "anthropic")).lower()
    spec = PROVIDERS.get(provider)
    models, err = _fetch_models_raw(provider)
    if err:
        return [err], False
    if not models:
        label = spec.label if spec else provider
        return [f"No free models found on {label}." if (spec and spec.free_only)
                else f"No models returned by {label}."], False

    header = (f"Free {spec.label} models ({len(models)} total — use these with /agent set model):"
              if spec.free_only else
              f"Available {spec.label} models ({len(models)} total):")
    lines = [header, ""]
    for m in sorted(models, key=lambda x: x.get("id", "")):
        mid     = m.get("id", "?")
        name    = m.get("name") or m.get("display_name") or ""
        ctx     = m.get("context_length", 0)
        ctx_str = f"{ctx // 1000}k ctx" if ctx else ""
        lines.append(f"  {mid:<50}  {name}  {ctx_str}".rstrip())
    if spec.free_only:
        lines.append("")
        lines.append("  All listed models are free (no prompt or completion cost).")
    lines += ["", "  Set one with: /agent set model global <model-id>"]
    return lines, True


def handle_agent_list() -> tuple[list[str], bool]:
    try:
        import re as re_mod
        import yaml
        from pathlib import Path
        from core.config import load_config

        from core.config import get_temperature_for_agent

        agents_dir = Path(__file__).parent.parent / "agents"
        cfg = load_config()
        overrides: dict = cfg.get("agent_models", {})
        temps: dict = cfg.get("agent_temperatures", {}) or {}
        global_model = overrides.get("global", "—")

        lines = [f"{'Agent':<34} {'Model override':<28} {'Temp':<6} Source", ""]
        for af in sorted(agents_dir.rglob("*.md")):
            if af.name == "base-instructions.md":
                continue
            content = af.read_text(encoding="utf-8")
            m = re_mod.match(r"^---\n(.*?)\n---", content, re_mod.DOTALL)
            if not m:
                continue
            try:
                meta = yaml.safe_load(m.group(1))
                name    = meta.get("name", af.stem)
                override = overrides.get(name, "")
                model_str = f"→ {override}" if override else f"({meta.get('model', '—')})"
                eff = get_temperature_for_agent(name)
                temp_str = "default" if eff is None else f"{eff:g}"
                src = "override" if name in temps else "default"
                lines.append(f"  {name:<32} {model_str:<28} {temp_str:<6} {src}")
            except Exception:
                pass

        td = cfg.get("temperature_default")
        lines += [
            "",
            f"  global model override:  {global_model}",
            f"  temperature_default:    {'provider default' if td is None else td}"
            "   (/agent set temp <name|global> <0.0-1.0>)",
        ]
        return lines, True
    except Exception as e:
        return [f"Error: {e}"], False


def handle_agent_set_model(args: list[str]) -> tuple[list[str], bool]:
    """
    Args: [<agent_name|global>, <model_id>]
    """
    if len(args) < 2:
        return [
            "Usage: /agent set model <agent-name|global> <model-id>",
            "",
            "Examples:",
            "  /agent set model global claude-sonnet-4-6",
            "  /agent set model pentest/exploitation claude-opus-4-7",
            "  /agent set model pentest/enumeration claude-haiku-4-5-20251001",
        ], False

    agent_name, model_id = args[0], args[1]

    try:
        from core.config import load_config, save_config, get
        cfg = load_config()
        overrides: dict = cfg.setdefault("agent_models", {})
        overrides[agent_name] = model_id
        save_config(cfg)

        lines = []
        if agent_name == "global":
            lines.append(f"Global default model set to: {model_id}")
        else:
            lines.append(f"Model for '{agent_name}' set to: {model_id}")

        # Warn if using OpenRouter with a model that doesn't look free
        if get("active_provider", "anthropic") == "openrouter" and not model_id.endswith(":free"):
            lines += [
                "",
                "  Warning: OpenRouter model does not end with :free — this may incur cost.",
                "  Run /models list openrouter to see available free models.",
            ]
        return lines, True
    except Exception as e:
        return [f"Error writing config: {e}"], False


def handle_agent_set_temp(args: list[str]) -> tuple[list[str], bool]:
    """
    Args: [<agent_name|global>, <0.0-1.0 | default>]

    Per-agent override, or 'global' to set the baseline (temperature_default).
    'default' clears: a per-agent override falls back to the baseline; 'global default'
    falls back to the provider default (no temperature sent).
    """
    if len(args) < 2:
        return [
            "Usage: /agent set temp <agent-name|global> <0.0-1.0|default>",
            "",
            "Examples:",
            "  /agent set temp global 0.4                  (baseline for all agents)",
            "  /agent set temp pentest/rce 0.5             (override one agent)",
            "  /agent set temp pentest/report 0.2",
            "  /agent set temp pentest/rce default         (clear the override)",
            "",
            "Lower = focused/deterministic (tool-heavy work, reports); higher = more "
            "exploratory (helps an agent break out of a rut).",
        ], False

    agent_name, val = args[0], args[1].lower()
    clearing = val in ("default", "off", "none", "clear")

    t = None
    if not clearing:
        try:
            t = float(val)
        except ValueError:
            return ["Temperature must be a number between 0.0 and 1.0 (or 'default' to clear).",
                    "Example: /agent set temp pentest/rce 0.5"], False
        if not (0.0 <= t <= 1.0):
            return [f"Temperature must be between 0.0 and 1.0 (got {t})."], False

    try:
        from core.config import load_config, save_config
        cfg = load_config()
        temps: dict = cfg.setdefault("agent_temperatures", {})

        if agent_name == "global":
            cfg["temperature_default"] = None if clearing else t
            save_config(cfg)
            if clearing:
                return ["Baseline temperature cleared — agents now use the provider default "
                        "(1.0) unless individually overridden."], True
            return [f"Baseline temperature set to {t} (every agent without its own override)."], True

        if clearing:
            temps.pop(agent_name, None)
            save_config(cfg)
            td = cfg.get("temperature_default")
            return [f"Temperature override for '{agent_name}' cleared — it now uses the baseline "
                    f"({'provider default' if td is None else td})."], True

        temps[agent_name] = t
        save_config(cfg)
        return [f"Temperature for '{agent_name}' set to {t}."], True
    except Exception as e:
        return [f"Error writing config: {e}"], False


def _config_list(group: str | None = None) -> list[str]:
    from core import settings
    groups = [group] if group else list(settings.GROUPS)
    shown = [s for g in groups for s in settings.settings_in_group(g)]
    kw = max((len(s.key) for s in shown), default=10)
    lines = ["Settings  —  /config <key> <value> to change · /config <key> for detail", ""]
    for g in groups:
        gs = settings.settings_in_group(g)
        if not gs:
            continue
        lines.append(f"  {g}")
        for s in gs:
            star = "*" if settings.is_changed(s) else " "
            val = settings.format_value(settings.current_value(s))
            lines.append(f"   {star} {s.key:<{kw}}  {val:<7}  {s.desc}")
        lines.append("")
    lines.append("  * = changed from default")
    return lines


def _config_show(s) -> list[str]:
    from core import settings
    val  = settings.format_value(settings.current_value(s))
    dflt = settings.format_value(s.default)
    if s.choices:
        typ = " | ".join(s.choices)
    elif s.type == "bool":
        typ = "on | off"
    elif s.type == "int":
        typ = "integer" + (f" ≥ {s.minimum}" if s.minimum is not None else "") + (" or null" if s.allow_null else "")
    else:
        typ = "text" + (" or null" if s.allow_null else "")
    return [
        f"  {s.key} = {val}",
        f"    {s.desc}",
        f"    Type: {typ}     Default: {dflt}     Group: {s.group}",
        f"    Change with: /config {s.key} <value>",
    ]


def _config_unknown(name: str) -> list[str]:
    import difflib
    from core import settings
    out = [f"Unknown setting: {name!r}"]
    near = difflib.get_close_matches(name, settings.all_keys(), n=3)
    if near:
        out.append("  Did you mean: " + ", ".join(near) + "?")
    out.append("  /config to list everything, or /config <group>.")
    return out


def handle_config(args: list[str]) -> tuple[list[str], bool]:
    """The single place to view/change scalar settings. /config lists all (grouped),
    /config <group> filters, /config <key> shows detail, /config <key> <value> sets."""
    from core import settings
    from core.config import set_value
    if not args:
        return _config_list(), True

    first = args[0]
    if len(args) == 1:
        if first.lower() in (g.lower() for g in settings.GROUPS):
            return _config_list(first), True
        s = settings.get_setting(first)
        if s:
            return _config_show(s), True
        return _config_unknown(first), False

    # /config <key> <value...>
    s = settings.get_setting(first)
    if not s:
        return _config_unknown(first), False
    value, err = settings.coerce(s, " ".join(args[1:]))
    if err:
        return [err], False
    old = settings.current_value(s)
    set_value(s.key, value)
    return [f"{s.key} = {settings.format_value(value)}   "
            f"(was {settings.format_value(old)})"], True


def handle_info() -> tuple[list[str], bool]:
    """A signal-only snapshot: the fixed anchors you always want to see, plus
    anything moved off its default and the keys you actually have. Everything at
    its default stays hidden — to browse/change all settings, use /config."""
    from core.config import load_config, get_global_model
    from core import settings

    cfg      = load_config()
    persona  = cfg.get("active_persona", "pentest")
    provider = cfg.get("active_provider", "anthropic")
    gmodel   = get_global_model()

    def _row(label: str, value: str) -> str:
        return f"  {label:<17}{value}".rstrip()

    def _on(key: str, default: bool) -> str:
        return "ON" if cfg.get(key, default) else "OFF"

    # Fixed anchors — always shown, even at default. No command hints.
    lines = [
        "Current configuration",
        "",
        _row("Persona", persona),
        _row("Provider", provider),
        _row("Global model", gmodel or "— (per-agent defaults)"),
        _row("Exploitation", _on("exploitation_enabled", True)),
        _row("Reporting", _on("reporting_enabled", True)),
        _row("Confirm exploit", _on("confirm_exploitation", True)),
    ]

    # Anything moved off its default (excluding the always-shown anchors).
    changed = [s for s in settings.SETTINGS
               if not s.info_static and settings.is_changed(s)]
    if changed:
        lines += ["", "  Changed from defaults:"]
        kw = max(len(s.label) for s in changed)
        for s in changed:
            val  = settings.format_value(settings.current_value(s))
            dflt = settings.format_value(s.default)
            lines.append(f"    {s.label:<{kw}}  {val:<10} (default {dflt})")

    # Per-agent model overrides — only when set.
    overrides = {k: v for k, v in (cfg.get("agent_models", {}) or {}).items() if k != "global"}
    if overrides:
        lines += ["", "  Per-agent model overrides:"]
        for name, model in overrides.items():
            lines.append(f"    {name:<28} → {model}")

    # API keys — populated providers only.
    keyed = [(spec.label, _masked_key_source(spec))
             for spec in PROVIDERS.values() if resolve_provider_key(spec)]
    if keyed:
        lines += ["", "  API keys:"]
        for label, src in keyed:
            lines.append(f"    {label:<12} {src}")

    return lines, True


def handle_help(args: list[str] | None = None) -> tuple[list[str], bool]:
    """No arg → grouped overview. '/help <command>' → that command in detail."""
    if args:
        detail = _command_help(args[0])
        if detail is not None:
            return detail, True
        return [f"No such command: /{args[0].lstrip('/')}", ""] + _overview_lines(), False
    return _overview_lines(), True


# ── Credential handlers ───────────────────────────────────────────────────────
# Session-level manual creds (list[dict]) stored in the app and injected into
# EngagementState when a pipeline/run starts. Not persisted to disk.

def handle_cred_add(args: list[str]) -> tuple[list[str], bool, dict | None]:
    """Always returns a 3-tuple — cred dict is None on usage errors."""
    if len(args) < 2:
        return [
            "Usage: /cred add <username> <secret> [service]",
            "",
            "Examples:",
            "  /cred add administrator Password123! smb",
            "  /cred add root toor ssh",
            "  /cred add admin 'P@ssw0rd' http",
        ], False, None
    username = args[0]
    secret   = args[1]
    service  = args[2] if len(args) > 2 else ""
    # Return the cred dict — caller stores it in app state
    return [f"Credential added: {username}  service={service or 'any'}"], True, {
        "username": username,
        "secret":   secret,
        "service":  service,
    }


def handle_cred_list(creds: list[dict]) -> tuple[list[str], bool]:
    if not creds:
        return ["No manual credentials loaded.  Use /cred add <user> <pass> [service]"], True
    from core.utils import mask_secret
    lines = [f"{'Username':<20} {'Secret':<20} Service", ""]
    for c in creds:
        lines.append(f"  {c['username']:<18} {mask_secret(c['secret']):<20} {c.get('service', '')}")
    return lines, True


def handle_cred_clear() -> tuple[list[str], bool]:
    # Returns sentinel — caller clears their cred list
    return ["Manual credentials cleared."], True


# ── Persona handlers ──────────────────────────────────────────────────────────

def handle_persona_list() -> tuple[list[str], bool]:
    try:
        from pathlib import Path
        agents_dir = Path(__file__).parent.parent / "agents"
        personas = []
        for persona_file in agents_dir.rglob("persona.md"):
            namespace = persona_file.parent.name
            personas.append(namespace)

        if not personas:
            return [
                "No persona files found.",
                "Expected: agents/<namespace>/persona.md",
                "Personas will be created when you run /persona set.",
            ], True

        from core.config import load_config
        current = load_config().get("active_persona", "pentest")
        lines = ["Available personas:", ""]
        for p in sorted(personas):
            active_marker = "  ← active" if p == current else ""
            lines.append(f"  {p}{active_marker}")
        lines += ["", f"Active: {current}"]
        return lines, True
    except Exception as e:
        return [f"Error: {e}"], False


def handle_persona_set(args: list[str]) -> tuple[list[str], bool]:
    if not args:
        return [
            "Usage: /persona set <persona-name>",
            "",
            "Examples:",
            "  /persona set pentest",
            "  /persona set pentest-ctf",
        ], False

    persona = args[0].lower()
    import re as _re
    if not _re.match(r'^[a-zA-Z0-9_-]+$', persona):
        return ["Persona name may only contain letters, digits, hyphens, and underscores."], False
    try:
        from pathlib import Path
        from core.config import set_value
        agents_base  = (Path(__file__).parent.parent / "agents").resolve()
        persona_path = (agents_base / persona / "persona.md").resolve()
        if not str(persona_path).startswith(str(agents_base)):
            return ["Invalid persona name."], False
        if not persona_path.exists():
            return [
                f"Persona '{persona}' not found  ({persona_path})",
                "Use /persona list to see available personas.",
            ], False
        set_value("active_persona", persona)
        return [f"Active persona set to: {persona}"], True
    except Exception as e:
        return [f"Error: {e}"], False


# ── Provider handlers ────────────────────────────────────────────────────────

def handle_provider_list() -> tuple[list[str], bool]:
    from core.config import get
    lines = [f"Active provider: {get('active_provider', 'anthropic')}", ""]
    for spec in PROVIDERS.values():
        is_set = bool(resolve_provider_key(spec))
        lines.append(f"  {spec.label:<12} {'set' if is_set else 'not set'}")
    lines += ["", f"  Switch with: /provider set <{'|'.join(_PROVIDER_NAMES)}>"]
    return lines, True


def handle_provider_set(args: list[str]) -> tuple[list[str], bool]:
    if not args:
        return [f"Usage: /provider set <{'|'.join(_PROVIDER_NAMES)}>  "
                f"(local also takes a base URL: /provider set local <http://host:port/v1>)"], False
    provider = args[0].lower()
    spec = PROVIDERS.get(provider)
    if spec is None:
        return [
            f"Unknown provider: {provider!r}",
            f"  Supported: {', '.join(_PROVIDER_NAMES)}",
        ], False
    from core.config import set_value, get, get_global_model

    # A config-driven provider (local) accepts its base URL inline and persists it.
    if spec.base_url_config:
        if len(args) > 1:
            set_value(spec.base_url_config, args[1].rstrip("/"))
        base = get(spec.base_url_config, "")
        if not base:
            return [
                f"{spec.label} needs a base URL.",
                f"  Run: /provider set {provider} http://localhost:11434/v1   (Ollama)",
                f"       /provider set {provider} http://localhost:1234/v1    (LM Studio)",
            ], False

    set_value("active_provider", provider)
    out = [f"Provider set to: {provider}"]
    if spec.base_url_config:
        out[0] += f"  ({get(spec.base_url_config, '')})"

    # Warn about a missing key — but only when the provider actually requires one.
    if not spec.key_optional and not resolve_provider_key(spec):
        pfx = spec.key_prefixes[0] if spec.key_prefixes else ""
        out.append(f"  Warning: no {spec.label} API key found — set one with /key set {pfx}...")
        return out, True
    # Non-native providers use OpenAI-style model IDs, so the per-agent Anthropic
    # defaults won't resolve — remind the operator to pin a global model.
    if not spec.native and not get_global_model():
        out.append(f"  Note: set a model for this provider — /agent set model global <id>"
                   f"  (list them with /models list {provider}).")
    return out, True


def handle_provider_login(args: list[str]) -> tuple[list[str], bool]:
    """Run a provider's login flow, if it has one. Most providers authenticate with
    an API key (/key set) and have no login step; a provider only supports this if it
    registered a `login` callable (an operator-private extension). The callable takes
    the remaining args and returns (lines, ok), so it can be multi-step (issue a URL on
    the first call, complete the exchange when a code is pasted on the second)."""
    if not args:
        return ["Usage: /provider login <provider> [code]"], False
    provider = args[0].lower()
    spec = PROVIDERS.get(provider)
    if spec is None:
        return [f"Unknown provider: {provider!r}",
                f"  Supported: {', '.join(_PROVIDER_NAMES)}"], False
    login = getattr(spec, "login", None)
    if not callable(login):
        return [f"{spec.label} doesn't use a login flow — set an API key with "
                f"/key set instead."], False
    try:
        return login(args[1:])
    except Exception as e:
        return [f"{spec.label} login failed: {e}"], False


# ── Main dispatcher ───────────────────────────────────────────────────────────

def dispatch(text: str) -> tuple[list[str], bool] | None:
    """Dispatch a slash command string.

    Returns (output_lines, success) or None if text is not a slash command.
    Caller is responsible for rendering output_lines.
    """
    parsed = parse(text)
    if parsed is None:
        return None

    cmd, args = parsed

    # A bare "/" (nothing typed after it) is a request for the command list, not
    # an unknown command — show the overview.
    if cmd == "/":
        return handle_help()

    # A bare group name ("/key", "/scope", …) shows that group's detailed help.
    if cmd in GROUP_NAMES:
        return handle_help([cmd])

    if cmd == "/help":
        return handle_help(args)
    if cmd == "/info":
        return handle_info()
    if cmd == "/config":
        return handle_config(args)
    if cmd == "/key list":
        return handle_key_list()
    if cmd == "/key clear":
        return handle_key_clear(args)
    if cmd == "/key set":
        if args:
            return handle_key_set(args)
        return [
            "Usage: /key set [provider] <api-key>",
            "  Auto-detected:    sk-ant-... (Anthropic), sk-or-... (OpenRouter), nvapi-... (NVIDIA)",
            "  Explicit provider: /key set local <api-key>   (for keys with no standard prefix)",
            "  Key will be stored in your system keychain, not on disk.",
        ], False
    if cmd == "/models list":
        provider = args[0] if args else ""
        return handle_models_list(provider)
    if cmd == "/agent list":
        return handle_agent_list()
    if cmd == "/agent set model":
        return handle_agent_set_model(args)
    if cmd == "/agent set temp":
        return handle_agent_set_temp(args)
    if cmd == "/cred add":
        # Cred injection requires app state — dispatch() only returns the message.
        lines, ok, _cred = handle_cred_add(args)
        return lines, ok
    if cmd == "/cred clear":
        return handle_cred_clear()
    if cmd == "/persona list":
        return handle_persona_list()
    if cmd == "/persona set":
        return handle_persona_set(args)
    if cmd == "/provider list":
        return handle_provider_list()
    if cmd == "/provider set":
        return handle_provider_set(args)
    if cmd == "/provider login":
        return handle_provider_login(args)

    # Unknown command
    return [
        f"Unknown command: {cmd}",
        "",
        *handle_help()[0],
    ], False
