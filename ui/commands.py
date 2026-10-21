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


def _persona_names() -> tuple[str, ...]:
    """Persona namespaces from agents/<ns>/persona.md — for /persona set completion."""
    try:
        from pathlib import Path
        agents_dir = Path(__file__).parent.parent / "agents"
        return tuple(sorted(p.parent.name for p in agents_dir.rglob("persona.md")))
    except Exception:
        return ()


_PERSONA_COMPLETIONS = _persona_names()
# Credential kinds for /cred add (matches record_credential's enum), with a few aliases.
_CRED_TYPES = ("password", "hash", "api_key", "token", "key")
_CRED_TYPE_ALIASES = {"api": "api_key", "apikey": "api_key", "ntlm": "hash",
                      "pass": "password", "pw": "password", "privkey": "key",
                      "ssh_key": "key", "jwt": "token"}

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


_IOC_TYPES = ("ip", "domain", "hash", "url", "c2", "email", "other")
# Persona sets used for /help filtering (mirrors core.settings constants)
_ALL_PERSONAS     = ()                                   # empty = show to everyone
_PIPELINE         = ("pentest", "pentest-ctf")           # automated pipeline only
_OPS_PERSONAS     = ("pentest", "redteam")               # daemon/analyst personas
_PENTEST_ONLY     = ("pentest",)


@dataclass(frozen=True)
class Command:
    name: str                          # "/key"
    summary: str                       # family one-liner (grouped overview)
    subs: tuple[Sub, ...]              # subcommands; a lone Sub(name="") = leaf
    detail: tuple[str, ...] = ()       # extra lines for per-command help
    personas: tuple[str, ...] = ()     # empty = all personas; else shown only to these

    @property
    def is_leaf(self) -> bool:
        return len(self.subs) == 1 and self.subs[0].name == ""

    def visible_for(self, persona: str) -> bool:
        return not self.personas or persona in self.personas


COMMANDS: list[Command] = [
    # ── Infrastructure (all personas) ─────────────────────────────────────────
    Command("/op", "Create or switch the active op (engagement)", (
        Sub("start",  "Create or resume an op and start the daemon", "<name> [persona]"),
        Sub("list",   "List existing ops in the ops directory"),
        Sub("status", "Show the active op name and daemon state"),
    )),
    Command("/info", "Snapshot: anchors, anything off-default, and your keys",
            (Sub("", "Snapshot of the active config — anchors + changed-from-default + keys"),)),
    Command("/config", "View or change any setting (persona-filtered)",
            (Sub("", "List all (grouped), /config <group>, /config <key>, or /config <key> <value>",
                 "[key|group] [value]", _CONFIG_COMPLETIONS),)),
    Command("/key", "Manage API keys (stored in the system keychain)", (
        Sub("set",   "Store a key (provider auto-detected, or name it explicitly)", "[provider] <api-key>"),
        Sub("list",  "Show API key status for all providers"),
        Sub("clear", "Remove key(s) from the keychain",
            f"[{'|'.join(_PROVIDER_NAMES)}]", _PROVIDER_NAMES),
    )),
    Command("/models", "List available models for a provider", (
        Sub("list",      "List model IDs for a provider (active if omitted)",
            f"[{'|'.join(_PROVIDER_NAMES)}] [BProvider]", _PROVIDER_NAMES),
        Sub("providers", "List model providers available in AWS Bedrock"),
    )),
    Command("/provider", "Switch the active LLM provider", (
        Sub("set",  "Switch active provider (local also takes a base URL)",
            f"<{'|'.join(_PROVIDER_NAMES)}> [baseURL]", _PROVIDER_NAMES),
        Sub("list", "Show current provider and key status"),
        Sub("login", "Authenticate a provider that uses a login flow",
            "<provider> [code]", _PROVIDER_NAMES),
    )),
    Command("/persona", "Switch the engagement persona", (
        Sub("set",  "Set the engagement persona", "<persona-name>", _PERSONA_COMPLETIONS),
        Sub("list", "List available personas"),
    )),
    Command("/agent", "Inspect and override per-agent models and temperatures", (
        Sub("set model", "Override the model for one agent (or 'global')",
            "<name|global> <model-id>", ("global",)),
        Sub("set temp", "Override the sampling temperature for one agent (or 'global')",
            "<name|global> <0.0-1.0|default>", ("global",)),
        Sub("list", "List all agents with their current model and temperature"),
    )),
    # ── Op data (all personas) ────────────────────────────────────────────────
    Command("/cred", "Pre-load or manage engagement credentials", (
        Sub("add",    "Pre-load a credential", "[type] <user> <secret> [service]", _CRED_TYPES),
        Sub("list",   "List credentials (operator + agent-discovered), numbered"),
        Sub("remove", "Remove a credential by its number from /cred list", "<n>"),
        Sub("clear",  "Remove all manually added credentials"),
    )),
    Command("/scope", "Manage the engagement's in-scope targets", (
        Sub("add",    "Approve a target for agent followups", "<target>"),
        Sub("remove", "Take a host/IP/CIDR out of scope (and keep it out)", "<target>"),
        Sub("list",   "Show approved (and excluded) scope targets"),
    )),
    # ── Ops persona commands (pentest + redteam — daemon-backed) ─────────────
    Command("/ioc", "Track indicators of compromise", (
        Sub("add",    "Record an IOC",
            f"<{'|'.join(_IOC_TYPES)}> <value> [context]", _IOC_TYPES),
        Sub("list",   "List all IOCs for the active op"),
        Sub("remove", "Remove an IOC by its number from /ioc list", "<n>"),
    ), personas=_OPS_PERSONAS),
    Command("/analyst", "Tune or check the background log analyst", (
        Sub("status",  "Show last advisory, opsec level, and token usage"),
        Sub("",        "View/set analyst settings: /analyst <key> [value]",
            "[key] [value]", ("interval", "debounce", "model")),
    ), personas=_OPS_PERSONAS),
    Command("/endop", "End the engagement — stops daemon, marks ended, clears active op",
            (Sub("", "Stops the daemon, marks the engagement ended, clears sentinel files"),),
            personas=_OPS_PERSONAS),
    # ── Pipeline commands (pentest + ctf only) ────────────────────────────────
    Command("/job", "List or kill running background jobs",
            (Sub("list", "List running jobs plus the last few finished"),
             Sub("kill", "Terminate a running job by id (or 'all')", "<id|all>", ("all",))),
            personas=_PIPELINE),
    Command("/abort", "Hard-stop the current agent and hold for guidance",
            (Sub("", "Kill all in-flight processes and hold the agent — then /continue or /skip"),),
            personas=_PIPELINE),
    Command("/skip", "Abandon a held agent (after /abort) and advance to the next",
            (Sub("", "Abandon a held agent (after /abort) and advance to the next agent"),),
            personas=_PIPELINE),
    Command("/pause", "Pause the engagement after the current agent — resume with /continue",
            (Sub("", "Temporarily pause the engagement after the current agent"),),
            personas=_PIPELINE),
    Command("/end", "Stop the pipeline, run always-last agents, generate the report",
            (Sub("", "Stop the pipeline, run always-last agents, generate the report"),),
            personas=_PIPELINE),
    Command("/continue", "Resume a held agent (/abort), paused engagement, or account-limit halt",
            (Sub("", "Resume a held agent with guidance, or resume a paused/halted engagement"),),
            personas=_PIPELINE),
    Command("/assessment", "List, load, or start a fresh assessment", (
        Sub("list", "List saved assessments (id, date, target, status)"),
        Sub("load", "Reload a saved assessment into the panels by id", "<assessment-id>"),
        Sub("new",  "Clear the board to start a fresh assessment"),
    ), personas=_PIPELINE),
    Command("/report", "Generate a report now, or regen a loaded assessment",
            (Sub("", "No arg renders the report now; regen re-runs the report agent on a "
                 "loaded assessment. (Auto-report toggle: /config reporting — ctf only.)",
                 "[regen]", ("regen",)),),
            personas=_PIPELINE),
    # ── Session (all personas) ────────────────────────────────────────────────
    Command("/clear", "Clear the command output pane (+ activity log with 'log')", (
        Sub("",    "Clear the command output pane only"),
        Sub("log", "Clear both the command output pane and the activity log"),
    )),
    Command("/help", "Show this help — '/help <command>' for detail on one command",
            (Sub("", "Show this help", "[command]"),)),
    Command("/exit", "Exit PDTMJ-AI  (/quit also works)",
            (Sub("", "Exit PDTMJ-AI"),)),
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

# Command families for the grouped /help overview.
_HELP_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Setup & config",          ("/info", "/config", "/key", "/models", "/agent", "/persona", "/provider")),
    ("Engagement data",         ("/scope", "/cred", "/ioc")),
    ("Ops (pentest/redteam)",   ("/analyst", "/endop")),
    ("Control (while running)", ("/abort", "/skip", "/pause", "/continue", "/end", "/job")),
    ("Assessments & reports",   ("/assessment", "/report")),
    ("Session",                 ("/clear", "/help", "/exit", "/quit")),
)


def _overview_lines() -> list[str]:
    """Grouped overview filtered by active persona."""
    persona = _active_persona()
    lines = ["Slash commands (work anytime, even while an agent is running):", ""]

    def _form(c: Command) -> str:
        if c.is_leaf:
            return c.name
        subs = [s.name for s in c.subs if s.name]
        return f"{c.name} ({' | '.join(subs)})" if subs else c.name

    visible = [c for c in COMMANDS if c.visible_for(persona)]
    width = max((len(_form(c)) for c in visible), default=10) + 2
    for title, names in _HELP_GROUPS:
        group_cmds = [_BY_NAME[n] for n in names if n in _BY_NAME and _BY_NAME[n].visible_for(persona)]
        if not group_cmds:
            continue
        lines.append(f"[bold]{title}[/bold]")
        for c in group_cmds:
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
                    from core.llm_client import invalidate_key_cache
                    invalidate_key_cache(spec.keyring_key)
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
        from core.llm_client import invalidate_key_cache
        invalidate_key_cache(spec.keyring_key)
        masked = (new_key[:8] + "..." + new_key[-4:]) if len(new_key) > 12 else "***"
        return [f"{spec.label} API key stored in system keychain  ({masked})"], True
    except Exception as e:
        return [f"Keychain error: {e}"], False


def _bedrock_fetch(bedrock_provider: str | None = None) -> tuple[list[dict], str]:
    """Fetch Bedrock foundation model summaries via boto3.

    Returns (models, error_message); error is "" on success.
    Auth: ABSKQ API key via AWS_BEARER_TOKEN_BEDROCK, or IAM profile fallback.
    """
    from core import config as _cfg
    import os
    region  = _cfg.get("bedrock.region", "us-east-1")
    profile = _cfg.get("bedrock.profile", "default")
    ak      = resolve_provider_key(PROVIDERS["bedrock"]) if "bedrock" in PROVIDERS else None
    try:
        import boto3
        prev = os.environ.get("AWS_BEARER_TOKEN_BEDROCK")
        if ak:
            os.environ["AWS_BEARER_TOKEN_BEDROCK"] = ak
        try:
            session = boto3.Session() if ak else boto3.Session(profile_name=profile)
            client  = session.client("bedrock", region_name=region)
            kwargs  = {"byProvider": bedrock_provider} if bedrock_provider else {}
            return client.list_foundation_models(**kwargs).get("modelSummaries", []), ""
        finally:
            if ak:
                if prev is None:
                    os.environ.pop("AWS_BEARER_TOKEN_BEDROCK", None)
                else:
                    os.environ["AWS_BEARER_TOKEN_BEDROCK"] = prev
    except Exception as e:
        return [], str(e)


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
    # Bedrock uses boto3, not an HTTP models endpoint
    if provider == "bedrock":
        summaries, err = _bedrock_fetch()
        if err:
            return [], f"Bedrock list_foundation_models failed: {err}"
        models = [{"id": m["modelId"], "name": m.get("modelName", ""),
                   "providerName": m.get("providerName", "")}
                  for m in summaries if m.get("modelId")]
        if not models:
            return [], "No Bedrock models returned — check credentials (/key set ABSKQ... or ~/.aws)"
        return models, ""
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

        td = cfg.get("temp")
        lines += [
            "",
            f"  global model override:  {global_model}",
            f"  temp:    {'provider default' if td is None else td}"
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

    Per-agent override, or 'global' to set the baseline (temp).
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
            cfg["temp"] = None if clearing else t
            save_config(cfg)
            if clearing:
                return ["Baseline temperature cleared — agents now use the provider default "
                        "(1.0) unless individually overridden."], True
            return [f"Baseline temperature set to {t} (every agent without its own override)."], True

        if clearing:
            temps.pop(agent_name, None)
            save_config(cfg)
            td = cfg.get("temp")
            return [f"Temperature override for '{agent_name}' cleared — it now uses the baseline "
                    f"({'provider default' if td is None else td})."], True

        temps[agent_name] = t
        save_config(cfg)
        return [f"Temperature for '{agent_name}' set to {t}."], True
    except Exception as e:
        return [f"Error writing config: {e}"], False


def _active_persona() -> str:
    # Sentinel file wins (written by both TUI daemon start and saddle start).
    try:
        from pathlib import Path
        _sentinel = Path.home() / ".local" / "share" / "pdtmj-ai" / ".active_persona"
        name = _sentinel.read_text().strip()
        if name:
            return name
    except Exception:
        pass
    from core.config import get as _cfg_get
    return _cfg_get("active_persona", "pentest") or "pentest"


def _config_list(group: str | None = None) -> list[str]:
    from core import settings
    persona = _active_persona()
    groups = [group] if group else list(settings.groups_for_persona(persona))
    shown = [s for g in groups for s in settings.settings_in_group(g, persona)]
    kw = max((len(s.key) for s in shown), default=10)
    lines = [f"Settings \\[{persona}]  —  /config <key> <value> to change · /config <key> for detail", ""]
    for g in groups:
        gs = settings.settings_in_group(g, persona)
        if not gs:
            continue
        lines.append(f"  {g}")
        for s in gs:
            star = "*" if settings.is_changed(s) else " "
            val = settings.format_value(settings.current_value(s, persona))
            lines.append(f"   {star} {s.key:<{kw}}  {val:<7}  {s.desc}")
        lines.append("")
    lines.append("  * = changed from default")
    return lines


def _config_show(s, persona: str | None = None) -> list[str]:
    from core import settings
    if persona is None:
        persona = _active_persona()
    val  = settings.format_value(settings.current_value(s, persona))
    dflt = settings.format_value(s.default)
    if s.choices:
        typ = " | ".join(s.choices)
    elif s.type == "bool":
        typ = "on | off"
    elif s.type == "int":
        typ = "integer" + (f" ≥ {s.minimum}" if s.minimum is not None else "") + (" or null" if s.allow_null else "")
    else:
        typ = "text" + (" or null" if s.allow_null else "")
    scope = f"ops only ({', '.join(s.personas)})" if s.personas else "all personas"
    return [
        f"  {s.key} = {val}",
        f"    {s.desc}",
        f"    Type: {typ}     Default: {dflt}     Group: {s.group}     Scope: {scope}",
        f"    Change with: /config {s.key} <value>",
    ]


def _config_unknown(name: str) -> list[str]:
    import difflib
    from core import settings
    persona = _active_persona()
    visible_keys = [s.key for s in settings.settings_for_persona(persona)]
    out = [f"Unknown setting: {name!r}"]
    near = difflib.get_close_matches(name, visible_keys, n=3)
    if near:
        out.append("  Did you mean: " + ", ".join(near) + "?")
    out.append("  /config to list everything, or /config <group>.")
    return out


def handle_analyst(args: list[str]) -> tuple[list[str], bool]:
    """/analyst — settings view or status."""
    _KEY_MAP = {"interval": "analyst_interval", "debounce": "analyst_debounce",
                "model": "analyst_model"}
    if not args:
        return _config_list("Analyst"), True
    if args[0] == "status":
        return handle_analyst_status()
    mapped = [_KEY_MAP.get(args[0], args[0])] + list(args[1:])
    return handle_config(mapped)


def handle_endop(app=None) -> tuple[list[str], bool]:
    """/endop — stop daemon, mark op ended, clear sentinel files."""
    from pathlib import Path
    from core.paths import OPS_DIR

    _active_op_file   = OPS_DIR / ".active_op"
    _active_pers_file = OPS_DIR.parent / ".active_persona"

    # Read active op before clearing
    try:
        op_name = _active_op_file.read_text().strip() or None
    except FileNotFoundError:
        op_name = None

    lines: list[str] = []

    # Stop daemon via socket
    if op_name:
        import json, socket as _sock
        _sock_path = OPS_DIR / op_name / ".saddle.sock"
        if _sock_path.exists():
            try:
                s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect(str(_sock_path))
                s.sendall(json.dumps({"type": "stop"}).encode() + b"\n")
                s.recv(256)
                s.close()
                lines.append("[green]saddle:[/green] daemon stopped")
            except Exception:
                pass

        # Mark engagement ended in the store
        try:
            from core.engagement_store import EngagementStore
            store, _, _ = EngagementStore.open_or_create(op_name)
            store.end_engagement()
            store.close()
            lines.append(f"[green]saddle:[/green] op [bold]{op_name}[/bold] marked ended")
        except Exception as e:
            lines.append(f"[yellow]warning:[/yellow] could not mark op ended: {e}")

    # Clear sentinel files
    try:
        _active_op_file.unlink(missing_ok=True)
        _active_pers_file.unlink(missing_ok=True)
    except Exception:
        pass

    if not lines:
        lines.append("[dim]no active op[/dim]")

    if app is not None:
        # Signal the TUI to exit after displaying the message
        try:
            app.call_later(app.exit)
        except Exception:
            pass

    return lines, True


def handle_ioc(args: list[str]) -> tuple[list[str], bool]:
    """/ioc add|list|remove — manual IOC tracking for the active op."""
    from pathlib import Path
    from core.paths import OPS_DIR

    def _open():
        try:
            op = (OPS_DIR / ".active_op").read_text().strip()
        except FileNotFoundError:
            op = None
        if not op:
            raise click_err("no active op")
        from core.engagement_store import EngagementStore
        store, _, _ = EngagementStore.open_or_create(op)
        return store, op

    def click_err(msg: str):
        class _E(Exception):
            pass
        e = _E(msg)
        return e

    sub = args[0].lower() if args else "list"

    if sub == "list":
        try:
            store, _ = _open()
            rows = store.load_iocs()
            store.close()
        except Exception as e:
            return [f"[red]{e}[/red]"], False
        if not rows:
            return ["[dim]no IOCs[/dim]"], True
        out = []
        for i, r in enumerate(rows, 1):
            ctx = f"  [dim]{r.context}[/dim]" if r.context else ""
            out.append(f"  {i:>3}.  [{r.ioc_type}]  {r.value}{ctx}")
        out.append(f"\n  [dim]{len(rows)} IOC(s)[/dim]")
        return out, True

    if sub == "add":
        rest = args[1:]
        if not rest:
            return [f"Usage: /ioc add <{'|'.join(_IOC_TYPES)}> <value> [context]"], False
        ioc_type = rest[0].lower() if rest[0].lower() in _IOC_TYPES else "other"
        value_idx = 1 if rest[0].lower() in _IOC_TYPES else 0
        if value_idx >= len(rest):
            return [f"Usage: /ioc add <{'|'.join(_IOC_TYPES)}> <value> [context]"], False
        value   = rest[value_idx]
        context = " ".join(rest[value_idx + 1:])
        try:
            store, _ = _open()
            from core.models import IOC
            store.upsert_ioc(IOC(ioc_type=ioc_type, value=value, context=context))
            store.close()
        except Exception as e:
            return [f"[red]{e}[/red]"], False
        return [f"IOC recorded: [{ioc_type}] {value}"], True

    if sub == "remove":
        if not args[1:] or not args[1].isdigit():
            return ["Usage: /ioc remove <n>  (number from /ioc list)"], False
        n = int(args[1])
        try:
            store, _ = _open()
            rows = store.load_iocs()
            if n < 1 or n > len(rows):
                store.close()
                return [f"No IOC #{n} — /ioc list to see current entries"], False
            target = rows[n - 1]
            store._conn.execute(
                "DELETE FROM iocs WHERE id = ?", (target.id,))
            store._conn.commit()
            store.close()
        except Exception as e:
            return [f"[red]{e}[/red]"], False
        return [f"IOC #{n} removed"], True

    return [f"Unknown subcommand {sub!r} — /ioc add|list|remove"], False


def handle_analyst_status() -> tuple[list[str], bool]:
    """/analyst status — last advisory, opsec level, and token usage."""
    import json
    from pathlib import Path
    from core.paths import OPS_DIR

    try:
        op = (OPS_DIR / ".active_op").read_text().strip()
    except FileNotFoundError:
        op = None
    if not op:
        return ["[dim]no active op[/dim]"], True

    lines: list[str] = [f"Analyst status for [bold]{op}[/bold]", ""]

    # Token usage
    usage_path = OPS_DIR / op / ".analyst_usage"
    if usage_path.exists():
        try:
            u = json.loads(usage_path.read_text())
            lines.append(f"  tokens in/out  {u.get('in', 0):,} / {u.get('out', 0):,}")
        except Exception:
            pass

    # Badge from daemon socket
    import socket as _sock
    sock_path = OPS_DIR / op / ".saddle.sock"
    if sock_path.exists():
        try:
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(str(sock_path))
            s.sendall(json.dumps({"type": "status"}).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
            s.close()
            resp = json.loads(data.split(b"\n")[0])
            badge = resp.get("badge")
            badge_type = resp.get("badge_type", "info")
            _colour = {"info": "dim", "warning": "yellow", "alert": "red", "critical": "bold red"}
            c = _colour.get(badge_type, "white")
            if badge:
                lines.append(f"  badge          [{c}]{badge}[/{c}]")
            else:
                lines.append("  badge          [dim]clear[/dim]")
        except Exception:
            lines.append("  daemon         [dim]not reachable[/dim]")
    else:
        lines.append("  daemon         [dim]not running[/dim]")

    # Last few analyst observations from the store
    try:
        from core.engagement_store import EngagementStore
        store, _, _ = EngagementStore.open_or_create(op)
        facts = [f for f in store.load_facts() if f.kind in ("opsec", "observation")]
        store.close()
        if facts:
            lines += ["", "  Recent observations:"]
            for f in facts[-3:]:
                lines.append(f"    [dim]{f.scope}[/dim]  {f.statement}")
    except Exception:
        pass

    return lines, True


def handle_config(args: list[str]) -> tuple[list[str], bool]:
    """The single place to view/change scalar settings. /config lists all (grouped),
    /config <group> filters, /config <key> shows detail, /config <key> <value> sets."""
    from core import settings
    from core.config import set_value
    persona = _active_persona()
    if not args:
        return _config_list(), True

    first = args[0]
    if len(args) == 1:
        if first.lower() in (g.lower() for g in settings.groups_for_persona(persona)):
            return _config_list(first), True
        s = settings.get_setting(first)
        if s:
            if not s.allowed_for(persona):
                return [f"{s.key!r} is not available for the {persona!r} persona."], False
            return _config_show(s, persona), True
        return _config_unknown(first), False

    # /config <key> <value...>
    s = settings.get_setting(first)
    if not s:
        return _config_unknown(first), False
    if not s.allowed_for(persona):
        return [f"{s.key!r} is not available for the {persona!r} persona."], False
    value, err = settings.coerce(s, " ".join(args[1:]))
    if err:
        return [err], False
    old = settings.current_value(s, persona)
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
        from core.config import get as _get
        return "ON" if _get(key, default) else "OFF"

    is_ops = persona in ("pentest", "redteam")

    # Fixed anchors — always shown, even at default. No command hints.
    lines = [
        "Current configuration",
        "",
        _row("Persona", persona),
        _row("Provider", provider),
        _row("Global model", gmodel or "— (per-agent defaults)"),
        _row("Reporting", _on("reporting", True)),
    ]
    if is_ops:
        lines += [
            _row("Exploitation", _on("exploitation", True)),
            _row("Confirm exploit", _on("confirm_exploit", True)),
        ]

    # Anything moved off its default (excluding the always-shown anchors, filtered by persona).
    changed = [s for s in settings.settings_for_persona(persona)
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

def _usage_cred_add() -> list[str]:
    return [
        "Usage: /cred add [type] <username> <secret> [service]",
        "",
        "type (optional, FIRST arg): " + ", ".join(_CRED_TYPES) + "  — default password",
        "username is optional: a lone secret is a usernameless credential (a password",
        "found with no known user, an API key). Put '-' in the username slot when you",
        "have a service but no username.",
        "",
        "Examples:",
        "  /cred add administrator Password123! smb",
        "  /cred add hash svc_sql aad3b435...:31d6cfe0...",
        "  /cred add api sk-abcd1234",
        "  /cred add MyPass123                    (password, unknown user)",
        "  /cred add - Password123! smb           (unknown user, with service)",
    ]


def handle_cred_add(args: list[str]) -> tuple[list[str], bool, dict | None]:
    """Always returns a 3-tuple — cred dict is None on usage errors.

    Form: /cred add [type] <username> <secret> [service]. An optional leading type
    keyword (password/hash/api_key/token/key, or an alias like api/ntlm) defaults to
    password. The remaining args are positional by count — 1=secret only (usernameless),
    2=username+secret, 3=username+secret+service — so a password whose user is unknown,
    or an API key, is a lone secret. '-' in the username slot means 'no username'."""
    toks = list(args)
    cred_type = "password"
    if toks:
        norm = _CRED_TYPE_ALIASES.get(toks[0].lower(), toks[0].lower())
        if norm in _CRED_TYPES:
            cred_type = norm
            toks = toks[1:]

    username: str | None = None
    secret = ""
    service = ""
    if len(toks) == 1:
        secret = toks[0]
    elif len(toks) == 2:
        username, secret = toks[0], toks[1]
    elif len(toks) >= 3:
        username, secret, service = toks[0], toks[1], toks[2]
    if username in ("-", ""):
        username = None

    if not secret:
        return _usage_cred_add(), False, None

    who = f"user={username}" if username else "user=(unknown)"
    return [f"Credential added: type={cred_type}  {who}  service={service or 'any'}"], True, {
        "username":  username,
        "secret":    secret,
        "service":   service,
        "cred_type": cred_type,
    }


def handle_cred_list(creds: list[dict]) -> tuple[list[str], bool]:
    if not creds:
        return ["No manual credentials loaded.  Use /cred add [type] <user> <pass> [service]"], True
    from core.utils import mask_secret
    lines = [f"{'Type':<10} {'Username':<20} {'Secret':<20} Service", ""]
    for c in creds:
        user = c.get("username") or "-"
        lines.append(f"  {(c.get('cred_type') or 'password'):<8} {user:<20} "
                     f"{mask_secret(c.get('secret', '')):<20} {c.get('service', '')}")
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
        try:
            from pathlib import Path
            _sentinel = Path.home() / ".local" / "share" / "pdtmj-ai" / ".active_persona"
            _sentinel.parent.mkdir(parents=True, exist_ok=True)
            _sentinel.write_text(persona)
        except Exception:
            pass
        return [f"Active persona set to: {persona}"], True
    except Exception as e:
        return [f"Error: {e}"], False


# ── Provider handlers ────────────────────────────────────────────────────────

def handle_provider_list() -> tuple[list[str], bool]:
    from core.config import get
    lines = [f"Active provider: {get('active_provider', 'anthropic')}", ""]
    for spec in PROVIDERS.values():
        ak = resolve_provider_key(spec)
        if spec.name == "bedrock":
            status = "API key" if ak else "IAM (~/.aws)"
        elif ak:
            status = "set"
        elif spec.key_optional:
            status = "optional"
        else:
            status = "not set"
        lines.append(f"  {spec.label:<22} {status}")
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


# ── Op handlers ──────────────────────────────────────────────────────────────

def handle_op_start(args: list[str]) -> tuple[list[str], bool]:
    """Create or resume an op and start the session daemon.

    Usage: /op start <name> [persona]
    Writes the active-op sentinel, creates the EngagementStore, and spawns
    the daemon process (same as `saddle start --op <name>`).
    """
    import re as _re, subprocess, sys, time
    from core.paths import OPS_DIR
    from core.engagement_store import EngagementStore

    if not args:
        return ["Usage: /op start <name> [persona]",
                "  persona defaults to the current active persona (or pentest)"], False

    op_name = args[0]
    if not _re.match(r'^[a-zA-Z0-9_.-]+$', op_name):
        return ["Op name may only contain letters, digits, hyphens, underscores, and dots."], False

    persona = args[1].lower() if len(args) > 1 else _active_persona()

    try:
        store, is_new, review_mode = EngagementStore.open_or_create(op_name, persona=persona)
        store.close()
    except Exception as e:
        return [f"Could not create op store: {e}"], False

    if review_mode:
        return [f"Op '{op_name}' was ended and is in review mode.",
                "  Use `saddle end --reopen` to reactivate it."], False

    # Write sentinel files
    try:
        OPS_DIR.mkdir(parents=True, exist_ok=True)
        (OPS_DIR / ".active_op").write_text(op_name)
        (OPS_DIR.parent / ".active_persona").write_text(persona)
        from core.config import set_value as _cfg_set
        _cfg_set("active_persona", persona)
    except Exception as e:
        return [f"Could not set active op: {e}"], False

    # Check if daemon already running (socket probe)
    sock_path = OPS_DIR / op_name / ".saddle.sock"
    def _daemon_up() -> bool:
        if not sock_path.exists():
            return False
        try:
            import socket as _s
            c = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            c.settimeout(1.0); c.connect(str(sock_path)); c.close()
            return True
        except Exception:
            return False

    if _daemon_up():
        label = "[dim](resumed — daemon already running)[/dim]"
        return [f"Op [bold]{op_name}[/bold] active  persona=[cyan]{persona}[/cyan]  {label}"], True

    # Spawn daemon
    try:
        project_dir = str(__import__("pathlib").Path(__file__).parent.parent)
        env = {**os.environ, "PYTHONPATH": project_dir}
        subprocess.Popen(
            [sys.executable, "-m", "core.saddle_daemon", "--op", op_name, "--persona", persona],
            start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, cwd=project_dir,
        )
    except Exception as e:
        return [f"Op store created but daemon failed to start: {e}",
                f"  Op [bold]{op_name}[/bold] is active — daemon can be retried with `saddle start --op {op_name}`"], False

    # Wait up to 3s for the daemon socket
    for _ in range(15):
        if _daemon_up():
            label = "[dim](new)[/dim]" if is_new else "[dim](resumed)[/dim]"
            return [f"Op [bold]{op_name}[/bold] started  persona=[cyan]{persona}[/cyan]  {label}"], True
        time.sleep(0.2)

    return [f"Op [bold]{op_name}[/bold] set as active  (daemon socket not yet ready — it may still be starting)"], True


def handle_op_list() -> tuple[list[str], bool]:
    from core.paths import OPS_DIR
    try:
        active = (OPS_DIR / ".active_op").read_text().strip()
    except FileNotFoundError:
        active = ""
    try:
        ops = sorted(p.name for p in OPS_DIR.iterdir()
                     if p.is_dir() and (p / "engagement.db").exists())
    except Exception as e:
        return [f"Could not list ops: {e}"], False
    if not ops:
        return ["No ops found. Start one with: /op start <name>"], True
    lines = ["Ops:", ""]
    for op in ops:
        marker = "  ← active" if op == active else ""
        lines.append(f"  {op}{marker}")
    lines += ["", "  /op start <name> to create or resume · /op status for detail"]
    return lines, True


def handle_op_status() -> tuple[list[str], bool]:
    import socket as _sock
    from core.paths import OPS_DIR
    try:
        op = (OPS_DIR / ".active_op").read_text().strip() or None
    except FileNotFoundError:
        op = None
    if not op:
        return ["No active op. Use /op start <name> to create one."], False
    persona = _active_persona()
    lines = [f"Active op: [bold]{op}[/bold]  persona=[cyan]{persona}[/cyan]", ""]
    sock_path = OPS_DIR / op / ".saddle.sock"
    if sock_path.exists():
        try:
            s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
            s.settimeout(1.0); s.connect(str(sock_path)); s.close()
            lines.append("  Daemon: [green]running[/green]")
        except Exception:
            lines.append("  Daemon: [yellow]socket exists but not responding[/yellow]")
    else:
        lines.append("  Daemon: [dim]not running[/dim]  (start with /op start " + op + ")")
    return lines, True


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

    if cmd == "/op start":
        return handle_op_start(args)
    if cmd == "/op list":
        return handle_op_list()
    if cmd == "/op status":
        return handle_op_status()
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
        # /models list [outer-provider] [BedRockProvider]
        # e.g. /models list bedrock Anthropic
        from core.config import get
        active = get("active_provider", "anthropic")
        if args and args[0].lower() in _PROVIDER_NAMES:
            outer = args[0].lower()
            bp    = args[1] if len(args) > 1 else None
        else:
            outer = active
            bp    = args[0] if args else None
        if outer == "bedrock" and bp:
            summaries, err = _bedrock_fetch(bp)
            if err:
                return [f"Bedrock error: {err}", "  Check credentials: /key set bedrock <ABSKQ...>"], False
            models = [{"id": m["modelId"], "name": m.get("modelName", "")}
                      for m in summaries if m.get("modelId")]
            if not models:
                return [f"No Bedrock models for provider {bp!r} — check credentials"], False
            lines = [f"AWS Bedrock — {bp} ({len(models)} models)", ""]
            for m in sorted(models, key=lambda x: x.get("id", "")):
                lines.append(f"  {m['id']}")
            lines += ["", "  Set: /agent set model global <model-id>"]
            return lines, True
        return handle_models_list(outer)
    if cmd == "/models providers":
        summaries, err = _bedrock_fetch()
        if err:
            return [f"Bedrock error: {err}", "", "  Check credentials: /key set bedrock <ABSKQ...>  or configure ~/.aws"], False
        providers  = sorted(set(m.get("providerName", "") for m in summaries if m.get("providerName")))
        lines = ["Bedrock model providers  [live from API]", ""]
        if providers:
            lines += [f"  {p}" for p in providers]
            lines += ["", "  List models: /models list bedrock <Provider>"]
        else:
            lines.append("  [dim](none — check credentials: /key set bedrock ABSKQ...)[/dim]")
        return lines, bool(providers)
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
