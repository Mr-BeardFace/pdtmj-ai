"""Settings registry — the single declarative catalogue of operator-tunable config.

Every flat, scalar setting the operator can change at runtime lives here as one
`Setting` row (key, friendly label, type, group, description, validation). The
`/config` command renders, validates, and writes straight from this table, and
`/info` derives its rows from it — so a new setting becomes listable, settable,
validated, tab-completable, and visible in /info by adding ONE row here.

Defaults are NOT duplicated — they're read from core.config._DEFAULTS, the single
source of truth, so this table can never drift from the real default.

Out of scope on purpose (owned by their own commands or not a flat scalar):
  - models + PER-AGENT temperatures (global_model, agent_models, agent_temperatures) → /agent
    (the global `temp` baseline IS here, as a flat scalar)
  - provider / base URL (active_provider, local_base_url) → /provider
  - list-valued keys (nudge_exempt_tools, kill_exempt_tools) → config file
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core import config

_ON_WORDS  = ("on", "true", "enable", "enabled", "yes", "1")
_OFF_WORDS = ("off", "false", "disable", "disabled", "no", "0")
_NULL_WORDS = ("null", "none", "-", "default")


_OPS = ("pentest", "redteam")   # ops-only personas
# empty personas tuple on a Setting means "all personas"


@dataclass(frozen=True)
class Setting:
    key:    str
    label:  str                 # friendly name shown in /info
    group:  str
    type:   str                 # "bool" | "int" | "str"
    desc:   str
    info_static: bool = False   # always show in /info (else: only when != default)
    minimum: float | None = None  # numeric floor (inclusive)
    maximum: float | None = None  # numeric ceiling (inclusive), float only
    allow_null: bool = False    # int/str/float may be null
    choices: tuple = field(default_factory=tuple)  # str enum, for completion/validation
    personas: tuple = field(default_factory=tuple)  # empty = all; else restrict to listed personas

    @property
    def default(self):
        return config._DEFAULTS.get(self.key)

    def allowed_for(self, persona: str) -> bool:
        return not self.personas or persona in self.personas


# ── The catalogue ────────────────────────────────────────────────────────────────
SETTINGS: tuple[Setting, ...] = (
    # Engagement — ops only
    Setting("exploitation",   "Exploitation",    "Engagement", "bool",
            "Run the plan → exploit → validate phase", info_static=True, personas=_OPS),
    Setting("confirm_exploit","Confirm exploit",  "Engagement", "bool",
            "Ask before each exploit action", info_static=True, personas=_OPS),
    Setting("tool_gate",      "Tool gate",        "Engagement", "str",
            "autonomous = run high-impact tools freely; gated = confirm before each high-impact tool call",
            info_static=True, choices=("autonomous", "gated"), personas=_OPS),
    Setting("validation",     "Validation pass",  "Engagement", "bool",
            "Dedicated agent independently reproduces each finding", personas=_OPS),
    Setting("package_install","Package install",  "Engagement", "bool",
            "Let agents pip/apt-install missing tooling", personas=_OPS),
    Setting("enum_turns",     "Enum turns/pass",  "Engagement", "int",
            "Turn budget for each staged enumeration pass", minimum=1, personas=_OPS),
    Setting("sliding_turns",  "Extend turns on progress", "Engagement", "bool",
            "Treat the turn budget as a sliding window reset by progress", personas=_OPS),
    Setting("turn_ceiling_factor", "Turn ceiling factor", "Engagement", "int",
            "Absolute turn ceiling = max_turns × this", minimum=1, personas=_OPS),
    # Engagement — all personas
    Setting("reporting",   "Reporting",      "Engagement", "bool",
            "Run the report-writer agent at engagement end", info_static=True),
    Setting("web_search",  "Web research",   "Engagement", "bool",
            "Allow the web_search + fetch_url tools"),
    Setting("agent_turns", "Max turns/agent","Engagement", "int",
            "Per-agent turn budget (0 = unlimited)", minimum=0),
    Setting("temp", "Temperature", "Engagement", "float",
            "Sampling temperature baseline, 0=focused … 1=varied (null=provider default; "
            "some models e.g. newer Opus reject it and it's dropped automatically). "
            "Per-agent overrides live in /agent set temp.",
            minimum=0.0, maximum=2.0, allow_null=True),

    # Parallelism — ops only
    Setting("parallel",          "Parallel",               "Parallelism", "bool",
            "Work independent surfaces + hypotheses concurrently", personas=_OPS),
    Setting("parallel_agents",   "Max parallel agents",    "Parallelism", "int",
            "Global cap on concurrent agent loops", minimum=1, personas=_OPS),
    Setting("surface_fanout",    "Surface fanout",         "Parallelism", "int",
            "Surfaces worked at once (1 = serial)", minimum=1, personas=_OPS),
    Setting("hypothesis_fanout", "Hypothesis fanout",      "Parallelism", "int",
            "Hypotheses proved/refuted at once per surface (1 = serial)", minimum=1, personas=_OPS),
    Setting("hypothesis_turns",  "Hypothesis worker turns","Parallelism", "int",
            "Per-worker turn budget for one prove/refute hypothesis", minimum=1, personas=_OPS),

    # Loop backstops — ops only
    Setting("cycles_per_surface",    "Cycles per surface",    "Loop backstops", "int",
            "Cap on enum→exploit cycles for one surface (null = off)", minimum=0, allow_null=True, personas=_OPS),
    Setting("dry_cycles_per_surface","Dry cycles per surface","Loop backstops", "int",
            "Stop a surface after N cycles with no new finding (0 = off)", minimum=0, personas=_OPS),
    Setting("total_cycles",          "Total cycles",          "Loop backstops", "int",
            "Global cycle backstop across all surfaces (null = unlimited)", minimum=0, allow_null=True, personas=_OPS),
    Setting("surfaces",              "Max surfaces",          "Loop backstops", "int",
            "Cap on surfaces investigated (null = unlimited)", minimum=0, allow_null=True, personas=_OPS),
    Setting("frontier_actions",      "Frontier max actions",  "Loop backstops", "int",
            "Max leads worked before stopping (null = use total cycles)", minimum=0, allow_null=True, personas=_OPS),
    Setting("frontier_attempts",     "Frontier attempts cap", "Loop backstops", "int",
            "Times a single lead is re-worked before it's exhausted", minimum=1, personas=_OPS),

    # Nudges — ops only
    Setting("repeat_nudge", "Repeat nudge",       "Nudges", "int",
            "Flag a tool call repeated N times as a loop (0 = off)", minimum=0, personas=_OPS),
    Setting("pivot_nudge",  "Pivot nudge",        "Nudges", "int",
            "Nudge to pivot after N consecutive failures (0 = off)", minimum=0, personas=_OPS),
    Setting("reuse_nudge",  "Script reuse nudge", "Nudges", "int",
            "Remind to reuse scripts after N writes without list_scripts (0 = off)", minimum=0, personas=_OPS),
    Setting("grind_nudge",  "Grind nudge",        "Nudges", "int",
            "Flag a grind after N scripts with no banked finding (0 = off)", minimum=0, personas=_OPS),

    # Routing — all personas
    Setting("llm_routing",  "LLM routing",  "Routing", "bool",
            "Pick specialist agents with a model vs keyword heuristics"),
    Setting("router_model", "Router model", "Routing", "str",
            "Model id used for routing (null = small default)", allow_null=True),

    # Diagnostics — all personas
    Setting("debug", "Debug capture", "Diagnostics", "bool",
            "Capture full LLM request/response/command transcript to llm_debug.log"),

    # Cracking — ops only
    Setting("hashcat_wordlist", "Hashcat wordlist", "Cracking", "str",
            "Wordlist path for hashcat jobs", personas=_OPS),
    Setting("hashcat_rules",    "Hashcat rules",    "Cracking", "str",
            "Rules file for hashcat jobs", personas=_OPS),
    Setting("hashcat_binary",   "Hashcat binary",   "Cracking", "str",
            "hashcat executable name or path", personas=_OPS),
)

_BY_KEY: dict[str, Setting] = {s.key: s for s in SETTINGS}
# Groups in first-seen order (stable, matches the catalogue layout above).
GROUPS: tuple[str, ...] = tuple(dict.fromkeys(s.group for s in SETTINGS))


def get_setting(key: str) -> Setting | None:
    return _BY_KEY.get(key)


def all_keys() -> tuple[str, ...]:
    return tuple(_BY_KEY)


def settings_for_persona(persona: str) -> tuple[Setting, ...]:
    return tuple(s for s in SETTINGS if s.allowed_for(persona))


def groups_for_persona(persona: str) -> tuple[str, ...]:
    visible = settings_for_persona(persona)
    return tuple(dict.fromkeys(s.group for s in visible))


def settings_in_group(group: str, persona: str | None = None) -> list[Setting]:
    g = group.lower()
    return [s for s in SETTINGS if s.group.lower() == g and (persona is None or s.allowed_for(persona))]


def current_value(s: Setting, persona: str | None = None):
    return config.get(s.key, s.default, persona=persona)


def is_changed(s: Setting) -> bool:
    return current_value(s) != s.default


def format_value(value) -> str:
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if value is None:
        return "—"
    return str(value)


def coerce(s: Setting, raw: str):
    """Parse + validate a raw string for this setting. Returns (value, error). On
    success error is None; on failure value is None and error is a message."""
    raw = raw.strip()
    if s.type == "bool":
        low = raw.lower()
        if low in _ON_WORDS:
            return True, None
        if low in _OFF_WORDS:
            return False, None
        return None, f"{s.key} expects on|off (got {raw!r})."

    if s.allow_null and raw.lower() in _NULL_WORDS:
        return None, None

    if s.type == "int":
        try:
            n = int(raw)
        except ValueError:
            return None, f"{s.key} expects an integer{' or null' if s.allow_null else ''} (got {raw!r})."
        if s.minimum is not None and n < s.minimum:
            return None, f"{s.key} must be ≥ {s.minimum} (got {n})."
        return n, None

    if s.type == "float":
        try:
            f = float(raw)
        except ValueError:
            return None, f"{s.key} expects a number{' or null' if s.allow_null else ''} (got {raw!r})."
        if s.minimum is not None and f < s.minimum:
            return None, f"{s.key} must be ≥ {s.minimum} (got {f})."
        if s.maximum is not None and f > s.maximum:
            return None, f"{s.key} must be ≤ {s.maximum} (got {f})."
        return f, None

    # str
    if s.choices and raw not in s.choices:
        return None, f"{s.key} must be one of: {', '.join(s.choices)}."
    return raw, None
