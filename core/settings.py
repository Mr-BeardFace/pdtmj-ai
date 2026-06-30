"""Settings registry — the single declarative catalogue of operator-tunable config.

Every flat, scalar setting the operator can change at runtime lives here as one
`Setting` row (key, friendly label, type, group, description, validation). The
`/config` command renders, validates, and writes straight from this table, and
`/info` derives its rows from it — so a new setting becomes listable, settable,
validated, tab-completable, and visible in /info by adding ONE row here.

Defaults are NOT duplicated — they're read from core.config._DEFAULTS, the single
source of truth, so this table can never drift from the real default.

Out of scope on purpose (owned by their own commands or not a flat scalar):
  - models / temperatures (global_model, agent_models, temperature_default) → /agent
  - provider / base URL (active_provider, local_base_url) → /provider
  - list-valued keys (nudge_exempt_tools, kill_exempt_tools) → config file
"""
from __future__ import annotations

from dataclasses import dataclass, field

from core import config

_ON_WORDS  = ("on", "true", "enable", "enabled", "yes", "1")
_OFF_WORDS = ("off", "false", "disable", "disabled", "no", "0")
_NULL_WORDS = ("null", "none", "-", "default")


@dataclass(frozen=True)
class Setting:
    key:    str
    label:  str                 # friendly name shown in /info
    group:  str
    type:   str                 # "bool" | "int" | "str"
    desc:   str
    info_static: bool = False   # always show in /info (else: only when != default)
    minimum: int | None = None  # int floor (inclusive)
    allow_null: bool = False    # int/str may be null
    choices: tuple = field(default_factory=tuple)  # str enum, for completion/validation

    @property
    def default(self):
        return config._DEFAULTS.get(self.key)


# ── The catalogue ────────────────────────────────────────────────────────────────
SETTINGS: tuple[Setting, ...] = (
    # Engagement
    Setting("exploitation_enabled", "Exploitation", "Engagement", "bool",
            "Run the plan → exploit → validate phase", info_static=True),
    Setting("confirm_exploitation", "Confirm exploit", "Engagement", "bool",
            "Ask before each exploit action", info_static=True),
    Setting("reporting_enabled", "Reporting", "Engagement", "bool",
            "Run the report-writer agent at engagement end", info_static=True),
    Setting("allow_web_search", "Web research", "Engagement", "bool",
            "Allow the web_search + fetch_url tools"),
    Setting("allow_package_install", "Package install", "Engagement", "bool",
            "Let agents pip/apt-install missing tooling"),
    Setting("validation_enabled", "Validation pass", "Engagement", "bool",
            "Dedicated agent independently reproduces each finding"),
    Setting("max_turns_default", "Max turns/agent", "Engagement", "int",
            "Per-agent turn budget (0 = unlimited)", minimum=0),
    Setting("enum_stage_turns", "Enum turns/pass", "Engagement", "int",
            "Turn budget for each staged enumeration pass", minimum=1),

    # Parallelism
    Setting("parallel_enabled", "Parallel", "Parallelism", "bool",
            "Work independent surfaces + hypotheses concurrently"),
    Setting("max_parallel_agents", "Max parallel agents", "Parallelism", "int",
            "Global cap on concurrent agent loops", minimum=1),
    Setting("surface_fanout", "Surface fanout", "Parallelism", "int",
            "Surfaces worked at once (1 = serial)", minimum=1),
    Setting("hypothesis_fanout", "Hypothesis fanout", "Parallelism", "int",
            "Hypotheses proved/refuted at once per surface (1 = serial)", minimum=1),
    Setting("hypothesis_worker_turns", "Hypothesis worker turns", "Parallelism", "int",
            "Per-worker turn budget for one prove/refute hypothesis", minimum=1),

    # Turn budget
    Setting("extend_turns_on_progress", "Extend turns on progress", "Turn budget", "bool",
            "Treat the turn budget as a sliding window reset by progress"),
    Setting("max_turns_progress_factor", "Turn ceiling factor", "Turn budget", "int",
            "Absolute turn ceiling = max_turns × this", minimum=1),

    # Loop backstops
    Setting("max_cycles_per_surface", "Cycles per surface", "Loop backstops", "int",
            "Cap on enum→exploit cycles for one surface (null = off)", minimum=0, allow_null=True),
    Setting("max_dry_cycles_per_surface", "Dry cycles per surface", "Loop backstops", "int",
            "Stop a surface after N cycles with no new finding (0 = off)", minimum=0),
    Setting("max_total_cycles", "Total cycles", "Loop backstops", "int",
            "Global cycle backstop across all surfaces (null = unlimited)", minimum=0, allow_null=True),
    Setting("max_surfaces", "Max surfaces", "Loop backstops", "int",
            "Cap on surfaces investigated (null = unlimited)", minimum=0, allow_null=True),
    Setting("frontier_max_actions", "Frontier max actions", "Loop backstops", "int",
            "Max leads worked before stopping (null = use total cycles)", minimum=0, allow_null=True),
    Setting("frontier_attempts_cap", "Frontier attempts cap", "Loop backstops", "int",
            "Times a single lead is re-worked before it's exhausted", minimum=1),

    # Nudges
    Setting("repeat_nudge_threshold", "Repeat nudge", "Nudges", "int",
            "Flag a tool call repeated N times as a loop (0 = off)", minimum=0),
    Setting("pivot_nudge_after_failures", "Pivot nudge", "Nudges", "int",
            "Nudge to pivot after N consecutive failures (0 = off)", minimum=0),
    Setting("run_script_volume_nudge", "Script reuse nudge", "Nudges", "int",
            "Remind to reuse scripts after N writes without list_scripts (0 = off)", minimum=0),
    Setting("grind_nudge_after_scripts", "Grind nudge", "Nudges", "int",
            "Flag a grind after N scripts with no banked finding (0 = off)", minimum=0),

    # Routing
    Setting("llm_routing", "LLM routing", "Routing", "bool",
            "Pick specialist agents with a model vs keyword heuristics"),
    Setting("router_model", "Router model", "Routing", "str",
            "Model id used for routing (null = small default)", allow_null=True),

    # Diagnostics
    Setting("debug_capture", "Debug capture", "Diagnostics", "bool",
            "Capture full LLM request/response/command transcript to llm_debug.log"),

    # Cracking
    Setting("hashcat_wordlist", "Hashcat wordlist", "Cracking", "str",
            "Wordlist path for hashcat jobs"),
    Setting("hashcat_rules", "Hashcat rules", "Cracking", "str",
            "Rules file for hashcat jobs"),
    Setting("hashcat_binary", "Hashcat binary", "Cracking", "str",
            "hashcat executable name or path"),
)

_BY_KEY: dict[str, Setting] = {s.key: s for s in SETTINGS}
# Groups in first-seen order (stable, matches the catalogue layout above).
GROUPS: tuple[str, ...] = tuple(dict.fromkeys(s.group for s in SETTINGS))


def get_setting(key: str) -> Setting | None:
    return _BY_KEY.get(key)


def all_keys() -> tuple[str, ...]:
    return tuple(_BY_KEY)


def settings_in_group(group: str) -> list[Setting]:
    g = group.lower()
    return [s for s in SETTINGS if s.group.lower() == g]


def current_value(s: Setting):
    return config.get(s.key, s.default)


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

    # str
    if s.choices and raw not in s.choices:
        return None, f"{s.key} must be one of: {', '.join(s.choices)}."
    return raw, None
