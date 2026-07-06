from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "confirm_exploit": True,
    # Master switch for the exploitation phase (plan → exploit → validate). On by
    # default for all personas; toggle with /config exploitation on|off.
    "exploitation": True,
    # Master switch for the reporting phase (the report-writer agent + HTML). On by
    # default; toggle with /config reporting on|off. Off is handy during testing so a run
    # doesn't spend tokens/time synthesizing a report — `/report` still generates
    # one on demand, and findings/state are saved either way.
    "reporting": True,
    "global_model": None,
    # Per-agent turn budget (one LLM round = one turn). 0 = unlimited (no cap —
    # an agent runs until it stops on its own; use with care, it can run long).
    # Change at runtime with /config agent_turns <n> (0 = unlimited).
    "agent_turns": 60,
    # Treat the turn budget as a SLIDING "turns since last progress" window rather
    # than a hard total: every turn that banks a finding/credential/flag, catches a
    # reverse shell, or drives a command on one resets the counter, so an agent is
    # never killed in the MIDDLE of a working exploit. An absolute ceiling
    # (max_turns × max_turns_progress_factor) still bounds a runaway. Off → the old
    # hard cap.
    "sliding_turns": True,
    "turn_ceiling_factor": 5,
    # Turn budget for each STAGED enumeration pass (service-ID, per-surface enum,
    # re-enum). Separate from agent_turns: enumeration mostly GATHERS intel
    # and rarely banks a finding/cred, so the progress-extension window never kicks
    # in — it just runs into this cap. Raise it if enum keeps stopping short.
    "enum_turns": 20,
    "agent_models": {},
    # ── Sampling temperature (0 = focused/deterministic, 1 = the provider default,
    # more varied/creative) ───────────────────────────────────────────────────────
    # Lower suits methodical, tool-heavy work and reproducibility; a little higher
    # helps an agent break out of a rut. `temp` applies to every agent unless overridden
    # in `agent_temperatures` (by exact agent name, or "global" for all). null anywhere →
    # fall through to the provider default. Some models (newer Opus) reject temperature —
    # it's detected and dropped automatically for those (see llm_client).
    "temp": 0.4,
    "agent_temperatures": {
        "pentest/report": 0.2,   # write-ups: consistent, factual, minimal drift
        # rce + everything else use the `temp` baseline (0.4)
    },
    "active_provider": "anthropic",  # "anthropic" | "openrouter" | "nvidia"
    # ── Methodology loop ──────────────────────────────────────────────────────
    # The engagement cycles Enum→Plan→Exploit→Validate per surface until a cycle
    # produces no new intel (exhaustion). These are safety backstops only — set
    # to null to disable. They exist to stop a pathological non-converging loop,
    # not to drive normal termination.
    "cycles_per_surface": 4,   # cap on cycles for a single surface
    # Stop re-cycling a surface after this many consecutive cycles that produce NO
    # new verified finding — tighter than the cycle cap, overrides the LLM judge's
    # optimism, and kills the "grind a dead surface" loop. 0 disables.
    "dry_cycles_per_surface": 2,
    "total_cycles": 40,        # global backstop across all surfaces (null = unlimited)
    "surfaces": 50,            # cap on surfaces investigated (null = unlimited)

    # ── Parallel hypothesis search ────────────────────────────────────────────
    # Master switch. OFF → the engagement runs exactly as before (one surface,
    # one agent at a time). ON → independent surfaces are worked concurrently and
    # the exploit phase fans out bounded "prove or refute" workers across the top
    # plan items, first solve cancelling the rest. Toggle with /config parallel on|off.
    "parallel": False,
    # Global ceiling on concurrent LLM agent loops, shared across BOTH parallel
    # layers (surfaces × hypotheses) so nesting can't multiply into a quota
    # blowout. K parallel agents hit the account rate limit ~K× faster — keep this
    # modest (3–4) on a single API key.
    "parallel_agents": 3,
    # How many independent surfaces to work concurrently per wave (still bounded
    # by parallel_agents). 1 → surfaces stay serial even with parallel on.
    "surface_fanout": 3,
    # How many ranked plan items (hypotheses) to prove/refute concurrently inside
    # one surface's exploit phase. 1 → the exploit phase stays single-agent.
    "hypothesis_fanout": 3,
    # Hard per-worker turn budget for a prove/refute hypothesis worker. A worker
    # gathers just enough to CONFIRM or REFUTE its one hypothesis, then stops —
    # this is the structural cure for the 100+ attempt grind (a worker cannot
    # grind past its budget by construction). Separate from agent_turns.
    "hypothesis_turns": 12,

    # ── Frontier control (lead-driven, objective-first) ───────────────────────
    # The driver works the single highest-value lead toward the objective,
    # advancing the frontier on a confirm and releasing a lead on a dead end.
    # These two keys are budget backstops only — the objective is the normal stop
    # condition, not these.
    #
    # Max leads worked (one agent run each) before stopping. null → total_cycles.
    "frontier_actions": None,
    # How many times a single unresolved lead is re-worked before it's exhausted and
    # released. Bounds grind on an inconclusive thread.
    "frontier_attempts": 3,

    # Post-exploitation validation pass. Off by default: the exploitation phase
    # already requires evidence and sets verified on its findings, so a separate
    # agent re-reproducing every finding per surface is largely a duplicate run.
    # Set true to have a dedicated agent independently reproduce each finding.
    "validation": False,

    # ── LLM-driven control (vs deterministic heuristics) ──────────────────────
    # When on, a fast model picks which specialist agent handles each slot
    # (enumeration/exploitation) instead of a keyword map; the keyword map stays
    # as the fallback. router_model null → a small default (Haiku).
    "llm_routing": True,
    "router_model": None,
    # Loop nudge: when an agent repeats an identical tool call this many times
    # without new results, inject a "step back" notice instead of letting it spin
    # (a soft redirect; max_turns is still the hard stop). 0 disables.
    "repeat_nudge": 3,
    # Tools exempt from the loop nudge — ones that are *meant* to be called
    # repeatedly with identical args (polling for OOB callbacks, background-job
    # completion, a reverse shell connecting back, or a run_daemon capturing hashes).
    # Repeating these is normal operation, not a stuck loop, so they never nudge.
    "nudge_exempt_tools": ["oob_listener", "check_jobs", "list_shells", "wait", "run_daemon"],
    # Pivot nudge: after this many CONSECUTIVE failed/empty tool results (errors or
    # non-zero exit codes), tell the agent it may be on a dead end — bank what it
    # has and change approach. Catches the "retry near-identical thing forever"
    # spiral that the exact-match loop nudge misses. 0 disables.
    "pivot_nudge": 4,
    # Reuse nudge: once this many run_script scripts have been written ACROSS the
    # engagement without ever calling list_scripts, remind the agent to reuse/adapt
    # instead of rewriting near-duplicates. 0 disables.
    "reuse_nudge": 10,
    # Grind nudge: this many run_script calls across the engagement WITHOUT banking
    # a new finding/credential/flag means a no-progress grind (the 100+ decrypt-loop
    # pattern). Nudge to bank results and pivot. Engagement-level so it survives the
    # agent cycling that resets per-run counters. 0 disables.
    "grind_nudge": 12,
    # Foothold capitalization. Two engagement-level nudges once code execution is
    # confirmed (an id/whoami readback, a caught shell, a driven shell_exec):
    #  • bank: turns before nudging to annotate the foothold as a verified finding.
    #  • capitalize: turns of exec-confirmed-but-nothing-extracted before nudging to
    #    loot it (flag/creds/privesc) with the primitive already in hand. Cleared by
    #    looted creds/flags or a stable channel — not by chasing a shell. Re-fires
    #    every `repeat` turns until something lands. 0 disables either nudge.
    "foothold_bank_nudge_after_turns": 2,
    "foothold_capitalize_nudge_after_turns": 3,
    "foothold_capitalize_repeat_turns": 5,
    # Tools exempt from the bulk /abort kill — ones where terminating a process
    # mid-flight is riskier than letting it finish (a package transaction can
    # corrupt the dpkg/pip state). /abort leaves these running; a targeted
    # /job kill <id> still works if you explicitly choose to stop one.
    "kill_exempt_tools": ["apt_install", "pip_install"],

    # Allow agents to use web_search / fetch_url (DuckDuckGo) for general product /
    # technology / CVE research. Queries are scrubbed against engagement state so target
    # IPs/hostnames/credentials never leave the box; set false to forbid ALL external
    # web calls (air-gapped or strict-OPSEC engagements).
    "web_search": True,

    # Let agents self-provision missing tooling (pip_install / apt_install).
    # Kill switch for operators who don't want the engagement touching the host's
    # packages. On by default — the agent runs on your authorized test box.
    "package_install": True,

    # Full-transcript debug capture (off unless /config debug on). Writes
    # every LLM request/response/command to llm_debug.log in the engagement dir.
    "debug": False,

    # ── hashcat (offline cracking, runs as a background job) ──────────────────
    "hashcat_wordlist": "/usr/share/wordlists/rockyou.txt",
    "hashcat_rules": "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
    "hashcat_binary": "hashcat",
}

# Old→new config-key renames (2026-07-02, terse-key pass). A config.yaml written
# before the rename is migrated on first load: the old key's value moves to the new
# key and the file is rewritten once, so tuned overrides aren't silently lost.
_KEY_ALIASES: dict[str, str] = {
    "exploitation_enabled": "exploitation",
    "confirm_exploitation": "confirm_exploit",
    "reporting_enabled": "reporting",
    "allow_web_search": "web_search",
    "allow_package_install": "package_install",
    "validation_enabled": "validation",
    "max_turns_default": "agent_turns",
    "enum_stage_turns": "enum_turns",
    "parallel_enabled": "parallel",
    "max_parallel_agents": "parallel_agents",
    "hypothesis_worker_turns": "hypothesis_turns",
    "extend_turns_on_progress": "sliding_turns",
    "max_turns_progress_factor": "turn_ceiling_factor",
    "max_cycles_per_surface": "cycles_per_surface",
    "max_dry_cycles_per_surface": "dry_cycles_per_surface",
    "max_total_cycles": "total_cycles",
    "max_surfaces": "surfaces",
    "frontier_max_actions": "frontier_actions",
    "frontier_attempts_cap": "frontier_attempts",
    "repeat_nudge_threshold": "repeat_nudge",
    "pivot_nudge_after_failures": "pivot_nudge",
    "run_script_volume_nudge": "reuse_nudge",
    "grind_nudge_after_scripts": "grind_nudge",
    "debug_capture": "debug",
    "temperature_default": "temp",
}

# Mtime-based cache — avoids a YAML parse on every get() call.
_cache: dict[str, Any] | None = None
_cache_mtime: float = 0.0


def _migrate_keys(data: dict[str, Any]) -> bool:
    """Rename any old keys in a loaded config dict in place. Returns True if anything
    changed (the on-disk file then needs a one-time rewrite)."""
    changed = False
    for old, new in _KEY_ALIASES.items():
        if old in data:
            if new not in data:
                data[new] = data[old]
            del data[old]
            changed = True
    return changed


def _raw_load() -> tuple[dict[str, Any], bool]:
    cfg = dict(_DEFAULTS)
    migrated = False
    if _CONFIG_PATH.exists():
        data = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
        migrated = _migrate_keys(data)
        cfg.update(data)
    return cfg, migrated


def load_config() -> dict[str, Any]:
    global _cache, _cache_mtime
    try:
        mtime = _CONFIG_PATH.stat().st_mtime if _CONFIG_PATH.exists() else 0.0
    except OSError:
        mtime = 0.0
    if _cache is not None and mtime == _cache_mtime:
        return dict(_cache)
    cfg, migrated = _raw_load()
    if migrated:
        save_config(cfg)     # one-time rewrite with the new key names
        try:
            mtime = _CONFIG_PATH.stat().st_mtime
        except OSError:
            pass
    _cache = cfg
    _cache_mtime = mtime
    return dict(_cache)


def save_config(cfg: dict[str, Any]) -> None:
    global _cache, _cache_mtime
    _CONFIG_PATH.write_text(
        yaml.dump(cfg, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    # Invalidate cache so the next read picks up the write.
    _cache = None
    _cache_mtime = 0.0


def get(key: str, default: Any = None) -> Any:
    return load_config().get(key, default)


def set_value(key: str, value: Any) -> None:
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)


def get_model_for_agent(agent_name: str) -> str | None:
    """Return a config-level model override for the given agent, or None."""
    overrides: dict = load_config().get("agent_models", {})
    return overrides.get(agent_name)


def get_global_model() -> str | None:
    """Return the global model override.

    Checks agent_models["global"] (set via /agent set model global ...) first,
    then the top-level global_model key documented in config.yaml.
    """
    cfg = load_config()
    overrides: dict = cfg.get("agent_models", {})
    return overrides.get("global") or cfg.get("global_model")


def get_temperature_for_agent(agent_name: str) -> float | None:
    """Resolve the sampling temperature for an agent: an exact per-agent override in
    `agent_temperatures`, else a `global` override there, else the `temp` baseline.
    Returns None to mean 'use the provider default' (no temperature sent)."""
    cfg = load_config()
    per: dict = cfg.get("agent_temperatures", {}) or {}
    if agent_name in per:
        return per[agent_name]
    if "global" in per:
        return per["global"]
    return cfg.get("temp")
