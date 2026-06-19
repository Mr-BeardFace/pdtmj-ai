from __future__ import annotations

import json
import re
import uuid
from core.timeutil import now_local
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import EngagementRun

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Evidence keys that hold a verbatim artifact (raw HTTP request/response, a
# command, tool output, a PoC) — rendered as a labelled raw text block rather
# than JSON. The first group is also pulled to the top, in this order, so a
# reader sees request → response the way they'd read a proxy capture.
_EVIDENCE_PRIORITY = (
    "request", "raw_request", "http_request",
    "response", "raw_response", "http_response",
)
_EVIDENCE_RAW_KEYS = set(_EVIDENCE_PRIORITY) | {
    "curl", "command", "cmd", "output", "stdout", "stderr",
    "payload", "poc", "proof", "proof_of_concept", "exploit", "log", "script",
}


def evidence_blocks(evidence) -> list[dict]:
    """Turn a finding's free-form evidence dict into ordered, render-ready blocks.

    Raw request/response (and any multiline / long string value) become verbatim
    text blocks so they read like a captured transcript instead of escaped JSON;
    short scalars stay inline as label: value; nested structures stay JSON. Request
    and response are surfaced first. Returns [{label, kind, text}] where kind is
    'raw' | 'inline' | 'json'."""
    if not isinstance(evidence, dict) or not evidence:
        return []

    def _rank(item) -> int:
        k = str(item[0]).lower()
        return _EVIDENCE_PRIORITY.index(k) if k in _EVIDENCE_PRIORITY else len(_EVIDENCE_PRIORITY)

    blocks: list[dict] = []
    for key, val in sorted(evidence.items(), key=_rank):  # stable: keeps original order within a rank
        label = str(key).replace("_", " ").strip().title()
        kl = str(key).lower()
        if isinstance(val, (dict, list)):
            blocks.append({"label": label, "kind": "json",
                           "text": json.dumps(val, indent=2)})
        elif isinstance(val, str):
            if "\n" in val or kl in _EVIDENCE_RAW_KEYS or len(val) > 100:
                blocks.append({"label": label, "kind": "raw", "text": val})
            else:
                blocks.append({"label": label, "kind": "inline", "text": val})
        else:
            blocks.append({"label": label, "kind": "inline", "text": str(val)})
    return blocks


def narrative_blocks(text) -> list[dict]:
    """Split a narrative string (technical details) into render-ready segments so
    fenced ``` code blocks (embedded working scripts/payloads) render as formatted
    code instead of being flattened into prose paragraphs. Returns ordered
    [{kind, content, lang}] where kind is 'text' | 'code'."""
    if not text or not isinstance(text, str):
        return []
    blocks: list[dict] = []
    parts = text.split("```")
    last = len(parts) - 1
    for i, part in enumerate(parts):
        # An odd-indexed part is a fenced code block ONLY if a closing fence follows.
        # If the fences are unbalanced (an agent left one open), the final part is the
        # unclosed remainder — render it as prose, not an endless code block, so a
        # stray ``` can't make the rest of the write-up "append into" one code section.
        if i % 2 == 1 and i != last:         # inside a properly-closed fenced block
            first, _, rest = part.partition("\n")
            lang = first.strip() if first.strip() and " " not in first.strip() else ""
            code = (rest if lang or first.strip() == "" else part).strip("\n")
            blocks.append({"kind": "code", "lang": lang, "content": code})
        else:                                # prose between fences → paragraphs
            for para in re.split(r"\n\s*\n", part):
                p = para.strip()
                if not p:
                    continue
                # A lone "## ..." line is a stitched phase heading (see _stitch_overviews).
                if p.startswith("## ") and "\n" not in p:
                    blocks.append({"kind": "heading", "lang": "", "content": p[3:].strip()})
                else:
                    blocks.append({"kind": "text", "lang": "", "content": p})
    return blocks


# ── auto-captured "screenshots" (engine-filled [IMAGE: …] markers) ─────────────
# Agents mark evidence points in the narrative with [IMAGE: <what it should show>].
# Rather than leave a placeholder for a human to paste a screenshot, the engine
# fills each marker with the REAL tool command + captured output from the run — its
# own "screenshot" — wherever a matching tool call exists. Unmatched markers (a
# purely manual visual) are dropped.
_IMAGE_MARKER_RE = re.compile(r"\[IMAGE:\s*(.*?)\]", re.IGNORECASE | re.DOTALL)

# Generic words that don't help tie a marker description to a specific tool call.
_CAPTURE_STOPWORDS = {
    "image", "screenshot", "showing", "shows", "output", "result", "results", "the",
    "and", "from", "with", "page", "via", "for", "that", "this", "into", "onto",
    "capture", "display", "displaying", "confirming", "confirm", "confirmed",
    "request", "response", "screen", "view", "where", "which", "after", "before",
    "above", "below", "here", "showing",
}

# Output fields to surface as the "terminal" text of a capture, in priority order.
# NOTE: stderr is deliberately excluded — it's almost always dependency/warning noise
# (e.g. urllib3 RequestsDependencyWarning), not evidence.
_CAPTURE_OUT_KEYS = ("stdout", "output", "decoded", "exfil", "body", "response",
                     "result", "note", "summary")

# Lines that are tooling noise, not evidence — stripped from a capture.
_CAPTURE_NOISE_RE = re.compile(
    r"RequestsDependencyWarning|warnings\.warn|site-packages|"
    r"doesn't match a supported version|InsecureRequestWarning", re.I)

# ANSI/VT escape sequences (colored script output) — stripped so a capture is plain.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_CAPTURE_OUT_CHARS = 460      # hard cap on a capture's output excerpt
_CAPTURE_OUT_LINES = 12       # …and on its line count


def _significant_tokens(desc: str) -> list[str]:
    """Distinctive tokens from a marker description used to find the tool call that
    produced what it describes. Keeps specific strings (uid=1000(wingftp), dir.html,
    a hostname, a version) and drops generic prose."""
    toks = re.findall(r"[a-z0-9][a-z0-9._=:/()@+-]{2,}", (desc or "").lower())
    seen: set[str] = set()
    out: list[str] = []
    for t in toks:
        strong = ("." in t) or any(c in t for c in "=(@/")   # dir.html, uid=1000(…), v7.4.3
        if (strong or (len(t) >= 4 and t not in _CAPTURE_STOPWORDS)) and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def _is_strong_token(t: str) -> bool:
    """A token distinctive enough that a single match is high-confidence — an
    identifier (uid=1000(wingftp)), a path/host (dir.html, ftp.wingdata.htb), a
    version, or anything long."""
    return any(c in t for c in "=()@/") or ("." in t and len(t) >= 6) or len(t) >= 10


def _clean_output(tc) -> str:
    """The denoised OUTPUT text of a tool call (no command, no inputs, no stderr,
    no dependency warnings) — this is what a capture is matched and rendered from, so
    a marker binds to the call that actually PRODUCED the result, not one whose script
    body merely mentions the same words."""
    out = getattr(tc, "output", None)
    if isinstance(out, dict):
        chunks = [out[k].strip() for k in _CAPTURE_OUT_KEYS
                  if isinstance(out.get(k), str) and out[k].strip()]
        if chunks:
            text = "\n".join(chunks)
        else:
            try:
                text = json.dumps({k: v for k, v in out.items()
                                   if not str(k).startswith("_")}, default=str)
            except Exception:
                text = str(out)
    else:
        text = "" if out is None else str(out)
    text = _ANSI_RE.sub("", text)
    lines = [ln for ln in text.splitlines() if not _CAPTURE_NOISE_RE.search(ln)]
    return "\n".join(lines).replace("```", "'''").strip()


def _window(text: str, tokens: list[str]) -> str:
    """A short excerpt of `text`, centered on the longest distinctive token present,
    capped to a handful of lines so a capture is a screenshot — not a dump."""
    if not text:
        return ""
    low = text.lower()
    here = sorted((t for t in (tokens or []) if len(t) >= 5 and t in low), key=len, reverse=True)
    start = max(0, low.index(here[0]) - 140) if here else 0
    seg = text[start:start + _CAPTURE_OUT_CHARS]
    if start > 0:
        seg = "…" + seg
    if start + _CAPTURE_OUT_CHARS < len(text):
        seg = seg + "…"
    ls = seg.splitlines()
    if len(ls) > _CAPTURE_OUT_LINES:
        seg = "\n".join(ls[:_CAPTURE_OUT_LINES]) + "\n…"
    return seg.strip()


def _best_capture(desc: str, calls: list):
    """The (command, output) of the tool call whose OUTPUT best matches a marker, or
    None. Matching is on output only (so a 'read the exploit file' call can't hijack a
    marker about the RCE's result), ranked by the longest distinctive token matched,
    then breadth. Requires a distinctive token OR two plain tokens IN THE OUTPUT."""
    tokens = _significant_tokens(desc)
    if not tokens:
        return None
    strong = {t for t in tokens if _is_strong_token(t)}
    best = None
    best_rank = (0, 0)
    for tc in calls:
        out_low = _clean_output(tc).lower()
        if not out_low:
            continue
        matched = [t for t in tokens if t in out_low]
        if not matched:
            continue
        longest_strong = max((len(t) for t in matched if t in strong), default=0)
        rank = (longest_strong, len(matched))   # distinctive match first, then breadth
        if rank > best_rank:
            best_rank, best = rank, tc
    if best is None or not (best_rank[0] or best_rank[1] >= 2):
        return None
    cmd = (getattr(best, "command_str", "") or getattr(best, "tool_name", "") or "").strip()
    out = _window(_clean_output(best), tokens)
    if not cmd and not out:
        return None
    return cmd, out


def embed_captures(overview, tool_calls) -> str:
    """Replace each [IMAGE: …] marker with the matching tool command + output as a
    fenced console block (the engine's own 'screenshot'); drop markers with no
    matching capture. Returns the rewritten narrative."""
    if not overview or "[image:" not in overview.lower():
        return overview or ""
    calls = list(tool_calls or [])
    seen: set = set()                       # collapse identical captures from reruns

    def _sub(m):
        desc = " ".join(m.group(1).split())
        cap = _best_capture(desc, calls)
        if not cap:
            return ""                       # manual-only visual → drop the placeholder
        cmd, out = cap
        # The same marker often recurs across an agent's reruns and binds to the same
        # call — render that capture once, drop the repeats.
        if (cmd, out) in seen:
            return ""
        seen.add((cmd, out))
        lines = []
        if desc:
            lines.append(f"# {desc}")
        if cmd:
            lines.append(f"$ {cmd}")
        if out:
            lines.append(out)
        return "\n\n```console\n" + "\n".join(lines) + "\n```\n\n"

    result = _IMAGE_MARKER_RE.sub(_sub, overview)
    return re.sub(r"\n{3,}", "\n\n", result).strip()


# (ended_early, explanatory text) for each way an engagement can stop. Drives the
# report's Limitations & Constraints section so a reader always knows whether the
# assessment finished and, if not, why.
_TERMINATION = {
    "completed":     (False, "The engagement ran to completion — the selected attack surfaces were "
                             "assessed and the objective pursued to a natural stopping point."),
    "ended_early":   (True,  "The engagement was ended early by the operator. Reporting was run on the "
                             "findings gathered up to that point, but exploitation of any remaining "
                             "surfaces was not pursued."),
    "paused":        (True,  "The engagement was paused by the operator before all surfaces were "
                             "exhausted. The findings below reflect the work completed up to the pause."),
    "cycle_cap":     (True,  "The engagement reached its configured cycle cap and stopped opening new "
                             "work. Some avenues may remain unexplored; raising the cap would allow a "
                             "deeper pass."),
    "account_limit": (True,  "The engagement was halted when the API account/usage limit was reached. "
                             "Work in progress at that moment — including any privilege-escalation or "
                             "post-exploitation steps underway — was not completed, and the full "
                             "write-up could not be synthesized, so sections may be incomplete."),
    "auth_failed":   (True,  "The engagement was halted by an API authentication failure. The findings "
                             "reflect only the work completed beforehand."),
}


def termination_note(reason: str):
    """Return (ended_early, text) for the report's Limitations section."""
    return _TERMINATION.get((reason or "completed"), _TERMINATION["completed"])


_NVD_CALCULATOR_BASE = "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator"


def nist_cvss_url(vector: str) -> str:
    """Deep-link a CVSS 3.x vector into the NVD calculator. NVD expects the vector
    WITHOUT the leading "CVSS:X.Y/" prefix, with the version passed separately."""
    from urllib.parse import quote
    v = (vector or "").strip()
    if not v:
        return _NVD_CALCULATOR_BASE
    version = "3.1" if "CVSS:3.1" in v else "3.0"
    stripped = v.removeprefix(f"CVSS:{version}/")
    return f"{_NVD_CALCULATOR_BASE}?vector={quote(stripped, safe=':./')}&version={version}"


_ENV: Environment | None = None


def _get_env() -> Environment:
    global _ENV
    if _ENV is None:
        template_dir = Path(__file__).parent / "templates"
        _ENV = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "htm"]),
        )
        _ENV.filters["tojson"] = lambda v, indent=None: json.dumps(v, indent=indent)
        _ENV.filters["evidence_blocks"] = evidence_blocks
        _ENV.filters["narrative_blocks"] = narrative_blocks
        _ENV.filters["nist_cvss_url"] = nist_cvss_url
    return _ENV


def _render(run: EngagementRun, fmt: str, output_dir: Path,
            persistence: list | None = None, termination: str = "completed") -> Path:
    output_dir.mkdir(exist_ok=True)
    env = _get_env()

    # Fill [IMAGE: …] evidence markers in the narrative with the real tool command +
    # output from this run's tool calls — the engine's own "screenshots" — wherever a
    # match exists. Idempotent (a second pass finds no markers).
    if run.technical_overview:
        run.technical_overview = embed_captures(run.technical_overview, run.tool_calls)

    findings_sorted = sorted(
        run.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )
    severity_counts = {
        sev: len([f for f in run.findings if f.severity == sev])
        for sev in ["critical", "high", "medium", "low", "info"]
    }
    generated_at = now_local().strftime("%Y-%m-%d %H:%M %Z")
    safe_target  = run.target.replace(".", "_").replace("/", "_").replace(":", "_")

    # The report-writer agent is what synthesizes an executive_summary; its absence
    # means this report was assembled from raw run data without that synthesis pass
    # (e.g. the engagement was paused/stopped before reporting). Flag it as a draft.
    is_draft = not (run.executive_summary or "").strip()
    ended_early, term_text = termination_note(termination)

    ctx = dict(
        run=run,
        findings=findings_sorted,
        severity_counts=severity_counts,
        generated_at=generated_at,
        persistence=persistence or [],
        is_draft=is_draft,
        limitations={"ended_early": ended_early, "text": term_text, "reason": termination},
    )

    if fmt == "html":
        template  = env.get_template("report.html.j2")
        out_path  = output_dir / f"report_{run.id}_{safe_target}.html"
    elif fmt == "markdown":
        template  = env.get_template("report.md.j2")
        out_path  = output_dir / f"report_{run.id}_{safe_target}.md"
    else:
        raise ValueError(f"Unsupported format: {fmt!r}")

    out_path.write_text(template.render(**ctx), encoding="utf-8")
    return out_path


def generate_report(run: EngagementRun, output_dir: Path, fmt: str = "html") -> Path:
    """Generate a report for a single EngagementRun."""
    return _render(run, fmt, output_dir)


def merge_runs(
    runs: list[EngagementRun],
    agent_name: str = "pipeline",
    target: str = "",
) -> EngagementRun:
    """Merge multiple EngagementRun objects into one for reporting.

    Findings are deduplicated by normalized title (IDs are per-run UUIDs and
    never collide, so ID-based dedup would keep cross-agent duplicates).
    When the same title appears in multiple runs, the verified copy wins.
    Tool call logs are concatenated and costs summed.
    """
    if not runs:
        raise ValueError("No runs to merge")

    merged = EngagementRun(
        id=str(uuid.uuid4())[:12],
        agent=agent_name,
        target=target or runs[0].target,
        start_time=runs[0].start_time,
        end_time=runs[-1].end_time or now_local(),
        status="complete",
        estimated_cost_usd=sum(r.estimated_cost_usd for r in runs),
        executive_summary=next((r.executive_summary for r in runs if r.executive_summary), None),
    )

    from core.utils import title_similarity

    def _match(f) -> int | None:
        for i, m in enumerate(merged.findings):
            if m.title.strip().lower() == f.title.strip().lower():
                return i
            if m.type == f.type and title_similarity(m.title, f.title) >= 0.6:
                return i
        return None

    for run in runs:
        for f in run.findings:
            idx = _match(f)
            if idx is None:
                merged.findings.append(f)
                continue
            cur = merged.findings[idx]
            # prefer a verified copy; otherwise the one with the richer description
            if (f.verified and not cur.verified) or \
               (f.verified == cur.verified and len(f.description) > len(cur.description)):
                merged.findings[idx] = f
        merged.tool_calls.extend(run.tool_calls)

    # Technical details = the WHOLE attack chain, start to finish — every agent's
    # narrative stitched in chronological order and labelled by phase.
    merged.technical_overview = _stitch_overviews(runs)

    return merged


# Agent → readable phase heading for the stitched Technical Details narrative.
_PHASE_LABEL = {
    "pentest/enumeration":       "Reconnaissance & Enumeration",
    "pentest/web":               "Web Application Assessment",
    "pentest/network":           "Network Service Assessment",
    "pentest/database":          "Database Assessment",
    "pentest/active-directory":  "Active Directory Assessment",
    "pentest/cloud":             "Cloud Assessment",
    "pentest/planning":          "Planning",
    "pentest/exploitation":      "Exploitation",
    "pentest/rce":               "Foothold & Code Execution",
    "pentest/validation":        "Validation",
    "pentest/report":            "Synthesis",
}


def _phase_label(agent: str) -> str:
    return _PHASE_LABEL.get(agent, (agent or "").split("/")[-1].replace("-", " ").title() or "Activity")


def _stitch_overviews(runs: list[EngagementRun]) -> str:
    """Concatenate every run's technical narrative into ONE chronological, start-to-
    finish walkthrough so the report reads as the full attack chain instead of
    whichever agent ran last. Each section is labelled with its phase (## heading);
    exact-duplicate narratives (re-confirmation passes that re-tell the same story)
    are collapsed so the chain doesn't stutter."""
    sections: list[str] = []
    seen: set[str] = set()
    for r in runs:
        ov = (r.technical_overview or "").strip()
        if not ov:
            continue
        norm = " ".join(ov.split()).lower()
        if norm in seen:
            continue
        seen.add(norm)
        sections.append(f"## {_phase_label(r.agent)}\n\n{ov}")
    return "\n\n".join(sections)


def generate_merged_report(
    runs: list[EngagementRun],
    output_dir: Path,
    fmt: str = "html",
    target: str = "",
    persistence: list | None = None,
    termination: str = "completed",
) -> Path:
    """Merge multiple EngagementRun objects into one report."""
    return _render(merge_runs(runs, target=target), fmt, output_dir,
                   persistence=persistence, termination=termination)
