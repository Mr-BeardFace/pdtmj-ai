# write_report is a meta-tool handled directly by the orchestrator (like
# annotate_finding). It is injected only into the reporting phase and intercepted
# before dispatch. Capturing the deliverable narrative through a structured tool
# call — instead of scraping one fenced ```json``` blob from the final message —
# is what makes it robust: the old blob carried the executive summary, the whole
# technical overview (with inline code fences that collide with the outer fence),
# AND every finding's enrichment, so any truncation or fence collision silently
# dropped the ENTIRE report. Findings enrich via annotate_finding; the narrative
# lands here.

TOOL_DEFINITION = {
    "name": "write_report",
    "description": (
        "Submit the report narrative — the executive summary and the technical overview. "
        "Call this once, after you have enriched every finding with annotate_finding. This "
        "is the deliverable's prose; findings (severity, CVSS, impact, remediation, evidence) "
        "are carried on the findings themselves, not here.\n"
        "Middle ground: a real report's story flow and reasoning, but tight and direct — no "
        "textbook tool definitions, no padding.\n"
        "executive_summary: for a decision-maker, three labelled parts (## Overview, ## Key "
        "Findings, ## Conclusion) — objective in business terms, a summary-level story of the "
        "engagement naming the worst finding(s), and whether the objective was met.\n"
        "technical_overview: the full attack path start to finish as a cause-and-effect STORY, "
        "organized into ## phase/asset sections (open with ## Summary). Narrate the reasoning "
        "('X because Y, which yielded Z'), not a list of steps. Show evidence with [IMAGE: <the "
        "command run + a distinctive output line>] markers (the engine fills each with the real "
        "captured command/output) — use a fenced code block only for the actual working "
        "exploit/payload. Include the failures that forced a pivot and what they revealed. Cover "
        "recon through the deepest access reached (and where/why the path stopped if the objective "
        "wasn't fully met)."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "3-4 paragraphs for a decision-maker. Separate paragraphs with a blank line.",
            },
            "technical_overview": {
                "type": "string",
                "description": "Chronological cause-and-effect narrative of the whole engagement, with working scripts inline as fenced code blocks and [IMAGE: …] evidence markers.",
            },
        },
        "required": ["executive_summary", "technical_overview"],
    },
}
