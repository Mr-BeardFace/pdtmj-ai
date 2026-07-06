"""Attacker-controlled tool output lands verbatim in finding fields. The HTML report
must escape it — else viewing the report executes the payload (self-XSS). Regression:
report.html.j2 ends in .j2, so select_autoescape used to return False and render raw."""
from pathlib import Path

from core.models import EngagementRun, Finding
from reporting.formatter import generate_report, _autoescape

_PAYLOAD = "<script>alert(1)</script>"


def test_autoescape_by_output_suffix():
    assert _autoescape("report.html.j2") is True     # escape HTML
    assert _autoescape("report.md.j2") is False       # leave Markdown alone


def test_html_report_escapes_tool_output(tmp_path: Path):
    run = EngagementRun(
        agent="pentest/report", target=f"10.0.0.5 {_PAYLOAD}",
        findings=[Finding(type="vuln", severity="high", title=f"XSS {_PAYLOAD}",
                          description=f"payload: {_PAYLOAD}", target="10.0.0.5",
                          evidence={"output": _PAYLOAD})],
        technical_overview=f"Recon found {_PAYLOAD} in a response.")
    html = generate_report(run, tmp_path, fmt="html").read_text(encoding="utf-8")
    assert _PAYLOAD not in html                        # never rendered raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
