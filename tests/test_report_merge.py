from core.models import EngagementRun, Finding, ToolCall
from reporting.formatter import merge_runs, embed_captures


# ── auto-captured "screenshots" — [IMAGE: …] markers filled with tool output ───

def test_image_marker_replaced_with_tool_command_and_output():
    tcs = [ToolCall(id="1", tool_name="run_script", inputs={"purpose": "wing rce"},
                    command_str="Wing FTP RCE (python x.py)",
                    output={"stdout": "id\nuid=1000(wingftp) gid=1000(wingftp) groups=1000\n"})]
    ov = ("Unauthenticated RCE was achieved. "
          "[IMAGE: dir.html RCE output showing uid=1000(wingftp)] "
          "The service runs as a daemon user.")
    out = embed_captures(ov, tcs)
    assert "[IMAGE" not in out                       # placeholder gone
    assert "```console" in out                        # rendered as a capture block
    assert "uid=1000(wingftp)" in out                 # real output embedded
    assert "$ Wing FTP RCE" in out                    # the command shown
    assert "Unauthenticated RCE was achieved." in out # surrounding prose preserved


def test_capture_binds_to_output_not_script_body():
    # The real bug: a marker about the RCE result matched a "read the exploit file"
    # run_script (its script body mentioned the same words) and dumped 1000 chars of
    # source. Matching is on OUTPUT only now, so the call that actually PRODUCED the
    # result wins.
    rce = ToolCall(id="1", tool_name="run_script", inputs={},
                   command_str="trigger RCE",
                   output={"stdout": "uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp)"})
    read = ToolCall(id="2", tool_name="run_script",
                    inputs={"script": "POST /loginok.html ... uid ... dir.html"},
                    command_str="read exploit file",
                    output={"stdout": "import requests\ndef run_exploit(): ...the whole script..."})
    out = embed_captures(
        "RCE proven. [IMAGE: dir.html output showing uid=1000(wingftp)] Next.", [read, rce])
    assert "uid=1000(wingftp)" in out
    assert "$ trigger RCE" in out and "run_exploit" not in out   # bound to the RCE call


def test_capture_strips_noise_and_stays_short():
    noisy = ToolCall(id="1", tool_name="run_script", inputs={},
                     command_str="cat shadow",
                     output={"stdout": "root:$6$abcd1234salt:19000:0:99999:7:::\n" + ("x" * 5000),
                             "stderr": "RequestsDependencyWarning: urllib3 (2.7.0) doesn't match\n"
                                       "  warnings.warn(\n"})
    out = embed_captures("Hashes read. [IMAGE: shadow showing root hash $6$abcd1234salt] done.", [noisy])
    assert "$6$abcd1234salt" in out
    assert "RequestsDependencyWarning" not in out and "warnings.warn" not in out  # denoised
    # the embedded console excerpt is bounded, not the whole 5 KB dump
    code = out.split("```console", 1)[1].split("```", 1)[0]
    assert len(code) < 700


def test_narrative_blocks_unclosed_fence_is_not_endless_code():
    # An agent leaving a code fence open must not turn the rest of the write-up into
    # one never-closing code block.
    blocks = narrative_blocks("Intro paragraph.\n\n```bash\nid\n\nThen more prose that was never fenced shut.")
    kinds = [b["kind"] for b in blocks]
    assert "code" not in kinds                       # the unclosed fence degrades to prose
    assert any("Intro paragraph" in b["content"] for b in blocks)
    assert any("never fenced shut" in b["content"] for b in blocks)


def test_image_marker_dropped_when_no_matching_capture():
    # A purely manual visual with no corresponding tool call → the placeholder is
    # dropped rather than left in the report.
    ov = "Intro narrative. [IMAGE: a hand-drawn diagram of the network] Closing text."
    out = embed_captures(ov, [])
    assert "[IMAGE" not in out and "hand-drawn" not in out
    assert "Intro narrative." in out and "Closing text." in out


def test_render_fills_capture_end_to_end(tmp_path):
    from reporting.formatter import generate_report
    run = EngagementRun(agent="report", target="10.0.0.5")
    run.executive_summary = "summary"
    run.technical_overview = ("Initial access. "
                              "[IMAGE: nmap output showing port 8080 open] proven.")
    run.tool_calls.append(ToolCall(
        id="1", tool_name="nmap_scan", inputs={"target": "10.0.0.5"},
        command_str="nmap -p- 10.0.0.5",
        output={"stdout": "PORT     STATE SERVICE\n8080/tcp open  http"}))
    run.findings.append(Finding(type="vuln", severity="high", title="X",
                                description="d", target="10.0.0.5"))
    html = generate_report(run, tmp_path, "html").read_text(encoding="utf-8")
    assert "[IMAGE" not in html
    assert "8080/tcp open" in html                    # capture embedded in the report


def _run(agent, titles_verified, overview=None):
    run = EngagementRun(agent=agent, target="10.10.10.5")
    for title, verified in titles_verified:
        run.findings.append(Finding(
            type="vuln", severity="high", title=title,
            description="d", target="10.10.10.5", verified=verified,
        ))
    run.technical_overview = overview
    run.estimated_cost_usd = 1.0
    return run


def test_cross_run_title_dedup():
    # IDs never collide across runs, so title-based dedup must catch this
    r1 = _run("pentest/enumeration", [("Anonymous FTP access", False)])
    r2 = _run("pentest/network",     [("Anonymous FTP access", True),
                                      ("SMB null session", False)])
    merged = merge_runs([r1, r2])
    titles = [f.title for f in merged.findings]
    assert titles.count("Anonymous FTP access") == 1
    assert len(merged.findings) == 2


def test_verified_copy_wins():
    r1 = _run("a", [("Anonymous FTP access", False)])
    r2 = _run("b", [("Anonymous FTP access", True)])
    merged = merge_runs([r1, r2])
    assert merged.findings[0].verified is True


def test_unverified_does_not_downgrade_verified():
    r1 = _run("a", [("Anonymous FTP access", True)])
    r2 = _run("b", [("Anonymous FTP access", False)])
    merged = merge_runs([r1, r2])
    assert merged.findings[0].verified is True


def test_costs_summed_and_overview_stitches_full_chain():
    # Technical Details must be the WHOLE chain (every agent's narrative, in order),
    # not just the last run's — otherwise the report "starts in the middle".
    r1 = _run("pentest/enumeration", [], overview="first narrative")
    r2 = _run("pentest/rce", [], overview="final narrative")
    merged = merge_runs([r1, r2])
    assert merged.estimated_cost_usd == 2.0
    assert "first narrative" in merged.technical_overview
    assert "final narrative" in merged.technical_overview
    assert merged.technical_overview.index("first narrative") < \
           merged.technical_overview.index("final narrative")    # chronological
    assert "## Reconnaissance & Enumeration" in merged.technical_overview  # phase labels


def test_overview_stitch_dedups_repeated_narratives():
    r1 = _run("pentest/rce", [], overview="same story")
    r2 = _run("pentest/rce", [], overview="same story")   # re-confirmation pass
    merged = merge_runs([r1, r2])
    assert merged.technical_overview.count("same story") == 1   # collapsed


def test_target_override():
    r1 = _run("a", [])
    merged = merge_runs([r1], target="custom-target")
    assert merged.target == "custom-target"


# ── evidence rendering (raw request/response over JSON) ───────────────────────

from reporting.formatter import evidence_blocks


def test_evidence_blocks_surfaces_request_response_first_as_raw():
    blocks = evidence_blocks({
        "url": "http://t/x",
        "response": "HTTP/1.1 200 OK\nServer: nginx\n\nroot:x:0:0",
        "request": "GET /../../etc/passwd HTTP/1.1\nHost: t",
    })
    # request then response lead, both raw verbatim blocks.
    assert [b["label"] for b in blocks[:2]] == ["Request", "Response"]
    assert blocks[0]["kind"] == "raw" and blocks[1]["kind"] == "raw"
    assert "etc/passwd" in blocks[0]["text"]


def test_evidence_blocks_scalar_vs_nested():
    blocks = {b["label"]: b for b in evidence_blocks({
        "status": "200",
        "meta": {"a": 1},
        "long": "x" * 150,
    })}
    assert blocks["Status"]["kind"] == "inline"     # short scalar
    assert blocks["Meta"]["kind"] == "json"         # nested structure
    assert blocks["Long"]["kind"] == "raw"          # long string → verbatim block


def test_evidence_blocks_empty():
    assert evidence_blocks({}) == []
    assert evidence_blocks(None) == []


# ── technical-details narrative blocks (embedded working scripts) ──────────────

from reporting.formatter import narrative_blocks


def test_narrative_blocks_splits_prose_and_code():
    text = (
        "Initial access was obtained via the API.\n\n"
        "The working exploit was:\n\n"
        "```groovy\n"
        "def p = 'curl http://x/'.execute()\n"
        "println p.text\n"
        "```\n\n"
        "This yielded command execution."
    )
    blocks = narrative_blocks(text)
    kinds = [b["kind"] for b in blocks]
    assert "code" in kinds
    code = next(b for b in blocks if b["kind"] == "code")
    assert code["lang"] == "groovy"
    assert "execute()" in code["content"]
    assert "```" not in code["content"]
    # prose on both sides survived as text blocks
    assert blocks[0]["kind"] == "text" and "Initial access" in blocks[0]["content"]
    assert blocks[-1]["kind"] == "text" and "command execution" in blocks[-1]["content"]


def test_narrative_blocks_plain_prose():
    blocks = narrative_blocks("One para.\n\nTwo para.")
    assert [b["kind"] for b in blocks] == ["text", "text"]


def test_narrative_blocks_empty():
    assert narrative_blocks("") == []
    assert narrative_blocks(None) == []


# ── draft stamp when the report-writer pass didn't run ────────────────────────

def test_report_marked_draft_without_executive_summary(tmp_path):
    from reporting.formatter import generate_report
    run = EngagementRun(agent="report", target="10.10.10.5")
    run.findings.append(Finding(type="vuln", severity="high", title="X",
                                description="d", target="10.10.10.5"))
    # no executive_summary → writer pass didn't run → draft
    html = generate_report(run, tmp_path, "html").read_text(encoding="utf-8")
    assert '<div class="draft-banner">' in html
    assert "DRAFT" in html


def test_report_not_draft_with_executive_summary(tmp_path):
    from reporting.formatter import generate_report
    run = EngagementRun(agent="report", target="10.10.10.5")
    run.executive_summary = "A real synthesized summary of the engagement."
    run.findings.append(Finding(type="vuln", severity="high", title="X",
                                description="d", target="10.10.10.5"))
    html = generate_report(run, tmp_path, "html").read_text(encoding="utf-8")
    assert '<div class="draft-banner">' not in html


# ── Limitations & Constraints section ─────────────────────────────────────────

def _f():
    return Finding(type="vuln", severity="high", title="X", description="d", target="t")


def test_limitations_section_flags_account_limit(tmp_path):
    from reporting.formatter import generate_merged_report
    run = EngagementRun(agent="report", target="t", findings=[_f()])
    html = generate_merged_report([run], tmp_path, "html", target="t",
                                  termination="account_limit").read_text(encoding="utf-8")
    assert "Limitations &amp; Constraints" in html
    assert "limitation-flag" in html                 # ended-early flag shown
    assert "account/usage limit" in html


def test_limitations_section_completed_no_flag(tmp_path):
    from reporting.formatter import generate_merged_report
    run = EngagementRun(agent="report", target="t", findings=[_f()])
    html = generate_merged_report([run], tmp_path, "html", target="t",
                                  termination="completed").read_text(encoding="utf-8")
    assert "Limitations &amp; Constraints" in html
    assert '<p class="limitation-flag">' not in html  # completed → no early-end flag
    assert "ran to completion" in html


def test_termination_note_defaults_unknown_to_completed():
    from reporting.formatter import termination_note
    assert termination_note("bogus") == termination_note("completed")
    assert termination_note(None)[0] is False        # not ended-early


# ── CVSS rendering (clean vector link + score grid; no screenshots) ───────────

from core.models import CvssScores
from reporting.formatter import nist_cvss_url


def test_nist_cvss_url_strips_prefix_and_sets_version():
    url = nist_cvss_url("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert url.startswith("https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=")
    assert "vector=AV:N/AC:L" in url        # CVSS:3.1/ prefix removed
    assert url.endswith("&version=3.1")
    assert nist_cvss_url("CVSS:3.0/AV:N").endswith("&version=3.0")


def _cvss_run():
    f = Finding(
        type="vuln", severity="high", title="SQLi", description="d", target="10.10.10.5",
        cvss=CvssScores(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        base_score=9.8, temporal_score=9.1, environmental_score=9.8),
    )
    return EngagementRun(agent="report", target="10.10.10.5", findings=[f])


def test_report_renders_clean_cvss_no_screenshot(tmp_path):
    import reporting.formatter as fmtmod
    p = fmtmod.generate_report(_cvss_run(), tmp_path, "html")
    txt = p.read_text(encoding="utf-8")
    assert "cvss-shot" not in txt                 # the screenshot feature is gone
    assert "<img" not in txt                       # no embedded image at all
    assert "Overall Severity" in txt               # clean score grid present
    assert "v3-calculator?vector=" in txt          # vector deep-link present
