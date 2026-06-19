import json

from core.session_log import SessionLogger


def test_writes_both_files(tmp_path):
    log = SessionLogger(tmp_path / "engagement.log")
    log.header("10.10.10.5", objective="map surface", persona="pentest")
    assert log.path.exists()
    assert log.jsonl_path.exists()
    assert log.jsonl_path.name == "engagement.jsonl"


def test_header_records_target(tmp_path):
    log = SessionLogger(tmp_path / "e.log")
    log.header("10.10.10.5", mode="pipeline")
    text = log.path.read_text(encoding="utf-8")
    assert "10.10.10.5" in text
    assert "pipeline" in text


def test_tool_done_text_and_full_jsonl(tmp_path):
    log = SessionLogger(tmp_path / "e.log")
    big = "A" * 5000
    log.log("tool_done", {
        "name": "nmap_scan",
        "command_str": "nmap -sV 10.10.10.5",
        "summary": "1 host, 2 ports",
        "output": {"raw": big},
    })
    text = log.path.read_text(encoding="utf-8")
    assert "$ nmap -sV 10.10.10.5" in text
    assert "1 host, 2 ports" in text
    assert "truncated" in text                    # text log caps output

    rec = json.loads(log.jsonl_path.read_text(encoding="utf-8").splitlines()[-1])
    assert rec["type"] == "tool_done"
    assert rec["output"]["raw"] == big            # jsonl keeps full output


def test_reasoning_and_annotation_formatting(tmp_path):
    log = SessionLogger(tmp_path / "e.log")
    log.log("agent_reasoning", {"text": "Checking the FTP port next."})
    log.log("annotation", {
        "severity": "high", "title": "Anon FTP", "verified": True,
        "description": "Anonymous login permitted.",
    })
    text = log.path.read_text(encoding="utf-8")
    assert "reasoning:" in text
    assert "Checking the FTP port next." in text
    assert "[HIGH] Anon FTP  (verified)" in text


def test_token_update_skipped_in_text_kept_in_jsonl(tmp_path):
    log = SessionLogger(tmp_path / "e.log")
    log.header("10.10.10.5")
    before = log.path.read_text(encoding="utf-8")
    log.log("token_update", {"input": 100, "output": 50})
    # Nothing human-facing added to the text log …
    assert log.path.read_text(encoding="utf-8") == before
    # … but the event is preserved in the machine-readable stream
    assert "token_update" in log.jsonl_path.read_text(encoding="utf-8")


def test_log_never_raises_on_bad_data(tmp_path):
    log = SessionLogger(tmp_path / "e.log")

    class Unserializable:
        pass

    # default=str handles odd objects; call must not raise
    log.log("tool_done", {"name": "x", "output": Unserializable()})
    log.log("unknown_event_type", {"weird": object()})
