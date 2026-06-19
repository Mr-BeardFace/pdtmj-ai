from ui.intent import parse_intent


def test_assessment_suffix_words_match():
    # "assessment" must match — a bare \b after "assess" used to reject it
    intent = parse_intent("run a full assessment against 10.10.10.1")
    assert intent is not None
    assert intent["action"] == "pipeline"
    assert intent["target"] == "10.10.10.1"


def test_vulnerabilities_suffix_matches():
    intent = parse_intent("find vulnerabilities in example.com")
    assert intent is not None
    assert intent["action"] == "pipeline"
    assert intent["target"] == "example.com"


def test_recon_only_excludes_exploitation():
    intent = parse_intent("scan 10.10.10.5 and map the attack surface")
    assert intent["action"] == "pipeline"
    assert "exploitation" not in intent["allowed_phases"]
    assert "discovery" in intent["allowed_phases"]
    assert "reporting" in intent["allowed_phases"]


def test_explicit_exploitation_enables_phase():
    intent = parse_intent("pentest 10.10.10.5 and exploit any vulns found")
    assert intent["action"] == "pipeline"
    assert "exploitation" in intent["allowed_phases"]


def test_named_agent_run():
    intent = parse_intent("run pentest/web against http://example.com")
    assert intent["action"] == "run"
    assert intent["agent"] == "pentest/web"
    assert intent["target"] == "http://example.com"


def test_unrecognized_returns_none():
    assert parse_intent("hello there") is None


def test_file_path_target_not_matched_by_regex():
    # File paths are the router's job — the regex parser must decline
    assert parse_intent("audit the code at /opt/app for secrets") is None


def test_list_runs():
    assert parse_intent("show run history")["action"] == "list_runs"


def test_report_with_run_id():
    intent = parse_intent("report for a1b2c3d4")
    assert intent["action"] == "report"
    assert intent["run_id"] == "a1b2c3d4"


def test_quit():
    assert parse_intent("quit")["action"] == "quit"
