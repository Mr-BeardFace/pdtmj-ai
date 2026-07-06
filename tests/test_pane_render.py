"""Activity-pane helpers: secret-shaped scrubbing (defends against a cred flashing in
the clear before it's recorded) and evidence-slicing (surface the source line + context
for a recorded credential/finding)."""
from ui.app import (_scrub_secretish, _evidence_slice, _result_text,
                    _pane_cap, _PANE_MAX_WIDTH, _strip_markup)


def test_scrub_secretish_masks_credential_shaped_values():
    line = 'ConnectionContext Dump: { BindUser: "svc", BindPass: "Em3rg3ncyPa$$2025" }'
    out = _scrub_secretish(line)
    assert "Em3rg3ncyPa$$2025" not in out
    assert "BindPass" in out and "svc" in out          # keys/usernames untouched


def test_scrub_secretish_handles_equals_and_keywords():
    assert "hunter2" not in _scrub_secretish("password=hunter2")
    assert "sk-abc123def" not in _scrub_secretish("api_key: sk-abc123def")
    assert "tok-xyz789" not in _scrub_secretish('token = "tok-xyz789"')


def test_scrub_leaves_non_secrets_alone():
    s = "HTTP 200 — 703 bytes; server Microsoft-IIS/10.0"
    assert _scrub_secretish(s) == s


def test_evidence_slice_marks_line_with_context():
    text = "\n".join(f"line {i}" for i in range(10))
    text = text.replace("line 5", "the SECRET is here")
    sl = _evidence_slice(text, "SECRET", context=2)
    assert any(l.startswith("► ") and "SECRET" in l for l in sl)
    assert len(sl) == 5                                 # line ±2
    assert sl[0].startswith("  line 3") and sl[-1].startswith("  line 7")


def test_evidence_slice_absent_needle_is_empty():
    assert _evidence_slice("nothing to see", "MISSING") == []
    assert _evidence_slice("x", "") == []


def test_result_text_prefers_stdout_then_structured():
    assert _result_text({"stdout": "hello", "exit_code": 0}) == "hello"
    assert "shares" in _result_text({"shares": ["C$", "IPC$"], "_command": "nxc"})
    assert _result_text("plain string") == "plain string"


def test_pane_cap_leaves_short_markup_untouched():
    msg = "[cyan]▶ nmap_scan[/cyan]  [dim]target=10.0.0.1[/dim]"
    assert _pane_cap(msg) == msg                          # short → unchanged, markup intact


def test_pane_cap_truncates_a_flooding_one_liner():
    long_cmd = "  [dim]$ " + ("A" * 4000) + "[/dim]"      # one huge command line
    out = _pane_cap(long_cmd)
    assert len(_strip_markup(out)) <= _PANE_MAX_WIDTH + 40   # capped, not 4000
    assert out.endswith("(Ctrl+L for full)[/dim]")
    assert "[/dim]" not in _strip_markup(out)             # no broken/partial tags leaked as text
