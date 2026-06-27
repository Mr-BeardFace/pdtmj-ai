from ui.commands import parse, handle_cred_add, handle_info, dispatch


def test_parse_simple_command():
    assert parse("/help") == ("/help", [])


def test_parse_command_with_args():
    cmd, args = parse("/scope add 10.10.10.5")
    assert cmd == "/scope add"
    assert args == ["10.10.10.5"]


def test_parse_longest_prefix_wins():
    cmd, args = parse("/agent set model global claude-sonnet-4-6")
    assert cmd == "/agent set model"
    assert args == ["global", "claude-sonnet-4-6"]


def test_parse_unknown_command_returns_first_word():
    cmd, args = parse("/bogus thing")
    assert cmd == "/bogus"
    assert args == []


def test_parse_non_slash_returns_none():
    assert parse("scan example.com") is None


def test_info_overview():
    lines, ok = handle_info()
    assert ok is True
    blob = "\n".join(lines)
    for label in ("Persona", "Provider", "Global model", "Parallel", "Debug capture", "API keys"):
        assert label in blob
    # Removed rows should no longer appear.
    assert "Loop caps" not in blob and "LLM routing" not in blob


def test_exploit_confirm_toggle():
    from core.config import get
    dispatch("/exploit confirm off")
    assert get("confirm_exploitation", True) is False
    dispatch("/exploit confirm on")
    assert get("confirm_exploitation", True) is True
    # The bare phase toggle still works and is independent of the confirm gate.
    dispatch("/exploit off")
    assert get("exploitation_enabled", True) is False
    assert get("confirm_exploitation", True) is True   # unchanged by the phase toggle
    dispatch("/exploit on")
    assert get("exploitation_enabled", True) is True


def test_info_routed_through_dispatch():
    result = dispatch("/info")
    assert result is not None
    lines, ok = result
    assert ok is True
    assert any("Provider" in ln for ln in lines)


def test_cred_add_always_three_tuple():
    # Usage error must still be a 3-tuple — dispatch() unpacks three values
    lines, ok, cred = handle_cred_add([])
    assert ok is False
    assert cred is None

    lines, ok, cred = handle_cred_add(["admin", "P@ss", "smb"])
    assert ok is True
    assert cred == {"username": "admin", "secret": "P@ss", "service": "smb"}
