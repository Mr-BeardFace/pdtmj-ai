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
    for label in ("Persona", "Provider", "Global model", "Loop caps", "API keys"):
        assert label in blob


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
