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
    # The fixed anchors are always shown.
    for label in ("Persona", "Provider", "Global model",
                  "Exploitation", "Reporting", "Confirm exploit"):
        assert label in blob
    # No command hints, and the old always-on rows are gone from the anchor block.
    assert "(/persona set)" not in blob and "(/exploit" not in blob
    assert "Loop caps" not in blob and "LLM routing" not in blob


def test_config_exploit_toggles():
    # Exploitation + confirm gate are now set through /config (the single config cmd).
    from core.config import get
    dispatch("/config confirm_exploit off")
    assert get("confirm_exploit", True) is False
    dispatch("/config confirm_exploit on")
    assert get("confirm_exploit", True) is True
    dispatch("/config exploitation off")
    assert get("exploitation", True) is False
    assert get("confirm_exploit", True) is True   # independent of the phase toggle
    dispatch("/config exploitation on")
    assert get("exploitation", True) is True


def test_old_toggle_commands_removed():
    for cmd in ("/exploit on", "/turns 5", "/websearch off", "/parallel on", "/debug on"):
        res = dispatch(cmd)
        assert res is not None and res[1] is False
        assert any("Unknown command" in ln for ln in res[0])


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
    assert cred == {"username": "admin", "secret": "P@ss", "service": "smb", "cred_type": "password"}


def test_cred_add_type_detection():
    # type defaults to password
    assert handle_cred_add(["u", "p"])[2]["cred_type"] == "password"
    # a type keyword anywhere in the trailing args sets the type, order-independent
    assert handle_cred_add(["u", "h", "hash"])[2] == {"username": "u", "secret": "h",
                                                      "service": "", "cred_type": "hash"}
    c = handle_cred_add(["u", "h", "smb", "hash"])[2]
    assert c["cred_type"] == "hash" and c["service"] == "smb"
    # aliases normalize (ntlm -> hash, api -> api_key)
    assert handle_cred_add(["u", "h", "ntlm"])[2]["cred_type"] == "hash"
    assert handle_cred_add(["u", "k", "api"])[2]["cred_type"] == "api_key"
