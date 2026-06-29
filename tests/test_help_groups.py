"""Grouped /help overview + the /assessment command consolidation."""
from ui.commands import COMMANDS, _HELP_GROUPS, dispatch, parse


def test_every_command_is_in_exactly_one_help_group():
    grouped = [name for _, names in _HELP_GROUPS for name in names]
    assert len(grouped) == len(set(grouped)), "a command appears in two groups"
    assert set(grouped) == {c.name for c in COMMANDS}, "groups drifted from COMMANDS"


def test_load_folded_into_assessment():
    names = {c.name for c in COMMANDS}
    assert "/load" not in names
    assert "/assessment" in names


def test_assessment_subcommands_parse():
    assert parse("/assessment list") == ("/assessment list", [])
    assert parse("/assessment load 3bd4") == ("/assessment load", ["3bd4"])
    assert parse("/assessment new") == ("/assessment new", [])


def test_bare_slash_shows_help_not_unknown():
    out, ok = dispatch("/")
    assert ok is True
    blob = "\n".join(out)
    assert "Slash commands" in blob
    assert "Unknown command" not in blob


def test_overview_is_grouped_and_aligned():
    out, _ = dispatch("/help")
    blob = "\n".join(out)
    # group headers present
    for title, _ in _HELP_GROUPS:
        assert title in blob
    # a long arg-string lives in the per-command detail, not the overview
    assert "<assessment-id>" not in blob
    detail = "\n".join(dispatch("/help assessment")[0])
    assert "assessment-id" in detail
