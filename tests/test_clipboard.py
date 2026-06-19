"""_os_clipboard_copy — the Linux/macOS/Windows clipboard backend that makes
TUI copy actually reach the desktop clipboard (OSC 52 alone is unreliable on a
Kali desktop)."""
import shutil
import subprocess
import sys
import types

import ui.app as appmod

# _os_clipboard_copy ignores `self`, so we can call it unbound with a stand-in.
_copy = appmod.PentestApp._os_clipboard_copy


class _Dummy:
    pass


def _ok(rc=0):
    return types.SimpleNamespace(returncode=rc)


def test_linux_uses_xclip_with_text(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(shutil, "which", lambda c: f"/usr/bin/{c}" if c == "xclip" else None)
    cap = {}
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: cap.update(cmd=cmd, input=kw.get("input")) or _ok())

    assert _copy(_Dummy(), "hello") is True
    assert cap["cmd"][0] == "xclip" and "clipboard" in cap["cmd"]
    assert cap["input"] == b"hello"


def test_wayland_tried_before_x11(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(shutil, "which", lambda c: f"/usr/bin/{c}")   # all present
    seen = []
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: seen.append(cmd[0]) or _ok())

    assert _copy(_Dummy(), "x") is True
    assert seen[0] == "wl-copy"


def test_falls_through_to_next_tool_on_failure(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    # xclip present but fails (rc=1); xsel present and succeeds.
    monkeypatch.setattr(shutil, "which", lambda c: f"/usr/bin/{c}" if c in ("xclip", "xsel") else None)
    order = []

    def fake_run(cmd, **kw):
        order.append(cmd[0])
        return _ok(1) if cmd[0] == "xclip" else _ok(0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert _copy(_Dummy(), "x") is True
    assert order == ["xclip", "xsel"]


def test_returns_false_when_no_tool_present(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(shutil, "which", lambda c: None)
    assert _copy(_Dummy(), "x") is False


def test_windows_uses_clip(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(shutil, "which", lambda c: f"C:\\{c}.exe" if c == "clip" else None)
    cap = {}
    monkeypatch.setattr(subprocess, "run",
                        lambda cmd, **kw: cap.update(cmd=cmd) or _ok())
    assert _copy(_Dummy(), "x") is True
    assert cap["cmd"] == ["clip"]
