import base64

import tools.ysoserial as yso
from tools.ysoserial import ysoserial, TOOL_DEFINITION


def test_tool_definition_shape():
    assert TOOL_DEFINITION["name"] == "ysoserial"
    props = TOOL_DEFINITION["input_schema"]["properties"]
    assert {"gadget", "command", "encode", "output_file", "timeout"} <= set(props)
    # No required fields — calling with nothing lists gadgets.
    assert "required" not in TOOL_DEFINITION["input_schema"]


def test_not_found_when_no_jar_or_binary(monkeypatch):
    monkeypatch.delenv("YSOSERIAL_JAR", raising=False)
    monkeypatch.setattr(yso, "_resolve_jar", lambda: None)
    monkeypatch.setattr(yso.shutil, "which", lambda _name: None)
    out = ysoserial(gadget="CommonsCollections5", command="id")
    assert "error" in out
    assert "ysoserial not found" in out["error"]


def test_gadget_without_command_is_rejected(monkeypatch):
    # Pretend ysoserial is invokable so we reach the command check.
    monkeypatch.setattr(yso, "_invocation", lambda: (["java", "-jar", "/x/ysoserial.jar"], None))
    out = ysoserial(gadget="CommonsCollections5")
    assert "error" in out
    assert "command is required" in out["error"]


def test_unsupported_encoding_rejected(monkeypatch):
    monkeypatch.setattr(yso, "_invocation", lambda: (["java", "-jar", "/x/ysoserial.jar"], None))
    out = ysoserial(gadget="URLDNS", command="http://x", encode="rot13")
    assert "error" in out
    assert "unsupported encode" in out["error"]


def test_list_gadgets_mode(monkeypatch):
    monkeypatch.setattr(yso, "_invocation", lambda: (["java", "-jar", "/x/ysoserial.jar"], None))

    class _Proc:
        stdout = ""
        stderr = "Available payload types:\n  CommonsCollections5\n  URLDNS\n"

    monkeypatch.setattr(yso.runner, "run", lambda *a, **k: _Proc())
    out = ysoserial()
    assert out["mode"] == "list_gadgets"
    assert "CommonsCollections5" in out["gadgets"]


def test_payload_base64_encoded(monkeypatch):
    monkeypatch.setattr(yso, "_invocation", lambda: (["java", "-jar", "/x/ysoserial.jar"], None))
    raw = b"\xac\xed\x00\x05fakepayload"

    class _Proc:
        stdout = raw
        stderr = b""

    monkeypatch.setattr(yso.runner, "run", lambda *a, **k: _Proc())
    out = ysoserial(gadget="CommonsCollections5", command="id")
    assert out["encoding"] == "base64"
    assert base64.b64decode(out["payload"]) == raw
    assert out["payload_bytes"] == len(raw)


def test_empty_payload_reports_error(monkeypatch):
    monkeypatch.setattr(yso, "_invocation", lambda: (["java", "-jar", "/x/ysoserial.jar"], None))

    class _Proc:
        stdout = b""
        stderr = b"Error: unknown gadget"

    monkeypatch.setattr(yso.runner, "run", lambda *a, **k: _Proc())
    out = ysoserial(gadget="NoSuchGadget", command="id")
    assert "error" in out
    assert "no payload" in out["error"]
