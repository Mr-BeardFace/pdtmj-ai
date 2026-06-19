from pathlib import Path

from core.registry import build_registry
from tools.run_script import run_script, TOOL_DEFINITION


# ── registration ──────────────────────────────────────────────────────────────

def test_run_script_registered():
    assert "run_script" in build_registry().list_tools()


def test_schema_enumerates_languages():
    langs = TOOL_DEFINITION["input_schema"]["properties"]["language"]["enum"]
    assert "python" in langs and "bash" in langs
    assert TOOL_DEFINITION["input_schema"]["required"] == ["purpose", "language", "script"]


# ── execution ─────────────────────────────────────────────────────────────────

def test_python_stdout_and_exit_code():
    res = run_script("python", "print('hello from script')", purpose="say hello")
    assert res["exit_code"] == 0
    assert "hello from script" in res["stdout"]
    assert res["stderr"] == ""


def test_python_nonzero_exit_and_stderr():
    res = run_script("python", "import sys; sys.stderr.write('boom'); sys.exit(3)", purpose="fail")
    assert res["exit_code"] == 3
    assert "boom" in res["stderr"]


def test_args_are_passed():
    res = run_script("python", "import sys; print(sys.argv[1])", purpose="echo arg", args=["payload42"])
    assert "payload42" in res["stdout"]


def test_script_is_saved_for_audit():
    res = run_script("python", "print(1)", purpose="print one")
    p = Path(res["script_file"])
    assert p.exists() and p.suffix == ".py"
    assert "print(1)" in p.read_text(encoding="utf-8")


def test_timeout_returns_error():
    res = run_script("python", "import time; time.sleep(5)", purpose="sleep", timeout=1)
    assert "error" in res and "timed out" in res["error"]


def test_unsupported_language_rejected():
    res = run_script("ruby", "puts 1", purpose="x")
    assert "error" in res


def test_empty_script_rejected():
    res = run_script("python", "   ", purpose="x")
    assert "error" in res


def test_purpose_is_required():
    res = run_script("python", "print(1)")
    assert "error" in res and "purpose" in res["error"]


def test_purpose_in_command_str_and_result():
    res = run_script("python", "print(1)", purpose="brute the PIN")
    assert res["purpose"] == "brute the PIN"
    assert "brute the PIN" in res["_command"]
