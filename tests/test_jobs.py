"""Background-job subsystem: JobManager, orchestrator background dispatch,
hashcat always-background + cracked-cred ingest."""
import time

from core.agent_loader import AgentDefinition
from core.engagement_state import EngagementState
from core.jobs import JobManager
from core.llm_client import _Message, _TextBlock, _ToolUseBlock, _Usage
from core.orchestrator import Orchestrator, _ALWAYS_BACKGROUND
from core.tool_registry import Tool, ToolRegistry


# ── JobManager ────────────────────────────────────────────────────────────────

def test_jobmanager_runs_and_completes():
    jm = JobManager()
    jm.start("fake", {"x": 1}, lambda: {"count": 3, "_command": "fake -x 1"})
    jm.wait_all()
    done = jm.poll_completed()
    assert len(done) == 1
    assert done[0].status == "done"
    assert done[0].result["count"] == 3
    # poll_completed marks collected — a second poll returns nothing
    assert jm.poll_completed() == []


def test_jobmanager_failure_captured():
    jm = JobManager()
    jm.start("boom", {}, lambda: (_ for _ in ()).throw(RuntimeError("nope")))
    jm.wait_all()
    job = jm.poll_completed()[0]
    assert job.status == "failed"
    assert "nope" in job.error


def test_jobmanager_error_result_is_failure():
    jm = JobManager()
    jm.start("t", {}, lambda: {"error": "tool not found"})
    jm.wait_all()
    assert jm.poll_completed()[0].status == "failed"


def test_jobmanager_running_then_empty():
    jm = JobManager()
    jm.start("slow", {}, lambda: (time.sleep(0.2) or {"ok": True}))
    assert jm.has_pending() is True
    jm.wait_all()
    assert jm.has_pending() is False


# ── orchestrator background dispatch ──────────────────────────────────────────

def _msg(*blocks):
    return _Message(content=list(blocks), usage=_Usage(input_tokens=1, output_tokens=1))


class FakeLLM:
    def __init__(self, responses):
        self._responses = list(responses)

    def run(self, model, system, messages, tools, max_tokens=8192, temperature=None):
        return self._responses.pop(0)


def _agent(scope):
    return AgentDefinition(name="t/a", description="", scope=scope,
                           model="m", system_prompt="go", metadata={})


def test_background_flag_defers_tool_and_flush_ingests(tmp_path):
    calls = []

    def fake_tool(**kw):
        calls.append(kw)
        return {"count": 5, "_command": "ffuf ..."}

    reg = ToolRegistry()
    reg.register(Tool("ffuf", "", {"type": "object"}, fake_tool))
    state = EngagementState(target="t")
    llm = FakeLLM([
        _msg(_ToolUseBlock(id="1", name="ffuf", input={"url": "http://t", "background": True})),
        _msg(_TextBlock(text="continuing")),
    ])
    orch = Orchestrator(llm, reg, tmp_path, quiet=True, engagement_state=state,
                        save_individual_runs=False)
    orch.run(_agent(["ffuf"]), "t", max_turns=4)

    # the tool was started as a job (not blocking), and 'background' never reached it
    assert len(orch._jobs.all_jobs()) == 1
    orch.flush_jobs()
    assert calls and "background" not in calls[0]
    assert any(e.tool_name == "ffuf" for e in state.tool_log)


def test_hashcat_is_always_background_and_feeds_credential(tmp_path):
    assert "hashcat_crack" in _ALWAYS_BACKGROUND

    def fake_hashcat(**kw):
        return {"cracked": [{"hash": "h", "plaintext": "Pwned123",
                             "username": "admin", "location": "DC01"}],
                "cracked_count": 1, "cracked_in": "rockyou", "_command": "hashcat ..."}

    reg = ToolRegistry()
    reg.register(Tool("hashcat_crack", "", {"type": "object"}, fake_hashcat))
    state = EngagementState(target="t")
    creds_events = []
    llm = FakeLLM([
        _msg(_ToolUseBlock(id="1", name="hashcat_crack",
                           input={"hash": "h", "hash_mode": 1000})),  # no background flag
        _msg(_TextBlock(text="done")),
    ])
    orch = Orchestrator(llm, reg, tmp_path, quiet=True, engagement_state=state,
                        save_individual_runs=False,
                        log_callback=lambda e: creds_events.append(e))
    orch.run(_agent(["hashcat_crack"]), "t", max_turns=4)
    orch.flush_jobs()

    # cracked plaintext became a verified credential
    cred = next(c for c in state.credentials if c.secret == "Pwned123")
    assert cred.verified and cred.username == "admin" and cred.location == "DC01"
    assert any(e.get("type") == "credential" and e.get("secret") == "Pwned123"
               for e in creds_events)


# ── hashcat tool wrapper ──────────────────────────────────────────────────────

def test_hashcat_format_mode_mapping():
    from tools.hashcat_crack import _FORMAT_MODES
    assert _FORMAT_MODES["ntlm"] == 1000
    assert _FORMAT_MODES["kerberoast"] == 13100
    assert _FORMAT_MODES["asrep"] == 18200


def test_hashcat_missing_binary_or_wordlist():
    from tools.hashcat_crack import hashcat_crack
    res = hashcat_crack("deadbeef", hash_mode=1000)
    assert "error" in res          # hashcat or wordlist absent on the test box


def test_hashcat_requires_mode():
    from tools.hashcat_crack import hashcat_crack
    # No mode and unknown format → clear error (when binary is present it still guards)
    res = hashcat_crack("deadbeef", hash_format="not-a-format")
    assert "error" in res


def test_hashcat_accepts_custom_words():
    import inspect
    from tools.hashcat_crack import hashcat_crack, TOOL_DEFINITION
    assert "custom_words" in inspect.signature(hashcat_crack).parameters
    assert "custom_words" in TOOL_DEFINITION["input_schema"]["properties"]
    # accepts the kwarg without exploding (errors out on missing binary/wordlist)
    res = hashcat_crack("deadbeef", hash_mode=1000, custom_words=["Summer2024", "admin"])
    assert "error" in res


def test_ingest_job_updates_state_and_returns_injection(tmp_path):
    state = EngagementState(target="t")
    reg = ToolRegistry()
    orch = Orchestrator(object(), reg, tmp_path, quiet=True, engagement_state=state,
                        save_individual_runs=False)
    job = orch._jobs.start("ffuf", {"url": "x"}, lambda: {"count": 2, "_command": "ffuf x"})
    orch._jobs.wait_all()
    (done,) = orch._jobs.poll_completed()
    text = orch._ingest_job(done, "t/a", None)
    assert "ffuf" in text and "finished" in text          # injected into agent context
    assert any(e.tool_name == "ffuf" for e in state.tool_log)


def test_inject_user_text_into_list_and_str():
    msgs = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "1", "content": "{}"}]}]
    Orchestrator._inject_user_text(msgs, "job done")
    assert msgs[-1]["content"][-1]["text"] == "job done"

    msgs = [{"role": "user", "content": "hello"}]
    Orchestrator._inject_user_text(msgs, "more")
    assert "more" in msgs[-1]["content"]

    msgs = [{"role": "assistant", "content": [{"type": "text", "text": "x"}]}]
    Orchestrator._inject_user_text(msgs, "y")
    assert msgs[-1] == {"role": "user", "content": "y"}    # appended a new user msg


def test_ingest_hashcat_records_credential():
    st = EngagementState(target="x")
    st.ingest_tool_result("hashcat_crack", {
        "cracked": [{"plaintext": "Pwned123", "username": "admin", "location": "DC01"}],
    })
    c = st.credentials[0]
    assert c.secret == "Pwned123" and c.verified and c.location == "DC01"
