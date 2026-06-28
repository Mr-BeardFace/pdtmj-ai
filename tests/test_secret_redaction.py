"""Display redaction: only confirmed (verified) credentials are masked; unproven
guesses stay visible, and identifiers (usernames, in-scope hostnames) aren't mangled."""
from core.engagement_state import EngagementState
from core.orchestrator import Orchestrator
from core.tool_registry import ToolRegistry


class _NoLLM:
    def run(self, *a, **k):
        raise AssertionError("LLM should not be called")


def _orch(tmp_path, target="active.htb") -> Orchestrator:
    return Orchestrator(_NoLLM(), ToolRegistry(), tmp_path, quiet=True,
                        engagement_state=EngagementState(target=target),
                        save_individual_runs=False)


def test_unverified_secret_is_not_masked(tmp_path):
    o = _orch(tmp_path)
    o.state.add_credential(secret="Sup3rSecret1", username="admin", verified=False)
    txt = "tried admin:Sup3rSecret1"
    assert o._redact_secrets(txt) == txt          # unproven → visible


def test_verified_secret_is_masked(tmp_path):
    o = _orch(tmp_path)
    o.state.add_credential(secret="Sup3rSecret1", username="admin", verified=True)
    out = o._redact_secrets("admin:Sup3rSecret1 works")
    assert "Sup3rSecret1" not in out


def test_generic_word_secret_not_masked_even_when_verified(tmp_path):
    # generic username — left alone so it isn't mangled wherever it appears
    o = _orch(tmp_path)
    o.state.add_credential(secret="guest", username="guest", verified=True)
    assert o._redact_secrets("guest account enabled") == "guest account enabled"


def test_secret_that_is_part_of_hostname_not_masked(tmp_path):
    # "active" coincides with the in-scope host active.htb — don't mangle the host
    o = _orch(tmp_path, target="active.htb")
    o.state.add_credential(secret="active", username="svc", verified=True)
    assert o._redact_secrets("connect to active.htb") == "connect to active.htb"


def test_sprayed_guess_in_secret_values_not_masked(tmp_path):
    o = _orch(tmp_path)
    o._register_input_secrets({"password": "Summer2024"}, "netexec")
    assert "Summer2024" in o._redact_secrets("spraying admin:Summer2024")


def test_emit_masks_only_after_a_cred_is_verified(tmp_path):
    o = _orch(tmp_path, target="active.htb")
    events: list = []
    o._log_callback = events.append            # cb exceptions are swallowed → assert outside

    # unproven guess → hostname and password both visible
    o.state.add_credential(secret="Summer2024", username="admin", verified=False)
    o._emit("agent_reasoning", text="hitting active.htb with admin:Summer2024")
    assert "active.htb" in events[-1]["text"]
    assert "Summer2024" in events[-1]["text"]

    # confirmed → secret masked, hostname intact
    o.state.add_credential(secret="Summer2024", username="admin", verified=True)
    o._emit("agent_reasoning", text="active.htb confirmed admin:Summer2024")
    assert "active.htb" in events[-1]["text"]
    assert "Summer2024" not in events[-1]["text"]
