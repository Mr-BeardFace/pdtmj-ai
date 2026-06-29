"""External-providers seam — the neutral, operator-private extension point.

The public repo ships no external module, so the hook is inert by default. These
tests drop a throwaway module via $PDTMJ_LOCAL_PROVIDERS and confirm the seam:
the module registers a provider, /provider login routes to its login callable,
and LLMClient delegates the request to its request_handler. Nothing here knows
anything about any specific provider — that lives only in the operator's module.

The loader mutates the live PROVIDERS dict in place, so these tests call it
directly (no module reload, which would fork exception classes and break other
tests' `pytest.raises` identity) and pop the one registered key in teardown.
"""
import textwrap

import pytest

import core.llm_client as L


def _write_module(tmp_path) -> str:
    mod = tmp_path / "providers_local.py"
    mod.write_text(textwrap.dedent('''
        def register(api):
            def _login(args):
                if not args:
                    return ["visit https://example/auth then paste the code"], True
                return [f"logged in with code {args[0]}"], True

            def _handler(client, model, system, messages, tools, max_tokens, temperature):
                return api.Message(
                    stop_reason="end_turn",
                    content=[api.TextBlock(type="text", text="from-external")],
                    usage=api.Usage(input_tokens=1, output_tokens=1),
                )

            api.PROVIDERS["unittest-ext"] = api.ProviderSpec(
                name="unittest-ext", label="Unit Test Ext",
                keyring_key="unittest_ext_key", env_var="UNITTEST_EXT_KEY",
                key_prefixes=(), key_optional=True,
                login=_login, request_handler=_handler,
            )
    '''), encoding="utf-8")
    return str(mod)


@pytest.fixture
def external(tmp_path, monkeypatch):
    """Load a throwaway external module into the live registry; clean up after."""
    monkeypatch.setenv("PDTMJ_LOCAL_PROVIDERS", _write_module(tmp_path))
    L._load_external_providers()
    yield
    L.PROVIDERS.pop("unittest-ext", None)


def test_no_external_module_is_a_noop(monkeypatch, tmp_path):
    monkeypatch.setenv("PDTMJ_LOCAL_PROVIDERS", str(tmp_path / "nope.py"))
    before = set(L.PROVIDERS)
    L._load_external_providers()
    assert set(L.PROVIDERS) == before  # missing path → silent no-op, registry intact


def test_external_provider_is_registered(external):
    spec = L.PROVIDERS["unittest-ext"]
    assert callable(spec.login) and callable(spec.request_handler)


def test_request_handler_replaces_transport(external, monkeypatch):
    # Make the external provider active, then run a request: it must hit the handler
    # (no SDK client, no key) and return the handler's block.
    import core.config as cfg
    monkeypatch.setattr(
        cfg, "get",
        lambda key, default=None: "unittest-ext" if key == "active_provider" else default,
    )
    client = L.LLMClient()
    assert client._anthropic_client is None and client._oai_key is None
    msg = client.run(model="x", system="s", messages=[], tools=[])
    assert msg.content[0].text == "from-external"


def test_login_routes_through_command(external):
    import ui.commands as commands
    # ui.commands shares the live PROVIDERS dict by reference, so the new provider is
    # visible without a reload.
    lines, ok = commands.handle_provider_login(["unittest-ext"])
    assert ok and any("paste the code" in ln for ln in lines)
    lines, ok = commands.handle_provider_login(["unittest-ext", "ABC123"])
    assert ok and any("ABC123" in ln for ln in lines)
    # A built-in key-based provider has no login flow.
    lines, ok = commands.handle_provider_login(["anthropic"])
    assert not ok and any("doesn't use a login flow" in ln for ln in lines)
