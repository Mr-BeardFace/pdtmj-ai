"""Model tab-completion reflects the ACTIVE provider's real models — not a hardcoded
default list, and not the previous provider's models left mixed in."""
import core.config as cfgmod
from ui.app import PentestApp, _DEFAULT_MODEL_IDS


class _Stub:
    def __init__(self):
        self._known_models: list[str] = []
        self.activity: list[str] = []
        self.refreshed = 0

    def _activity(self, msg):
        self.activity.append(msg)

    def _refresh_models_async(self):
        self.refreshed += 1                    # a real worker; here just count it


def test_capture_models_replaces_not_appends():
    s = _Stub()
    s._known_models = ["stale-old-model", "claude-opus-4-7"]
    lines = ["  claude-sonnet-4-6   Sonnet", "  meta-llama/llama-3.1-8b-instruct:free  Llama"]
    PentestApp._capture_models(s, lines)
    # the stale entry is gone — pool is exactly what was just listed
    assert s._known_models == ["claude-sonnet-4-6", "meta-llama/llama-3.1-8b-instruct:free"]


def test_capture_models_announce_toggle():
    s = _Stub()
    PentestApp._capture_models(s, ["  claude-sonnet-4-6  Sonnet"], announce=False)
    assert s.activity == []                    # background refresh stays quiet


def test_seed_uses_anthropic_defaults_only_for_anthropic(monkeypatch):
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: "anthropic" if k == "active_provider" else d)
    s = _Stub()
    PentestApp._seed_models_for_active_provider(s)
    assert s._known_models == list(_DEFAULT_MODEL_IDS)   # placeholder for anthropic
    assert s.refreshed == 1                              # and a real fetch kicked off


def test_seed_empty_for_non_anthropic_provider(monkeypatch):
    monkeypatch.setattr(cfgmod, "get",
                        lambda k, d=None: "nvidia" if k == "active_provider" else d)
    s = _Stub()
    PentestApp._seed_models_for_active_provider(s)
    # no Anthropic defaults bleeding into a different provider's completion
    assert s._known_models == []
    assert s.refreshed == 1
