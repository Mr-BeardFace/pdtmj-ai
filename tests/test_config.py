import core.config as config


def _use_tmp_config(monkeypatch, tmp_path, content: str | None):
    cfg_path = tmp_path / "config.yaml"
    if content is not None:
        cfg_path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(config, "_CONFIG_PATH", cfg_path)
    monkeypatch.setattr(config, "_cache", None)
    monkeypatch.setattr(config, "_cache_mtime", 0.0)


def test_global_model_top_level_key_is_honored(monkeypatch, tmp_path):
    # The documented config.yaml key must work — it used to be dead
    _use_tmp_config(monkeypatch, tmp_path, "global_model: claude-opus-4-7\n")
    assert config.get_global_model() == "claude-opus-4-7"


def test_global_model_agent_models_entry_wins(monkeypatch, tmp_path):
    _use_tmp_config(monkeypatch, tmp_path,
                    "global_model: claude-opus-4-7\n"
                    "agent_models:\n  global: claude-sonnet-4-6\n")
    assert config.get_global_model() == "claude-sonnet-4-6"


def test_global_model_none_when_unset(monkeypatch, tmp_path):
    _use_tmp_config(monkeypatch, tmp_path, None)
    assert config.get_global_model() is None


def test_agent_override(monkeypatch, tmp_path):
    _use_tmp_config(monkeypatch, tmp_path,
                    "agent_models:\n  pentest/web: claude-haiku-4-5-20251001\n")
    assert config.get_model_for_agent("pentest/web") == "claude-haiku-4-5-20251001"
    assert config.get_model_for_agent("pentest/network") is None
