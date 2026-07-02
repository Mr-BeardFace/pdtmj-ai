"""Old→new /config key rename is migrated on load: a config.yaml written before the
rename keeps its tuned values (moved to the new key) and the file is rewritten once."""
import yaml

import core.config as config


def _reset_cache():
    config._cache = None
    config._cache_mtime = 0.0


def test_old_keys_migrate_and_file_rewritten(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    # a pre-rename file with tuned overrides under OLD keys
    cfg_file.write_text(yaml.dump({
        "max_turns_default": 80,
        "allow_web_search": False,
        "grind_nudge_after_scripts": 20,
    }), encoding="utf-8")
    monkeypatch.setattr(config, "_CONFIG_PATH", cfg_file)
    _reset_cache()

    cfg = config.load_config()
    # values survive under the NEW keys
    assert cfg["agent_turns"] == 80
    assert cfg["web_search"] is False
    assert cfg["grind_nudge"] == 20
    # old keys are gone from the loaded config
    assert "max_turns_default" not in cfg and "allow_web_search" not in cfg
    # and the file itself was rewritten with new keys
    on_disk = yaml.safe_load(cfg_file.read_text(encoding="utf-8"))
    assert "agent_turns" in on_disk and "max_turns_default" not in on_disk

    _reset_cache()


def test_new_key_wins_if_both_present(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.dump({"max_turns_default": 80, "agent_turns": 99}), encoding="utf-8")
    monkeypatch.setattr(config, "_CONFIG_PATH", cfg_file)
    _reset_cache()
    assert config.load_config()["agent_turns"] == 99
    _reset_cache()
