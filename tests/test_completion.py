from ui.completion import (
    compute_candidates, best_suggestion, suggest, extract_model_ids,
)

AGENTS = ["pentest/enumeration", "pentest/web"]
MODELS = ["claude-sonnet-4-6", "claude-opus-4-7"]


def test_first_arg_suggests_agents_and_global():
    cands = compute_candidates("/agent set model ", AGENTS, MODELS)
    assert "/agent set model global" in cands
    assert "/agent set model pentest/web" in cands


def test_first_arg_partial_match():
    s = suggest("/agent set model pentest/w", AGENTS, MODELS)
    assert s == "/agent set model pentest/web"


def test_second_arg_suggests_models_keeping_agent():
    cands = compute_candidates("/agent set model pentest/web ", AGENTS, MODELS)
    assert "/agent set model pentest/web claude-sonnet-4-6" in cands


def test_second_arg_partial_model_completion():
    s = suggest("/agent set model global claude-op", AGENTS, MODELS)
    assert s == "/agent set model global claude-opus-4-7"


def test_models_list_provider_completion():
    s = suggest("/models list open", AGENTS, MODELS)
    assert s == "/models list openrouter"


def test_provider_set_completion():
    s = suggest("/provider set anth", AGENTS, MODELS)
    assert s == "/provider set anthropic"


def test_slash_prefix_uses_static_completions():
    s = suggest("/per", AGENTS, MODELS)
    assert s is not None and s.startswith("/persona")


def test_best_suggestion_no_match_returns_none():
    assert best_suggestion("/zzz", ["/abc", "/def"]) is None


def test_best_suggestion_empty_value():
    assert best_suggestion("", ["/abc"]) is None


def test_extract_model_ids_anthropic_format():
    lines = [
        "Available Anthropic models:",
        "",
        "  claude-sonnet-4-6                              Claude Sonnet 4.6",
        "  claude-haiku-4-5-20251001                     Claude Haiku 4.5",
    ]
    assert extract_model_ids(lines) == [
        "claude-sonnet-4-6", "claude-haiku-4-5-20251001",
    ]


def test_extract_model_ids_openrouter_format():
    lines = [
        "Free OpenRouter models (2 total — use these with /agent set model):",
        "",
        "  meta-llama/llama-3.1-8b-instruct:free   Llama 3.1 8B  128k ctx",
        "  google/gemma-2-9b-it:free               Gemma 2 9B    8k ctx",
        "",
        "  All listed models are free (no prompt or completion cost).",
    ]
    assert extract_model_ids(lines) == [
        "meta-llama/llama-3.1-8b-instruct:free",
        "google/gemma-2-9b-it:free",
    ]


def test_extract_model_ids_ignores_prose():
    assert extract_model_ids(["No models returned.", "API error: nope"]) == []
