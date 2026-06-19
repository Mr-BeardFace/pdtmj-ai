_PER_MTOK = {
    "claude-opus-4-7": {
        "input": 15.00, "output": 75.00,
        "cache_read": 1.50, "cache_write": 18.75,
    },
    "claude-sonnet-4-6": {
        "input": 3.00, "output": 15.00,
        "cache_read": 0.30, "cache_write": 3.75,
    },
    "claude-haiku-4-5-20251001": {
        "input": 0.80, "output": 4.00,
        "cache_read": 0.08, "cache_write": 1.00,
    },
}

_FALLBACK = _PER_MTOK["claude-sonnet-4-6"]

# Models we've already warned about — avoid spamming once per API call.
_warned_models: set[str] = set()


def estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    p = _PER_MTOK.get(model)
    if p is None:
        if model not in _warned_models:
            _warned_models.add(model)
            import sys
            print(f"[pricing] no pricing data for {model!r} — "
                  f"estimating at claude-sonnet-4-6 rates", file=sys.stderr)
        p = _FALLBACK
    cost = (
        input_tokens      * p["input"]        / 1_000_000
        + output_tokens   * p["output"]       / 1_000_000
        + cache_read_tokens  * p["cache_read"]  / 1_000_000
        + cache_write_tokens * p["cache_write"] / 1_000_000
    )
    return round(cost, 5)
