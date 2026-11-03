"""Token cost estimation — provider-aware.

Anthropic direct / anthropic-sub: hardcoded table (no per-request pricing API).
Bedrock: live query via AWS Pricing API, cached per model for the session.
"""
from __future__ import annotations

import json
import sys

# ── Anthropic direct rates (per 1M tokens) ──────────────────────────────────
_ANTHROPIC_PER_MTOK: dict[str, dict[str, float]] = {
    "claude-opus-4-7": {
        "input": 15.00, "output": 75.00,
        "cache_read": 1.50, "cache_write": 18.75,
    },
    "claude-sonnet-4-6": {
        "input": 3.00, "output": 15.00,
        "cache_read": 0.30, "cache_write": 3.75,
    },
    "claude-haiku-5-5": {
        "input": 0.10, "output": 0.50,
        "cache_read": 0.01, "cache_write": 0.0125,
    },
    "claude-haiku-4-5-20251001": {
        "input": 0.80, "output": 4.00,
        "cache_read": 0.08, "cache_write": 1.00,
    },
}

_FALLBACK = _ANTHROPIC_PER_MTOK["claude-sonnet-4-6"]

# Session-level caches
_bedrock_cache: dict[str, dict[str, float]] = {}
_warned_models: set[str] = set()
_bedrock_unavailable = False


# ── Bedrock live pricing ─────────────────────────────────────────────────────

def _canonical(model: str) -> str:
    """Strip Bedrock region/vendor prefix → canonical model name.
    'us.anthropic.claude-sonnet-4-6' → 'claude-sonnet-4-6'"""
    parts = model.rsplit(".", 1)
    return parts[-1] if len(parts) > 1 and parts[-1].startswith("claude-") else model


def _bedrock_pricing_model_id(model: str) -> str:
    """Convert a canonical model name to the Bedrock Pricing API's modelId format.
    The Pricing API uses 'anthropic.claude-sonnet-4-6-v1:0' style IDs — vendor
    prefix, version suffix. We search without the version suffix to be resilient."""
    canon = _canonical(model)
    return f"anthropic.{canon}"


_USAGE_TYPE_MAP = {
    "InputToken":      "input",
    "OutputToken":     "output",
    "CacheReadInput":  "cache_read",
    "CacheWriteInput": "cache_write",
}


def _parse_usage_type(usage_type: str) -> str | None:
    """Extract the pricing dimension from a Bedrock usagetype string.
    e.g. 'USE1-InferenceInputToken' → 'input'"""
    for fragment, key in _USAGE_TYPE_MAP.items():
        if fragment in usage_type:
            return key
    return None


def _query_bedrock_pricing(model: str, region_name: str = "us-east-1") -> dict[str, float] | None:
    """Query AWS Pricing API for Bedrock token rates. Returns per-1M-token dict
    or None on failure. The Pricing API is only in us-east-1 / ap-south-1."""
    global _bedrock_unavailable
    if _bedrock_unavailable:
        return None
    try:
        import boto3
    except ImportError:
        _bedrock_unavailable = True
        print("[pricing] boto3 not available — cannot query Bedrock pricing",
              file=sys.stderr)
        return None

    search_id = _bedrock_pricing_model_id(model)
    try:
        client = boto3.client("pricing", region_name=region_name)
        paginator = client.get_paginator("get_products")
        pages = paginator.paginate(
            ServiceCode="AmazonBedrock",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "modelId", "Value": search_id},
            ],
            FormatVersion="aws_v1",
        )

        rates: dict[str, float] = {}
        for page in pages:
            for price_json in page["PriceList"]:
                item = json.loads(price_json)
                attrs = item.get("product", {}).get("attributes", {})
                usage_type = attrs.get("usagetype", "")
                dim = _parse_usage_type(usage_type)
                if dim is None:
                    continue
                # Already have this dimension (first region match wins)
                if dim in rates:
                    continue
                for term in item.get("terms", {}).get("OnDemand", {}).values():
                    for pd in term.get("priceDimensions", {}).values():
                        usd = float(pd["pricePerUnit"].get("USD", "0"))
                        # AWS prices are per-token; convert to per-1M-token
                        rates[dim] = usd * 1_000_000
                        break
                    break

        if not rates:
            return None
        # Fill missing dimensions with 0 (e.g. model doesn't support caching)
        for key in ("input", "output", "cache_read", "cache_write"):
            rates.setdefault(key, 0.0)
        return rates

    except Exception as e:
        if model not in _warned_models:
            print(f"[pricing] Bedrock pricing query failed for {model!r}: {e}",
                  file=sys.stderr)
        return None


def _get_bedrock_rates(model: str) -> dict[str, float]:
    """Cached Bedrock rate lookup. Falls back to Anthropic table on failure."""
    canon = _canonical(model)
    if canon in _bedrock_cache:
        return _bedrock_cache[canon]

    rates = _query_bedrock_pricing(model)
    if rates:
        _bedrock_cache[canon] = rates
        return rates

    # Fallback: try the Anthropic table by canonical name
    fallback = _ANTHROPIC_PER_MTOK.get(canon)
    if fallback:
        _bedrock_cache[canon] = fallback
        return fallback

    if model not in _warned_models:
        _warned_models.add(model)
        print(f"[pricing] no pricing data for {model!r} — "
              f"estimating at claude-sonnet-4-6 rates", file=sys.stderr)
    _bedrock_cache[canon] = _FALLBACK
    return _FALLBACK


# ── Public API ───────────────────────────────────────────────────────────────

def _get_rates(model: str) -> dict[str, float]:
    """Resolve per-1M-token rates for a model, provider-aware."""
    from core.config import load_config
    provider = load_config().get("active_provider", "anthropic")

    if provider.startswith("bedrock"):
        return _get_bedrock_rates(model)

    # Anthropic direct, anthropic-sub, or unknown — use the static table
    canon = _canonical(model)
    p = _ANTHROPIC_PER_MTOK.get(canon)
    if p is not None:
        return p

    if model not in _warned_models:
        _warned_models.add(model)
        print(f"[pricing] no pricing data for {model!r} — "
              f"estimating at claude-sonnet-4-6 rates", file=sys.stderr)
    return _FALLBACK


def estimate_cost(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    p = _get_rates(model)
    cost = (
        input_tokens         * p["input"]       / 1_000_000
        + output_tokens      * p["output"]      / 1_000_000
        + cache_read_tokens  * p["cache_read"]  / 1_000_000
        + cache_write_tokens * p["cache_write"] / 1_000_000
    )
    return round(cost, 5)
