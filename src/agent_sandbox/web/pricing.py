"""Rough, clearly-labeled cost estimation for real Gemini calls."""

from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_MODELS: list[str] = [
    "gemini-2.5-flash-lite",
    "gemini-2.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-3.6-flash",
]

DEFAULT_MODEL = SUPPORTED_MODELS[0]


@dataclass(frozen=True, slots=True)
class ModelPrice:
    input_per_million: float
    output_per_million: float
    note: str = ""


_FALLBACK = ModelPrice(0.30, 2.50, note="no published price for this model id; using a conservative fallback")

_PRICES: dict[str, ModelPrice] = {
    "gemini-2.5-flash-lite": ModelPrice(0.10, 0.40),
    "gemini-2.5-flash": ModelPrice(0.30, 2.50),
    "gemini-3.5-flash-lite": ModelPrice(0.10, 0.40, note="unpublished model id; price is an estimate by analogy to 2.5 Flash-Lite"),
    "gemini-3.6-flash": ModelPrice(0.30, 2.50, note="unpublished model id; price is an estimate by analogy to 2.5 Flash"),
}

ESTIMATED_TOKENS_PER_CALL = 550


def price_for(model: str) -> ModelPrice:
    return _PRICES.get(model, _FALLBACK)


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    price = price_for(model)
    return (input_tokens / 1_000_000) * price.input_per_million + (
        output_tokens / 1_000_000
    ) * price.output_per_million


def rough_precall_estimate(model: str, num_calls: int) -> dict[str, float | int]:
    """Cost estimate shown *before* a corpus run starts, from call-count alone."""
    total_tokens = num_calls * ESTIMATED_TOKENS_PER_CALL
    input_tokens = int(total_tokens * 0.7)
    output_tokens = total_tokens - input_tokens
    cost = estimate_cost_usd(model, input_tokens, output_tokens)
    return {
        "num_calls": num_calls,
        "estimated_tokens": total_tokens,
        "estimated_cost_usd": round(cost, 4),
    }
