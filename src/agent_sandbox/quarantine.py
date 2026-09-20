"""The quarantined-LLM pattern."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

DIGEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "entities"],
    "properties": {
        "summary": {"type": "string", "maxLength": 400},
        "entities": {
            "type": "array",
            "maxItems": 20,
            "items": {"type": "string", "maxLength": 120, "pattern": r"^[^<>{}\\]*$"},
        },
    },
}

_VALIDATOR = Draft202012Validator(DIGEST_SCHEMA)

_INSTRUCTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)ignore (all |any )?(previous|prior|above) instructions?"),
    re.compile(r"(?i)disregard (the |your |all )?(system|previous|prior) (prompt|instructions?)"),
    re.compile(r"(?i)\bsystem\s*:\s*"),
    re.compile(r"(?i)\bnew instructions?\s*:"),
    re.compile(r"(?i)you (must|should|are required to) (now |immediately )?(call|invoke|run|send|delete|execute|grant)"),
    re.compile(r"(?i)\bassistant\s*:\s*i will"),
    re.compile(r"(?i)override"),
    re.compile(r"(?i)act as (an? )?(admin|root|system|developer)"),
    re.compile(r"(?i)send (this|the|your|all) (data|secret|token|key|credentials?)"),
    re.compile(r"(?i)when you (see|read|encounter) the (word|phrase|token)"),
    re.compile(r"(?i)from now on"),
    re.compile(r"(?i)\bsudo\b"),
    re.compile(r"(?i)base64|rot13|hex[- ]?decode"),
    re.compile(r"(?i)\b(?:call|invoke|run|execute)\s+[a-z_][a-z0-9_]*\s*\("),
    re.compile(r"(?i)(pre-?approved|cleared|declassif\w*)\s+(for|to|by)\b"),
]

_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


def _clean(text: str) -> str:
    return _ZERO_WIDTH.sub("", text)


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


@dataclass(slots=True)
class Digest:
    """The only thing a quarantined extraction is allowed to produce."""

    summary: str
    entities: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "entities": self.entities}


class QuarantineViolation(Exception):
    """Raised when the extractor tried to produce something outside the schema."""


_ENTITY_PATTERN = re.compile(r"\b[A-Z][a-zA-Z0-9_.-]{2,}\b|\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def extract(raw_text: str, *, max_summary_len: int = 400) -> Digest:
    """Run the quarantined extraction over untrusted text."""
    cleaned = _clean(raw_text)
    safe_sentences = [s for s in _split_sentences(cleaned) if not _matches_instruction(s)]
    summary = " ".join(safe_sentences)[:max_summary_len]

    entities: list[str] = []
    for sentence in safe_sentences:
        for match in _ENTITY_PATTERN.findall(sentence):
            trimmed = match[:120]
            if trimmed not in entities:
                entities.append(trimmed)
    entities = entities[:20]

    digest = Digest(summary=summary, entities=entities)
    validate_digest(digest)
    return digest


def _matches_instruction(sentence: str) -> bool:
    return any(p.search(sentence) for p in _INSTRUCTION_PATTERNS)


def validate_digest(digest: Digest) -> None:
    """Validate a :class:`Digest` against :data:`DIGEST_SCHEMA`."""
    try:
        _VALIDATOR.validate(digest.to_dict())
    except ValidationError as exc:
        raise QuarantineViolation(f"quarantine output failed schema validation: {exc.message}") from exc


def contains_instruction_language(text: str) -> bool:
    """Public helper: does this raw text contain instruction-like language?"""
    cleaned = _clean(text)
    return any(_matches_instruction(s) for s in _split_sentences(cleaned))
