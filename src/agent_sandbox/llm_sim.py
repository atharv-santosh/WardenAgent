"""Deterministic, offline simulated agent "brain"."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any

from agent_sandbox.quarantine import Digest, _clean


DIGEST_SUMMARY_PLACEHOLDER = "{{DIGEST_SUMMARY}}"
DIGEST_ENTITY_PLACEHOLDER = "{{DIGEST_ENTITY}}"


@dataclass(slots=True)
class ToolCallIntent:
    """A decision by the simulated brain to call a tool."""

    tool: str
    args: dict[str, Any]
    triggered_by: str
    source: str = "trusted"
    arg_sources: dict[str, str] = None  # type: ignore[assignment]  # per-arg override; see below

    def __post_init__(self) -> None:
        if self.arg_sources is None:
            self.arg_sources = {name: self.source for name in self.args}

    def source_of(self, arg_name: str) -> str:
        """Provenance tag for one argument: ``"trusted"``, ``"untrusted"``, ``"untrusted_digest_summary"``, or ``"untrusted_digest_entity"``."""
        return self.arg_sources.get(arg_name, self.source)


_DIRECTIVE_RE = re.compile(
    r"(?i)\b(?:call|invoke|run|execute)\s+([a-z_][a-z0-9_]*)\s*\(([^)]*)\)"
)


def _parse_directive_args(raw_args: str) -> dict[str, str]:
    args: dict[str, str] = {}
    for part in raw_args.split(","):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        args[key.strip()] = value.strip().strip("'\"")
    return args


def _try_base64_decode(text: str) -> str | None:
    candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            return decoded
    return None


def find_directive(text: str, source: str = "trusted") -> ToolCallIntent | None:
    """Look for an embedded tool-call directive in raw text."""
    cleaned = _clean(text)
    match = _DIRECTIVE_RE.search(cleaned)
    if match:
        tool, raw_args = match.group(1), match.group(2)
        return ToolCallIntent(
            tool=tool,
            args=_parse_directive_args(raw_args),
            triggered_by=match.group(0),
            source=source,
        )
    return None


def naive_decide(context_text: str) -> ToolCallIntent | None:
    """The undefended brain: scans raw text, decodes base64, obeys directives."""
    intent = find_directive(context_text, source="untrusted")
    if intent is not None:
        return intent
    decoded = _try_base64_decode(context_text)
    if decoded is not None:
        return find_directive(decoded, source="untrusted")
    return None


def _apply_digest_placeholders(intent: ToolCallIntent, digests: list[Digest]) -> ToolCallIntent:
    """Fill any digest placeholder in a *trusted* directive's arguments."""
    if not digests:
        return intent
    args = dict(intent.args)
    arg_sources = dict(intent.arg_sources)
    changed = False
    for name, value in intent.args.items():
        if value == DIGEST_SUMMARY_PLACEHOLDER:
            args[name] = digests[0].summary
            arg_sources[name] = "untrusted_digest_summary"
            changed = True
        elif value == DIGEST_ENTITY_PLACEHOLDER:
            args[name] = digests[0].entities[0] if digests[0].entities else ""
            arg_sources[name] = "untrusted_digest_entity"
            changed = True
    if not changed:
        return intent
    return ToolCallIntent(
        tool=intent.tool,
        args=args,
        triggered_by=intent.triggered_by,
        source=intent.source,
        arg_sources=arg_sources,
    )


def sandboxed_decide(trusted_text: str, digests: list[Digest]) -> ToolCallIntent | None:
    """The sandboxed brain: only ever sees trusted text and quarantine digests."""
    intent = find_directive(trusted_text, source="trusted")
    if intent is not None:
        return _apply_digest_placeholders(intent, digests)
    for digest in digests:
        intent = find_directive(digest.summary, source="untrusted")
        if intent is not None:
            return intent
        for entity in digest.entities:
            intent = find_directive(entity, source="untrusted")
            if intent is not None:
                return intent
    return None
