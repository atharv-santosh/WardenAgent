"""Provenance / taint tracking for data flowing through the agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Label = Literal["trusted", "untrusted", "declassified"]

_RANK: dict[Label, int] = {"trusted": 0, "declassified": 1, "untrusted": 2}


@dataclass(slots=True)
class Hop:
    """One step in a value's provenance chain."""

    description: str
    label: Label


@dataclass(slots=True)
class Tainted:
    """A value tagged with a provenance label and full lineage."""

    value: Any
    label: Label
    chain: list[Hop] = field(default_factory=list)

    @classmethod
    def trusted(cls, value: Any, origin: str) -> "Tainted":
        return cls(value=value, label="trusted", chain=[Hop(origin, "trusted")])

    @classmethod
    def untrusted(cls, value: Any, origin: str) -> "Tainted":
        return cls(value=value, label="untrusted", chain=[Hop(origin, "untrusted")])

    def derive(self, value: Any, step: str) -> "Tainted":
        """Produce a derived value that inherits this value's label."""
        return Tainted(value=value, label=self.label, chain=[*self.chain, Hop(step, self.label)])

    def declassify(self, reason: str, approved_by: str) -> "Tainted":
        """Explicitly downgrade ``untrusted`` to ``declassified``."""
        if self.label == "trusted":
            raise ValueError("cannot declassify already-trusted data")
        step = f"declassified by {approved_by}: {reason}"
        return Tainted(
            value=self.value,
            label="declassified",
            chain=[*self.chain, Hop(step, "declassified")],
        )

    def chain_description(self) -> str:
        return " -> ".join(f"[{hop.label}] {hop.description}" for hop in self.chain)


def combine(*values: Tainted) -> Tainted:
    """Merge several tainted values into one, taking the least-trusted label."""
    if not values:
        raise ValueError("combine() requires at least one value")
    worst = max(values, key=lambda t: _RANK[t.label])
    chain: list[Hop] = []
    for v in values:
        chain.extend(v.chain)
    return Tainted(value=tuple(v.value for v in values), label=worst.label, chain=chain)


class TaintViolation(Exception):
    """Raised when untrusted data would flow into a privileged sink."""

    def __init__(self, sink: str, arg_name: str, tainted: Tainted) -> None:
        self.sink = sink
        self.arg_name = arg_name
        self.tainted = tainted
        chain = tainted.chain_description()
        super().__init__(
            f"taint violation: untrusted data reached privileged sink "
            f"'{sink}' via argument '{arg_name}'. Provenance chain: {chain}"
        )

    def report(self) -> dict[str, Any]:
        """A structured, loggable description of the violation."""
        return {
            "sink": self.sink,
            "arg_name": self.arg_name,
            "label": self.tainted.label,
            "chain": [{"description": h.description, "label": h.label} for h in self.tainted.chain],
        }


def require_flow(sink: str, arg_name: str, value: Tainted, *, allow_declassified: bool = True) -> None:
    """Enforce the flow rule for one argument of a privileged-sink tool call."""
    if value.label == "untrusted":
        raise TaintViolation(sink, arg_name, value)
    if value.label == "declassified" and not allow_declassified:
        raise TaintViolation(sink, arg_name, value)
