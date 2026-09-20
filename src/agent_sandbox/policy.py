"""Declarative, deny-by-default policy engine."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from agent_sandbox.taint import Tainted, TaintViolation, require_flow


@dataclass(slots=True)
class ArgSpec:
    """Permitted shape for a single tool argument."""

    type: str = "string"
    pattern: str | None = None
    enum: list[str] | None = None
    roots: list[str] | None = None
    max_length: int | None = None


@dataclass(slots=True)
class ToolPolicy:
    """Policy for a single tool."""

    name: str
    allow: bool = False
    requires_approval: bool = False
    sink: bool = False
    args: dict[str, ArgSpec] = field(default_factory=dict)
    network_hosts: list[str] | None = None
    network_schemes: list[str] | None = None
    max_calls: int | None = None


@dataclass(slots=True)
class Decision:
    """The outcome of evaluating one tool call against the policy."""

    allow: bool
    rule: str
    reason: str
    requires_approval: bool = False
    tool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "rule": self.rule,
            "reason": self.reason,
            "requires_approval": self.requires_approval,
            "tool": self.tool,
        }


class PolicyError(Exception):
    """Malformed policy file."""


def _load_arg_spec(raw: dict[str, Any]) -> ArgSpec:
    return ArgSpec(
        type=raw.get("type", "string"),
        pattern=raw.get("pattern"),
        enum=raw.get("enum"),
        roots=raw.get("roots"),
        max_length=raw.get("max_length"),
    )


@dataclass(slots=True)
class Policy:
    """A fully parsed policy document."""

    default_deny: bool
    tools: dict[str, ToolPolicy]
    max_total_calls: int | None = None

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise PolicyError("policy document must be a mapping")
        default = raw.get("default", "deny")
        if default not in ("deny", "allow"):
            raise PolicyError("'default' must be 'deny' or 'allow'")
        tools: dict[str, ToolPolicy] = {}
        for name, spec in (raw.get("tools") or {}).items():
            spec = spec or {}
            args = {k: _load_arg_spec(v or {}) for k, v in (spec.get("args") or {}).items()}
            network = spec.get("network") or {}
            tools[name] = ToolPolicy(
                name=name,
                allow=bool(spec.get("allow", False)),
                requires_approval=bool(spec.get("requires_approval", False)),
                sink=bool(spec.get("sink", False)),
                args=args,
                network_hosts=network.get("hosts"),
                network_schemes=network.get("schemes"),
                max_calls=spec.get("max_calls"),
            )
        budgets = raw.get("budgets") or {}
        return cls(
            default_deny=(default == "deny"),
            tools=tools,
            max_total_calls=budgets.get("max_total_calls"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_yaml(Path(path).read_text(encoding="utf-8"))


def _validate_path_jail(value: str, roots: list[str]) -> tuple[bool, str]:
    try:
        resolved = PurePosixPath(value)
        if not resolved.is_absolute():
            resolved = PurePosixPath("/") / resolved
        parts: list[str] = []
        for part in resolved.parts:
            if part == "..":
                if parts:
                    parts.pop()
            elif part not in (".", "/"):
                parts.append(part)
        normalized = "/" + "/".join(parts)
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"unparseable path: {exc}"
    for root in roots:
        root_norm = root.rstrip("/")
        if normalized == root_norm or normalized.startswith(root_norm + "/"):
            return True, normalized
    return False, normalized


def _validate_network(url: str, hosts: list[str], schemes: list[str]) -> tuple[bool, str]:
    parts = urlsplit(url)
    if parts.scheme not in schemes:
        return False, f"scheme '{parts.scheme}' not in allowlist {schemes}"
    hostname = (parts.hostname or "").lower()
    try:
        ipaddress.ip_address(hostname)
        return False, f"IP-literal host '{hostname}' is not permitted"
    except ValueError:
        pass
    for allowed in hosts:
        allowed = allowed.lower()
        if hostname == allowed or hostname.endswith("." + allowed):
            return True, hostname
    return False, f"host '{hostname}' not in allowlist {hosts}"


class PolicyEngine:
    """Evaluates tool calls against a :class:`Policy`, deny-by-default."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._call_counts: dict[str, int] = {}
        self._total_calls = 0

    def evaluate(self, tool_name: str, args: dict[str, Any]) -> Decision:
        """Evaluate argument shape, budgets, and existence -- not taint."""
        tool = self.policy.tools.get(tool_name)
        if tool is None or not tool.allow:
            return Decision(
                allow=False,
                rule=f"default:{'deny' if self.policy.default_deny else 'allow'}",
                reason=f"tool '{tool_name}' is not in the policy allowlist",
                tool=tool_name,
            )

        if self.policy.max_total_calls is not None and self._total_calls >= self.policy.max_total_calls:
            return Decision(
                allow=False,
                rule="budget:max_total_calls",
                reason=f"run exceeded max_total_calls={self.policy.max_total_calls}",
                tool=tool_name,
            )
        if tool.max_calls is not None and self._call_counts.get(tool_name, 0) >= tool.max_calls:
            return Decision(
                allow=False,
                rule=f"budget:{tool_name}.max_calls",
                reason=f"tool '{tool_name}' exceeded max_calls={tool.max_calls}",
                tool=tool_name,
            )

        for arg_name, spec in tool.args.items():
            if arg_name not in args:
                continue
            value = args[arg_name]
            ok, detail = self._check_arg(spec, value)
            if not ok:
                return Decision(
                    allow=False,
                    rule=f"arg_shape:{tool_name}.{arg_name}",
                    reason=f"argument '{arg_name}' rejected: {detail}",
                    tool=tool_name,
                )

        if tool.network_hosts is not None:
            url_arg = args.get("url")
            if url_arg is None:
                return Decision(
                    allow=False,
                    rule=f"network:{tool_name}",
                    reason="tool has a network policy but call has no 'url' argument",
                    tool=tool_name,
                )
            ok, detail = _validate_network(url_arg, tool.network_hosts, tool.network_schemes or ["https"])
            if not ok:
                return Decision(
                    allow=False,
                    rule=f"network_allowlist:{tool_name}",
                    reason=f"network egress rejected: {detail}",
                    tool=tool_name,
                )

        self._call_counts[tool_name] = self._call_counts.get(tool_name, 0) + 1
        self._total_calls += 1
        return Decision(
            allow=True,
            rule=f"tool_allow:{tool_name}",
            reason=f"tool '{tool_name}' permitted by policy",
            requires_approval=tool.requires_approval,
            tool=tool_name,
        )

    def _check_arg(self, spec: ArgSpec, value: Any) -> tuple[bool, str]:
        if spec.type == "path_jail":
            if not isinstance(value, str):
                return False, "expected string path"
            if not spec.roots:
                return False, "path_jail spec has no roots configured"
            return _validate_path_jail(value, spec.roots)
        if spec.max_length is not None and isinstance(value, str) and len(value) > spec.max_length:
            return False, f"exceeds max_length={spec.max_length}"
        if spec.enum is not None and value not in spec.enum:
            return False, f"'{value}' not in enum {spec.enum}"
        if spec.pattern is not None:
            if not isinstance(value, str) or not re.match(spec.pattern, value):
                return False, f"does not match pattern {spec.pattern!r}"
        return True, "ok"

    def check_taint_flow(self, tool_name: str, tainted_args: dict[str, Tainted]) -> None:
        """Raise :class:`TaintViolation` if a sink tool receives untrusted data."""
        tool = self.policy.tools.get(tool_name)
        if tool is None or not tool.sink:
            return
        for arg_name, tainted in tainted_args.items():
            require_flow(tool_name, arg_name, tainted)

    def is_sink(self, tool_name: str) -> bool:
        tool = self.policy.tools.get(tool_name)
        return bool(tool and tool.sink)

    def requires_approval(self, tool_name: str) -> bool:
        tool = self.policy.tools.get(tool_name)
        return bool(tool and tool.requires_approval)
