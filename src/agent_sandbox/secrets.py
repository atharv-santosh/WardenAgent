"""Secret handling: credentials never enter model context."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_HANDLE_PATTERN = re.compile(r"^\$SECRET:([A-Za-z0-9_.-]+)$")


class SecretError(Exception):
    """Base class for secret-handling failures."""


class UnknownSecretHandle(SecretError):
    pass


class SecretLeakage(SecretError):
    """Raised when a raw secret value is found somewhere it must not be."""

    def __init__(self, handle: str, location: str) -> None:
        self.handle = handle
        self.location = location
        super().__init__(f"raw value of secret '{handle}' found in {location}; leakage blocked")


@dataclass(slots=True)
class SecretStore:
    """Holds raw secret values, addressable only by handle."""

    _values: dict[str, str]

    def __init__(self, values: dict[str, str] | None = None) -> None:
        self._values = dict(values or {})

    def put(self, name: str, value: str) -> str:
        """Register a secret and return its handle string."""
        self._values[name] = value
        return f"$SECRET:{name}"

    def handle_for(self, name: str) -> str:
        if name not in self._values:
            raise UnknownSecretHandle(name)
        return f"$SECRET:{name}"

    def resolve(self, handle: str) -> str:
        """Resolve a handle to its raw value. Called only inside tool execution."""
        match = _HANDLE_PATTERN.match(handle)
        if not match:
            raise UnknownSecretHandle(handle)
        name = match.group(1)
        if name not in self._values:
            raise UnknownSecretHandle(name)
        return self._values[name]

    def is_handle(self, value: Any) -> bool:
        return isinstance(value, str) and bool(_HANDLE_PATTERN.match(value))

    def raw_values(self) -> dict[str, str]:
        """All known raw secret values, keyed by name -- used only for redaction scans."""
        return dict(self._values)


def redact(text: str, store: SecretStore) -> tuple[str, list[str]]:
    """Replace any raw secret value found in ``text`` with a redaction marker."""
    found: list[str] = []
    redacted = text
    for name, value in store.raw_values().items():
        if value and value in redacted:
            redacted = redacted.replace(value, f"[REDACTED:{name}]")
            found.append(name)
    return redacted, found


def scan_for_leakage(tool_name: str, args: dict[str, Any], store: SecretStore) -> None:
    """Raise :class:`SecretLeakage` if any argument contains a raw secret value."""
    for arg_name, value in args.items():
        if not isinstance(value, str):
            continue
        for name, raw in store.raw_values().items():
            if raw and raw in value:
                raise SecretLeakage(name, f"argument '{arg_name}' of tool '{tool_name}'")
