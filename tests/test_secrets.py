"""Behavioral tests for secret handling and outbound redaction."""

from __future__ import annotations

import pytest

from agent_sandbox.secrets import (
    SecretLeakage,
    SecretStore,
    UnknownSecretHandle,
    redact,
    scan_for_leakage,
)


def test_put_returns_opaque_handle_not_raw_value() -> None:
    store = SecretStore()
    handle = store.put("github_token", "ghp_abcdef123456")
    assert handle == "$SECRET:github_token"
    assert "ghp_abcdef123456" not in handle


def test_resolve_returns_raw_value_only_via_handle() -> None:
    store = SecretStore()
    handle = store.put("api_key", "sk-live-999")
    assert store.resolve(handle) == "sk-live-999"


def test_resolve_unknown_handle_raises() -> None:
    store = SecretStore()
    with pytest.raises(UnknownSecretHandle):
        store.resolve("$SECRET:nonexistent")


def test_redact_replaces_raw_secret_in_text() -> None:
    store = SecretStore({"db_password": "s3cr3t-value"})
    text = "connection string uses password s3cr3t-value for auth"
    redacted, found = redact(text, store)
    assert "s3cr3t-value" not in redacted
    assert "db_password" in found
    assert "[REDACTED:db_password]" in redacted


def test_redact_is_noop_when_no_secret_present() -> None:
    store = SecretStore({"db_password": "s3cr3t-value"})
    text = "nothing sensitive here"
    redacted, found = redact(text, store)
    assert redacted == text
    assert found == []


def test_scan_for_leakage_raises_when_raw_secret_in_tool_argument() -> None:
    store = SecretStore({"api_key": "sk-live-999"})
    with pytest.raises(SecretLeakage):
        scan_for_leakage("send_email", {"body": "here is the key: sk-live-999"}, store)


def test_scan_for_leakage_passes_when_only_handle_is_present() -> None:
    store = SecretStore({"api_key": "sk-live-999"})
    scan_for_leakage("send_email", {"body": "use handle $SECRET:api_key"}, store)


def test_is_handle_recognizes_handle_strings() -> None:
    store = SecretStore({"x": "y"})
    assert store.is_handle("$SECRET:x") is True
    assert store.is_handle("not a handle") is False
    assert store.is_handle(123) is False
