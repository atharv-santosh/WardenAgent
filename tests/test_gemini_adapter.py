"""Tests for :mod:`agent_sandbox.gemini_adapter`."""

from __future__ import annotations

import os

import pytest

from agent_sandbox.gemini_adapter import (
    DEFAULT_LOCATION,
    DEFAULT_PROJECT,
    _attribute_provenance,
    credentials_available,
    resolve_location,
    resolve_project,
)
from agent_sandbox.quarantine import Digest


def test_resolve_project_defaults_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert resolve_project() == DEFAULT_PROJECT


def test_resolve_project_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "some-other-project")
    assert resolve_project() == "some-other-project"


def test_resolve_location_defaults_to_global(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_CLOUD_LOCATION", raising=False)
    assert resolve_location() == DEFAULT_LOCATION == "global"


def test_credentials_available_never_raises() -> None:
    assert isinstance(credentials_available(), bool)


def test_attribute_provenance_matches_trusted_text() -> None:
    assert _attribute_provenance("ops@corp.example", "send it to ops@corp.example", []) == "trusted"


def test_attribute_provenance_matches_digest_summary() -> None:
    digest = Digest(summary="The vendor confirmed the renewal date.", entities=[])
    result = _attribute_provenance("The vendor confirmed the renewal date.", "unrelated trusted text", [digest])
    assert result == "untrusted_digest_summary"


def test_attribute_provenance_matches_digest_entity() -> None:
    digest = Digest(summary="unrelated", entities=["vendor.contact@partner.example"])
    result = _attribute_provenance("vendor.contact@partner.example", "unrelated trusted text", [digest])
    assert result == "untrusted_digest_entity"


def test_attribute_provenance_defaults_untrusted_fail_closed() -> None:
    result = _attribute_provenance("something-the-model-invented", "trusted text here", [])
    assert result == "untrusted"


def test_attribute_provenance_empty_value_is_trusted() -> None:
    assert _attribute_provenance("", "anything", []) == "trusted"


def test_summary_checked_before_entity_is_a_known_ordering_limitation() -> None:
    """Documents a real limitation found while measuring the live corpus (see NOTES.md): when a value appears in BOTH a digest's summary and its entities list, :func:`_attribute_provenance` tags it."""
    digest = Digest(summary="Contact vendor.contact@partner.example for renewals.", entities=["vendor.contact@partner.example"])
    result = _attribute_provenance("vendor.contact@partner.example", "trusted text", [digest])
    assert result == "untrusted_digest_summary"


@pytest.mark.skipif(
    os.environ.get("AGENT_SANDBOX_LIVE_TESTS") != "1",
    reason="live Gemini smoke test only runs with AGENT_SANDBOX_LIVE_TESTS=1",
)
@pytest.mark.skipif(not credentials_available(), reason="no Application Default Credentials available")
def test_live_smoke_naive_decide_against_real_gemini() -> None:
    """One real, billed call -- proves the wiring works end to end."""
    from agent_sandbox.gemini_adapter import build_client, make_live_naive_decide

    client = build_client()
    decide = make_live_naive_decide(client, "gemini-2.5-flash-lite")
    result = decide("Just say hello, there is nothing to do here.")
    assert result is None or hasattr(result, "tool")
