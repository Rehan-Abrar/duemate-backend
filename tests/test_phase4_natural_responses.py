"""
Phase 4 Tests: Natural Response Generation & Containment Guard

Verifies LLM #2 response configuration, containment guard validation (preventing invented
times/rooms/teachers), and graceful deterministic fallback.
"""
import os
import sys
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.nlu import (
    response_enabled,
    _containment_guard,
    respond,
    OUT_OF_SCOPE_CASUAL,
)


class TestPhase4ResponseConfig:
    def test_response_enabled_by_default(self, monkeypatch):
        monkeypatch.delenv("NLU_LLM_RESPONSE_ENABLED", raising=False)
        assert response_enabled() is True

    def test_response_can_be_disabled(self, monkeypatch):
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "false")
        assert response_enabled() is False


class TestContainmentGuard:
    def test_containment_guard_passes_same_facts(self):
        det = "Your next class is Database Systems at 10:00 AM in Room 204."
        llm_out = "You have Database Systems at 10:00 AM in Room 204!"
        assert _containment_guard(llm_out, det) is True

    def test_containment_guard_rejects_invented_times(self):
        det = "Your next class is Database Systems at 10:00 AM."
        llm_out = "You have Database Systems at 10:00 AM and another class at 14:00 PM!"
        assert _containment_guard(llm_out, det) is False

    def test_containment_guard_rejects_placeholder_punctuation(self):
        det = "Your instructor for PDC is Dr. Ali."
        llm_out = "Instructor: … 😄 Dr. Ali teaches PDC."
        assert _containment_guard(llm_out, det) is False


class TestRespondFallback:
    def test_respond_returns_deterministic_text_on_failure(self, monkeypatch):
        # Force LLM transport failure by zeroing timeout or invalid call
        monkeypatch.setenv("NLU_LLM_TIMEOUT_SECONDS", "0.001")

        grounded = {
            "intent": "schedule_query",
            "text": "Your next class is Database Systems at 10:00 AM in Room 204.",
            "language": "ur",
        }
        result = respond(grounded)
        # Should safely return grounded text on transport exception
        assert "Database Systems" in result
        assert "10:00 AM" in result
