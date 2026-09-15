"""
Tests for utils/nlu.respond() — deterministic fallback, flag, and containment guard.
All offline.
"""
import os
import sys
import pytest
import json
from unittest.mock import MagicMock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.nlu import respond, _containment_guard


# ── _containment_guard ────────────────────────────────────────────────────────

class TestContainmentGuard:
    def test_empty_output_rejected(self):
        assert _containment_guard("", "You have Computer Networks at 2:00 PM.") is False

    def test_whitespace_only_rejected(self):
        assert _containment_guard("   ", "You have class at 2:00 PM.") is False

    def test_invented_time_rejected(self):
        # deterministic text has 2:00, LLM invents 3:00
        assert _containment_guard(
            "Aapki class 3:00 PM hai.",
            "Your class is at 2:00 PM.",
        ) is False

    def test_same_times_accepted(self):
        assert _containment_guard(
            "Aapki Computer Networks 2:00 PM par hai.",
            "Your Computer Networks class is at 2:00 PM.",
        ) is True

    def test_no_times_accepted(self):
        assert _containment_guard(
            "You're free on Monday! Great.",
            "No classes on Monday. You're free.",
        ) is True

    def test_suspiciously_short_rejected(self):
        # Short response vs long deterministic
        long_det = "You have Computer Networks at 2:00 PM in Lab 1 on Monday.\n" * 3
        short_llm = "ok"
        assert _containment_guard(short_llm, long_det) is False

    def test_acceptable_shorter_rephrasing_passes(self):
        det = "You have Computer Networks at 2:00 PM in Lab 1."
        llm = "CN 2:00 PM Lab 1 hai."
        assert _containment_guard(llm, det) is True


# ── respond() — flag disabled ─────────────────────────────────────────────────

class TestRespondFlagOff:
    def test_flag_off_returns_deterministic(self, monkeypatch):
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "false")
        grounded = {"kind": "schedule_query", "text": "Next class: CN at 2:00 PM.", "language": "mixed", "no_timetable": False}
        result = respond(grounded)
        assert result == "Next class: CN at 2:00 PM."

    def test_flag_off_even_for_urdu(self, monkeypatch):
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "false")
        grounded = {"kind": "schedule_query", "text": "No classes today.", "language": "ur", "no_timetable": False}
        assert respond(grounded) == "No classes today."


# ── respond() — flag enabled ──────────────────────────────────────────────────

class TestRespondFlagOn:
    def _make_groq_response(self, content: str):
        m = MagicMock()
        m.raise_for_status.return_value = None
        m.json.return_value = {
            "choices": [{"message": {"content": content}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
        }
        return m

    def test_english_bypasses_llm_even_with_flag_on(self, monkeypatch):
        """English responses skip LLM #2 (cost saving) regardless of flag."""
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        grounded = {"kind": "schedule_query", "text": "Next class: CN at 2:00 PM.", "language": "en", "no_timetable": False}
        result = respond(grounded)
        # Should return deterministic text without calling Groq
        assert result == "Next class: CN at 2:00 PM."

    def test_urdu_calls_llm_and_returns_rephrased(self, monkeypatch):
        import requests as req
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        expected_reply = "Aapki agly class *Computer Networks* 2:00 PM par hai."
        monkeypatch.setattr(
            req, "post",
            lambda *a, **kw: self._make_groq_response(expected_reply),
        )
        grounded = {
            "kind": "schedule_query",
            "text": "Next class:\nComputer Networks\nMonday, 2:00 PM - 3:30 PM\nRoom: Lab 1\nInstructor: Dr. Ahsan",
            "language": "ur",
            "no_timetable": False,
        }
        result = respond(grounded)
        assert result == expected_reply

    def test_llm_invents_time_falls_back_to_deterministic(self, monkeypatch):
        import requests as req
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        # LLM invents 5:00 — not in deterministic text which has 2:00
        bad_reply = "Aapki class 5:00 PM par hai."
        monkeypatch.setattr(req, "post", lambda *a, **kw: self._make_groq_response(bad_reply))
        deterministic = "Next class: CN at 2:00 PM."
        grounded = {"kind": "schedule_query", "text": deterministic, "language": "ur", "no_timetable": False}
        result = respond(grounded)
        assert result == deterministic  # guard rejects → fallback

    def test_llm_failure_returns_deterministic(self, monkeypatch):
        import requests as req
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        monkeypatch.setattr(req, "post", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("timeout")))
        deterministic = "No classes today."
        grounded = {"kind": "schedule_query", "text": deterministic, "language": "ur", "no_timetable": False}
        result = respond(grounded)
        assert result == deterministic

    def test_empty_deterministic_returns_empty(self, monkeypatch):
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        grounded = {"kind": "save_task", "text": "", "language": "mixed", "no_timetable": False}
        assert respond(grounded) == ""

    def test_no_timetable_skips_llm(self, monkeypatch):
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        det = "You haven't uploaded a timetable yet. Please visit your dashboard."
        grounded = {"kind": "schedule_query", "text": det, "language": "ur", "no_timetable": True}
        result = respond(grounded)
        assert result == det  # guidance messages must not be rephrased

    def test_greeting_skips_llm(self, monkeypatch):
        """Greeting reply is pre-formatted — skip LLM #2."""
        monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "true")
        grounded = {"kind": "greeting", "text": "Hey! 👋 ...", "language": "ur", "no_timetable": False}
        result = respond(grounded)
        assert result == "Hey! 👋 ..."
