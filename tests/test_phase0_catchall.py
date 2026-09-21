"""
Phase 0 tests — Fix the deterministic catch-all in agent.py.

What is tested here:
  - "im sad", "bro my class is killing me", "what's the weather" all return
    out_of_scope (not query_schedule) from classify_intent.
  - Schedule / task / greeting fast-paths are unaffected.
  - _fallback_handle returns action="reply" with intent="out_of_scope" when
    classify_intent returns out_of_scope.
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock


# ── classify_intent tests ──────────────────────────────────────────────────────

class TestClassifyIntentPhase0:
    """No-task-trigger messages must NOT be routed to query_schedule."""

    def test_im_sad_does_not_reach_schedule(self):
        from utils.agent import classify_intent
        result = classify_intent("im sad")
        assert result == "out_of_scope", (
            f"Expected 'out_of_scope', got {result!r}. "
            "The catch-all should no longer force-route to query_schedule."
        )

    def test_bro_my_class_is_killing_me(self):
        """Casual sentence containing 'class' must route to out_of_scope, not query_schedule.
        Phase 1 tightens _is_schedule_query() so single academic words in casual context
        no longer trigger the schedule fast-path."""
        from utils.agent import classify_intent
        result = classify_intent("bro my class is killing me")
        assert result == "out_of_scope", (
            f"Expected 'out_of_scope', got {result!r}. "
            "Casual sentences with academic words must not be routed to schedule queries."
        )

    def test_whats_the_weather(self):
        from utils.agent import classify_intent
        result = classify_intent("what's the weather?")
        # No task trigger, no schedule keyword → out_of_scope
        assert result == "out_of_scope"

    def test_plain_emotional_message(self):
        from utils.agent import classify_intent
        result = classify_intent("I'm feeling really down today")
        assert result == "out_of_scope"

    def test_random_unrelated_message(self):
        from utils.agent import classify_intent
        result = classify_intent("lol that's so funny")
        assert result == "out_of_scope"

    # ── Fast-path preservation checks ─────────────────────────────────────────

    def test_when_is_my_next_class_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("when is my next class?")
        assert result == "query_schedule"

    def test_schedule_keyword_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("who teaches PDC?")
        assert result == "query_schedule"

    def test_quiz_tomorrow_still_goes_to_llm_path(self):
        """Has a task trigger word → passes the no-task-trigger gate and
        would proceed to the LLM path (or classify via LLM). It must not
        return out_of_scope from the deterministic gate alone."""
        from utils.agent import classify_intent
        # The LLM may or may not be available in CI; mock it to return save_task
        with patch("utils.agent._call_groq", return_value='{"intent": "save_task", "reason": "task"}'):
            result = classify_intent("quiz tomorrow")
        assert result == "save_task"

    def test_hello_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("hello")
        assert result == "greeting"

    def test_hi_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("hi")
        assert result == "greeting"

    def test_tasks_query_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("what do i have due today")
        assert result == "query_tasks"

    def test_my_assignments_still_works(self):
        from utils.agent import classify_intent
        result = classify_intent("my assignments")
        assert result == "query_tasks"


# ── _fallback_handle tests ─────────────────────────────────────────────────────

class TestFallbackHandlePhase0:
    """_fallback_handle must return a reply for out_of_scope, not save_task."""

    def test_out_of_scope_handler_returns_reply(self):
        from utils.nlu import _fallback_handle
        with patch("utils.agent.classify_intent", return_value="out_of_scope"):
            result = _fallback_handle(None, "user1", "+92300000", "im sad")
        assert result["action"] == "reply"
        assert result["intent"] == "out_of_scope"
        assert isinstance(result["text"], str) and len(result["text"]) > 0

    def test_out_of_scope_does_not_return_save_task(self):
        from utils.nlu import _fallback_handle
        with patch("utils.agent.classify_intent", return_value="out_of_scope"):
            result = _fallback_handle(None, "user1", "+92300000", "im tired bro")
        assert result["action"] != "save_task", (
            "out_of_scope messages must never silently fall through to save_task."
        )

    def test_greeting_fallback_still_returns_reply(self):
        from utils.nlu import _fallback_handle
        mock_db = MagicMock()
        with patch("utils.agent.classify_intent", return_value="greeting"), \
             patch("utils.agent.handle_agent_query", return_value="Hey! 👋"):
            result = _fallback_handle(mock_db, "user1", "+92300000", "hey")
        assert result["action"] == "reply"
        assert result["intent"] == "greeting"

    def test_query_schedule_fallback_still_works(self):
        from utils.nlu import _fallback_handle
        mock_db = MagicMock()
        with patch("utils.agent.classify_intent", return_value="query_schedule"), \
             patch("utils.agent.handle_agent_query", return_value="Your next class is..."):
            result = _fallback_handle(mock_db, "user1", "+92300000", "when is my next class?")
        assert result["action"] == "reply"
        assert result["intent"] == "query_schedule"

    def test_fallback_exception_still_returns_save_task(self):
        """If classify_intent itself raises, we fall back to save_task sentinel."""
        from utils.nlu import _fallback_handle
        with patch("utils.agent.classify_intent", side_effect=RuntimeError("boom")):
            result = _fallback_handle(None, "user1", "+92300000", "quiz tomorrow")
        assert result["action"] == "save_task"
