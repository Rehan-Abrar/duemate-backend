"""
Phase 1 tests — Enable LLM routing + section_set intent + tightened fallback classifier.

What is tested here:

A. Tightened _is_schedule_query():
   - Casual messages with academic words are now out_of_scope, not query_schedule.
   - Genuine schedule questions still fire the fast-path correctly.

B. LLM routing is enabled by default (NLU_LLM_ROUTING_ENABLED default = true).

C. _clamp_request accepts and parses section_set intent.

D. validate_and_resolve_section():
   - Bare identifiers always ambiguous.
   - Valid full sections pass.
   - Unknown sections return not_found + suggestions.

E. _handle_section_set multi-turn flow:
   - Bare "7B" → ask clarification, saves pending_section.
   - Next message "BSCS" combined with pending suffix "7B" → tries "BSCS-7B".

F. _fallback_handle routing flag parity (routing off → _fallback_handle used).
"""

from __future__ import annotations

import os
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock


# ── A. Tightened _is_schedule_query ──────────────────────────────────────────

class TestTightenedScheduleQuery:
    """Single academic words in casual sentences no longer trigger schedule fast-path."""

    def test_bro_my_class_is_killing_me_is_out_of_scope(self):
        from utils.agent import classify_intent
        assert classify_intent("bro my class is killing me") == "out_of_scope"

    def test_stressed_about_assignment_is_out_of_scope(self):
        """'stressed about my assignment' contains the task-trigger word 'assignment',
        so the deterministic classifier passes it to the LLM. The LLM correctly returns
        out_of_scope. We test via the full pipeline with LLM mocked."""
        import utils.nlu as nlu_mod
        with patch.object(nlu_mod, "understand",
                          return_value={"intent": "out_of_scope", "language": "en", "confidence": 0.90,
                                        "out_of_scope": {"kind": "casual", "topic": None}}):
            result = nlu_mod.handle_message(None, "u1", "+92300", "I'm stressed about my assignment")
        assert result["intent"] == "out_of_scope"
        assert result["action"] == "reply"

    def test_i_hate_having_8am_class_is_out_of_scope(self):
        from utils.agent import classify_intent
        assert classify_intent("I hate having an 8am class") == "out_of_scope"

    def test_this_lecture_is_boring_is_out_of_scope(self):
        from utils.agent import classify_intent
        assert classify_intent("this lecture is so boring") == "out_of_scope"

    # Genuine schedule questions still work
    def test_when_is_my_next_class_still_schedule(self):
        from utils.agent import classify_intent
        assert classify_intent("when is my next class?") == "query_schedule"

    def test_who_teaches_pdc_still_schedule(self):
        from utils.agent import classify_intent
        assert classify_intent("who teaches PDC?") == "query_schedule"

    def test_timetable_keyword_still_schedule(self):
        from utils.agent import classify_intent
        assert classify_intent("show my timetable") == "query_schedule"

    def test_kab_hai_urdu_still_schedule(self):
        from utils.agent import classify_intent
        assert classify_intent("CN kab hai?") == "query_schedule"

    def test_monday_class_still_schedule(self):
        from utils.agent import classify_intent
        # "kal class hai?" — has day + class with question context
        assert classify_intent("kal class schedule hai?") == "query_schedule"

    def test_next_class_phrase_still_schedule(self):
        from utils.agent import classify_intent
        assert classify_intent("next class kab hai?") == "query_schedule"


# ── B. Routing enabled by default ────────────────────────────────────────────

class TestRoutingEnabledByDefault:
    """NLU_LLM_ROUTING_ENABLED must default to True in Phase 1."""

    def test_default_is_now_true(self):
        # Unset the env var and check default
        env = dict(os.environ)
        env.pop("NLU_LLM_ROUTING_ENABLED", None)
        with patch.dict(os.environ, env, clear=True):
            # Re-import to get fresh evaluation of default
            import importlib
            import utils.nlu as nlu_mod
            importlib.reload(nlu_mod)
            assert nlu_mod.routing_enabled() is True

    def test_can_still_override_to_false(self):
        import utils.nlu as nlu_mod
        with patch.dict(os.environ, {"NLU_LLM_ROUTING_ENABLED": "false"}):
            assert nlu_mod.routing_enabled() is False

    def test_dispatch_uses_handle_message_when_routing_on(self):
        import utils.nlu as nlu_mod
        with patch.object(nlu_mod, "routing_enabled", return_value=True), \
             patch.object(nlu_mod, "handle_message", return_value={"action": "reply", "text": "ok", "intent": "greeting"}) as mock_hm:
            nlu_mod.dispatch_message(None, "u1", "+92300", "hi")
        mock_hm.assert_called_once()

    def test_dispatch_uses_fallback_when_routing_off(self):
        import utils.nlu as nlu_mod
        with patch.object(nlu_mod, "routing_enabled", return_value=False), \
             patch.object(nlu_mod, "_fallback_handle", return_value={"action": "reply", "text": "hi", "intent": "greeting"}) as mock_fb:
            nlu_mod.dispatch_message(None, "u1", "+92300", "hi")
        mock_fb.assert_called_once()


# ── C. _clamp_request section_set ────────────────────────────────────────────

class TestClampRequestSectionSet:

    def test_section_set_valid_input(self):
        from utils.nlu import _clamp_request
        result = _clamp_request({
            "intent": "section_set",
            "language": "en",
            "section": {"raw": "BSCS-7A"},
            "confidence": 0.97,
        })
        assert result["intent"] == "section_set"
        assert result["section"]["raw"] == "BSCS-7A"

    def test_section_set_bare_still_passed_through(self):
        """Bare sections are passed through by _clamp_request; validation happens in application code."""
        from utils.nlu import _clamp_request
        result = _clamp_request({
            "intent": "section_set",
            "language": "en",
            "section": {"raw": "7B"},
            "confidence": 0.95,
        })
        assert result["intent"] == "section_set"
        assert result["section"]["raw"] == "7B"

    def test_unknown_intent_clamped_to_out_of_scope(self):
        from utils.nlu import _clamp_request
        result = _clamp_request({"intent": "made_up_intent", "language": "en", "confidence": 0.9})
        assert result["intent"] == "out_of_scope"


# ── D. validate_and_resolve_section ──────────────────────────────────────────

class TestValidateAndResolveSection:

    def _make_db(self, sections):
        """Build a minimal mock db with official_timetables containing `sections`."""
        db = MagicMock()
        now = datetime.now(timezone.utc)
        doc = {
            "status": "published",
            "detected_sections": sections,
            "effective_from": now - timedelta(days=1),
            "effective_to": None,
            "sections": {s: [{"day": "Monday", "course": "Test", "time": "09:00"}] for s in sections},
        }
        db.official_timetables.find_one.return_value = doc
        # aggregate for bare-suffix lookup
        db.official_timetables.aggregate.return_value = iter([doc])
        db.official_timetables.find.return_value = iter([doc])
        return db

    def test_explicit_valid_section(self):
        from utils.academic import validate_and_resolve_section
        db = self._make_db(["BSCS-7A", "BSCS-7B"])
        result = validate_and_resolve_section("BSCS-7A", db)
        assert result["status"] == "valid"
        assert result["section"] == "BSCS-7A"

    def test_explicit_valid_section_with_space(self):
        from utils.academic import validate_and_resolve_section
        db = self._make_db(["BSCS-7A"])
        result = validate_and_resolve_section("BSCS 7A", db)
        # normalize_requested_section should convert "BSCS 7A" -> "BSCS-7A"
        assert result["status"] == "valid"
        assert result["section"] == "BSCS-7A"

    def test_bare_7a_always_ambiguous(self):
        from utils.academic import validate_and_resolve_section
        db = self._make_db(["BSCS-7A"])
        result = validate_and_resolve_section("7A", db)
        assert result["status"] == "ambiguous"
        assert result["section"] is None
        assert result["suffix"] == "7A"

    def test_bare_7b_always_ambiguous_even_if_unique(self):
        """Even when only one program has 7B, it is still ambiguous."""
        from utils.academic import validate_and_resolve_section
        db = self._make_db(["BSCS-7B"])
        result = validate_and_resolve_section("7B", db)
        assert result["status"] == "ambiguous"
        assert result["section"] is None

    def test_not_found_section(self):
        from utils.academic import validate_and_resolve_section
        db = MagicMock()
        db.official_timetables.find_one.return_value = None  # not found
        db.official_timetables.find.return_value = iter([])
        result = validate_and_resolve_section("BSCS-99Z", db)
        assert result["status"] == "not_found"
        assert result["section"] is None

    def test_no_db_returns_not_found(self):
        from utils.academic import validate_and_resolve_section
        result = validate_and_resolve_section("BSCS-7A", None)
        assert result["status"] == "not_found"

    def test_empty_raw_returns_not_found(self):
        from utils.academic import validate_and_resolve_section
        result = validate_and_resolve_section("", None)
        assert result["status"] == "not_found"


# ── E. _handle_section_set multi-turn ────────────────────────────────────────

class TestHandleSectionSetMultiTurn:

    def _mock_ambiguous(self, suffix, available):
        return {
            "status": "ambiguous",
            "section": None,
            "suffix": suffix,
            "message": f"'{suffix}' is ambiguous",
            "available": available,
        }

    def _mock_valid(self, section):
        return {
            "status": "valid",
            "section": section,
            "suffix": section,
            "message": f"Section {section} found.",
            "available": [],
        }

    def test_bare_section_asks_for_program(self):
        """'7B' → ambiguous → bot asks which program → saves pending_section."""
        import utils.nlu as nlu_mod
        from utils.nlu_session import get_nlu_session, save_nlu_session
        db = MagicMock()
        session = {}

        request = {"intent": "section_set", "language": "en", "section": {"raw": "7B"}, "confidence": 0.95}

        with patch("utils.academic.validate_and_resolve_section",
                   return_value=self._mock_ambiguous("7B", ["BSCS-7B", "BSSE-7B"])):
            result = nlu_mod._handle_section_set(db, "user1", "+923000", "I'm in 7B", request, session)

        assert result["action"] == "reply"
        assert result["intent"] == "section_set"
        assert "7B" in result["text"]
        assert "BSCS" in result["text"] or "program" in result["text"].lower()
        # pending_section should have been saved
        db.nlu_sessions.update_one.assert_called()

    def test_program_name_combines_with_pending_suffix(self):
        """User sends 'BSCS' after bot asked about '7B' — should try BSCS-7B."""
        import utils.nlu as nlu_mod
        db = MagicMock()
        db.users.update_one.return_value = MagicMock()
        db.user_timetables.update_one.return_value = MagicMock()
        db.official_timetables.find_one.return_value = None  # for next_class lookup

        session = {"pending_section": {"raw_suffix": "7B"}}
        request = {"intent": "section_set", "language": "en", "section": {"raw": "BSCS"}, "confidence": 0.95}

        def fake_validate(raw_text, db):
            if raw_text == "BSCS-7B":
                return {"status": "valid", "section": "BSCS-7B", "suffix": "BSCS-7B", "message": "found", "available": []}
            return {"status": "ambiguous", "section": None, "suffix": raw_text, "message": "ambiguous", "available": []}

        with patch("utils.academic.validate_and_resolve_section", side_effect=fake_validate), \
             patch("utils.nlu_session.clear_pending_section"), \
             patch("utils.academic.get_published_section_context", return_value={"status": "no_timetable"}):
            result = nlu_mod._handle_section_set(db, "user1", "+923000", "BSCS", request, session)

        assert result["action"] == "reply"
        assert result["intent"] == "section_set"
        assert "BSCS-7B" in result["text"]
        assert "Done" in result["text"] or "set" in result["text"].lower()

    def test_full_section_skips_pending_and_saves_directly(self):
        """'BSCS-7A' with no pending section → valid → saved immediately."""
        import utils.nlu as nlu_mod
        db = MagicMock()
        db.users.update_one.return_value = MagicMock()
        db.user_timetables.update_one.return_value = MagicMock()
        session = {}
        request = {"intent": "section_set", "language": "en", "section": {"raw": "BSCS-7A"}, "confidence": 0.97}

        with patch("utils.academic.validate_and_resolve_section",
                   return_value=self._mock_valid("BSCS-7A")), \
             patch("utils.nlu_session.clear_pending_section"), \
             patch("utils.academic.get_published_section_context", return_value={"status": "no_timetable"}):
            result = nlu_mod._handle_section_set(db, "user1", "+923000", "my section is BSCS-7A", request, session)

        assert result["action"] == "reply"
        assert result["intent"] == "section_set"
        assert "BSCS-7A" in result["text"]
        db.users.update_one.assert_called_once()
        db.user_timetables.update_one.assert_called_once()

    def test_not_found_section_returns_error(self):
        """'BSCS-99Z' → not_found → returns helpful error."""
        import utils.nlu as nlu_mod
        db = MagicMock()
        session = {}
        request = {"intent": "section_set", "language": "en", "section": {"raw": "BSCS-99Z"}, "confidence": 0.95}

        with patch("utils.academic.validate_and_resolve_section",
                   return_value={"status": "not_found", "section": None, "suffix": "BSCS-99Z",
                                 "message": "I couldn't find *BSCS-99Z* in the current timetable.", "available": []}), \
             patch("utils.nlu_session.clear_pending_section"):
            result = nlu_mod._handle_section_set(db, "user1", "+923000", "I'm in BSCS-99Z", request, session)

        assert result["action"] == "reply"
        assert result["intent"] == "section_set"
        assert "BSCS-99Z" in result["text"] or "find" in result["text"].lower()


# ── F. Existing fallback + routing parity ────────────────────────────────────

class TestPhase1FallbackParity:
    """Ensure existing paths still work now that routing defaults to True."""

    def test_fallback_handle_still_works_when_routing_off(self):
        import utils.nlu as nlu_mod
        with patch.object(nlu_mod, "routing_enabled", return_value=False), \
             patch.object(nlu_mod, "_fallback_handle",
                          return_value={"action": "reply", "text": "Hi!", "intent": "greeting"}) as mock_fb:
            result = nlu_mod.dispatch_message(None, "u1", "+92300", "hello")
        assert result["action"] == "reply"
        mock_fb.assert_called_once()

    def test_im_stressed_about_quiz_is_out_of_scope_not_task_query(self):
        """'stressed about my quiz' contains 'quiz' which is in _MY_TASKS_WORDS,
        so the deterministic classifier fires query_tasks. Only the LLM correctly
        classifies this as casual. Test via pipeline with LLM mocked."""
        import utils.nlu as nlu_mod
        with patch.object(nlu_mod, "understand",
                          return_value={"intent": "out_of_scope", "language": "en", "confidence": 0.90,
                                        "out_of_scope": {"kind": "casual", "topic": None}}):
            result = nlu_mod.handle_message(None, "u1", "+92300", "I'm so stressed about my quiz")
        assert result["intent"] == "out_of_scope"

    def test_my_tasks_query_unchanged(self):
        from utils.agent import classify_intent
        result = classify_intent("what do i have due")
        assert result == "query_tasks"
