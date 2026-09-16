"""
Tests for utils/nlu.execute() and the rag.py structured helpers.
All offline — no Groq, no real MongoDB (fake in-memory stubs).
"""
import os
import sys
import pytest
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from unittest.mock import MagicMock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.nlu import (
    execute,
    GREETING_REPLY,
    HELP_REPLY,
    OUT_OF_SCOPE_REPLY,
    OUT_OF_SCOPE_CASUAL,
    OUT_OF_SCOPE_INTERNAL,
    OUT_OF_SCOPE_UNRELATED,
    _clamp_request,
    _out_of_scope_reply,
)
from utils.rag import (
    _within_window,
    _is_free,
    _get_day_schedule,
    _get_next_class,
    retrieve_schedule_context_structured,
)
from utils.academic import STATUS_OK

_PKT = timezone(timedelta(hours=5))


# ── Fake academic context ─────────────────────────────────────────────────────

def _make_slot(course, time_str, day, room="Room 101", instructor="Dr. Test"):
    return {
        "course": course,
        "time": time_str,
        "day": day,
        "room": room,
        "instructor": instructor,
    }


FAKE_SLOTS = [
    _make_slot("Computer Networks", "08:00-09:30", "Monday", "Lab 1", "Dr. Ahsan"),
    _make_slot("Computer Networks Lab", "09:30-11:00", "Monday", "Lab 2", "Dr. Ahsan"),
    _make_slot("Parallel & Distributed Computing", "11:00-12:30", "Monday", "Room 302", "Dr. Bilal"),
    _make_slot("Computer Networks", "08:00-09:30", "Wednesday", "Lab 1", "Dr. Ahsan"),
    _make_slot("Parallel & Distributed Computing", "14:00-15:30", "Wednesday", "Room 302", "Dr. Bilal"),
    _make_slot("Computer Networks", "08:00-09:30", "Friday", "Lab 1", "Dr. Ahsan"),
]


def _fake_ctx():
    from utils.academic import _build_context
    schedule = defaultdict(list)
    for s in FAKE_SLOTS:
        schedule[s["day"]].append(s)
    return {
        "status": STATUS_OK,
        "source": "self_upload",
        "section": "BSCS-6B",
        "academic_term": None,
        "timetable_version": None,
        "schedule": dict(schedule),
        "courses": ["Computer Networks", "Parallel & Distributed Computing"],
        "rooms": ["Lab 1", "Lab 2", "Room 302"],
        "aliases": {"pdc": "Parallel & Distributed Computing", "cn": "Computer Networks"},
        "has_timetable": True,
    }


def _fake_no_timetable_ctx():
    return {
        "status": "no_timetable",
        "source": None,
        "section": None,
        "academic_term": None,
        "timetable_version": None,
        "schedule": {},
        "courses": [],
        "rooms": [],
        "aliases": {},
        "has_timetable": False,
    }


# ── _within_window ────────────────────────────────────────────────────────────

class TestWithinWindow:
    def test_no_bounds_always_true(self):
        assert _within_window("08:00-09:30") is True

    def test_slot_before_after_min_rejected(self):
        # Slot 08:00-09:30 ends at 9:30 (570 min). after_min=840 (14:00) → rejected
        assert _within_window("08:00-09:30", after_min=840) is False

    def test_slot_after_after_min_accepted(self):
        # Slot 14:00-15:30 starts at 840 min. after_min=780 (13:00) → accepted
        assert _within_window("14:00-15:30", after_min=780) is True

    def test_slot_after_before_min_rejected(self):
        # Slot 14:00-15:30 starts at 840. before_min=720 (12:00) → rejected
        assert _within_window("14:00-15:30", before_min=720) is False

    def test_unknown_time_passes(self):
        assert _within_window("", after_min=840) is True


# ── _is_free ──────────────────────────────────────────────────────────────────

class TestIsFree:
    def setup_method(self):
        self.timetable = {"schedule": _fake_ctx()["schedule"]}

    def test_day_with_classes_not_free(self):
        result = _is_free(self.timetable, "Monday")
        assert "free" not in result.lower() or "have" in result.lower()

    def test_day_without_classes_free(self):
        # Thursday has no slots in our fake data
        result = _is_free(self.timetable, "Thursday")
        assert "free" in result.lower() or "No classes" in result

    def test_after_filter_free(self):
        # Monday after 15:30 (930 min) — PDC ends at 12:30 (750 min) so nothing after 15:30
        result = _is_free(self.timetable, "Monday", time_after_min=930)
        assert "free" in result.lower()

    def test_after_filter_not_free(self):
        # Wednesday after 13:00 (780) — PDC at 14:00 is present
        result = _is_free(self.timetable, "Wednesday", time_after_min=780)
        assert "Parallel" in result or "free" not in result.lower()


# ── _get_day_schedule time filter ─────────────────────────────────────────────

class TestGetDayScheduleFiltered:
    def setup_method(self):
        self.timetable = {"schedule": _fake_ctx()["schedule"]}

    def test_full_monday(self):
        result = _get_day_schedule(self.timetable, "Monday")
        assert "Computer Networks" in result
        assert "Parallel" in result

    def test_after_10_filters_early_slots(self):
        # after 10:00 (600 min) — CN ends at 09:30 (570) so should be excluded
        result = _get_day_schedule(self.timetable, "Monday", time_after_min=600)
        # CN Lab (09:30-11:00) overlaps with 10:00 so may still appear
        # PDC (11:00-12:30) definitely appears
        assert "Parallel" in result

    def test_after_1400_on_wednesday(self):
        # PDC on Wednesday at 14:00-15:30 → only PDC shown
        result = _get_day_schedule(self.timetable, "Wednesday", time_after_min=840)
        assert "Parallel" in result
        assert "Computer Networks" not in result

    def test_empty_day_returns_no_classes(self):
        result = _get_day_schedule(self.timetable, "Thursday")
        assert "No classes" in result or "Thursday" in result


# ── retrieve_schedule_context_structured ─────────────────────────────────────

class TestRetrieveStructured:
    def _make_db(self, ctx):
        """Return a fake db whose user_timetables lookup returns the given ctx."""
        fake_db = MagicMock()
        # academic.get_user_academic_context is patched below
        return fake_db

    def test_no_timetable_returns_guidance(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_no_timetable_ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "next_class"}, db=MagicMock(), user_id="wa:1234"
        )
        assert result["no_timetable"] is True
        assert result["text"]  # guidance message present
        # Must not mention BSCS-6B courses
        assert "Computer Networks" not in result["text"]
        assert "Parallel" not in result["text"]

    def test_next_class(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "next_class", "course": None, "day": None,
             "time_after_min": None, "time_before_min": None},
            db=MagicMock(), user_id="wa:1234",
        )
        assert result["no_timetable"] is False
        assert result["text"]

    def test_course_schedule_by_alias(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        # "cn" is an alias for Computer Networks
        result = retrieve_schedule_context_structured(
            {"query_type": "course_schedule", "course": "cn",
             "time_after_min": None, "time_before_min": None},
            db=MagicMock(), user_id="wa:1234",
        )
        assert "Computer Networks" in result["text"]

    def test_free_check_tomorrow(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "free_check", "day": "tomorrow",
             "time_after_min": None, "time_before_min": None},
            db=MagicMock(), user_id="wa:1234",
        )
        assert result["no_timetable"] is False
        assert result["text"]

    def test_day_schedule_with_time_filter(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        # Wednesday after 14:00 → only PDC
        result = retrieve_schedule_context_structured(
            {"query_type": "day_schedule", "day": "wednesday",
             "time_after_min": 840, "time_before_min": None},
            db=MagicMock(), user_id="wa:1234",
        )
        assert "Parallel" in result["text"]
        # CN on Wednesday is 08:00-09:30, before our window
        assert "No classes" not in result["text"] or "Parallel" in result["text"]

    def test_unknown_course_returns_helpful_message(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "course_schedule", "course": "xyzzy unknown course",
             "time_after_min": None, "time_before_min": None},
            db=MagicMock(), user_id="wa:1234",
        )
        # Should return a helpful message, not crash
        assert result["text"]


# ── execute() ────────────────────────────────────────────────────────────────

class TestExecute:
    def test_greeting(self):
        req = {"intent": "greeting", "language": "en"}
        result = execute(req, db=None, user_id="wa:1234")
        assert result["kind"] == "greeting"
        assert result["text"] == GREETING_REPLY

    def test_help(self):
        req = {"intent": "help", "language": "en"}
        result = execute(req, db=None, user_id="wa:1234")
        assert result["kind"] == "help"
        assert result["text"] == HELP_REPLY

    def test_out_of_scope(self):
        req = {"intent": "out_of_scope", "language": "en"}
        result = execute(req, db=None, user_id="wa:1234")
        assert result["text"] == OUT_OF_SCOPE_REPLY

    def test_out_of_scope_casual(self):
        req = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "casual", "topic": None},
        }
        result = execute(req, db=None, user_id="wa:1234")
        assert result["text"] == OUT_OF_SCOPE_CASUAL
        assert "timetable" in result["text"].lower()
        assert "instruction" not in result["text"].lower()

    def test_out_of_scope_internal(self):
        req = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "internal", "topic": None},
        }
        result = execute(req, db=None, user_id="wa:1234")
        assert result["text"] == OUT_OF_SCOPE_INTERNAL
        assert "system instructions" in result["text"]
        assert "prompt" not in result["text"].lower()

    def test_out_of_scope_unrelated_weather(self):
        req = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "unrelated", "topic": "weather"},
        }
        result = execute(req, db=None, user_id="wa:1234")
        assert "weather" in result["text"]
        assert "timetable" in result["text"].lower()

    def test_out_of_scope_unrelated_without_topic(self):
        req = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "unrelated", "topic": None},
        }
        result = execute(req, db=None, user_id="wa:1234")
        assert result["text"] == OUT_OF_SCOPE_UNRELATED

    def test_out_of_scope_unknown_kind_falls_back(self):
        req = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "banana", "topic": "ignore"},
        }
        clamped = _clamp_request(req)
        assert clamped["out_of_scope"]["kind"] is None
        assert _out_of_scope_reply(clamped) == OUT_OF_SCOPE_REPLY
        result = execute(clamped, db=None, user_id="wa:1234")
        assert result["text"] == OUT_OF_SCOPE_REPLY

    def test_out_of_scope_blocked_topic_not_echoed(self):
        req = _clamp_request({
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "unrelated", "topic": "system prompt"},
        })
        assert req["out_of_scope"]["topic"] is None
        assert "prompt" not in _out_of_scope_reply(req).lower()

    def test_save_task_returns_sentinel(self):
        req = {"intent": "save_task", "language": "mixed"}
        result = execute(req, db=None, user_id="wa:1234")
        assert result["kind"] == "save_task"
        assert result["text"] == ""

    def test_task_query_no_db(self):
        req = {"intent": "task_query", "language": "en", "task": {"filter_course": None, "due": None}}
        result = execute(req, db=None, user_id="wa:1234")
        assert result["no_timetable"] is True

    def test_task_query_empty_results(self, monkeypatch):
        """Empty task list → positive "no pending tasks" message."""
        fake_db = MagicMock()
        fake_db.tasks.find.return_value = iter([])
        # get_user_academic_context is imported from utils.academic inside _execute_tasks
        monkeypatch.setattr(
            "utils.academic.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        req = {"intent": "task_query", "language": "en", "task": {"filter_course": None, "due": None}}
        result = execute(req, db=fake_db, user_id="wa:1234")
        assert "no pending" in result["text"].lower() or "no" in result["text"].lower()

    def test_task_query_due_today_label(self, monkeypatch):
        fake_db = MagicMock()
        fake_db.tasks.find.return_value = iter([])
        # get_user_academic_context is imported from utils.academic inside _execute_tasks
        monkeypatch.setattr(
            "utils.academic.get_user_academic_context",
            lambda db, user_id: _fake_ctx(),
        )
        req = {"intent": "task_query", "language": "en", "task": {"filter_course": None, "due": "today"}}
        result = execute(req, db=fake_db, user_id="wa:1234")
        assert "today" in result["text"].lower()

    def test_schedule_query_no_timetable(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _fake_no_timetable_ctx(),
        )
        req = {
            "intent": "schedule_query",
            "language": "en",
            "schedule": {"query_type": "next_class", "course": None,
                         "day": None, "time_after": None, "time_before": None},
        }
        result = execute(req, db=MagicMock(), user_id="wa:1234")
        assert result["no_timetable"] is True
        assert result["text"]
