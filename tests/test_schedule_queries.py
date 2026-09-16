"""
Focused timetable-query tests: AM/PM + 24h parsing, next-class / tomorrow,
multi-occurrence courses, teacher/room, today/tomorrow, free/busy filters.

Uses a data-driven fixture shaped like a real official timetable (AM/PM ranges).
No Groq, no MongoDB.
"""
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.academic import STATUS_OK
from utils.rag import (
    _MISSING_INSTRUCTOR,
    _format_slot,
    _get_course_schedule,
    _get_day_schedule,
    _get_next_class,
    _is_free,
    _parse_slot_time,
    _slot_bounds,
    retrieve_schedule_context_structured,
)

_PKT = timezone(timedelta(hours=5))
WED_458 = datetime(2026, 9, 16, 4, 58, tzinfo=_PKT)  # Wednesday
WED_0900 = datetime(2026, 9, 16, 9, 0, tzinfo=_PKT)
WED_1130 = datetime(2026, 9, 16, 11, 30, tzinfo=_PKT)
WED_1600 = datetime(2026, 9, 16, 16, 0, tzinfo=_PKT)


def _slot(course, time_str, day, room="Classroom 1", instructor=""):
    return {
        "course": course,
        "time": time_str,
        "day": day,
        "room": room,
        "instructor": instructor,
    }


# Official-style AM/PM ranges (the format that previously failed to parse).
AMP_SLOTS = [
    _slot("Computer Vision", "8:00 AM-10:00 AM", "Monday", "Classroom 1", "Dr. Vision"),
    _slot("Compiler Construction", "1:30 PM-3:30 PM", "Monday", "Classroom 1", "Dr. Compiler"),
    _slot("Theory of Visual Data Mining", "11:00 AM-1:00 PM", "Tuesday", "Classroom 2", "Dr. TVDM"),
    _slot("Information Security Lab", "8:00 AM-11:00 AM", "Wednesday", "Computer Lab 1", ""),
    _slot("Information Security", "1:00 PM-3:00 PM", "Wednesday", "Classroom 1", "Dr. Sec"),
    _slot("Computer Vision Lab", "2:00 PM-5:00 PM", "Thursday", "Computer Lab 1", ""),
    _slot("Compiler Construction Lab", "10:30 AM-1:00 PM", "Friday", "Computer Lab 2", "Dr. Compiler"),
]


def _timetable(slots=None):
    slots = slots if slots is not None else AMP_SLOTS
    schedule = defaultdict(list)
    for s in slots:
        schedule[s["day"]].append(s)
    return {"schedule": dict(schedule)}


def _ctx(slots=None):
    slots = slots if slots is not None else AMP_SLOTS
    courses = sorted({s["course"] for s in slots})
    rooms = sorted({s["room"] for s in slots})
    return {
        "status": STATUS_OK,
        "source": "official",
        "section": "BSCS-7B",
        "academic_term": None,
        "timetable_version": None,
        "schedule": _timetable(slots)["schedule"],
        "courses": courses,
        "rooms": rooms,
        "aliases": {},
        "has_timetable": True,
    }


def _freeze(monkeypatch, when: datetime):
    monkeypatch.setattr("utils.rag._now_pkt", lambda: when)


# ── Time parsing ──────────────────────────────────────────────────────────────

class TestParseSlotTime:
    def test_ampm_morning_range(self):
        assert _parse_slot_time("8:00 AM-11:00 AM") == (8 * 60, 11 * 60)

    def test_ampm_crossing_noon(self):
        assert _parse_slot_time("10:30 AM-1:00 PM") == (10 * 60 + 30, 13 * 60)

    def test_ampm_afternoon(self):
        assert _parse_slot_time("1:00 PM-3:00 PM") == (13 * 60, 15 * 60)

    def test_24h_padded(self):
        assert _parse_slot_time("08:00-10:00") == (8 * 60, 10 * 60)

    def test_24h_afternoon(self):
        assert _parse_slot_time("13:00-15:00") == (13 * 60, 15 * 60)

    def test_en_dash_and_spaces(self):
        assert _parse_slot_time("8:00 AM – 11:00 AM") == (8 * 60, 11 * 60)

    def test_start_end_fields_fallback(self):
        slot = {
            "course": "X",
            "time": "",
            "start_time": "8:00 AM",
            "end_time": "10:00 AM",
        }
        assert _slot_bounds(slot) == (8 * 60, 10 * 60)


# ── Next class ────────────────────────────────────────────────────────────────

class TestNextClass:
    def test_wednesday_dawn_finds_8am_today(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        text = _get_next_class(_timetable(), None)
        assert "Information Security Lab" in text
        assert "Wednesday" in text
        assert "8:00 AM" in text
        assert "No upcoming" not in text

    def test_wednesday_during_morning_lab_is_current(self, monkeypatch):
        _freeze(monkeypatch, WED_0900)
        text = _get_next_class(_timetable(), None)
        assert "Current class" in text
        assert "Information Security Lab" in text

    def test_wednesday_late_morning_rolls_to_afternoon(self, monkeypatch):
        _freeze(monkeypatch, WED_1130)
        text = _get_next_class(_timetable(), None)
        assert "Information Security" in text
        assert "Information Security Lab" not in text
        assert "1:00 PM" in text

    def test_weekend_rolls_to_monday_without_treating_it_as_now(self, monkeypatch):
        # Saturday 4:00 PM must not skip Monday's 8:00 AM class.
        _freeze(monkeypatch, datetime(2026, 9, 19, 16, 0, tzinfo=_PKT))
        text = _get_next_class(_timetable(), None)
        assert "Computer Vision" in text
        assert "Monday" in text
        assert "8:00 AM" in text

    def test_wednesday_evening_rolls_to_thursday(self, monkeypatch):
        _freeze(monkeypatch, WED_1600)
        text = _get_next_class(_timetable(), None)
        assert "Computer Vision Lab" in text
        assert "Thursday" in text
        assert "2:00 PM" in text

    def test_tomorrow_starts_thursday_not_today(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        text = _get_next_class(_timetable(), None, from_day="Thursday")
        assert "Computer Vision Lab" in text
        assert "Thursday" in text
        assert "2:00 PM" in text
        assert "Information Security" not in text

    def test_structured_next_class_honors_tomorrow(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "next_class", "day": "tomorrow"},
            db=MagicMock(),
            user_id="wa:1",
        )
        assert "Computer Vision Lab" in result["text"]
        assert "Thursday" in result["text"]
        assert "No upcoming" not in result["text"]

    def test_structured_next_class_now(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "next_class"},
            db=MagicMock(),
            user_id="wa:1",
        )
        assert "Information Security Lab" in result["text"]

    def test_24h_slots_still_work(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        slots = [_slot("Evening Seminar", "13:00-15:00", "Wednesday", "Hall A", "Dr. Eve")]
        text = _get_next_class(_timetable(slots), None)
        assert "Evening Seminar" in text
        assert "1:00 PM" in text


# ── Course with multiple occurrences ──────────────────────────────────────────

class TestCourseOccurrences:
    def test_compiler_construction_lists_lecture_and_lab(self):
        text = _get_course_schedule(_timetable(), "Compiler Construction")
        assert "Monday" in text
        assert "1:30 PM" in text
        assert "Friday" in text
        assert "10:30 AM" in text
        assert "Classroom 1" in text
        assert "Computer Lab 2" in text

    def test_structured_course_schedule(self, monkeypatch):
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "course_schedule", "course": "compiler construction"},
            db=MagicMock(),
            user_id="wa:1",
        )
        assert "Compiler Construction" in result["text"]
        assert "Monday" in result["text"]
        assert "Friday" in result["text"]


# ── Teacher / room ────────────────────────────────────────────────────────────

class TestTeacherRoom:
    def test_missing_instructor_uses_explicit_sentence(self):
        slot = _slot("Computer Vision Lab", "2:00 PM-5:00 PM", "Thursday", "Computer Lab 1", "")
        text = _format_slot(slot, "Thursday")
        assert _MISSING_INSTRUCTOR in text
        assert "Instructor:" not in text
        assert "…" not in text

    def test_present_instructor_is_shown(self):
        slot = _slot("Compiler Construction", "1:30 PM-3:30 PM", "Monday", "Classroom 1", "Dr. Compiler")
        text = _format_slot(slot, "Monday")
        assert "Instructor: Dr. Compiler" in text
        assert "Classroom 1" in text
        assert _MISSING_INSTRUCTOR not in text

    def test_day_schedule_keeps_room_and_teacher(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        text = _get_day_schedule(_timetable(), "Monday")
        assert "Computer Vision" in text
        assert "Dr. Vision" in text
        assert "Classroom 1" in text


# ── Today / tomorrow day schedule ─────────────────────────────────────────────

class TestTodayTomorrow:
    def test_tomorrow_day_schedule(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "day_schedule", "day": "tomorrow"},
            db=MagicMock(),
            user_id="wa:1",
        )
        assert "Computer Vision Lab" in result["text"]
        assert "Thursday" in result["text"]
        assert "2:00 PM" in result["text"]
        assert "Instructor:" not in result["text"] or _MISSING_INSTRUCTOR in result["text"]

    def test_today_day_schedule(self, monkeypatch):
        _freeze(monkeypatch, WED_458)
        monkeypatch.setattr(
            "utils.rag.get_user_academic_context",
            lambda db, user_id: _ctx(),
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "day_schedule", "day": "today"},
            db=MagicMock(),
            user_id="wa:1",
        )
        assert "Information Security Lab" in result["text"]
        assert "Information Security" in result["text"]
        assert "Wednesday" in result["text"]


# ── Free / busy + time filters ────────────────────────────────────────────────

class TestFreeBusyFilters:
    def test_thursday_is_busy(self):
        text = _is_free(_timetable(), "Thursday")
        assert "Computer Vision Lab" in text
        assert "free" not in text.lower() or "have" in text.lower()

    def test_thursday_after_5pm_is_free(self):
        text = _is_free(_timetable(), "Thursday", time_after_min=17 * 60)
        assert "free" in text.lower()

    def test_thursday_after_1pm_is_busy(self):
        text = _is_free(_timetable(), "Thursday", time_after_min=13 * 60)
        assert "Computer Vision Lab" in text

    def test_wednesday_after_noon_filters_morning_lab(self):
        text = _get_day_schedule(_timetable(), "Wednesday", time_after_min=12 * 60)
        assert "1:00 PM" in text
        assert "Information Security Lab" not in text

    def test_ampm_window_on_friday_lab(self):
        text = _get_day_schedule(_timetable(), "Friday", time_after_min=10 * 60)
        assert "Compiler Construction Lab" in text
        assert "10:30 AM" in text
