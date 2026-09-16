"""
Public official-section timetable queries.

Explicit section labels (BSCS-7A, 'BSCS 7B', …) resolve against published
official_timetables only — no users.settings, no user_timetables, no default section.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import mongomock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.academic import (
    STATUS_OK,
    STATUS_UNKNOWN_SECTION,
    get_published_section_context,
    get_user_academic_context,
    normalize_requested_section,
)
from utils.nlu import _clamp_request, execute, understand
from utils.rag import retrieve_schedule_context, retrieve_schedule_context_structured

_PKT = timezone(timedelta(hours=5))
WED_458 = datetime(2026, 9, 16, 4, 58, tzinfo=_PKT)


def _slot(day, time, course, section, room="R1", instr=""):
    start, end = time.split("-")
    return {
        "day": day,
        "start_time": start,
        "end_time": end,
        "time": time,
        "course": course,
        "instructor": instr,
        "room": room,
        "section": section,
    }


SEC_A = "BSCS-7A"
SEC_B = "BSCS-7B"
COURSE_A = "Discrete Mathematics"
COURSE_B = "Information Security Lab"


def _official_doc(now=None):
    now = now or datetime.now(timezone.utc)
    return {
        "timetable_id": "riphah-fall-2026",
        "university_id": "riphah",
        "academic_term": "Fall 2026",
        "version": 1,
        "status": "published",
        "detected_sections": [SEC_A, SEC_B],
        "effective_from": now - timedelta(days=1),
        "effective_to": None,
        "sections": {
            SEC_A: [
                _slot("Monday", "08:00-10:00", COURSE_A, SEC_A, "Classroom 2"),
                _slot("Thursday", "11:00-13:00", COURSE_A, SEC_A, "Classroom 2"),
            ],
            SEC_B: [
                _slot("Wednesday", "08:00-11:00", COURSE_B, SEC_B, "Computer Lab 1"),
                _slot("Friday", "13:00-15:00", "Compiler Construction", SEC_B, "Classroom 1"),
            ],
        },
    }


def _seed_official(db):
    db.official_timetables.insert_one(_official_doc())
    return db


class TestNormalizeSection:
    def test_spaced_and_dashed(self):
        assert normalize_requested_section("BSCS 7B") == "BSCS-7B"
        assert normalize_requested_section("bscs-7a") == "BSCS-7A"
        assert normalize_requested_section("BSSE-7C") == "BSSE-7C"

    def test_embedded_in_sentence(self):
        assert normalize_requested_section("show me BSCS 7B timetable") == "BSCS-7B"

    def test_my_timetable_has_no_section(self):
        assert normalize_requested_section("what's my timetable") is None
        assert normalize_requested_section("when is my next class") is None


class TestPublicSectionQueries:
    def test_unauthenticated_explicit_section(self):
        db = _seed_official(mongomock.MongoClient().db)
        result = retrieve_schedule_context_structured(
            {"query_type": "full_timetable", "section": "BSCS 7A"},
            db=db,
            user_id="",
        )
        assert result["no_timetable"] is False
        assert COURSE_A in result["text"]
        assert COURSE_B not in result["text"]
        assert db.users.find_one({}) is None
        assert db.user_timetables.find_one({}) is None

    def test_authenticated_explicit_different_section(self):
        db = _seed_official(mongomock.MongoClient().db)
        db.users.insert_one({
            "user_id": "wa:92",
            "settings": {
                "timetable_section": SEC_B,
                "university_id": "riphah",
                "academic_term": "Fall 2026",
            },
        })
        personal = get_user_academic_context(db, "wa:92")
        assert personal["section"] == SEC_B
        assert "Information Security" in personal["courses"]

        result = retrieve_schedule_context_structured(
            {"query_type": "full_timetable", "section": SEC_A},
            db=db,
            user_id="wa:92",
        )
        assert COURSE_A in result["text"]
        assert COURSE_B not in result["text"]

    def test_unauthenticated_my_timetable_stays_empty(self):
        db = _seed_official(mongomock.MongoClient().db)
        result = retrieve_schedule_context_structured(
            {"query_type": "full_timetable"},
            db=db,
            user_id="wa:unknown",
        )
        assert result["no_timetable"] is True
        assert COURSE_A not in result["text"]
        assert COURSE_B not in result["text"]
        assert "timetable" in result["text"].lower()

        via_execute = execute(
            {
                "intent": "schedule_query",
                "language": "en",
                "schedule": {"query_type": "full_timetable", "section": None},
            },
            db=db,
            user_id="wa:unknown",
        )
        assert via_execute["no_timetable"] is True
        assert COURSE_A not in via_execute["text"]

    def test_unknown_section(self):
        db = _seed_official(mongomock.MongoClient().db)
        result = retrieve_schedule_context_structured(
            {"query_type": "full_timetable", "section": "BSCS-9Z"},
            db=db,
            user_id="",
        )
        assert result["no_timetable"] is True
        assert "BSCS-9Z" in result["text"]
        assert COURSE_A not in result["text"]
        assert COURSE_B not in result["text"]
        ctx = get_published_section_context(db, "BSCS-9Z")
        assert ctx["status"] == STATUS_UNKNOWN_SECTION

    def test_section_plus_day(self, monkeypatch):
        db = _seed_official(mongomock.MongoClient().db)
        monkeypatch.setattr(
            "utils.rag._now_pkt",
            lambda: WED_458,
        )
        result = retrieve_schedule_context_structured(
            {"query_type": "day_schedule", "section": "BSCS 7B", "day": "tomorrow"},
            db=db,
            user_id="",
        )
        assert result["no_timetable"] is False
        # Wednesday 4:58 → tomorrow is Thursday. 7B has no Thursday class.
        assert "No classes" in result["text"] or "Thursday" in result["text"]
        assert COURSE_B not in result["text"]

        monday = retrieve_schedule_context_structured(
            {"query_type": "day_schedule", "section": SEC_A, "day": "monday"},
            db=db,
            user_id="",
        )
        assert COURSE_A in monday["text"]
        assert "Monday" in monday["text"]
        assert COURSE_B not in monday["text"]

    def test_section_plus_next_class(self, monkeypatch):
        db = _seed_official(mongomock.MongoClient().db)
        monkeypatch.setattr("utils.rag._now_pkt", lambda: WED_458)
        result = retrieve_schedule_context_structured(
            {"query_type": "next_class", "section": SEC_B},
            db=db,
            user_id="",
        )
        assert COURSE_B in result["text"]
        assert "Wednesday" in result["text"]
        assert "8:00 AM" in result["text"]
        assert COURSE_A not in result["text"]

    def test_legacy_query_string_extracts_section(self):
        db = _seed_official(mongomock.MongoClient().db)
        text = retrieve_schedule_context("BSCS 7A ka timetable", db=db, user_id=None)
        assert COURSE_A in text
        assert COURSE_B not in text

    def test_understand_fills_section_from_message(self, monkeypatch):
        import requests as req
        payload = {
            "intent": "schedule_query",
            "language": "en",
            "confidence": 0.97,
            "schedule": {
                "query_type": "full_timetable",
                "course": None,
                "teacher": None,
                "day": None,
                "time_after": None,
                "time_before": None,
            },
        }
        mock = MagicMock()
        mock.raise_for_status.return_value = None
        mock.json.return_value = {
            "choices": [{"message": {"content": __import__("json").dumps(payload)}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        monkeypatch.setattr(req, "post", lambda *a, **kw: mock)
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        result = understand("show me BSCS 7B timetable")
        assert result["schedule"]["section"] == "BSCS-7B"

    def test_public_context_ignores_other_user_upload(self):
        db = _seed_official(mongomock.MongoClient().db)
        db.user_timetables.insert_one({
            "user_id": "wa:someone",
            "selected_section": SEC_B,
            "sections": {SEC_B: [_slot("Monday", "08:00-10:00", "Private Course", SEC_B)]},
        })
        ctx = get_published_section_context(db, SEC_A)
        assert ctx["status"] == STATUS_OK
        assert "Private Course" not in ctx["courses"]
        assert COURSE_A in ctx["courses"]


class TestClampAndExecutePublic:
    def test_execute_unauthenticated_section(self):
        db = _seed_official(mongomock.MongoClient().db)
        req = _clamp_request({
            "intent": "schedule_query",
            "language": "en",
            "schedule": {"query_type": "full_timetable", "section": "bscs 7a"},
        })
        result = execute(req, db=db, user_id="")
        assert COURSE_A in result["text"]
        assert result["no_timetable"] is False
