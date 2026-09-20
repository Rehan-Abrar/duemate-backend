"""
Regression tests proving the BSCS-6B data-integrity leak is closed and that the
chatbot answers strictly from the user's own timetable.
"""

import os
import sys

import mongomock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import utils.rag as rag

# Course strings that ONLY exist in the old hardcoded BSCS-6B fixture. If any of
# these ever appears for a user who didn't upload them, the static fallback leaked.
BSCS6B_MARKERS = [
    "Parallel & Distributed Computing",
    "AI Driven Software Development",
    "AI-Driven Software Development",
    "Theory of Automata",
    "Advance Database Management Systems",
    "Zia ul Murtaza",
    "Ramisha",
]


def _slot(day, time, course, room="R1", instr="Dr X", section="BSCS-6B"):
    start, end = time.split("-")
    return {
        "day": day, "start_time": start, "end_time": end, "time": time,
        "course": course, "instructor": instr, "room": room, "section": section,
    }


def _assert_no_leak(text):
    for marker in BSCS6B_MARKERS:
        assert marker not in text, f"BSCS-6B leak: {marker!r} in reply"


class TestNoTimetableLeak:
    def test_no_db_returns_message_not_data(self):
        reply = rag.retrieve_schedule_context("when is my next class", db=None, user_id="wa:1")
        _assert_no_leak(reply)
        assert "database" in reply.lower()

    def test_no_timetable_message(self):
        db = mongomock.MongoClient().db
        reply = rag.retrieve_schedule_context("when is my next class", db=db, user_id="wa:1")
        _assert_no_leak(reply)
        assert "section" in reply.lower()

    def test_no_section_message(self):
        db = mongomock.MongoClient().db
        db.user_timetables.insert_one({"user_id": "wa:1", "sections": {"BSCS-6B": [_slot("Monday", "08:00-10:00", "X")]}})
        reply = rag.retrieve_schedule_context("show my timetable", db=db, user_id="wa:1")
        _assert_no_leak(reply)
        assert "section" in reply.lower()

    def test_various_queries_never_leak_for_no_timetable_user(self):
        db = mongomock.MongoClient().db
        for q in ["who teaches pdc", "when is pdc class", "show timetable", "next class", "monday schedule"]:
            reply = rag.retrieve_schedule_context(q, db=db, user_id="wa:1")
            _assert_no_leak(reply)


class TestAnswersFromOwnTimetable:
    def _seed(self):
        db = mongomock.MongoClient().db
        db.user_timetables.insert_one({
            "user_id": "wa:1",
            "selected_section": "BSDS-4A",
            "sections": {"BSDS-4A": [
                _slot("Monday", "08:00-10:00", "Operating Systems", instr="Dr Alice", section="BSDS-4A"),
                _slot("Tuesday", "09:00-11:00", "Computer Networks", instr="Dr Bob", section="BSDS-4A"),
            ]},
        })
        return db

    def test_full_timetable_uses_own_courses(self):
        db = self._seed()
        reply = rag.retrieve_schedule_context("show my timetable", db=db, user_id="wa:1")
        _assert_no_leak(reply)
        assert "Operating Systems" in reply
        assert "Computer Networks" in reply

    def test_teacher_query_resolves_dynamically(self):
        db = self._seed()
        reply = rag.retrieve_schedule_context("who teaches operating systems", db=db, user_id="wa:1")
        _assert_no_leak(reply)
        assert "Dr Alice" in reply

    def test_course_query_by_initialism(self):
        db = self._seed()
        reply = rag.retrieve_schedule_context("when is my os class", db=db, user_id="wa:1")
        _assert_no_leak(reply)
        assert "Operating Systems" in reply
