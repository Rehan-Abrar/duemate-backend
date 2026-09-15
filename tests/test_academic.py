"""
Regression tests for the shared academic-context layer (utils/academic.py):
  - dynamic course matching (initialism / token overlap / per-user override / no-match)
  - context status enum + course de-duplication (treats 'X Lab' as course 'X')
  - official → self-upload → none resolution precedence
  - versioning + effective-date resolution (student auto-uses latest published)
  - NO BSCS-6B / static fallback leak
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import mongomock

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.academic import (
    get_user_academic_context,
    match_course,
    course_matches,
    base_course,
    STATUS_OK,
    STATUS_NO_DB,
    STATUS_NO_TIMETABLE,
    STATUS_NO_SECTION,
    STATUS_EMPTY,
)


def _slot(day, time, course, room="R1", instr="Dr X", section="BSCS-6B"):
    start, end = time.split("-")
    return {
        "day": day, "start_time": start, "end_time": end, "time": time,
        "course": course, "instructor": instr, "room": room, "section": section,
    }


SELF_SLOTS = [
    _slot("Monday", "08:00-10:00", "Operating Systems"),
    _slot("Monday", "10:00-13:00", "Operating Systems Lab"),
    _slot("Tuesday", "09:00-11:00", "Computer Networks"),
]

COURSES = ["Operating Systems", "Computer Networks"]


def _now():
    return datetime.now(timezone.utc)


# ── course matching ──────────────────────────────────────────────────────────

class TestCourseMatching:
    def test_initialism(self):
        assert match_course("when is my os class", COURSES) == "Operating Systems"
        assert match_course("cn timing", COURSES) == "Computer Networks"

    def test_token_overlap(self):
        assert match_course("networks", COURSES) == "Computer Networks"
        assert match_course("operating system schedule", COURSES) == "Operating Systems"

    def test_per_user_override_wins(self):
        # slang the generator can't infer resolves via per-user override
        overrides = {"algo": "Operating Systems"}
        assert match_course("algo lab kab hai", COURSES, overrides) == "Operating Systems"

    def test_no_match_returns_none(self):
        assert match_course("what's the weather", COURSES) is None
        assert match_course("random gibberish xyz", COURSES) is None

    def test_empty_courses(self):
        assert match_course("os", []) is None

    def test_course_matches_treats_lab_as_same(self):
        assert course_matches("Operating Systems Lab", "Operating Systems") is True
        assert course_matches("Computer Networks", "Operating Systems") is False

    def test_base_course(self):
        assert base_course("Parallel & Distributed Computing Lab") == "Parallel & Distributed Computing"


# ── context status enum ──────────────────────────────────────────────────────

class TestContextStatus:
    def test_no_db(self):
        ctx = get_user_academic_context(None, "wa:1")
        assert ctx["status"] == STATUS_NO_DB
        assert ctx["courses"] == []
        assert ctx["has_timetable"] is False

    def test_no_timetable(self):
        db = mongomock.MongoClient().db
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["status"] == STATUS_NO_TIMETABLE

    def test_no_section(self):
        db = mongomock.MongoClient().db
        db.user_timetables.insert_one({"user_id": "wa:1", "sections": {"BSCS-6B": SELF_SLOTS}})
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["status"] == STATUS_NO_SECTION

    def test_empty_section(self):
        db = mongomock.MongoClient().db
        db.user_timetables.insert_one(
            {"user_id": "wa:1", "selected_section": "BSCS-6B", "sections": {"BSCS-6B": []}}
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["status"] == STATUS_EMPTY

    def test_self_upload_ok_and_dedup(self):
        db = mongomock.MongoClient().db
        db.user_timetables.insert_one(
            {"user_id": "wa:1", "selected_section": "BSCS-6B", "sections": {"BSCS-6B": SELF_SLOTS}}
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["status"] == STATUS_OK
        assert ctx["source"] == "self_upload"
        # "Operating Systems Lab" collapses into "Operating Systems"
        assert ctx["courses"] == ["Computer Networks", "Operating Systems"]
        assert ctx["section"] == "BSCS-6B"


# ── official-first precedence + versioning ───────────────────────────────────

class TestOfficialPrecedence:
    def _seed_user(self, db, university=True):
        settings = {"timetable_section": "BSCS-6B"}
        if university:
            settings.update({"university_id": "riphah", "academic_term": "Fall 2026"})
        db.users.insert_one({"user_id": "wa:1", "settings": settings})
        db.user_timetables.insert_one(
            {"user_id": "wa:1", "selected_section": "BSCS-6B", "sections": {"BSCS-6B": SELF_SLOTS}}
        )

    def _official(self, version, course, effective_from, effective_to=None):
        return {
            "timetable_id": "riphah-fall-2026",
            "university_id": "riphah",
            "academic_term": "Fall 2026",
            "version": version,
            "status": "published",
            "detected_sections": ["BSCS-6B"],
            "effective_from": effective_from,
            "effective_to": effective_to,
            "sections": {"BSCS-6B": [_slot("Wednesday", "08:00-10:00", course)]},
        }

    def test_official_takes_precedence_over_self_upload(self):
        db = mongomock.MongoClient().db
        self._seed_user(db)
        db.official_timetables.insert_one(
            self._official(2, "Artificial Intelligence", _now() - timedelta(days=1))
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["source"] == "official"
        assert ctx["timetable_version"] == 2
        assert "Artificial Intelligence" in ctx["courses"]
        assert "Operating Systems" not in ctx["courses"]  # self-upload NOT used

    def test_student_auto_uses_latest_published_version(self):
        db = mongomock.MongoClient().db
        self._seed_user(db)
        now = _now()
        # v2 bounded (superseded), v3 currently effective — student never re-uploaded
        db.official_timetables.insert_one(
            self._official(2, "Artificial Intelligence", now - timedelta(days=5), effective_to=now - timedelta(minutes=1))
        )
        db.official_timetables.insert_one(
            self._official(3, "Machine Learning", now - timedelta(minutes=1))
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["timetable_version"] == 3
        assert "Machine Learning" in ctx["courses"]

    def test_future_effective_version_not_yet_active(self):
        db = mongomock.MongoClient().db
        self._seed_user(db)
        now = _now()
        db.official_timetables.insert_one(
            self._official(3, "Machine Learning", now - timedelta(days=1))
        )
        # v4 scheduled for the future — must NOT be used yet
        db.official_timetables.insert_one(
            self._official(4, "Deep Learning", now + timedelta(days=2))
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["timetable_version"] == 3
        assert "Deep Learning" not in ctx["courses"]

    def test_official_ignored_without_university_id(self):
        # Legacy self-upload user (no university_id) must not match an official
        # timetable by bare section label — avoids cross-university collisions.
        db = mongomock.MongoClient().db
        self._seed_user(db, university=False)
        db.official_timetables.insert_one(
            self._official(1, "Artificial Intelligence", _now() - timedelta(days=1))
        )
        ctx = get_user_academic_context(db, "wa:1")
        assert ctx["source"] == "self_upload"
        assert "Operating Systems" in ctx["courses"]

    def test_draft_not_used(self):
        db = mongomock.MongoClient().db
        self._seed_user(db)
        draft = self._official(2, "Artificial Intelligence", _now() - timedelta(days=1))
        draft["status"] = "draft"
        db.official_timetables.insert_one(draft)
        ctx = get_user_academic_context(db, "wa:1")
        # draft ignored → falls back to self-upload
        assert ctx["source"] == "self_upload"
