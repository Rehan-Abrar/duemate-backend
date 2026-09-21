"""
Phase 3 Tests: Section Assignment via Chat

Verifies setting user section through conversation (WhatsApp/web), explicit vs bare section
validation, multi-turn program resolution, database persistence, and flow interruption.
"""
import os
import sys
from datetime import datetime, timezone
import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.academic import validate_and_resolve_section
from utils.nlu import _handle_section_set, handle_message, dispatch_message
from utils.nlu_session import get_nlu_session, save_nlu_session


@pytest.fixture
def mock_db():
    db = mongomock.MongoClient().db
    # Seed a published timetable with detected sections
    db.official_timetables.insert_one({
        "status": "published",
        "detected_sections": ["BSCS-7A", "BSCS-7B", "BSSE-7A", "BSDS-6A"],
        "effective_from": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "effective_to": None,
    })
    return db


class TestValidateAndResolveSectionPhase3:
    def test_section_set_explicit_valid(self, mock_db):
        res = validate_and_resolve_section("BSCS-7A", mock_db)
        assert res["status"] == "valid"
        assert res["section"] == "BSCS-7A"

    def test_section_set_explicit_with_space(self, mock_db):
        res = validate_and_resolve_section("BSCS 7A", mock_db)
        assert res["status"] == "valid"
        assert res["section"] == "BSCS-7A"

    def test_section_set_bare_always_ambiguous(self, mock_db):
        res = validate_and_resolve_section("7A", mock_db)
        assert res["status"] == "ambiguous"
        assert "BSCS-7A" in res["available"]
        assert "BSSE-7A" in res["available"]

    def test_section_set_bare_suffix_unique_still_ambiguous(self, mock_db):
        # 6A only exists under BSDS-6A, but bare 6A must STILL be ambiguous
        res = validate_and_resolve_section("6A", mock_db)
        assert res["status"] == "ambiguous"
        assert res["section"] is None
        assert "BSDS-6A" in res["available"]

    def test_section_set_not_found(self, mock_db):
        res = validate_and_resolve_section("BSCS-99Z", mock_db)
        assert res["status"] == "not_found"
        assert res["section"] is None


class TestHandleSectionSetMultiTurn:
    def test_section_set_my_section_is_bare(self, mock_db):
        user_id = "u_sec_1"
        phone = "+923000000001"
        req = {"section": {"raw": "7A"}}

        res = _handle_section_set(mock_db, user_id, phone, "my section is 7A", req, None)
        assert res["action"] == "reply"
        assert "Which program is *7A* for?" in res["text"]

        session = get_nlu_session(mock_db, user_id)
        assert session.get("pending_section", {}).get("raw_suffix") == "7A"

    def test_section_set_im_in_bare(self, mock_db):
        user_id = "u_sec_2"
        phone = "+923000000002"
        req = {"section": {"raw": "7B"}}

        res = _handle_section_set(mock_db, user_id, phone, "I'm in 7B", req, None)
        assert res["action"] == "reply"
        assert "7B" in res["text"]

    def test_section_set_changes_existing(self, mock_db):
        user_id = "u_sec_3"
        phone = "+923000000003"

        # Pre-set user to BSCS-7A
        mock_db.users.insert_one({"user_id": user_id, "settings": {"timetable_section": "BSCS-7A"}})
        mock_db.user_timetables.insert_one({"user_id": user_id, "selected_section": "BSCS-7A"})

        # Change to BSCS-7B
        req = {"section": {"raw": "BSCS-7B"}}
        res = _handle_section_set(mock_db, user_id, phone, "change my section to BSCS-7B", req, None)

        assert res["action"] == "reply"
        assert "Done! You're set to *BSCS-7B*" in res["text"]

        user_doc = mock_db.users.find_one({"user_id": user_id})
        assert user_doc["settings"]["timetable_section"] == "BSCS-7B"

        ut_doc = mock_db.user_timetables.find_one({"user_id": user_id})
        assert ut_doc["selected_section"] == "BSCS-7B"

    def test_section_set_does_not_affect_other_users(self, mock_db):
        u1, u2 = "u_sec_4", "u_sec_5"
        mock_db.users.insert_one({"user_id": u1, "settings": {"timetable_section": "BSCS-7A"}})
        mock_db.users.insert_one({"user_id": u2, "settings": {"timetable_section": "BSSE-7A"}})

        req = {"section": {"raw": "BSCS-7B"}}
        _handle_section_set(mock_db, u1, "+923000000004", "BSCS-7B", req, None)

        # u1 changed, u2 remains unchanged
        assert mock_db.users.find_one({"user_id": u1})["settings"]["timetable_section"] == "BSCS-7B"
        assert mock_db.users.find_one({"user_id": u2})["settings"]["timetable_section"] == "BSSE-7A"

    def test_section_set_interrupts_pending_create(self, mock_db):
        user_id = "u_sec_6"
        phone = "+923000000006"

        # Save active pending create session
        save_nlu_session(mock_db, user_id, phone, pending_create={"draft": {"task_type": "quiz"}})

        session = get_nlu_session(mock_db, user_id)
        assert session.get("pending_create") is not None

        # Process section_set
        req = {"section": {"raw": "BSCS-7A"}}
        res = _handle_section_set(mock_db, user_id, phone, "my section is BSCS-7A", req, session)

        assert "Done! You're set to *BSCS-7A*" in res["text"]
        # Section saved
        assert mock_db.users.find_one({"user_id": user_id})["settings"]["timetable_section"] == "BSCS-7A"
