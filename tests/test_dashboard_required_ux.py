"""
Tests for Dashboard-Required UX & Link Containment

Verifies:
1. Dashboard-required operations (timetable upload, profile/university changes, account deletion, open dashboard)
   clearly inform the user and provide the centralized DASHBOARD_URL.
2. Chat-supported operations (section setting, schedule queries, follow-ups, task listing, casual chat, help)
   never receive an unnecessary dashboard URL.
3. Centralized DASHBOARD_URL consistency.
4. Containment guard enforces dashboard URL presence only when grounded text requires it.
"""
import os
import sys
import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.config import DASHBOARD_URL
from utils.nlu import (
    dispatch_message,
    _containment_guard,
    _clamp_request,
    _out_of_scope_reply,
    _is_dashboard_required,
    DASHBOARD_REQUIRED_REPLY,
)


class TestDashboardConfigConsistency:
    def test_dashboard_url_constant(self):
        assert DASHBOARD_URL == "https://duemate-dashboard.vercel.app/"
        assert DASHBOARD_URL in DASHBOARD_REQUIRED_REPLY


class TestDashboardRequiredOperations:
    @pytest.mark.parametrize("user_msg", [
        "I want to upload my timetable PDF file",
        "change my university settings",
        "delete my account",
        "open dashboard",
    ])
    def test_dashboard_required_responses_contain_link(self, user_msg):
        db = mongomock.MongoClient().db
        user_id = "user_dash_req_1"
        phone = "+923000000000"

        res = dispatch_message(db, user_id, phone, user_msg)
        assert res["action"] == "reply"
        assert DASHBOARD_URL in res["text"]
        # Explains naturally that dashboard is required
        assert any(phrase in res["text"].lower() for phrase in ["dashboard", "here", "need"])

    def test_is_dashboard_required_helper(self):
        assert _is_dashboard_required("upload timetable pdf") is True
        assert _is_dashboard_required("change my university") is True
        assert _is_dashboard_required("delete account") is True
        assert _is_dashboard_required("open dashboard") is True


class TestChatSupportedOperationsNoLink:
    @pytest.mark.parametrize("chat_msg", [
        "my section is BSCS-7A",
        "when is my next class?",
        "where?",
        "what assignments do I have?",
        "im sad",
        "help",
    ])
    def test_chat_supported_messages_do_not_contain_dashboard_link(self, chat_msg):
        db = mongomock.MongoClient().db
        user_id = "user_chat_sup_1"
        phone = "+923000000001"

        res = dispatch_message(db, user_id, phone, chat_msg)
        assert res["action"] == "reply"
        assert DASHBOARD_URL not in res["text"]

    def test_is_dashboard_required_returns_false_for_chat_supported(self):
        assert _is_dashboard_required("my section is BSCS-7A") is False
        assert _is_dashboard_required("when is my next class?") is False
        assert _is_dashboard_required("where?") is False
        assert _is_dashboard_required("what assignments do I have?") is False
        assert _is_dashboard_required("im sad") is False


class TestContainmentGuardDashboardUrl:
    def test_guard_rejects_unnecessary_dashboard_url(self):
        det_text = "Your next class is Database Systems at 10 AM in Room 204."
        llm_out = f"Your next class is DB at 10 AM in Room 204. Open dashboard here: {DASHBOARD_URL}"

        # Must fail containment guard because det_text did NOT ask for dashboard
        assert _containment_guard(llm_out, det_text) is False

    def test_guard_rejects_omitting_required_dashboard_url(self):
        det_text = f"You need to change that on your dashboard: {DASHBOARD_URL}"
        llm_out = "You need to change that on your dashboard."

        # Must fail containment guard because llm_out dropped the required URL
        assert _containment_guard(llm_out, det_text) is False

    def test_guard_accepts_valid_dashboard_url_preservation(self):
        det_text = f"You need to do that from your dashboard: {DASHBOARD_URL}"
        llm_out = f"You'll need to update that from your DueMate dashboard: {DASHBOARD_URL}"

        assert _containment_guard(llm_out, det_text) is True


class TestClampDashboardRequiredSchema:
    def test_clamp_out_of_scope_dashboard_required(self):
        raw = {
            "intent": "out_of_scope",
            "language": "en",
            "out_of_scope": {"kind": "dashboard_required", "topic": "upload_timetable"},
            "confidence": 0.95,
        }
        clamped = _clamp_request(raw)
        assert clamped["intent"] == "out_of_scope"
        assert clamped["out_of_scope"]["kind"] == "dashboard_required"
        assert _out_of_scope_reply(clamped) == DASHBOARD_REQUIRED_REPLY
