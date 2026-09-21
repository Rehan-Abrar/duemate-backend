"""
Phase 2 Tests: Conversation Context & History

Verifies recent message history tracking in nlu_session, inclusion of recent exchanges
in LLM #1 prompt context, and follow-up query resolution.
"""
import os
import sys
import mongomock
from datetime import datetime, timezone
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.nlu_session import (
    append_to_recent_messages,
    get_nlu_session,
    clear_nlu_session,
)
from utils.nlu import _understand_user_content, dispatch_message


class TestRecentMessagesSession:
    def test_recent_messages_append(self):
        db = mongomock.MongoClient().db
        user_id = "user_p2_1"

        append_to_recent_messages(db, user_id, "when is my next class?", "Your next class is Database Systems at 10 AM.")
        session = get_nlu_session(db, user_id)

        assert "recent_messages" in session
        assert len(session["recent_messages"]) == 1
        assert session["recent_messages"][0]["user"] == "when is my next class?"
        assert session["recent_messages"][0]["bot"] == "Your next class is Database Systems at 10 AM."

    def test_recent_messages_limited_to_5(self):
        db = mongomock.MongoClient().db
        user_id = "user_p2_2"

        for i in range(10):
            append_to_recent_messages(db, user_id, f"User msg {i}", f"Bot reply {i}", max_messages=5)

        session = get_nlu_session(db, user_id)
        assert len(session["recent_messages"]) == 5
        assert session["recent_messages"][0]["user"] == "User msg 5"
        assert session["recent_messages"][-1]["user"] == "User msg 9"


class TestUnderstandPromptContext:
    def test_context_in_llm1_prompt(self):
        session = {
            "user_id": "user_p2_3",
            "recent_messages": [
                {"user": "when is my next class?", "bot": "Your next class is DB at 10 AM in Room 204."},
                {"user": "thanks", "bot": "You're welcome!"},
            ]
        }

        user_content = _understand_user_content("where?", session)

        assert "Message: where?" in user_content
        assert "Recent conversation:" in user_content
        assert "User: when is my next class?" in user_content
        assert "Bot: Your next class is DB at 10 AM in Room 204." in user_content
        assert "User: thanks" in user_content


class TestDispatchAppendsRecentMessages:
    def test_dispatch_appends_to_recent(self, monkeypatch):
        db = mongomock.MongoClient().db
        user_id = "user_p2_4"
        phone = "+923001234567"

        # Turn routing off for predictable fallback reply
        monkeypatch.setenv("NLU_LLM_ROUTING_ENABLED", "false")

        res = dispatch_message(db, user_id, phone, "hello")
        assert res["action"] == "reply"

        session = get_nlu_session(db, user_id)
        assert "recent_messages" in session
        assert len(session["recent_messages"]) == 1
        assert session["recent_messages"][0]["user"] == "hello"
        assert session["recent_messages"][0]["bot"] == res["text"]
