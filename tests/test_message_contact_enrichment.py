"""
Read-time contact-name enrichment for GET /api/messages/recent.

Names stay on contacts (wa_id → profile_name). messages.from is joined on
read; nothing is written back onto the messages documents.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import app as appmod

SECRET = "test-jwt-secret"


@pytest.fixture
def ctx(monkeypatch):
    db = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: db)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "ensure_mongo_indexes", lambda: None)
    db.users.insert_one({
        "user_id": "admin:system",
        "username": "admin",
        "settings": {"is_admin": True},
    })
    application = appmod.create_app()
    application.testing = True
    return application.test_client(), db


def _token(user_id=appmod._build_admin_id(), secret=SECRET):
    return jwt.encode(
        {
            "sub": user_id,
            "user_id": user_id,
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        secret,
        algorithm="HS256",
    )


def _admin_headers():
    return {"Authorization": f"Bearer {_token()}"}


def _message(from_wa, text, message_id="wamid.1"):
    now = datetime.now(timezone.utc)
    return {
        "message_id": message_id,
        "from": from_wa,
        "text": text,
        "type": "text",
        "received_at": now,
        "delivery_status": "received",
    }


class TestEnrichMessagesWithContactNames:
    def test_matching_contact_gets_profile_name(self):
        db = mongomock.MongoClient().db
        db.contacts.insert_one({
            "wa_id": "923334892624",
            "profile_name": "Rehan Abrar",
        })
        items = appmod._enrich_messages_with_contact_names(db, [
            _message("923334892624", "quiz1 ho ga. wednesday ko lab-3 ma 10:30 per"),
        ])
        assert items[0]["from"] == "923334892624"
        assert items[0]["from_name"] == "Rehan Abrar"
        assert items[0]["text"].startswith("quiz1 ho ga")

    def test_no_matching_contact_leaves_name_null(self):
        db = mongomock.MongoClient().db
        items = appmod._enrich_messages_with_contact_names(db, [
            _message("923000000000", "hello"),
        ])
        assert items[0]["from"] == "923000000000"
        assert items[0]["from_name"] is None
        assert items[0]["text"] == "hello"

    def test_blank_profile_name_not_invented(self):
        db = mongomock.MongoClient().db
        db.contacts.insert_one({"wa_id": "923001111111", "profile_name": "  "})
        items = appmod._enrich_messages_with_contact_names(db, [
            _message("923001111111", "hi"),
        ])
        assert items[0]["from_name"] is None

    def test_batch_lookup_not_n_plus_one(self, monkeypatch):
        db = mongomock.MongoClient().db
        db.contacts.insert_one({
            "wa_id": "923334892624",
            "profile_name": "Rehan Abrar",
        })
        db.contacts.insert_one({
            "wa_id": "923217857439",
            "profile_name": "Alina Asif Khan",
        })
        calls = {"find": 0}
        original = db.contacts.find

        def counting_find(*args, **kwargs):
            calls["find"] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(db.contacts, "find", counting_find)

        items = appmod._enrich_messages_with_contact_names(db, [
            _message("923334892624", "one", "wamid.a"),
            _message("923334892624", "two", "wamid.b"),
            _message("923217857439", "three", "wamid.c"),
            _message("923000000000", "unknown", "wamid.d"),
        ])

        assert calls["find"] == 1
        assert items[0]["from_name"] == "Rehan Abrar"
        assert items[1]["from_name"] == "Rehan Abrar"
        assert items[2]["from_name"] == "Alina Asif Khan"
        assert items[3]["from_name"] is None


class TestRecentMessagesApi:
    def test_api_enriches_matching_contact(self, ctx):
        client, db = ctx
        db.contacts.insert_one({
            "wa_id": "923334892624",
            "profile_name": "Rehan Abrar",
        })
        db.messages.insert_one(_message(
            "923334892624",
            "quiz1 ho ga. wednesday ko lab-3 ma 10:30 per",
        ))

        response = client.get("/api/messages/recent", headers=_admin_headers())
        assert response.status_code == 200
        body = response.get_json()
        assert body["count"] == 1
        item = body["items"][0]
        assert item["from"] == "923334892624"
        assert item["from_name"] == "Rehan Abrar"
        assert item["text"].startswith("quiz1 ho ga")
        stored = db.messages.find_one({"from": "923334892624"})
        assert "from_name" not in stored

    def test_api_unknown_sender_still_returns_message(self, ctx):
        client, db = ctx
        db.messages.insert_one(_message("923000000000", "hello there"))

        response = client.get("/api/messages/recent", headers=_admin_headers())
        assert response.status_code == 200
        item = response.get_json()["items"][0]
        assert item["from"] == "923000000000"
        assert item["from_name"] is None
        assert item["text"] == "hello there"
        assert item["message_id"] == "wamid.1"
