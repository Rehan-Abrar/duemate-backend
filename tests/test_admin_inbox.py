"""
Admin inbox APIs: contacts list, contact search, and per-sender message history.

Names stay on contacts. Messages are matched with messages.from == contacts.wa_id.
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
NOW = datetime(2026, 8, 10, 20, 21, tzinfo=timezone.utc)


@pytest.fixture
def ctx(monkeypatch):
    db = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: db)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "ensure_mongo_indexes", lambda: None)
    monkeypatch.setattr(appmod, "_utc_now", lambda: NOW)
    monkeypatch.setattr(appmod, "_pkt_today_start_utc", lambda: NOW.replace(
        hour=0, minute=0, second=0, microsecond=0
    ))
    db.users.insert_one({
        "user_id": "admin:system",
        "username": "admin",
        "settings": {"is_admin": True},
    })
    db.users.insert_one({"user_id": "wa:923001111111", "phone_number": "923001111111"})
    application = appmod.create_app()
    application.testing = True
    return application.test_client(), db


def _token(user_id="admin:system"):
    return jwt.encode(
        {
            "sub": user_id,
            "user_id": user_id,
            "type": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        SECRET,
        algorithm="HS256",
    )


def _admin():
    return {"Authorization": f"Bearer {_token()}"}


def _student():
    return {"Authorization": f"Bearer {_token('wa:923001111111')}"}


def _contact(wa_id, name, last_seen=None):
    return {
        "wa_id": wa_id,
        "profile_name": name,
        "last_seen": last_seen or NOW,
        "updated_at": last_seen or NOW,
    }


def _msg(wa_id, text, when=None, message_id=None):
    when = when or NOW
    return {
        "message_id": message_id or f"wamid.{wa_id}.{text[:8]}",
        "from": wa_id,
        "to": "DueMate",
        "text": text,
        "type": "text",
        "timestamp": when,
        "received_at": when,
        "delivery_status": "received",
    }


def _seed(db):
    db.contacts.insert_many([
        _contact("923217857439", "Alina Asif Khan", NOW),
        _contact("923004445555", "Ch Usman", NOW - timedelta(days=1)),
        _contact("923334892624", "Rehan Abrar", NOW - timedelta(hours=2)),
        _contact("923000000001", None, NOW - timedelta(days=20)),
    ])
    db.messages.insert_many([
        _msg("923217857439", "kal compiler construction hai?", NOW, "wamid.alina.1"),
        _msg("923217857439", "aur assignment bhi?", NOW - timedelta(minutes=2), "wamid.alina.2"),
        _msg("923217857439", "what's my next class?", NOW - timedelta(days=1), "wamid.alina.3"),
        _msg("923334892624", "quiz1 ho ga. wednesday ko lab-3 ma 10:30 per", NOW, "wamid.rehan.1"),
        _msg("923000000099", "orphan sender with no contact", NOW, "wamid.orphan.1"),
    ])


class TestAdminInboxAuth:
    def test_contacts_requires_auth(self, ctx):
        client, _ = ctx
        assert client.get("/api/admin/inbox/contacts").status_code == 401

    def test_messages_requires_auth(self, ctx):
        client, _ = ctx
        assert client.get("/api/admin/inbox/contacts/923217857439/messages").status_code == 401

    def test_student_token_forbidden(self, ctx):
        client, db = ctx
        _seed(db)
        assert client.get("/api/admin/inbox/contacts", headers=_student()).status_code == 403
        assert client.get(
            "/api/admin/inbox/contacts/923217857439/messages",
            headers=_student(),
        ).status_code == 403


class TestAdminInboxContacts:
    def test_contact_list_loads(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get("/api/admin/inbox/contacts", headers=_admin())
        assert response.status_code == 200
        body = response.get_json()
        assert body["count"] == 4
        names = {item["profile_name"] for item in body["items"]}
        assert "Alina Asif Khan" in names
        alina = next(item for item in body["items"] if item["wa_id"] == "923217857439")
        assert alina["message_count"] == 3
        assert alina["latest_text"] == "kal compiler construction hai?"

    def test_search_by_name(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get("/api/admin/inbox/contacts?q=alina", headers=_admin())
        body = response.get_json()
        assert body["count"] == 1
        assert body["items"][0]["profile_name"] == "Alina Asif Khan"
        assert body["items"][0]["wa_id"] == "923217857439"

    def test_search_by_phone(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get("/api/admin/inbox/contacts?q=3334892624", headers=_admin())
        body = response.get_json()
        assert body["count"] == 1
        assert body["items"][0]["profile_name"] == "Rehan Abrar"

    def test_contact_with_no_messages(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get("/api/admin/inbox/contacts?q=Usman", headers=_admin())
        item = response.get_json()["items"][0]
        assert item["profile_name"] == "Ch Usman"
        assert item["message_count"] == 0
        assert item["latest_text"] == ""

    def test_pagination(self, ctx):
        client, db = ctx
        _seed(db)
        first = client.get("/api/admin/inbox/contacts?limit=2&page=1", headers=_admin()).get_json()
        second = client.get("/api/admin/inbox/contacts?limit=2&page=2", headers=_admin()).get_json()
        assert first["pages"] == 2
        assert first["count"] == 4
        assert len(first["items"]) == 2
        assert len(second["items"]) == 2
        first_ids = {item["wa_id"] for item in first["items"]}
        second_ids = {item["wa_id"] for item in second["items"]}
        assert first_ids.isdisjoint(second_ids)

    def test_batch_stats_not_n_plus_one(self, ctx, monkeypatch):
        client, db = ctx
        _seed(db)
        calls = {"aggregate": 0, "find_one": 0}
        original_agg = db.messages.aggregate
        original_find_one = db.contacts.find_one

        def counting_agg(*args, **kwargs):
            calls["aggregate"] += 1
            return original_agg(*args, **kwargs)

        def counting_find_one(*args, **kwargs):
            calls["find_one"] += 1
            return original_find_one(*args, **kwargs)

        monkeypatch.setattr(db.messages, "aggregate", counting_agg)
        monkeypatch.setattr(db.contacts, "find_one", counting_find_one)

        response = client.get("/api/admin/inbox/contacts", headers=_admin())
        assert response.status_code == 200
        assert len(response.get_json()["items"]) == 4
        assert calls["aggregate"] == 1
        assert calls["find_one"] == 0


class TestAdminInboxMessages:
    def test_contact_selection_loads_messages(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get(
            "/api/admin/inbox/contacts/923217857439/messages",
            headers=_admin(),
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["contact"]["profile_name"] == "Alina Asif Khan"
        assert body["contact"]["wa_id"] == "923217857439"
        assert body["count"] == 3
        assert [item["text"] for item in body["items"]] == [
            "kal compiler construction hai?",
            "aur assignment bhi?",
            "what's my next class?",
        ]
        assert all(item["from"] == "923217857439" for item in body["items"])
        assert all(item["from_name"] == "Alina Asif Khan" for item in body["items"])

    def test_messages_matched_by_from_equals_wa_id(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get(
            "/api/admin/inbox/contacts/923334892624/messages",
            headers=_admin(),
        )
        body = response.get_json()
        assert body["count"] == 1
        assert body["items"][0]["from"] == "923334892624"
        assert "quiz1" in body["items"][0]["text"]
        stored = db.messages.find_one({"from": "923334892624"})
        assert "from_name" not in stored

    def test_contact_with_no_messages_history(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get(
            "/api/admin/inbox/contacts/923004445555/messages",
            headers=_admin(),
        )
        body = response.get_json()
        assert body["contact"]["profile_name"] == "Ch Usman"
        assert body["items"] == []
        assert body["count"] == 0

    def test_message_with_no_matching_contact(self, ctx):
        client, db = ctx
        _seed(db)
        response = client.get(
            "/api/admin/inbox/contacts/923000000099/messages",
            headers=_admin(),
        )
        body = response.get_json()
        assert body["contact"]["profile_name"] is None
        assert body["count"] == 1
        assert body["items"][0]["from_name"] is None
        assert body["items"][0]["text"] == "orphan sender with no contact"

    def test_message_search_and_pagination(self, ctx):
        client, db = ctx
        _seed(db)
        searched = client.get(
            "/api/admin/inbox/contacts/923217857439/messages?q=assignment",
            headers=_admin(),
        ).get_json()
        assert searched["count"] == 1
        assert "assignment" in searched["items"][0]["text"]

        page1 = client.get(
            "/api/admin/inbox/contacts/923217857439/messages?limit=2&page=1",
            headers=_admin(),
        ).get_json()
        page2 = client.get(
            "/api/admin/inbox/contacts/923217857439/messages?limit=2&page=2",
            headers=_admin(),
        ).get_json()
        assert page1["pages"] == 2
        assert len(page1["items"]) == 2
        assert len(page2["items"]) == 1

    def test_summary_uses_real_counts(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/inbox/summary", headers=_admin()).get_json()
        assert body["total_contacts"] == 4
        assert body["total_messages"] == 5
        assert body["messages_today"] >= 1
        assert body["recent_contacts"] >= 1

    def test_message_bot_response_serialization_and_search(self, ctx):
        client, db = ctx
        _seed(db)
        from app import _utc_now
        db.messages.insert_one({
            "message_id": "msg_bot_test_123",
            "from": "923217857439",
            "from_name": "Alina Asif Khan",
            "text": "bscs 7b timetable",
            "bot_response": "Here is the timetable for BSCS 7B: PDC at 8:00 AM.",
            "intent": "timetable_query",
            "action": "reply",
            "received_at": _utc_now(),
        })
        response = client.get(
            "/api/admin/inbox/contacts/923217857439/messages?q=PDC",
            headers=_admin(),
        )
        assert response.status_code == 200
        body = response.get_json()
        assert body["count"] == 1
        item = body["items"][0]
        assert item["bot_response"] == "Here is the timetable for BSCS 7B: PDC at 8:00 AM."
        assert item["intent"] == "timetable_query"
        assert item["action"] == "reply"

