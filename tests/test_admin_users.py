"""
Admin users APIs: list, search, filters, detail, and summary.

Names stay on contacts (wa_id). users never store profile_name.
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
    db.users.insert_one({
        "user_id": "admin:system",
        "username": "admin",
        "password_hash": "secret-hash",
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


def _user(user_id, phone, settings=None, last_seen=None, created_at=None, **extra):
    doc = {
        "user_id": user_id,
        "phone_number": phone,
        "last_seen": last_seen or NOW,
        "created_at": created_at or NOW,
        "updated_at": last_seen or NOW,
        "settings": settings or {},
        "password_hash": "should-never-leak",
    }
    doc.update(extra)
    return doc


def _seed(db):
    db.users.insert_many([
        _user(
            "wa:923217857439",
            "923217857439",
            {
                "university_id": "riphah",
                "program": "BSCS",
                "semester": 7,
                "timetable_section": "BSCS-7B",
                "academic_term": "Fall 2026",
                "timezone": "Asia/Karachi",
                "reminder_enabled": True,
            },
            last_seen=NOW,
            created_at=NOW - timedelta(days=20),
        ),
        _user(
            "wa:923334892624",
            "923334892624",
            {
                "university_id": "riphah",
                "program": "BSCS",
                "semester": 6,
                "timetable_section": "BSCS-6B",
                "academic_term": "Fall 2026",
            },
            last_seen=NOW - timedelta(days=2),
            created_at=NOW - timedelta(days=10),
        ),
        _user(
            "wa:923004445555",
            "923004445555",
            {"timetable_section": "BSCS-6B"},
            last_seen=NOW - timedelta(days=30),
            created_at=NOW - timedelta(days=40),
        ),
        _user(
            "wa:923000000001",
            "923000000001",
            {},
            last_seen=NOW - timedelta(days=40),
            created_at=NOW - timedelta(days=50),
        ),
    ])
    db.contacts.insert_many([
        {"wa_id": "923217857439", "profile_name": "Alina Asif Khan", "last_seen": NOW},
        {"wa_id": "923334892624", "profile_name": "Rehan Abrar", "last_seen": NOW},
    ])
    db.user_timetables.insert_one({
        "user_id": "wa:923004445555",
        "selected_section": "BSCS-6B",
        "sections": {"BSCS-6B": [{"day": "Monday", "course": "CN"}]},
    })
    db.messages.insert_many([
        {"message_id": "m1", "from": "923217857439", "text": "hi", "received_at": NOW},
        {"message_id": "m2", "from": "923217857439", "text": "quiz", "received_at": NOW},
    ])
    db.tasks.insert_one({
        "user_id": "wa:923217857439",
        "parsed_title": "Information Security Quiz",
        "parsed_course": "Information Security",
        "task_type": "quiz",
        "status": "pending",
        "created_at": NOW,
    })
    db.official_timetables.insert_one({
        "status": "published",
        "university_id": "riphah",
        "academic_term": "Fall 2026",
        "detected_sections": ["BSCS-7B", "BSCS-6B"],
        "sections": {"BSCS-7B": [{"day": "Monday", "course": "IS"}], "BSCS-6B": []},
        "effective_from": NOW - timedelta(days=5),
        "effective_to": None,
        "version": 3,
    })


class TestAdminUsersAuth:
    def test_list_requires_auth(self, ctx):
        client, _ = ctx
        assert client.get("/api/admin/users").status_code == 401

    def test_student_jwt_rejected(self, ctx):
        client, db = ctx
        _seed(db)
        assert client.get("/api/admin/users", headers=_student()).status_code == 403
        assert client.get("/api/admin/users/wa:923217857439", headers=_student()).status_code == 403


class TestAdminUsersList:
    def test_users_list_loads(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users", headers=_admin()).get_json()
        assert body["count"] == 5
        ids = {item["user_id"] for item in body["items"]}
        assert "admin:system" not in ids
        assert "wa:923217857439" in ids
        alina = next(item for item in body["items"] if item["user_id"] == "wa:923217857439")
        assert alina["profile_name"] == "Alina Asif Khan"
        assert alina["section"] == "BSCS-7B"
        assert alina["timetable_source"] == "official"
        assert alina["message_count"] == 2
        assert alina["task_count"] == 1

    def test_search_by_phone(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?q=3334892624", headers=_admin()).get_json()
        assert body["count"] == 1
        assert body["items"][0]["user_id"] == "wa:923334892624"

    def test_search_by_user_id(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?q=wa:923000000001", headers=_admin()).get_json()
        assert body["count"] == 1
        assert body["items"][0]["phone_number"] == "923000000001"

    def test_search_by_contact_name(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?q=alina", headers=_admin()).get_json()
        assert body["count"] == 1
        assert body["items"][0]["profile_name"] == "Alina Asif Khan"
        assert body["items"][0]["wa_id"] == "923217857439"

    def test_university_filter(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?university=riphah", headers=_admin()).get_json()
        assert body["count"] == 2
        assert all(item["university"] == "riphah" for item in body["items"])

    def test_program_filter(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?program=BSCS", headers=_admin()).get_json()
        assert body["count"] == 2

    def test_semester_filter(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?semester=7", headers=_admin()).get_json()
        assert body["count"] == 1
        assert body["items"][0]["user_id"] == "wa:923217857439"

    def test_section_filter(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?section=BSCS-6B", headers=_admin()).get_json()
        assert {item["user_id"] for item in body["items"]} == {
            "wa:923334892624",
            "wa:923004445555",
        }

    def test_timetable_source_filter(self, ctx):
        client, db = ctx
        _seed(db)
        official = client.get("/api/admin/users?timetable_source=official", headers=_admin()).get_json()
        self_up = client.get("/api/admin/users?timetable_source=self_upload", headers=_admin()).get_json()
        none = client.get("/api/admin/users?timetable_source=none", headers=_admin()).get_json()
        assert official["count"] == 2
        assert self_up["count"] == 1
        assert self_up["items"][0]["user_id"] == "wa:923004445555"
        assert none["count"] == 2

    def test_pagination(self, ctx):
        client, db = ctx
        _seed(db)
        first = client.get("/api/admin/users?limit=2&page=1", headers=_admin()).get_json()
        second = client.get("/api/admin/users?limit=2&page=2", headers=_admin()).get_json()
        assert first["pages"] == 3
        assert first["count"] == 5
        first_ids = {item["user_id"] for item in first["items"]}
        second_ids = {item["user_id"] for item in second["items"]}
        assert first_ids.isdisjoint(second_ids)

    def test_sorting(self, ctx):
        client, db = ctx
        _seed(db)
        newest = [item["user_id"] for item in client.get("/api/admin/users?sort=newest", headers=_admin()).get_json()["items"]]
        oldest = [item["user_id"] for item in client.get("/api/admin/users?sort=oldest", headers=_admin()).get_json()["items"]]
        last_seen = [item["user_id"] for item in client.get("/api/admin/users?sort=last_seen", headers=_admin()).get_json()["items"]]
        assert newest.index("wa:923334892624") < newest.index("wa:923000000001")
        assert oldest.index("wa:923000000001") < oldest.index("wa:923334892624")
        assert last_seen[0] == "wa:923217857439"

    def test_no_secrets_returned(self, ctx):
        client, db = ctx
        _seed(db)
        listing = client.get("/api/admin/users", headers=_admin()).get_json()
        detail = client.get("/api/admin/users/wa:923217857439", headers=_admin()).get_json()
        blob = str(listing) + str(detail)
        assert "should-never-leak" not in blob
        assert "password_hash" not in blob
        assert "secret-hash" not in blob
        assert "password" not in detail.get("settings", {})

    def test_user_with_no_contact(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users?q=923000000001", headers=_admin()).get_json()
        assert body["count"] == 1
        assert body["items"][0]["profile_name"] is None
        assert body["items"][0]["user_id"] == "wa:923000000001"

    def test_no_n_plus_one(self, ctx, monkeypatch):
        client, db = ctx
        _seed(db)
        calls = {"contact_find": 0, "contact_find_one": 0, "msg_agg": 0, "task_agg": 0}
        orig_cfind = db.contacts.find
        orig_cfone = db.contacts.find_one
        orig_magg = db.messages.aggregate
        orig_tagg = db.tasks.aggregate

        def counting_cfind(*a, **k):
            calls["contact_find"] += 1
            return orig_cfind(*a, **k)

        def counting_cfone(*a, **k):
            calls["contact_find_one"] += 1
            return orig_cfone(*a, **k)

        def counting_magg(*a, **k):
            calls["msg_agg"] += 1
            return orig_magg(*a, **k)

        def counting_tagg(*a, **k):
            calls["task_agg"] += 1
            return orig_tagg(*a, **k)

        monkeypatch.setattr(db.contacts, "find", counting_cfind)
        monkeypatch.setattr(db.contacts, "find_one", counting_cfone)
        monkeypatch.setattr(db.messages, "aggregate", counting_magg)
        monkeypatch.setattr(db.tasks, "aggregate", counting_tagg)

        body = client.get("/api/admin/users", headers=_admin()).get_json()
        assert body["count"] == 5
        assert calls["contact_find"] == 1
        assert calls["contact_find_one"] == 0
        assert calls["msg_agg"] == 1
        assert calls["task_agg"] == 1


class TestAdminUserDetail:
    def test_user_detail(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users/wa:923217857439", headers=_admin()).get_json()
        assert body["profile_name"] == "Alina Asif Khan"
        assert body["contact"]["linked"] is True
        assert body["contact"]["wa_id"] == "923217857439"
        assert body["timetable"]["source"] == "official"
        assert body["timetable"]["version"] == 3
        assert body["settings"]["timezone"] == "Asia/Karachi"
        assert body["recent_tasks"][0]["title"] == "Information Security Quiz"

    def test_contact_name_via_wa_id(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users/wa:923334892624", headers=_admin()).get_json()
        assert body["profile_name"] == "Rehan Abrar"
        stored = db.users.find_one({"user_id": "wa:923334892624"})
        assert "profile_name" not in stored

    def test_user_without_contact_detail(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users/wa:923000000001", headers=_admin()).get_json()
        assert body["profile_name"] is None
        assert body["contact"]["linked"] is False
        assert body["timetable_source"] == "none"


class TestAdminUsersSummary:
    def test_summary_counts(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/users/summary", headers=_admin()).get_json()
        assert body["total_users"] == 5
        assert body["official_timetable"] == 2
        assert body["self_uploaded_timetable"] == 1
        assert body["no_timetable"] == 2
        assert body["active_users"] >= 1
