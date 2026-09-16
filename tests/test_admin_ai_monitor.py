"""Admin AI Monitor APIs over existing db.llm_calls."""
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
NOW = datetime(2026, 9, 16, 6, 40, tzinfo=timezone.utc)
RANGE = "since=2026-09-16T00:00:00Z&until=2026-09-16T23:59:59Z"


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


def _call(**overrides):
    doc = {
        "call_id": overrides.pop("call_id", "call-1"),
        "model": "openai/gpt-oss-20b",
        "prompt_version": "nlu_understand_v1",
        "caller": "nlu_understand",
        "input_tokens": 10,
        "output_tokens": 5,
        "total_tokens": 15,
        "latency_ms": 1100.0,
        "confidence": 0.9,
        "parse_method": "nlu",
        "success": True,
        "error": None,
        "provider": "groq",
        "credential_slot": "primary",
        "fallback_reason": None,
        "system_prompt_hash": "abc123def456",
        "user_message_len": 28,
        "created_at": NOW,
        "user_id": "wa:923217857439",
        "channel": "whatsapp",
        "request_id": "req-1",
        "intent": "task_action",
        "action": "complete",
        "query_type": None,
        "task_type": None,
    }
    doc.update(overrides)
    return doc


def _seed(db):
    db.contacts.insert_many([
        {"wa_id": "923217857439", "profile_name": "Rehan"},
        {"wa_id": "923334892624", "profile_name": "Usman"},
        {"wa_id": "923001112233", "profile_name": "Ali"},
    ])
    db.llm_calls.insert_many([
        _call(call_id="c1", user_id="wa:923217857439", intent="task_action", action="complete", latency_ms=1100),
        _call(
            call_id="c2",
            user_id="wa:923334892624",
            intent="schedule_query",
            action=None,
            query_type="next_class",
            latency_ms=800,
            created_at=NOW - timedelta(minutes=1),
        ),
        _call(
            call_id="c3",
            user_id="wa:923001112233",
            caller="_parse_with_groq",
            prompt_version="parse_task_v2",
            intent="save_task",
            action="create",
            provider="gemini",
            credential_slot="primary",
            model="gemini-2.5-flash-lite",
            latency_ms=2300,
            created_at=NOW - timedelta(minutes=2),
        ),
        _call(
            call_id="c4",
            user_id="wa:923217857439",
            success=False,
            error="Bearer gsk_THISISASECRETKEYVALUE exploded",
            fallback_reason="rate_limit",
            latency_ms=90,
            intent=None,
            action=None,
            created_at=NOW - timedelta(minutes=3),
            api_key="gsk_THISISASECRETKEYVALUE",
            user_message="mark all my tasks completed",
            authorization="Bearer student-jwt",
        ),
        _call(
            call_id="c5",
            user_id="wa:923334892624",
            provider="groq",
            credential_slot="secondary",
            fallback_reason=None,
            latency_ms=1400,
            created_at=NOW - timedelta(minutes=4),
            request_id="req-fb",
        ),
        _call(
            call_id="old",
            created_at=NOW - timedelta(days=8),
            user_id="wa:923217857439",
            intent="help",
        ),
    ])


class TestAdminAiMonitorAuth:
    def test_unauthenticated(self, ctx):
        client, _db = ctx
        assert client.get("/api/admin/ai/summary").status_code == 401
        assert client.get("/api/admin/ai/calls").status_code == 401
        assert client.get("/api/admin/ai/calls/c1").status_code == 401

    def test_student_forbidden(self, ctx):
        client, _db = ctx
        assert client.get("/api/admin/ai/summary", headers=_student()).status_code == 403
        assert client.get("/api/admin/ai/calls", headers=_student()).status_code == 403
        assert client.get("/api/admin/ai/calls/c1", headers=_student()).status_code == 403


class TestAdminAiMonitorSummary:
    def test_today_counts_and_providers(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get(f"/api/admin/ai/summary?{RANGE}", headers=_admin()).get_json()
        assert body["requests"] == 5
        assert body["successful"] == 4
        assert body["failed"] == 1
        assert body["fallbacks"] == 2  # gemini + groq secondary
        assert body["avg_latency_ms"] == 1138.0
        labels = {row["label"]: row["count"] for row in body["providers"]}
        assert labels["Groq groq_1"] == 3
        assert labels["Groq groq_2"] == 1
        assert labels["Gemini"] == 1

    def test_summary_respects_success_filter(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get(
            f"/api/admin/ai/summary?{RANGE}&success=false",
            headers=_admin(),
        ).get_json()
        assert body["requests"] == 1
        assert body["failed"] == 1
        assert body["successful"] == 0


class TestAdminAiMonitorList:
    def test_date_only_filter_uses_pakistan_calendar_day(self, ctx):
        client, db = ctx
        early_pkt = datetime(2026, 9, 15, 20, 0, tzinfo=timezone.utc)  # 01:00 PKT on Sep 16
        db.llm_calls.insert_one(_call(call_id="early", created_at=early_pkt))
        body = client.get(
            "/api/admin/ai/calls?since=2026-09-16&until=2026-09-16",
            headers=_admin(),
        ).get_json()
        assert [row["call_id"] for row in body["items"]] == ["early"]

    def test_pagination(self, ctx):
        client, db = ctx
        _seed(db)
        first = client.get(f"/api/admin/ai/calls?{RANGE}&limit=2&page=1", headers=_admin()).get_json()
        second = client.get(f"/api/admin/ai/calls?{RANGE}&limit=2&page=2", headers=_admin()).get_json()
        assert first["count"] == 5
        assert first["pages"] == 3
        assert [row["call_id"] for row in first["items"]] == ["c1", "c2"]
        assert [row["call_id"] for row in second["items"]] == ["c3", "c4"]

    def test_filters_and_search(self, ctx):
        client, db = ctx
        _seed(db)
        by_user = client.get(
            f"/api/admin/ai/calls?{RANGE}&user=wa:923217857439",
            headers=_admin(),
        ).get_json()
        assert {row["call_id"] for row in by_user["items"]} == {"c1", "c4"}

        by_name = client.get(f"/api/admin/ai/calls?{RANGE}&q=Usman", headers=_admin()).get_json()
        assert {row["call_id"] for row in by_name["items"]} == {"c2", "c5"}

        by_intent = client.get(
            f"/api/admin/ai/calls?{RANGE}&intent=schedule_query",
            headers=_admin(),
        ).get_json()
        assert [row["call_id"] for row in by_intent["items"]] == ["c2"]

        by_stage = client.get(
            f"/api/admin/ai/calls?{RANGE}&stage=task",
            headers=_admin(),
        ).get_json()
        assert [row["call_id"] for row in by_stage["items"]] == ["c3"]
        assert by_stage["items"][0]["stage"] == "task"

        by_provider = client.get(
            f"/api/admin/ai/calls?{RANGE}&provider=gemini",
            headers=_admin(),
        ).get_json()
        assert [row["call_id"] for row in by_provider["items"]] == ["c3"]

        failed = client.get(
            f"/api/admin/ai/calls?{RANGE}&success=false",
            headers=_admin(),
        ).get_json()
        assert [row["call_id"] for row in failed["items"]] == ["c4"]

    def test_names_from_contacts_no_n_plus_one(self, ctx):
        client, db = ctx
        _seed(db)
        original = db.contacts.find
        calls = {"n": 0}

        def wrapped(*args, **kwargs):
            calls["n"] += 1
            return original(*args, **kwargs)

        def boom(*args, **kwargs):
            raise AssertionError("N+1 contacts.find_one")

        db.contacts.find = wrapped
        db.contacts.find_one = boom
        body = client.get(f"/api/admin/ai/calls?{RANGE}&limit=20", headers=_admin()).get_json()
        assert calls["n"] == 1
        by_id = {row["call_id"]: row for row in body["items"]}
        assert by_id["c1"]["profile_name"] == "Rehan"
        assert by_id["c2"]["profile_name"] == "Usman"
        assert by_id["c3"]["stage"] == "task"
        assert by_id["c5"]["used_fallback"] is True
        assert by_id["c5"]["provider_label"] == "Groq groq_2"


class TestAdminAiMonitorDetail:
    def test_detail_and_no_secrets(self, ctx):
        client, db = ctx
        _seed(db)
        body = client.get("/api/admin/ai/calls/c4", headers=_admin()).get_json()
        assert body["call_id"] == "c4"
        assert body["success"] is False
        assert body["profile_name"] == "Rehan"
        dumped = str(body)
        assert "gsk_THISISASECRETKEYVALUE" not in dumped
        assert "student-jwt" not in dumped
        assert "mark all my tasks completed" not in dumped
        assert "user_message" not in body
        assert "api_key" not in body
        assert "authorization" not in body
        assert body["error"] is None or "gsk_" not in body["error"]

    def test_detail_related_same_request(self, ctx):
        client, db = ctx
        _seed(db)
        db.llm_calls.insert_one(_call(
            call_id="c5b",
            request_id="req-fb",
            caller="nlu_respond",
            user_id="wa:923334892624",
            intent=None,
            created_at=NOW - timedelta(minutes=4, seconds=-1),
        ))
        body = client.get("/api/admin/ai/calls/c5", headers=_admin()).get_json()
        assert [row["call_id"] for row in body["related"]] == ["c5b"]

    def test_missing_call(self, ctx):
        client, db = ctx
        _seed(db)
        assert client.get("/api/admin/ai/calls/missing", headers=_admin()).status_code == 404
