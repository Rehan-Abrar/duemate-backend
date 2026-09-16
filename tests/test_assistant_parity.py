"""
Web assistant and WhatsApp must share one AI pipeline.

Same message → dispatch_message (WhatsApp) and POST /api/student/assistant/chat
must produce the same understanding, data, and grounding. Web never trusts
client-supplied user_id / section / timetable.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import app as appmod
from utils.nlu import (
    dispatch_message,
    GREETING_REPLY,
    HELP_REPLY,
    OUT_OF_SCOPE_CASUAL,
)
from utils.auth import create_access_token

SECRET = "test-jwt-secret"
USER_A = "wa:923001111111"
USER_B = "wa:923002222222"
SEC_A = "BSCS-7A"
SEC_B = "BSCS-7B"
COURSE_A = "Discrete Mathematics"
COURSE_B = "Information Security Lab"
TASK_A_TITLE = "Secret Quiz Only For A"
TASK_B_TITLE = "Secret Quiz Only For B"


def _slot(day, time, course, section, room="R1", instr="Dr X"):
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


def _student_token(user_id):
    return create_access_token(user_id)


def _headers(user_id):
    return {"Authorization": f"Bearer {_student_token(user_id)}"}


def _seed_user(db, user_id, section, phone):
    db.users.insert_one({
        "user_id": user_id,
        "phone_number": phone,
        "settings": {
            "timetable_section": section,
            "university_id": "riphah",
            "academic_term": "Fall 2026",
        },
    })


def _seed_official(db):
    now = datetime.now(timezone.utc) - timedelta(days=1)
    db.official_timetables.insert_one({
        "timetable_id": "riphah-fall-2026",
        "university_id": "riphah",
        "academic_term": "Fall 2026",
        "version": 1,
        "status": "published",
        "detected_sections": [SEC_A, SEC_B],
        "effective_from": now,
        "effective_to": None,
        "sections": {
            SEC_A: [
                _slot("Monday", "08:00-10:00", COURSE_A, SEC_A, "Classroom 2"),
            ],
            SEC_B: [
                _slot("Wednesday", "08:00-11:00", COURSE_B, SEC_B, "Computer Lab 1"),
            ],
        },
    })


def _seed_task(db, user_id, title, course):
    db.tasks.insert_one({
        "user_id": user_id,
        "status": "pending",
        "task_type": "quiz",
        "parsed_course": course,
        "parsed_title": title,
        "raw_message": title,
        "parsed_due_date": datetime.now(timezone.utc) + timedelta(days=1),
    })


@pytest.fixture
def ctx(monkeypatch):
    db = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("NLU_LLM_ROUTING_ENABLED", "true")
    monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "false")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY_v2", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: db)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "ensure_mongo_indexes", lambda: None)

    _seed_official(db)
    _seed_user(db, USER_A, SEC_A, "923001111111")
    _seed_user(db, USER_B, SEC_B, "923002222222")
    _seed_task(db, USER_A, TASK_A_TITLE, COURSE_A)
    _seed_task(db, USER_B, TASK_B_TITLE, COURSE_B)

    application = appmod.create_app()
    application.testing = True
    return application.test_client(), db


def _chat(client, user_id, message, extra=None):
    body = {"message": message}
    if extra:
        body.update(extra)
    return client.post(
        "/api/student/assistant/chat",
        json=body,
        headers=_headers(user_id),
    )


def _stub_understand(monkeypatch, payload):
    monkeypatch.setattr("utils.nlu.understand", lambda *a, **kw: payload)


def _full_timetable(section=None):
    return {
        "intent": "schedule_query",
        "language": "en",
        "confidence": 0.95,
        "schedule": {
            "query_type": "full_timetable",
            "course": None,
            "teacher": None,
            "section": section,
            "day": None,
            "time_after": None,
            "time_before": None,
        },
    }


class TestAuthIsolation:
    def test_unauthenticated_cannot_chat(self, ctx):
        client, _db = ctx
        resp = client.post(
            "/api/student/assistant/chat",
            json={"message": "show my timetable"},
        )
        assert resp.status_code == 401

    def test_unauthenticated_cannot_spoof_user_id(self, ctx):
        client, _db = ctx
        resp = client.post(
            "/api/student/assistant/chat",
            json={
                "message": "show my timetable",
                "user_id": USER_A,
                "section": SEC_A,
            },
        )
        assert resp.status_code == 401

    def test_client_user_id_and_section_are_ignored(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, _full_timetable())

        resp = _chat(
            client,
            USER_B,
            "show my timetable",
            extra={
                "user_id": USER_A,
                "section": SEC_A,
                "timetable": {"courses": [COURSE_A]},
            },
        )
        assert resp.status_code == 200
        text = resp.get_json()["reply"]
        assert COURSE_B in text
        assert COURSE_A not in text


class TestWebWhatsAppParity:
    def test_greeting_same_text(self, ctx):
        client, db = ctx
        wa = dispatch_message(db, USER_A, "923001111111", "hi")
        web = _chat(client, USER_A, "hi")
        assert web.status_code == 200
        assert wa["action"] == "reply"
        assert wa["text"] == GREETING_REPLY
        assert web.get_json()["reply"] == wa["text"]

    def test_help_same_text(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "help",
            "language": "en",
            "confidence": 0.9,
        })
        message = "what can you do"
        wa = dispatch_message(db, USER_A, "923001111111", message)
        web = _chat(client, USER_A, message)
        assert web.status_code == 200
        assert wa["text"] == HELP_REPLY
        assert web.get_json()["reply"] == wa["text"]

    def test_casual_oos_same_text(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "out_of_scope",
            "language": "en",
            "confidence": 0.9,
            "out_of_scope": {"kind": "casual", "topic": None},
        })
        message = "good shit"
        wa = dispatch_message(db, USER_A, "923001111111", message)
        web = _chat(client, USER_A, message)
        assert wa["text"] == OUT_OF_SCOPE_CASUAL
        assert web.get_json()["reply"] == wa["text"]

    def test_unrelated_oos_same_grounding(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "out_of_scope",
            "language": "mixed",
            "confidence": 0.96,
            "out_of_scope": {"kind": "unrelated", "topic": "weather"},
        })
        message = "Lahore ka weather kaisa hai"
        wa = dispatch_message(db, USER_A, "923001111111", message)
        web = _chat(client, USER_A, message)
        assert web.status_code == 200
        assert wa["text"] == web.get_json()["reply"]
        assert "weather" in wa["text"]
        assert "timetable" in wa["text"].lower()

    def test_next_class_same_text(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "schedule_query",
            "language": "mixed",
            "confidence": 0.94,
            "schedule": {
                "query_type": "next_class",
                "course": None,
                "teacher": None,
                "section": None,
                "day": None,
                "time_after": None,
                "time_before": None,
            },
        })
        message = "meri next class kab hai"
        wa = dispatch_message(db, USER_A, "923001111111", message)
        web = _chat(client, USER_A, message)
        assert web.status_code == 200
        assert wa["action"] == "reply"
        assert wa["text"] == web.get_json()["reply"]
        assert COURSE_B not in wa["text"]

    def test_personal_timetable_same_and_isolated(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, _full_timetable())
        message = "mera timetable dikhao"

        wa_a = dispatch_message(db, USER_A, "923001111111", message)
        web_a = _chat(client, USER_A, message)
        wa_b = dispatch_message(db, USER_B, "923002222222", message)
        web_b = _chat(client, USER_B, message)

        assert web_a.status_code == 200
        assert web_b.status_code == 200
        assert wa_a["text"] == web_a.get_json()["reply"]
        assert wa_b["text"] == web_b.get_json()["reply"]
        assert COURSE_A in wa_a["text"]
        assert COURSE_B not in wa_a["text"]
        assert COURSE_B in wa_b["text"]
        assert COURSE_A not in wa_b["text"]

    def test_public_section_query_same_source(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, _full_timetable(SEC_A))
        message = "show BSCS-7A timetable"

        # User B asking about section A — official public lookup, not B's personal slots
        wa = dispatch_message(db, USER_B, "923002222222", message)
        web = _chat(client, USER_B, message)
        assert web.status_code == 200
        assert wa["text"] == web.get_json()["reply"]
        assert COURSE_A in wa["text"]
        assert COURSE_B not in wa["text"]

    def test_task_query_same_and_isolated(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "task_query",
            "language": "en",
            "confidence": 0.93,
            "task": {"due": None, "filter_course": None},
        })
        message = "what do I have due"

        wa_a = dispatch_message(db, USER_A, "923001111111", message)
        web_a = _chat(client, USER_A, message)
        wa_b = dispatch_message(db, USER_B, "923002222222", message)
        web_b = _chat(client, USER_B, message)

        assert wa_a["text"] == web_a.get_json()["reply"]
        assert wa_b["text"] == web_b.get_json()["reply"]
        assert TASK_A_TITLE in wa_a["text"]
        assert TASK_B_TITLE not in wa_a["text"]
        assert TASK_B_TITLE in wa_b["text"]
        assert TASK_A_TITLE not in wa_b["text"]

    def test_save_task_uses_jwt_user_not_body(self, ctx, monkeypatch):
        client, db = ctx
        _stub_understand(monkeypatch, {
            "intent": "save_task",
            "language": "ur",
            "confidence": 0.97,
        })
        due = datetime(2026, 9, 20, 14, 0, tzinfo=timezone.utc)

        def fake_parse(text, course_hint=None, user_courses=None, overrides=None, db=None):
            return {
                "task_type": "quiz",
                "course": COURSE_B,
                "title": "CN Quiz",
                "due_date": due,
                "quiz_material": None,
                "quiz_duration": None,
                "quiz_time": None,
                "confidence": 0.9,
                "parse_method": "test",
                "groq_raw_response": None,
                "needs_review": False,
                "date_uncertain": False,
                "has_explicit_time": True,
            }

        monkeypatch.setattr(appmod, "parse_task", fake_parse)
        monkeypatch.setattr("utils.parse_task.parse_task", fake_parse)

        message = "kal CN ka quiz hai"
        wa = dispatch_message(db, USER_B, "923002222222", message)
        assert wa["action"] == "reply"
        assert "saved" in wa["text"].lower()
        assert "Task saved!" not in wa["text"] or COURSE_B in wa["text"]

        web = _chat(
            client,
            USER_B,
            message,
            extra={"user_id": USER_A, "section": SEC_A},
        )
        assert web.status_code == 200
        body = web.get_json()
        assert body["reply"] == wa["text"]
        owned = list(db.tasks.find({"user_id": USER_B}))
        assert len(owned) >= 1
        assert db.tasks.find_one({"user_id": USER_A, "source_key": "nlu_create"}) is None
        assert owned[-1]["parsed_course"] == COURSE_B
