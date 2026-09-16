"""
Conversational NLU: pending state is context, not a routing override.

Covers create-clarification, complete/delete/reschedule, isolation, and
query-vs-action. LLM #1 is stubbed; Python performs all DB writes.
"""
import os
import sys
from datetime import datetime, timezone

import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import app as appmod
from utils.nlu import handle_message, dispatch_message, GREETING_REPLY
from utils.auth import create_access_token
from utils.nlu_session import save_nlu_session, get_nlu_session

SECRET = "test-jwt-secret"
USER_A = "wa:923001111111"
USER_B = "wa:923002222222"
DUE = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)


def _parse(**overrides):
    base = {
        "task_type": "quiz",
        "course": None,
        "title": "Quiz",
        "due_date": None,
        "quiz_material": None,
        "quiz_duration": None,
        "quiz_time": None,
        "confidence": 0.8,
        "parse_method": "test",
        "groq_raw_response": None,
        "needs_review": True,
        "date_uncertain": True,
        "has_explicit_time": False,
    }
    base.update(overrides)
    return base


@pytest.fixture
def db(monkeypatch):
    database = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setenv("NLU_LLM_ROUTING_ENABLED", "true")
    monkeypatch.setenv("NLU_LLM_RESPONSE_ENABLED", "false")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: database)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "ensure_mongo_indexes", lambda: None)
    database.users.insert_one({
        "user_id": USER_A,
        "phone_number": "923001111111",
        "settings": {"timetable_section": "BSCS-7A", "university_id": "riphah"},
    })
    database.users.insert_one({
        "user_id": USER_B,
        "phone_number": "923002222222",
        "settings": {"timetable_section": "BSCS-7B", "university_id": "riphah"},
    })
    return database


@pytest.fixture
def client(db, monkeypatch):
    application = appmod.create_app()
    application.testing = True
    return application.test_client()


def _headers(user_id):
    return {"Authorization": f"Bearer {create_access_token(user_id)}"}


def _stub_understand(monkeypatch, payload):
    monkeypatch.setattr("utils.nlu.understand", lambda *a, **kw: payload)


def _seed_task(db, user_id, title, course="Information Security", status="pending", task_type="quiz"):
    db.tasks.insert_one({
        "user_id": user_id,
        "status": status,
        "task_type": task_type,
        "parsed_course": course,
        "parsed_title": title,
        "raw_message": title,
        "parsed_due_date": DUE,
    })
    return db.tasks.find_one({"user_id": user_id, "parsed_title": title})


class TestIncompleteCreate:
    def test_quiz_goes_through_nlu_and_does_not_save(self, db, monkeypatch):
        called = {}

        def understand(text, db=None, session=None):
            called["text"] = text
            called["had_session"] = session is not None
            return {"intent": "save_task", "language": "en", "confidence": 0.94}

        monkeypatch.setattr("utils.nlu.understand", understand)
        monkeypatch.setattr("utils.parse_task.parse_task", lambda *a, **kw: _parse(task_type="quiz"))

        result = handle_message(db, USER_A, "923001111111", "quiz")
        assert called["text"] == "quiz"
        assert result["action"] == "reply"
        assert "Task saved" not in result["text"]
        assert "which course" in result["text"].lower()
        assert db.tasks.count_documents({"user_id": USER_A}) == 0
        pending = get_nlu_session(db, USER_A).get("pending_create")
        assert pending

    def test_missing_course_detected(self, db, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.9})
        monkeypatch.setattr("utils.parse_task.parse_task", lambda *a, **kw: _parse(task_type="quiz"))
        result = handle_message(db, USER_A, "923001111111", "quiz")
        assert "course" in result["text"].lower()

    def test_missing_date_detected(self, db, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.9})
        monkeypatch.setattr(
            "utils.parse_task.parse_task",
            lambda *a, **kw: _parse(task_type="quiz", course="Information Security"),
        )
        result = handle_message(db, USER_A, "923001111111", "Information Security quiz")
        assert "when" in result["text"].lower()
        assert db.tasks.count_documents({}) == 0

    def test_missing_time_detected(self, db, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.9})
        monkeypatch.setattr(
            "utils.parse_task.parse_task",
            lambda *a, **kw: _parse(
                task_type="quiz",
                course="Information Security",
                due_date=DUE.replace(hour=18, minute=59),
                has_explicit_time=False,
            ),
        )
        result = handle_message(db, USER_A, "923001111111", "Information Security quiz Monday")
        assert "time" in result["text"].lower()
        assert db.tasks.count_documents({}) == 0

    def test_complete_create_saves_once(self, db, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.97})
        complete = _parse(
            course="Information Security",
            task_type="quiz",
            title="Quiz",
            due_date=DUE,
            needs_review=False,
            has_explicit_time=True,
        )
        monkeypatch.setattr("utils.parse_task.parse_task", lambda *a, **kw: complete)
        monkeypatch.setattr(appmod, "parse_task", lambda *a, **kw: complete)

        result = handle_message(db, USER_A, "923001111111", "Information Security quiz Monday at 10 AM")
        assert result["action"] == "reply"
        assert "saved" in result["text"].lower()
        assert "Task saved!" not in result["text"]
        saved = list(db.tasks.find({"user_id": USER_A}))
        assert len(saved) == 1
        assert saved[0]["parsed_course"] == "Information Security"
        assert saved[0]["status"] == "pending"


class TestMultiTurnCreate:
    def test_clarification_and_correction(self, db, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.9})

        monkeypatch.setattr("utils.parse_task.parse_task", lambda *a, **kw: _parse(task_type="quiz"))
        r1 = handle_message(db, USER_A, "923001111111", "quiz")
        assert "course" in r1["text"].lower()
        assert db.tasks.count_documents({}) == 0

        monkeypatch.setattr(
            "utils.parse_task.parse_task",
            lambda *a, **kw: _parse(task_type="quiz", course="Information Security"),
        )
        r2 = handle_message(db, USER_A, "923001111111", "Information Security")
        assert "when" in r2["text"].lower()

        monkeypatch.setattr(
            "utils.parse_task.parse_task",
            lambda *a, **kw: _parse(task_type="quiz", course="Computer Vision"),
        )
        r3 = handle_message(db, USER_A, "923001111111", "Actually it's Computer Vision")
        assert "Computer Vision" in r3["text"]
        assert "when" in r3["text"].lower()
        draft = get_nlu_session(db, USER_A)["pending_create"]["draft"]
        assert draft["course"] == "Computer Vision"

        monkeypatch.setattr(
            "utils.parse_task.parse_task",
            lambda *a, **kw: _parse(
                task_type="quiz",
                course="Computer Vision",
                due_date=DUE,
                has_explicit_time=True,
                needs_review=False,
            ),
        )
        monkeypatch.setattr(
            appmod, "parse_task",
            lambda *a, **kw: _parse(
                task_type="quiz",
                course="Computer Vision",
                due_date=DUE,
                has_explicit_time=True,
                needs_review=False,
            ),
        )
        r4 = handle_message(db, USER_A, "923001111111", "Monday at 10 AM")
        assert "saved" in r4["text"].lower()
        assert db.tasks.count_documents({"user_id": USER_A, "parsed_course": "Computer Vision"}) == 1


class TestPendingDoesNotOverrideNlu:
    def test_show_tasks_during_pending_create(self, db, monkeypatch):
        save_nlu_session(db, USER_A, "923001111111", pending_create={"draft": {"task_type": "quiz"}})
        _seed_task(db, USER_A, "Secret Quiz Only For A")
        _stub_understand(monkeypatch, {
            "intent": "task_query",
            "language": "en",
            "confidence": 0.96,
            "task": {"filter_course": None, "due": None},
        })
        result = handle_message(db, USER_A, "923001111111", "show tasks")
        assert result["intent"] == "task_query"
        assert "Secret Quiz Only For A" in result["text"]
        assert "didn't recognise" not in result["text"].lower()
        assert get_nlu_session(db, USER_A).get("pending_create")

    def test_hi_during_pending_create_is_greeting(self, db, monkeypatch):
        save_nlu_session(db, USER_A, "923001111111", pending_create={"draft": {"task_type": "quiz"}})
        _stub_understand(monkeypatch, {
            "intent": "greeting", "language": "en", "confidence": 1.0,
        })
        result = handle_message(db, USER_A, "923001111111", "hi")
        assert result["intent"] == "greeting"
        assert result["text"] == GREETING_REPLY
        assert "didn't recognise" not in result["text"].lower()

    def test_next_class_during_pending_create(self, db, monkeypatch):
        save_nlu_session(db, USER_A, "923001111111", pending_create={"draft": {"task_type": "quiz"}})
        _stub_understand(monkeypatch, {
            "intent": "schedule_query",
            "language": "en",
            "confidence": 0.95,
            "schedule": {
                "query_type": "next_class",
                "course": None, "teacher": None, "section": None,
                "day": None, "time_after": None, "time_before": None,
            },
        })
        result = handle_message(db, USER_A, "923001111111", "when is my next class?")
        assert result["intent"] == "schedule_query"
        assert "didn't recognise" not in result["text"].lower()

    def test_cancel_clears_pending(self, db, monkeypatch):
        save_nlu_session(db, USER_A, "923001111111", pending_create={"draft": {"task_type": "quiz"}})
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.9,
            "task_action": {"action": "cancel", "scope": "matching"},
        })
        result = handle_message(db, USER_A, "923001111111", "cancel")
        assert "cancel" in result["text"].lower()
        assert not get_nlu_session(db, USER_A).get("pending_create")


class TestCompleteAll:
    def test_complete_all_pending(self, db, monkeypatch):
        _seed_task(db, USER_A, "Quiz One")
        _seed_task(db, USER_A, "Quiz Two")
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.97,
            "task_action": {"action": "complete", "scope": "all"},
        })
        result = handle_message(db, USER_A, "923001111111", "mark all my tasks as completed")
        assert "2" in result["text"]
        assert db.tasks.count_documents({"user_id": USER_A, "status": "completed"}) == 2
        assert db.tasks.count_documents({"user_id": USER_A, "status": "pending"}) == 0

    def test_no_pending_tasks(self, db, monkeypatch):
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.97,
            "task_action": {"action": "complete", "scope": "all"},
        })
        result = handle_message(db, USER_A, "923001111111", "complete all my pending tasks")
        assert "pending" in result["text"].lower()
        assert db.tasks.count_documents({"status": "completed"}) == 0

    def test_already_completed_not_modified(self, db, monkeypatch):
        _seed_task(db, USER_A, "Old Quiz", status="completed")
        _seed_task(db, USER_A, "Open Quiz", status="pending")
        before = db.tasks.find_one({"parsed_title": "Old Quiz"})["status"]
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.94,
            "task_action": {"action": "complete", "scope": "all"},
        })
        result = handle_message(db, USER_A, "923001111111", "I've finished everything, mark them done")
        assert "Open Quiz" in result["text"]
        assert db.tasks.find_one({"parsed_title": "Old Quiz"})["status"] == before
        assert db.tasks.find_one({"parsed_title": "Open Quiz"})["status"] == "completed"

    def test_user_isolation(self, db, monkeypatch):
        _seed_task(db, USER_A, "A Quiz")
        _seed_task(db, USER_B, "B Quiz")
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.97,
            "task_action": {"action": "complete", "scope": "all"},
        })
        handle_message(db, USER_A, "923001111111", "mark all my tasks as completed")
        assert db.tasks.find_one({"user_id": USER_A})["status"] == "completed"
        assert db.tasks.find_one({"user_id": USER_B})["status"] == "pending"

    def test_natural_language_variations_same_action(self, db, monkeypatch):
        for msg in (
            "mark all my tasks as completed",
            "complete all my pending tasks",
            "I've finished everything, mark them done",
        ):
            db.tasks.delete_many({"user_id": USER_A})
            _seed_task(db, USER_A, "Only Quiz")
            _stub_understand(monkeypatch, {
                "intent": "task_action",
                "language": "en",
                "confidence": 0.95,
                "task_action": {"action": "complete", "scope": "all"},
            })
            result = handle_message(db, USER_A, "923001111111", msg)
            assert db.tasks.find_one({"user_id": USER_A})["status"] == "completed"
            assert "completed" in result["text"].lower()


class TestTaskReferences:
    def test_whats_due_remains_task_query(self, db, monkeypatch):
        _seed_task(db, USER_A, "Due Quiz")
        _stub_understand(monkeypatch, {
            "intent": "task_query",
            "language": "en",
            "confidence": 0.95,
            "task": {"filter_course": None, "due": None},
        })
        result = handle_message(db, USER_A, "923001111111", "what's due?")
        assert result["intent"] == "task_query"
        assert "Due Quiz" in result["text"]
        assert db.tasks.find_one({"parsed_title": "Due Quiz"})["status"] == "pending"

    def test_ambiguous_delete_asks(self, db, monkeypatch):
        _seed_task(db, USER_A, "Quiz One")
        _seed_task(db, USER_A, "Quiz Two")
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.94,
            "task_action": {"action": "delete", "scope": "matching", "filter_type": "quiz"},
        })
        result = handle_message(db, USER_A, "923001111111", "delete my quiz")
        assert "which" in result["text"].lower()
        assert db.tasks.count_documents({"user_id": USER_A}) == 2

    def test_unambiguous_delete_performs(self, db, monkeypatch):
        _seed_task(db, USER_A, "Only Quiz")
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.94,
            "task_action": {"action": "delete", "scope": "matching", "filter_type": "quiz"},
        })
        result = handle_message(db, USER_A, "923001111111", "delete my quiz")
        assert "deleted" in result["text"].lower()
        assert db.tasks.count_documents({"user_id": USER_A}) == 0

    def test_mark_that_done_uses_last_listed(self, db, monkeypatch):
        task = _seed_task(db, USER_A, "Listed Quiz")
        save_nlu_session(db, USER_A, "923001111111", last_task_ids=[str(task["_id"])])
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.93,
            "task_action": {"action": "complete", "scope": "reference", "reference": "that"},
        })
        result = handle_message(db, USER_A, "923001111111", "mark that done")
        assert "completed" in result["text"].lower()
        assert db.tasks.find_one({"_id": task["_id"]})["status"] == "completed"

    def test_no_success_without_db_change(self, db, monkeypatch):
        _stub_understand(monkeypatch, {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.97,
            "task_action": {"action": "complete", "scope": "all"},
        })
        result = handle_message(db, USER_A, "923001111111", "mark all my tasks as completed")
        assert "completed" not in result["text"].lower() or "pending" in result["text"].lower()
        assert "Done" not in result["text"]


class TestWebWhatsAppSamePipeline:
    def test_quiz_same_on_web_and_dispatch(self, db, client, monkeypatch):
        _stub_understand(monkeypatch, {"intent": "save_task", "language": "en", "confidence": 0.94})
        monkeypatch.setattr("utils.parse_task.parse_task", lambda *a, **kw: _parse(task_type="quiz"))
        wa = dispatch_message(db, USER_A, "923001111111", "quiz")
        web = client.post(
            "/api/student/assistant/chat",
            json={"message": "quiz"},
            headers=_headers(USER_A),
        )
        assert web.status_code == 200
        assert wa["text"] == web.get_json()["reply"]
        assert "which course" in wa["text"].lower()
        assert db.tasks.count_documents({}) == 0

    def test_complete_all_same_on_web_and_dispatch(self, db, client, monkeypatch):
        _seed_task(db, USER_A, "Shared Quiz")
        payload = {
            "intent": "task_action",
            "language": "en",
            "confidence": 0.97,
            "task_action": {"action": "complete", "scope": "all"},
        }
        _stub_understand(monkeypatch, payload)
        wa = dispatch_message(db, USER_A, "923001111111", "mark all my tasks as completed")
        # Reset the task for the web call
        db.tasks.update_one({"parsed_title": "Shared Quiz"}, {"$set": {"status": "pending"}})
        web = client.post(
            "/api/student/assistant/chat",
            json={"message": "mark all my tasks as completed"},
            headers=_headers(USER_A),
        )
        assert web.status_code == 200
        assert wa["text"] == web.get_json()["reply"]
        assert db.tasks.find_one({"parsed_title": "Shared Quiz"})["status"] == "completed"
