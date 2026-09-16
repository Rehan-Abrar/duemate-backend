"""llm_logger: existing llm_calls insert stays on the user path; no extra writes."""
import os
import sys
TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.llm_logger import llm_call_context, log_llm_call


class _Calls:
    def __init__(self):
        self.docs = []

    def insert_one(self, doc):
        self.docs.append(doc)


class _DB:
    def __init__(self):
        self.llm_calls = _Calls()


def _raw(content: str) -> dict:
    return {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
    }


def test_logs_routing_fields_without_message_body():
    db = _DB()
    with llm_call_context(user_id="wa:923001111111", channel="whatsapp", request_id="req-1"):
        log_llm_call(
            db=db,
            model="openai/gpt-oss-20b",
            prompt_version="nlu_understand_v1",
            caller="nlu_understand",
            system_prompt="secret prompt text",
            user_message="mark all my tasks completed",
            response_data=_raw(
                '{"intent":"task_action","language":"en","confidence":0.91,'
                '"task_action":{"action":"complete","scope":"all"}}'
            ),
            latency_ms=1140,
            success=True,
            provider="groq",
            credential_slot="primary",
        )
    doc = db.llm_calls.docs[0]
    assert doc["user_id"] == "wa:923001111111"
    assert doc["channel"] == "whatsapp"
    assert doc["request_id"] == "req-1"
    assert doc["intent"] == "task_action"
    assert doc["action"] == "complete"
    assert doc["confidence"] == 0.91
    assert doc["user_message_len"] == len("mark all my tasks completed")
    assert "user_message" not in doc
    assert "mark all my tasks completed" not in str(doc)
    assert "secret prompt text" not in str(doc)
    assert "system_prompt" not in doc
    assert doc["system_prompt_hash"]


def test_failed_call_does_not_parse_intent():
    db = _DB()
    log_llm_call(
        db=db,
        model="openai/gpt-oss-20b",
        prompt_version="nlu_understand_v1",
        caller="nlu_understand",
        system_prompt="sys",
        user_message="hi",
        response_data=None,
        latency_ms=80,
        success=False,
        error="Bearer gsk_THISISASECRETKEYVALUE rate limited",
        provider="groq",
        credential_slot="primary",
        fallback_reason="rate_limit",
    )
    doc = db.llm_calls.docs[0]
    assert doc["success"] is False
    assert doc["intent"] is None
    assert "gsk_THISISASECRETKEYVALUE" not in (doc["error"] or "")
    assert "[redacted]" in (doc["error"] or "")


def test_insert_failure_never_raises():
    class Boom:
        def insert_one(self, doc):
            raise RuntimeError("mongo down")

    db = type("DB", (), {"llm_calls": Boom()})()
    log_llm_call(
        db=db,
        model="openai/gpt-oss-20b",
        prompt_version="nlu_understand_v1",
        caller="nlu_understand",
        system_prompt="sys",
        user_message="hi",
        response_data=_raw('{"intent":"greeting"}'),
        latency_ms=10,
        success=True,
        provider="groq",
        credential_slot="primary",
    )


def test_skips_when_db_missing():
    log_llm_call(
        db=None,
        model="x",
        prompt_version="nlu_understand_v1",
        caller="nlu_understand",
        system_prompt="sys",
        user_message="hi",
        response_data=None,
        latency_ms=1,
    )
