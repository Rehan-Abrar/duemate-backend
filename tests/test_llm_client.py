"""Central LLM pool: Groq groq_1..n with cooldown/RR, then Gemini."""
import json
import logging
import os
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.llm_client import (
    LLMError,
    complete_chat,
    configured_targets,
    credential_available,
    redact,
    reset_runtime_state,
)
from utils.nlu import _clamp_request, dispatch_message, understand
from utils.parse_task import _extract_json_from_response, _parse_with_groq
from utils.rate_limiter import allow_ai_user, reset_rate_limiter


def _clear_llm_env(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    for i in range(2, 9):
        monkeypatch.delenv(f"GROQ_API_KEY_v{i}", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash-lite")
    reset_runtime_state()


def _groq_ok(content='{"intent":"out_of_scope","language":"en","confidence":0.9}'):
    m = MagicMock()
    m.raise_for_status.return_value = None
    m.headers = {}
    m.json.return_value = {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    return m


def _gemini_ok(content='{"intent":"out_of_scope","language":"en","confidence":0.9}'):
    m = MagicMock()
    m.raise_for_status.return_value = None
    m.headers = {}
    m.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": content}]}}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
    }
    return m


def _status(code: int, retry_after=None):
    m = MagicMock()
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    m.headers = headers
    m.status_code = code
    m.json.return_value = {"error": {"message": "failed"}}

    def _raise():
        err = requests.HTTPError(f"{code} Client Error")
        err.response = m
        raise err

    m.raise_for_status.side_effect = _raise
    return m


def _auth_label(headers) -> str:
    token = (headers or {}).get("Authorization") or (headers or {}).get("x-goog-api-key") or ""
    return str(token)


class TestConfiguredTargets:
    def test_order_and_omission(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GROQ_API_KEY_v3", "gsk_three")
        monkeypatch.setenv("GROQ_API_KEY_v4", "gsk_four")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        slots = [(t["provider"], t["credential"]) for t in configured_targets()]
        assert slots == [
            ("groq", "groq_1"),
            ("groq", "groq_2"),
            ("groq", "groq_3"),
            ("groq", "groq_4"),
            ("gemini", "gemini"),
        ]

    def test_only_v2(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        targets = configured_targets()
        assert len(targets) == 1
        assert targets[0]["credential"] == "groq_2"

    def test_empty_keys_ignored(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "  ")
        monkeypatch.setenv("GROQ_API_KEY_v3", "gsk_three")
        labels = [t["credential"] for t in configured_targets()]
        assert labels == ["groq_1", "groq_3"]


class TestCompleteChatFallback:
    def test_groq1_success_no_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        calls = []

        def post(*a, **kw):
            calls.append(kw.get("headers") or {})
            return _groq_ok()

        monkeypatch.setattr(requests, "post", post)
        result = complete_chat("sys", "user")
        assert result.provider == "groq"
        assert result.credential == "groq_1"
        assert result.model == "openai/gpt-oss-20b"
        assert result.fallback_used is False
        assert result.fallback_attempts == 0
        assert json.loads(result.content)["intent"] == "out_of_scope"
        assert len(calls) == 1

    def test_groq1_fails_groq2_succeeds(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        responses = [_status(429), _groq_ok('{"intent":"task_query","language":"en","confidence":0.9}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "what's due")
        assert result.provider == "groq"
        assert result.credential == "groq_2"
        assert result.fallback_used is True
        assert result.fallback_attempts == 1
        assert json.loads(result.content)["intent"] == "task_query"

    def test_first_two_fail_groq3_succeeds(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GROQ_API_KEY_v3", "gsk_three")
        responses = [_status(429), _status(503), _groq_ok('{"intent":"help"}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "help")
        assert result.credential == "groq_3"
        assert result.fallback_attempts == 2

    def test_first_three_fail_groq4_succeeds(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GROQ_API_KEY_v3", "gsk_three")
        monkeypatch.setenv("GROQ_API_KEY_v4", "gsk_four")
        responses = [_status(429), _status(500), _status(503), _groq_ok('{"intent":"greeting"}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "hi")
        assert result.credential == "groq_4"
        assert result.fallback_used is True

    def test_all_groq_fail_uses_gemini(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        responses = [_status(429), _status(500), _gemini_ok('{"intent":"greeting","language":"en","confidence":1}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "hi")
        assert result.provider == "gemini"
        assert result.credential == "gemini"
        assert result.model == "gemini-2.5-flash-lite"
        assert json.loads(result.content)["intent"] == "greeting"

    def test_only_groq4_configured(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY_v4", "gsk_four")
        monkeypatch.setattr(requests, "post", lambda *a, **kw: _groq_ok())
        result = complete_chat("sys", "hi")
        assert result.provider == "groq"
        assert result.credential == "groq_4"
        assert result.fallback_used is False

    def test_only_gemini_works(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        monkeypatch.setattr(requests, "post", lambda *a, **kw: _gemini_ok())
        result = complete_chat("sys", "hi")
        assert result.provider == "gemini"

    def test_no_credentials_raises(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        with pytest.raises(LLMError) as exc:
            complete_chat("sys", "hi")
        assert exc.value.reason == "no_credentials"

    def test_http_400_does_not_rotate(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        calls = []

        def post(*a, **kw):
            calls.append(1)
            return _status(400)

        monkeypatch.setattr(requests, "post", post)
        with pytest.raises(LLMError) as exc:
            complete_chat("sys", "hi")
        assert exc.value.reason == "provider_error"
        assert len(calls) == 1
        assert credential_available("groq_1")

    def test_nlu_json_valid_after_gemini_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        payload = {
            "intent": "schedule_query",
            "language": "en",
            "confidence": 0.95,
            "schedule": {
                "query_type": "next_class",
                "course": None, "teacher": None, "day": None,
                "time_after": None, "time_before": None,
            },
        }
        responses = [_status(429), _gemini_ok(json.dumps(payload))]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = understand("when's my next class?")
        assert result["intent"] == "schedule_query"
        assert result["schedule"]["query_type"] == "next_class"
        clamped = _clamp_request(result)
        assert clamped["intent"] == "schedule_query"

    def test_parse_task_valid_after_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        task_json = json.dumps({
            "task_type": "quiz",
            "course": "Information Security",
            "title": "quiz",
            "due_date": "2026-09-21T23:59:00",
            "confidence": 0.9,
        })
        responses = [_status(503), _groq_ok(task_json)]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        parsed = _parse_with_groq(
            "information security quiz on Monday",
            "information security quiz on monday",
            datetime(2026, 9, 16, tzinfo=timezone.utc),
        )
        assert parsed["task_type"] == "quiz"
        assert parsed["course"] == "Information Security"
        _extract_json_from_response(task_json)

    def test_keys_never_logged(self, monkeypatch, caplog):
        _clear_llm_env(monkeypatch)
        secret = "gsk_THISISASECRETKEYVALUE"
        monkeypatch.setenv("GROQ_API_KEY", secret)
        caplog.set_level(logging.DEBUG)

        def boom(*a, **kw):
            raise requests.HTTPError(f"401 Unauthorized Bearer {secret}")

        monkeypatch.setattr(requests, "post", boom)
        with pytest.raises(LLMError):
            complete_chat("sys", "hi")
        combined = "\n".join(r.getMessage() for r in caplog.records)
        assert secret not in combined
        assert "gsk_THISISASECRETKEYVALUE" not in combined
        assert secret not in redact(f"Bearer {secret}")
        assert "[redacted]" in redact(f"Bearer {secret}")

    def test_logger_failure_does_not_block_reply(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setattr(requests, "post", lambda *a, **kw: _groq_ok())

        class Boom:
            def insert_one(self, doc):
                raise RuntimeError("mongo down")

        result = complete_chat("sys", "hi", db=type("DB", (), {"llm_calls": Boom()})())
        assert result.provider == "groq"
        assert json.loads(result.content)["intent"] == "out_of_scope"

    def test_logs_provider_credential_and_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        docs = []

        class Col:
            def insert_one(self, doc):
                docs.append(doc)

        responses = [_status(429), _groq_ok(
            '{"intent":"task_action","task_action":{"action":"complete"},"confidence":0.88}'
        )]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        from utils.llm_logger import llm_call_context
        with llm_call_context(user_id="wa:923001111111", channel="web", request_id="r1"):
            complete_chat(
                "sys",
                "mark all my tasks completed",
                db=type("DB", (), {"llm_calls": Col()})(),
                caller="nlu_understand",
            )
        assert len(docs) == 2
        assert docs[0]["success"] is False
        assert docs[0]["credential_slot"] == "groq_1"
        assert docs[0]["error_type"] == "rate_limit"
        assert "gsk_" not in str(docs)
        assert docs[1]["success"] is True
        assert docs[1]["provider"] == "groq"
        assert docs[1]["credential_slot"] == "groq_2"
        assert docs[1]["fallback_used"] is True
        assert docs[1]["fallback_attempts"] == 1
        assert docs[1]["intent"] == "task_action"
        assert "user_message" not in docs[1]
        assert "mark all my tasks completed" not in str(docs)


class TestCooldownAndBalance:
    def test_429_puts_credential_in_cooldown(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        first = [_status(429), _groq_ok()]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: first.pop(0))
        complete_chat("sys", "a")
        assert credential_available("groq_1") is False
        assert credential_available("groq_2") is True

        seen = []

        def second(*a, **kw):
            seen.append(_auth_label(kw.get("headers")))
            return _groq_ok()

        monkeypatch.setattr(requests, "post", second)
        result = complete_chat("sys", "b")
        assert result.credential == "groq_2"
        assert all("gsk_one" not in h for h in seen)

    def test_retry_after_is_respected(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        first = [_status(429, retry_after=0.05), _groq_ok()]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: first.pop(0))
        complete_chat("sys", "a")
        assert credential_available("groq_1") is False
        time.sleep(0.06)
        assert credential_available("groq_1") is True

    def test_healthy_credentials_are_round_robin(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        monkeypatch.setenv("GROQ_API_KEY_v3", "gsk_three")
        monkeypatch.setenv("GROQ_API_KEY_v4", "gsk_four")
        seen = []

        def post(*a, **kw):
            seen.append(_auth_label(kw.get("headers")))
            return _groq_ok()

        monkeypatch.setattr(requests, "post", post)
        for _ in range(8):
            complete_chat("sys", "hi")
        counts = Counter(seen)
        assert counts["Bearer gsk_one"] == 2
        assert counts["Bearer gsk_two"] == 2
        assert counts["Bearer gsk_three"] == 2
        assert counts["Bearer gsk_four"] == 2
        assert len(seen) == 8

    def test_concurrent_requests_do_not_corrupt_cooldown(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_one")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_two")
        lock = threading.Lock()

        def post(*a, **kw):
            auth = _auth_label(kw.get("headers"))
            if "gsk_one" in auth:
                return _status(429)
            return _groq_ok()

        monkeypatch.setattr(requests, "post", post)
        errors = []

        def worker():
            try:
                with lock:
                    pass
                result = complete_chat("sys", "hi")
                assert result.credential == "groq_2"
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert errors == []
        assert credential_available("groq_1") is False
        assert credential_available("groq_2") is True


class TestRedact:
    def test_gemini_key(self):
        assert "AIza" not in redact("header AIzaSyDummyKeyValue123")
        assert "[redacted]" in redact("AIzaSyDummyKeyValue123")


class TestAiUserRateLimit:
    def test_normal_use_is_allowed(self):
        reset_rate_limiter()
        for _ in range(10):
            assert allow_ai_user("wa:923001111111", max_requests=40) is True

    def test_flood_is_blocked(self):
        reset_rate_limiter()
        uid = "wa:923009999999"
        for _ in range(5):
            assert allow_ai_user(uid, max_requests=5) is True
        assert allow_ai_user(uid, max_requests=5) is False

    def test_dispatch_returns_safe_reply(self, monkeypatch):
        reset_rate_limiter()
        monkeypatch.setenv("AI_RATE_LIMIT_PER_MINUTE", "5")
        monkeypatch.setenv("NLU_LLM_ROUTING_ENABLED", "true")
        uid = "wa:923001110000"
        for _ in range(5):
            result = dispatch_message(None, uid, "923001110000", "hi")
            assert result["intent"] != "rate_limited"
        blocked = dispatch_message(None, uid, "923001110000", "hi")
        assert blocked["action"] == "reply"
        assert blocked["intent"] == "rate_limited"
        assert "quickly" in blocked["text"].lower()
