"""Central LLM fallback: Groq primary → Groq v2 → Gemini."""
import json
import logging
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import requests

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.llm_client import LLMError, complete_chat, configured_targets, redact
from utils.nlu import _clamp_request, understand
from utils.parse_task import _extract_json_from_response, _parse_with_groq


def _clear_llm_env(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY_v2", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-2.5-flash-lite")


def _groq_ok(content='{"intent":"out_of_scope","language":"en","confidence":0.9}'):
    m = MagicMock()
    m.raise_for_status.return_value = None
    m.json.return_value = {
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    return m


def _gemini_ok(content='{"intent":"out_of_scope","language":"en","confidence":0.9}'):
    m = MagicMock()
    m.raise_for_status.return_value = None
    m.json.return_value = {
        "candidates": [{"content": {"parts": [{"text": content}]}}],
        "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
    }
    return m


def _status(code: int):
    m = MagicMock()

    def _raise():
        err = requests.HTTPError(f"{code} Client Error")
        err.response = MagicMock(status_code=code)
        raise err

    m.raise_for_status.side_effect = _raise
    m.json.return_value = {"error": {"message": "failed"}}
    return m


class TestConfiguredTargets:
    def test_order_and_omission(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        slots = [(t["provider"], t["credential"]) for t in configured_targets()]
        assert slots == [
            ("groq", "primary"),
            ("groq", "secondary"),
            ("gemini", "primary"),
        ]

    def test_only_v2(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        targets = configured_targets()
        assert len(targets) == 1
        assert targets[0]["credential"] == "secondary"


class TestCompleteChatFallback:
    def test_primary_success_no_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        calls = []

        def post(*a, **kw):
            calls.append(kw.get("headers") or {})
            return _groq_ok()

        monkeypatch.setattr(requests, "post", post)
        result = complete_chat("sys", "user")
        assert result.provider == "groq"
        assert result.credential == "primary"
        assert result.model == "openai/gpt-oss-20b"
        assert json.loads(result.content)["intent"] == "out_of_scope"
        assert len(calls) == 1

    def test_primary_rate_limit_uses_secondary(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        responses = [_status(429), _groq_ok('{"intent":"task_query","language":"en","confidence":0.9}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "what's due")
        assert result.provider == "groq"
        assert result.credential == "secondary"
        assert json.loads(result.content)["intent"] == "task_query"

    def test_primary_unavailable_uses_secondary(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        responses = [_status(503), _groq_ok()]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "hi")
        assert result.credential == "secondary"

    def test_both_groq_fail_uses_gemini(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyDummy")
        responses = [_status(429), _status(500), _gemini_ok('{"intent":"greeting","language":"en","confidence":1}')]
        monkeypatch.setattr(requests, "post", lambda *a, **kw: responses.pop(0))
        result = complete_chat("sys", "hi")
        assert result.provider == "gemini"
        assert result.model == "gemini-2.5-flash-lite"
        assert json.loads(result.content)["intent"] == "greeting"

    def test_only_v2_works(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
        monkeypatch.setattr(requests, "post", lambda *a, **kw: _groq_ok())
        result = complete_chat("sys", "hi")
        assert result.provider == "groq"
        assert result.credential == "secondary"

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

    def test_nlu_json_valid_after_gemini_fallback(self, monkeypatch):
        _clear_llm_env(monkeypatch)
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
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
        monkeypatch.setenv("GROQ_API_KEY", "gsk_primary")
        monkeypatch.setenv("GROQ_API_KEY_v2", "gsk_secondary")
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


class TestRedact:
    def test_gemini_key(self):
        assert "AIza" not in redact("header AIzaSyDummyKeyValue123")
        assert "[redacted]" in redact("AIzaSyDummyKeyValue123")
