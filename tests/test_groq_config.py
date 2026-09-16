"""GROQ_MODEL is the single source of truth for every Groq caller."""
import os
import sys

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils.groq_config import DEFAULT_GEMINI_MODEL, DEFAULT_GROQ_MODEL, get_gemini_model, get_groq_model


class TestGroqModelConfig:
    def test_default_is_gpt_oss_20b(self, monkeypatch):
        monkeypatch.delenv("GROQ_MODEL", raising=False)
        assert DEFAULT_GROQ_MODEL == "openai/gpt-oss-20b"
        assert get_groq_model() == "openai/gpt-oss-20b"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "some-other-model")
        assert get_groq_model() == "some-other-model"

    def test_blank_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "   ")
        assert get_groq_model() == "openai/gpt-oss-20b"

    def test_gemini_default_is_flash_lite(self, monkeypatch):
        monkeypatch.delenv("GEMINI_MODEL", raising=False)
        assert DEFAULT_GEMINI_MODEL == "gemini-2.5-flash-lite"
        assert get_gemini_model() == "gemini-2.5-flash-lite"

    def test_callers_use_central_helper(self, monkeypatch):
        monkeypatch.setenv("GROQ_MODEL", "central-test-model")
        from utils.nlu import _groq_model
        from utils.parse_task import get_groq_model as parse_get
        from utils.agent import get_groq_model as agent_get

        assert _groq_model() == "central-test-model"
        assert parse_get() == "central-test-model"
        assert agent_get() == "central-test-model"
