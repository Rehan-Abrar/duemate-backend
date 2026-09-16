"""
Central Groq configuration for DueMate.

GROQ_MODEL (env) is the Groq model for every Groq credential (groq_1..groq_n).
GEMINI_MODEL (env) is used only after healthy Groq accounts fail or are unset.
"""

from __future__ import annotations

import os

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
# Highest published free-tier RPM among current Gemini models (2.0 Flash-Lite retired).
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite"


def get_groq_model() -> str:
    """Return the configured Groq model slug. Empty env values fall back to default."""
    configured = (os.getenv("GROQ_MODEL") or "").strip()
    return configured or DEFAULT_GROQ_MODEL


def get_gemini_model() -> str:
    """Return the configured Gemini model slug used only as LLM fallback."""
    configured = (os.getenv("GEMINI_MODEL") or "").strip()
    return configured or DEFAULT_GEMINI_MODEL
