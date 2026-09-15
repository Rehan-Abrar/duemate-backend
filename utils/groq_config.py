"""
Central Groq configuration for DueMate.

GROQ_MODEL (env) is the single source of truth for every Groq chat call:
  NLU understand, NLU respond, parse_task, and the legacy agent classifier.
"""

from __future__ import annotations

import os

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"


def get_groq_model() -> str:
    """Return the configured Groq model slug. Empty env values fall back to default."""
    configured = (os.getenv("GROQ_MODEL") or "").strip()
    return configured or DEFAULT_GROQ_MODEL
