"""
LLMOps Logger — DueMate
========================
Logs every LLM API call to MongoDB collection `llm_calls` for observability,
cost tracking, and prompt audit purposes.

Schema of each document:
    {
        "call_id":       str,          # unique UUID
        "model":         str,          # e.g. "llama-3.3-70b-versatile"
        "prompt_version": str,         # e.g. "parse_task_v2"
        "caller":        str,          # which function triggered this call
        "input_tokens":  int,
        "output_tokens": int,
        "total_tokens":  int,
        "latency_ms":    float,
        "confidence":    float | None,
        "parse_method":  str,          # "groq" | "regex_fallback" | "agent"
        "success":       bool,
        "error":         str | None,
        "system_prompt_hash": str,     # MD5 of the system prompt for dedup
        "user_message_len": int,       # character count of user message
        "created_at":    datetime,
    }
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Lazy mongo reference ─────────────────────────────────────────────────────
_db_ref = None  # set by log_llm_call if db is passed in


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_prompt(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def log_llm_call(
    *,
    db,
    model: str,
    prompt_version: str,
    caller: str,
    system_prompt: str,
    user_message: str,
    response_data: Optional[dict],
    latency_ms: float,
    confidence: Optional[float] = None,
    parse_method: str = "groq",
    success: bool = True,
    error: Optional[str] = None,
) -> None:
    """
    Persist one LLM call record.  Safe to call even if db is None.
    """
    if db is None:
        logger.debug("llm_logger: db is None, skipping log")
        return

    usage = {}
    if response_data and isinstance(response_data, dict):
        usage = response_data.get("usage") or {}

    doc = {
        "call_id": str(uuid.uuid4()),
        "model": model,
        "prompt_version": prompt_version,
        "caller": caller,
        "input_tokens": usage.get("prompt_tokens", 0),
        "output_tokens": usage.get("completion_tokens", 0),
        "total_tokens": usage.get("total_tokens", 0),
        "latency_ms": round(latency_ms, 1),
        "confidence": round(confidence, 3) if confidence is not None else None,
        "parse_method": parse_method,
        "success": success,
        "error": error,
        "system_prompt_hash": _hash_prompt(system_prompt),
        "user_message_len": len(user_message),
        "created_at": _utc_now(),
    }

    try:
        db.llm_calls.insert_one(doc)
        logger.debug(
            "llm_logged call_id=%s tokens=%s latency=%.0fms confidence=%s",
            doc["call_id"], doc["total_tokens"], latency_ms, confidence,
        )
    except Exception as exc:
        # Never let logging break the main flow
        logger.warning("llm_logger insert failed: %s", exc)
