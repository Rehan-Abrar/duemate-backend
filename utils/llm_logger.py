"""
LLMOps Logger — DueMate
========================
Logs every LLM API call to MongoDB collection `llm_calls` for observability,
cost tracking, and prompt audit purposes.

Schema of each document:
    {
        "call_id":       str,          # unique UUID
        "model":         str,          # e.g. "openai/gpt-oss-20b"
        "provider":      str,          # "groq" | "gemini"
        "credential_slot": str,        # groq_1..groq_n | gemini — never the key
        "fallback_reason": str | None, # why this attempt ran / failed
        "fallback_used": bool,         # True if a prior attempt failed this request
        "fallback_attempts": int,      # failed attempts before this one
        "error_type":    str | None,   # rate_limit | timeout | ...
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
        "user_id":       str | None,   # from request context; never the message body
        "channel":       str | None,   # "whatsapp" | "web"
        "request_id":    str | None,   # groups LLM #1 / #2 for one user message
        "intent":        str | None,   # compact routing field from JSON output
        "action":        str | None,
        "query_type":    str | None,
        "task_type":     str | None,
    }

Never stores user message text, API keys, or authorization headers.
Insert failures are swallowed so logging cannot affect the user-facing AI path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_log_ctx: ContextVar[dict] = ContextVar("llm_log_ctx", default={})

_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_prompt(text: str) -> str:
    return hashlib.md5(text.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]


def _redact_error(error: Optional[str]) -> Optional[str]:
    if error is None:
        return None
    try:
        from utils.llm_client import redact
        return redact(error)
    except Exception:
        return error


def get_llm_call_context() -> dict:
    return dict(_log_ctx.get() or {})


@contextmanager
def llm_call_context(**kwargs):
    """Attach request metadata to every llm_calls insert on this stack.

    Used by dispatch_message so complete_chat does not need extra args and
    does not perform a second Mongo write.
    """
    merged = get_llm_call_context()
    for key, value in kwargs.items():
        if value is not None and value != "":
            merged[key] = value
    token = _log_ctx.set(merged)
    try:
        yield
    finally:
        _log_ctx.reset(token)


def _clip(value, limit: int = 64) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:limit]


def _content_from_raw(response_data: Optional[dict]) -> str:
    if not isinstance(response_data, dict):
        return ""
    choices = response_data.get("choices")
    if isinstance(choices, list) and choices:
        message = (choices[0] or {}).get("message") or {}
        return str(message.get("content") or "")
    candidates = response_data.get("candidates")
    if isinstance(candidates, list) and candidates:
        parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
        return "".join(
            str(part.get("text") or "")
            for part in parts
            if isinstance(part, dict)
        )
    return ""


def _compact_routing(caller: str, response_data: Optional[dict]) -> dict:
    """Pull a few routing fields out of JSON already returned by the model.

    No extra LLM call. Does not store the user message or the full JSON body.
    """
    raw = _content_from_raw(response_data)
    if not raw:
        return {}
    stripped = _FENCE_RE.sub("", raw.strip())
    try:
        parsed = json.loads(stripped)
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}

    out: dict = {}
    intent = _clip(parsed.get("intent"))
    if intent:
        out["intent"] = intent

    confidence = parsed.get("confidence")
    if isinstance(confidence, (int, float)):
        out["confidence"] = round(float(confidence), 3)

    if caller == "nlu_understand":
        task_action = parsed.get("task_action") or {}
        if isinstance(task_action, dict):
            action = _clip(task_action.get("action"), 32)
            if action:
                out["action"] = action
        schedule = parsed.get("schedule") or {}
        if isinstance(schedule, dict):
            query_type = _clip(schedule.get("query_type"), 32)
            if query_type:
                out["query_type"] = query_type

    if caller == "_parse_with_groq":
        task_type = _clip(parsed.get("task_type"), 32)
        if task_type:
            out["task_type"] = task_type
        out.setdefault("intent", "save_task")
        out.setdefault("action", "create")

    return out


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
    provider: Optional[str] = None,
    credential_slot: Optional[str] = None,
    fallback_reason: Optional[str] = None,
    fallback_used: bool = False,
    fallback_attempts: int = 0,
    error_type: Optional[str] = None,
    user_id: Optional[str] = None,
    channel: Optional[str] = None,
    request_id: Optional[str] = None,
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

    ctx = get_llm_call_context()
    routing = _compact_routing(caller, response_data) if success else {}
    routed_confidence = routing.pop("confidence", None)

    doc = {
        "call_id": str(uuid.uuid4()),
        "model": model,
        "prompt_version": prompt_version,
        "caller": caller,
        "input_tokens": usage.get("prompt_tokens", 0),
        "output_tokens": usage.get("completion_tokens", 0),
        "total_tokens": usage.get("total_tokens", 0),
        "latency_ms": round(latency_ms, 1),
        "confidence": round(confidence, 3) if confidence is not None else routed_confidence,
        "parse_method": parse_method,
        "success": success,
        "error": _redact_error(error),
        "provider": provider,
        "credential_slot": credential_slot,
        "fallback_reason": fallback_reason,
        "fallback_used": bool(fallback_used),
        "fallback_attempts": int(fallback_attempts or 0),
        "error_type": error_type or fallback_reason,
        "system_prompt_hash": _hash_prompt(system_prompt or ""),
        "user_message_len": len(user_message or ""),
        "created_at": _utc_now(),
        "user_id": user_id or ctx.get("user_id"),
        "channel": channel or ctx.get("channel"),
        "request_id": request_id or ctx.get("request_id"),
        "intent": routing.get("intent"),
        "action": routing.get("action"),
        "query_type": routing.get("query_type"),
        "task_type": routing.get("task_type"),
    }

    try:
        db.llm_calls.insert_one(doc)
        logger.debug(
            "llm_logged call_id=%s tokens=%s latency=%.0fms confidence=%s",
            doc["call_id"], doc["total_tokens"], latency_ms, doc.get("confidence"),
        )
    except Exception as exc:
        # Never let logging break the main flow
        logger.warning("llm_logger insert failed: %s", exc)
