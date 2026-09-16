"""
NLU conversation session — pending create/action is CONTEXT for LLM #1, not a router.

Keyed by user_id so WhatsApp and web share the same pending state.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

SESSION_TTL_MINUTES = 30


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_nlu_session(db, user_id: Optional[str]) -> dict:
    if db is None or not user_id:
        return {}
    doc = db.nlu_sessions.find_one({
        "user_id": user_id,
        "expires_at": {"$gt": _utc_now()},
    })
    if not doc or not isinstance(doc, dict):
        return {}
    return doc


def save_nlu_session(db, user_id: str, phone: Optional[str], **fields) -> dict:
    if db is None or not user_id:
        return {}
    now = _utc_now()
    payload = {
        "user_id": user_id,
        "phone": phone,
        "updated_at": now,
        "expires_at": now + timedelta(minutes=SESSION_TTL_MINUTES),
    }
    payload.update(fields)
    db.nlu_sessions.update_one(
        {"user_id": user_id},
        {"$set": payload},
        upsert=True,
    )
    return get_nlu_session(db, user_id)


def clear_pending_create(db, user_id: Optional[str]) -> None:
    if db is None or not user_id:
        return
    db.nlu_sessions.update_one(
        {"user_id": user_id},
        {"$set": {
            "pending_create": None,
            "updated_at": _utc_now(),
        }},
    )


def clear_pending_action(db, user_id: Optional[str]) -> None:
    if db is None or not user_id:
        return
    db.nlu_sessions.update_one(
        {"user_id": user_id},
        {"$set": {
            "pending_action": None,
            "updated_at": _utc_now(),
        }},
    )


def clear_nlu_session(db, user_id: Optional[str]) -> None:
    if db is None or not user_id:
        return
    db.nlu_sessions.delete_many({"user_id": user_id})


def ensure_nlu_session_index(db) -> None:
    if db is None:
        return
    db.nlu_sessions.create_index("user_id", unique=True)
    db.nlu_sessions.create_index("expires_at", expireAfterSeconds=0)
