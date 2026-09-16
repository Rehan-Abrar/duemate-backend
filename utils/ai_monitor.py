"""
Admin AI Monitor — read-only queries over db.llm_calls.

Admin analytics run only when an admin opens the page. Nothing here is called
from the WhatsApp/web AI request path.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from utils.llm_client import redact

_STAGE_BY_CALLER = {
    "nlu_understand": "nlu",
    "nlu_respond": "response",
    "_parse_with_groq": "task",
    "classify_intent": "intent",
}
_CALLERS_BY_STAGE = {
    stage: caller for caller, stage in _STAGE_BY_CALLER.items()
}

_LIST_FIELDS = {
    "_id": 0,
    "call_id": 1,
    "created_at": 1,
    "user_id": 1,
    "channel": 1,
    "caller": 1,
    "intent": 1,
    "action": 1,
    "query_type": 1,
    "task_type": 1,
    "model": 1,
    "provider": 1,
    "credential_slot": 1,
    "fallback_reason": 1,
    "fallback_used": 1,
    "fallback_attempts": 1,
    "error_type": 1,
    "success": 1,
    "latency_ms": 1,
    "prompt_version": 1,
    "parse_method": 1,
    "request_id": 1,
    "error": 1,
    "confidence": 1,
    "input_tokens": 1,
    "output_tokens": 1,
    "total_tokens": 1,
    "user_message_len": 1,
}

_SECRET_KEYS = frozenset({
    "api_key",
    "authorization",
    "headers",
    "jwt",
    "password",
    "password_hash",
    "raw",
    "system_prompt",
    "token",
    "user_message",
    "x-goog-api-key",
})


def ensure_llm_calls_indexes(db) -> None:
    if db is None:
        return
    db.llm_calls.create_index("call_id")
    db.llm_calls.create_index([("created_at", -1)])
    db.llm_calls.create_index([("user_id", 1), ("created_at", -1)])


def stage_from_caller(caller: Optional[str]) -> str:
    caller = caller or ""
    return _STAGE_BY_CALLER.get(caller, caller or "unknown")


def provider_label(provider: Optional[str], credential_slot: Optional[str]) -> str:
    provider = (provider or "").strip().lower()
    slot = (credential_slot or "").strip().lower()
    if provider == "gemini" or slot == "gemini":
        return "Gemini"
    if provider == "groq":
        if slot in ("primary", ""):
            return "Groq groq_1"
        if slot == "secondary":
            return "Groq groq_2"
        if slot.startswith("groq_"):
            return f"Groq {slot}"
        return "Groq"
    return (provider or "unknown").title()


def is_fallback(doc: dict) -> bool:
    if "fallback_used" in doc and doc.get("fallback_used") is not None:
        return bool(doc.get("fallback_used"))
    provider = (doc.get("provider") or "").strip().lower()
    slot = (doc.get("credential_slot") or "").strip().lower()
    return slot == "secondary" or provider == "gemini"


def _wa_id_from_user_id(user_id: Optional[str]) -> Optional[str]:
    uid = (user_id or "").strip()
    if uid.startswith("wa:"):
        return uid[3:] or None
    if uid and not uid.startswith("admin:"):
        return uid
    return None


def _batch_profile_names(db, user_ids: list) -> dict:
    """One contacts.find $in. Names stay on contacts; llm_calls never copies them."""
    wa_ids = []
    seen = set()
    for user_id in user_ids:
        wa_id = _wa_id_from_user_id(user_id)
        if wa_id and wa_id not in seen:
            seen.add(wa_id)
            wa_ids.append(wa_id)
    if not wa_ids:
        return {}
    names = {}
    for contact in db.contacts.find(
        {"wa_id": {"$in": wa_ids}},
        {"wa_id": 1, "profile_name": 1, "_id": 0},
    ):
        wa_id = contact.get("wa_id")
        name = contact.get("profile_name")
        if wa_id and isinstance(name, str) and name.strip():
            names[wa_id] = name.strip()
    return names


def _profile_name(names: dict, user_id: Optional[str]) -> Optional[str]:
    wa_id = _wa_id_from_user_id(user_id)
    if not wa_id:
        return None
    return names.get(wa_id)


def _safe_error(error) -> Optional[str]:
    if error is None:
        return None
    return redact(error)


def serialize_call(doc: dict, names: Optional[dict] = None, *, detail: bool = False) -> dict:
    names = names or {}
    user_id = doc.get("user_id")
    provider = doc.get("provider")
    slot = doc.get("credential_slot")
    row = {
        "call_id": doc.get("call_id"),
        "created_at": doc.get("created_at"),
        "user_id": user_id,
        "profile_name": _profile_name(names, user_id),
        "wa_id": _wa_id_from_user_id(user_id),
        "channel": doc.get("channel"),
        "stage": stage_from_caller(doc.get("caller")),
        "caller": doc.get("caller"),
        "intent": doc.get("intent"),
        "action": doc.get("action"),
        "query_type": doc.get("query_type"),
        "task_type": doc.get("task_type"),
        "model": doc.get("model"),
        "provider": provider,
        "credential_slot": slot,
        "provider_label": provider_label(provider, slot),
        "used_fallback": is_fallback(doc),
        "fallback_reason": doc.get("fallback_reason"),
        "fallback_attempts": int(doc.get("fallback_attempts") or 0),
        "error_type": doc.get("error_type") or doc.get("fallback_reason"),
        "success": bool(doc.get("success")),
        "latency_ms": doc.get("latency_ms"),
        "prompt_version": doc.get("prompt_version"),
        "parse_method": doc.get("parse_method"),
        "request_id": doc.get("request_id"),
    }
    if detail:
        row.update({
            "error": _safe_error(doc.get("error")),
            "confidence": doc.get("confidence"),
            "input_tokens": int(doc.get("input_tokens") or 0),
            "output_tokens": int(doc.get("output_tokens") or 0),
            "total_tokens": int(doc.get("total_tokens") or 0),
            "user_message_len": int(doc.get("user_message_len") or 0),
            "system_prompt_hash": doc.get("system_prompt_hash"),
        })
    for key in _SECRET_KEYS:
        row.pop(key, None)
    return row


def _parse_bool(raw: Optional[str]) -> Optional[bool]:
    if raw is None or raw == "":
        return None
    value = str(raw).strip().lower()
    if value in ("1", "true", "yes", "ok", "success"):
        return True
    if value in ("0", "false", "no", "failed", "failure", "error"):
        return False
    return None


def _name_user_ids(db, q: str, limit: int = 50) -> list:
    contacts = db.contacts.find(
        {"profile_name": {"$regex": re.escape(q), "$options": "i"}},
        {"wa_id": 1, "_id": 0},
    ).limit(limit)
    user_ids = []
    for contact in contacts:
        wa_id = contact.get("wa_id")
        if wa_id:
            user_ids.append(f"wa:{wa_id}")
            user_ids.append(wa_id)
    return user_ids


def build_match(
    args,
    *,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    db=None,
) -> dict:
    clauses: list[dict] = []
    created: dict = {}
    if since is not None:
        created["$gte"] = since
    if until is not None:
        created["$lte"] = until
    if created:
        clauses.append({"created_at": created})

    user = (args.get("user") or args.get("user_id") or "").strip()
    if user:
        clauses.append({"user_id": user})

    provider = (args.get("provider") or "").strip().lower()
    if provider:
        clauses.append({"provider": provider})

    model = (args.get("model") or "").strip()
    if model:
        clauses.append({"model": model})

    stage = (args.get("stage") or "").strip().lower()
    if stage:
        caller = _CALLERS_BY_STAGE.get(stage, stage)
        clauses.append({"caller": caller})

    success = _parse_bool(args.get("success") or args.get("status"))
    if success is not None:
        clauses.append({"success": success})

    intent = (args.get("intent") or "").strip()
    if intent:
        clauses.append({"intent": intent})

    q = (args.get("q") or "").strip()
    if q:
        search = [
            {"call_id": q},
            {"user_id": {"$regex": re.escape(q), "$options": "i"}},
            {"model": {"$regex": re.escape(q), "$options": "i"}},
            {"intent": {"$regex": re.escape(q), "$options": "i"}},
            {"caller": {"$regex": re.escape(q), "$options": "i"}},
            {"provider": {"$regex": re.escape(q), "$options": "i"}},
            {"action": {"$regex": re.escape(q), "$options": "i"}},
        ]
        if db is not None:
            named = _name_user_ids(db, q)
            if named:
                search.append({"user_id": {"$in": named}})
        clauses.append({"$or": search})

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}


def _avg_latency_ms(db, match: dict) -> Optional[float]:
    rows = list(db.llm_calls.aggregate([
        {"$match": match} if match else {"$match": {}},
        {"$group": {"_id": None, "avg": {"$avg": "$latency_ms"}}},
    ]))
    if not rows:
        return None
    avg = rows[0].get("avg")
    if avg is None:
        return None
    return round(float(avg), 1)


def _provider_breakdown(db, match: dict) -> list[dict]:
    pipeline = []
    if match:
        pipeline.append({"$match": match})
    pipeline.extend([
        {"$group": {
            "_id": {
                "provider": "$provider",
                "credential_slot": "$credential_slot",
                "model": "$model",
            },
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1}},
    ])
    items = []
    for row in db.llm_calls.aggregate(pipeline):
        ident = row.get("_id") or {}
        provider = ident.get("provider")
        slot = ident.get("credential_slot")
        items.append({
            "provider": provider,
            "credential_slot": slot,
            "model": ident.get("model"),
            "label": provider_label(provider, slot),
            "count": int(row.get("count") or 0),
        })
    return items


def _and_match(match: dict, extra: dict) -> dict:
    if not match:
        return extra
    return {"$and": [match, extra]}


def summarize(db, match: dict) -> dict:
    fallback_match = _and_match(match, {
        "$or": [
            {"fallback_used": True},
            {"credential_slot": "secondary"},
            {"provider": "gemini"},
        ],
    })
    requests = db.llm_calls.count_documents(match)
    successful = db.llm_calls.count_documents(_and_match(match, {"success": True}))
    failed = db.llm_calls.count_documents(_and_match(match, {"success": False}))
    return {
        "requests": requests,
        "successful": successful,
        "failed": failed,
        "avg_latency_ms": _avg_latency_ms(db, match),
        "fallbacks": db.llm_calls.count_documents(fallback_match),
        "providers": _provider_breakdown(db, match),
    }


def list_calls(db, match: dict, *, page: int, limit: int) -> dict:
    total = db.llm_calls.count_documents(match)
    cursor = (
        db.llm_calls.find(match, _LIST_FIELDS)
        .sort("created_at", -1)
        .skip((page - 1) * limit)
        .limit(limit)
    )
    rows = list(cursor)
    names = _batch_profile_names(db, [row.get("user_id") for row in rows])
    pages = (total + limit - 1) // limit if total else 0
    return {
        "items": [serialize_call(row, names) for row in rows],
        "count": total,
        "page": page,
        "limit": limit,
        "pages": pages,
    }


def get_call(db, call_id: str) -> Optional[dict]:
    call_id = (call_id or "").strip()
    if not call_id:
        return None
    doc = db.llm_calls.find_one({"call_id": call_id}, {"_id": 0})
    if not doc:
        return None
    for key in list(doc.keys()):
        if key in _SECRET_KEYS or str(key).lower() in _SECRET_KEYS:
            doc.pop(key, None)
    names = _batch_profile_names(db, [doc.get("user_id")])
    related = []
    request_id = doc.get("request_id")
    if request_id:
        related_docs = list(
            db.llm_calls.find(
                {"request_id": request_id, "call_id": {"$ne": call_id}},
                _LIST_FIELDS,
            ).sort("created_at", 1).limit(8)
        )
        related = [serialize_call(item, names) for item in related_docs]
    payload = serialize_call(doc, names, detail=True)
    payload["related"] = related
    return payload
