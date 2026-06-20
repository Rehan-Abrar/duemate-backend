"""
Conversational context manager for DueMate.

When a task is saved with a missing course or date, the bot starts a short
multi-turn WhatsApp conversation to collect the missing information and then
updates the stored task.

State machine:
    awaiting_course  →  (user replies course)  →  save / next state
    awaiting_date    →  (user replies date)    →  save
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# How long a conversation stays open waiting for a reply
CONVERSATION_TTL_MINUTES = 8

STATE_AWAITING_COURSE = "awaiting_course"
STATE_AWAITING_DATE = "awaiting_date"

CANCEL_TOKENS = {"cancel", "stop", "nevermind", "never mind", "quit", "exit", "skip", "done"}

COURSE_MENU = (
    "Which course is this for?\n\n"
    "📚 Your courses:\n"
    "• *AI-Driven Software Development* (aisd)\n"
    "• *Parallel & Distributed Computing* (pdc)\n"
    "• *Technology Entrepreneurship* (te)\n"
    "• *Computer Networks* (cn)\n"
    "• *Advanced DBMS* (adbms)\n"
    "• *Theory of Automata* (toa)\n\n"
    "_(Reply 'cancel' to skip)_"
)

DATE_PROMPT = (
    "When is it due? You can say:\n"
    "• *tomorrow*, *Friday*, *next Monday*\n"
    "• *June 25*, *25 June*\n"
    "• *tomorrow 5pm*, *Friday 2-5pm*\n\n"
    "_(Reply 'cancel' to skip)_"
)


# ─── helpers ──────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _expire_at() -> datetime:
    return _utc_now() + timedelta(minutes=CONVERSATION_TTL_MINUTES)


def _resolve_course(text: str) -> Optional[str]:
    """Try to match free text to a canonical semester course."""
    # Import here to avoid circular deps at module level
    from utils.parse_task import COURSE_ALIASES, SEMESTER_COURSES, detect_course, _normalize_course_value  # noqa: F401

    lower = text.strip().lower()
    if lower in CANCEL_TOKENS:
        return None

    # Direct alias table match
    if lower in COURSE_ALIASES:
        return COURSE_ALIASES[lower]

    # Canonical name match (case-insensitive)
    for name in SEMESTER_COURSES:
        if lower == name.lower():
            return name

    # Run the full detect_course heuristic
    found = detect_course(text)
    if found:
        normalized = _normalize_course_value(found)
        if normalized:
            return normalized

    # Fuzzy: does any alias appear inside the reply?
    for alias, canonical in COURSE_ALIASES.items():
        if alias in lower:
            return canonical

    return None


def _resolve_date(text: str) -> Optional[datetime]:
    from utils.parse_task import detect_due_date, _utc_now as _p_utc_now
    return detect_due_date(text, _p_utc_now())


# ─── public API ───────────────────────────────────────────────────────────────

def get_active_conversation(db, phone: str) -> Optional[dict]:
    """Return the non-expired conversation for a phone number, or None."""
    return db.conversations.find_one({
        "phone": phone,
        "expires_at": {"$gt": _utc_now()},
    })


def clear_conversation(db, phone: str) -> None:
    db.conversations.delete_many({"phone": phone})


def start_conversation(
    db,
    phone: str,
    user_id: str,
    task_id: str,
    missing: str,          # "course", "date", or "both"
) -> str:
    """
    Persist a new conversation and return the prompt to send back.

    Args:
        missing: which field(s) are needed.  "both" asks for course first.
    """
    clear_conversation(db, phone)

    if missing in ("course", "both"):
        state = STATE_AWAITING_COURSE
        prompt = COURSE_MENU
    else:
        state = STATE_AWAITING_DATE
        prompt = DATE_PROMPT

    db.conversations.insert_one({
        "phone": phone,
        "user_id": user_id,
        "task_id": task_id,
        "state": state,
        "missing_originally": missing,
        "created_at": _utc_now(),
        "expires_at": _expire_at(),
    })
    return prompt


def handle_reply(db, conv: dict, reply_text: str) -> dict:
    """
    Process a user reply inside an active conversation.

    Returns a result dict:
        {
            "action":   "update_task" | "ask_next" | "cancelled" | "unrecognized",
            "task_id":  str,
            "updates":  dict,          # fields to $set on the task (if action == update_task)
            "prompt":   str | None,    # next message to send to user
        }
    """
    state = conv["state"]
    task_id = conv["task_id"]
    reply_clean = reply_text.strip()

    # ── Cancel ──────────────────────────────────────────────────────────────
    if reply_clean.lower() in CANCEL_TOKENS:
        clear_conversation(db, conv["phone"])
        return {
            "action": "cancelled",
            "task_id": task_id,
            "updates": {},
            "prompt": "👍 Skipped. You can always edit it from the dashboard.",
        }

    # ── Awaiting course ─────────────────────────────────────────────────────
    if state == STATE_AWAITING_COURSE:
        course = _resolve_course(reply_clean)

        if not course:
            # Extend TTL and ask again
            db.conversations.update_one(
                {"_id": conv["_id"]},
                {"$set": {"expires_at": _expire_at()}},
            )
            return {
                "action": "unrecognized",
                "task_id": task_id,
                "updates": {},
                "prompt": (
                    f"❓ I didn't recognise *{reply_clean[:30]}* as a course.\n\n"
                    + COURSE_MENU
                ),
            }

        # Course resolved — do we still need the date?
        if conv.get("missing_originally") == "both":
            # Transition to date state, remember the course answer
            db.conversations.update_one(
                {"_id": conv["_id"]},
                {"$set": {
                    "state": STATE_AWAITING_DATE,
                    "resolved_course": course,
                    "expires_at": _expire_at(),
                }},
            )
            return {
                "action": "ask_next",
                "task_id": task_id,
                "updates": {},
                "prompt": f"Got it — *{course}*! 👍\n\n" + DATE_PROMPT,
            }

        # Only course was missing — we're done
        clear_conversation(db, conv["phone"])
        return {
            "action": "update_task",
            "task_id": task_id,
            "updates": {
                "parsed_course": course,
                "course_unresolved": False,
                "course_resolution_method": "conversation",
            },
            "prompt": None,   # caller sends the confirmation
        }

    # ── Awaiting date ────────────────────────────────────────────────────────
    if state == STATE_AWAITING_DATE:
        due_date = _resolve_date(reply_clean)

        if not due_date:
            db.conversations.update_one(
                {"_id": conv["_id"]},
                {"$set": {"expires_at": _expire_at()}},
            )
            return {
                "action": "unrecognized",
                "task_id": task_id,
                "updates": {},
                "prompt": "❓ I couldn't parse that date.\n\n" + DATE_PROMPT,
            }

        has_explicit_time = True
        if due_date:
            if due_date.hour == 18 and due_date.minute == 59:
                has_explicit_time = False
            elif due_date.hour == 23 and due_date.minute == 59:
                has_explicit_time = False

        updates: dict = {
            "parsed_due_date": due_date,
            "has_explicit_time": has_explicit_time,
            "date_uncertain": False,
            "needs_review": False,
            "status": "pending",
        }

        # If we collected a course in the previous step, include it
        if conv.get("resolved_course"):
            updates["parsed_course"] = conv["resolved_course"]
            updates["course_unresolved"] = False
            updates["course_resolution_method"] = "conversation"

        clear_conversation(db, conv["phone"])
        return {
            "action": "update_task",
            "task_id": task_id,
            "updates": updates,
            "prompt": None,
        }

    # Unknown state — reset
    clear_conversation(db, conv["phone"])
    return {
        "action": "cancelled",
        "task_id": task_id,
        "updates": {},
        "prompt": "Something went wrong. Send your task again and I'll re-save it.",
    }


def ensure_conversation_index(db) -> None:
    """Create TTL index so MongoDB auto-expires old conversations."""
    db.conversations.create_index("expires_at", expireAfterSeconds=0)
    db.conversations.create_index("phone")
