"""
Backend task mutations for the NLU pipeline.

The LLM only interprets the request. This module decides which of the
authenticated user's documents to change, and only reports success after
MongoDB actually modified them.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from bson import ObjectId

logger = logging.getLogger(__name__)

_PKT = timezone(timedelta(hours=5))

OPEN_STATUSES = ("pending", "needs_review")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def task_label(task: dict) -> str:
    from utils.parse_task import compose_task_title

    course = task.get("parsed_course") or "Unknown course"
    title = compose_task_title(
        task.get("parsed_course"),
        task.get("task_type"),
        task.get("parsed_title"),
        task.get("raw_message"),
    )
    return f"*{course}*: {title}"


def apply_parse_to_draft(draft: dict, parsed: dict) -> dict:
    """Overlay parse_task fields onto a pending create draft. New values win."""
    out = dict(draft or {})
    if parsed.get("course"):
        out["course"] = parsed["course"]
    if parsed.get("task_type"):
        out["task_type"] = parsed["task_type"]
    if parsed.get("title"):
        out["title"] = parsed["title"]
    if parsed.get("due_date"):
        out["due_date"] = parsed["due_date"]
        out["has_explicit_time"] = bool(parsed.get("has_explicit_time"))
    elif "has_explicit_time" in parsed and out.get("due_date"):
        if parsed.get("has_explicit_time"):
            out["has_explicit_time"] = True
    return out


def missing_create_fields(draft: dict) -> list[str]:
    """Required to save: course, due date, and an explicit time."""
    missing = []
    if not (draft or {}).get("course"):
        missing.append("course")
    if not (draft or {}).get("due_date"):
        missing.append("due_date")
    elif not (draft or {}).get("has_explicit_time"):
        missing.append("due_time")
    return missing


def clarify_create(draft: dict, field: str) -> str:
    kind = (draft or {}).get("task_type") or "task"
    course = (draft or {}).get("course")
    if field == "course":
        return f"Sure — which course is the {kind} for?"
    if field == "due_date":
        if course:
            return f"When is the {course} {kind}?"
        return f"When is the {kind}?"
    if field == "due_time":
        if course:
            return f"What time is the {course} {kind}?"
        return f"What time is the {kind}?"
    return "I need a bit more information before I can save that."


def confirm_create(task_doc: dict) -> str:
    kind = task_doc.get("task_type") or "task"
    course = task_doc.get("parsed_course") or "your course"
    due = task_doc.get("parsed_due_date")
    due_str = _fmt_due(due)
    if due_str:
        return f"Got it — I've saved your {course} {kind} for {due_str}."
    return f"Got it — I've saved your {course} {kind}."


def _fmt_due(due) -> Optional[str]:
    if not due:
        return None
    if hasattr(due, "strftime"):
        if due.tzinfo:
            due_pkt = due.astimezone(_PKT)
        else:
            due_pkt = due.replace(tzinfo=timezone.utc).astimezone(_PKT)
        return due_pkt.strftime("%A at %I:%M %p")
    return str(due)


def list_open_tasks(db, user_id: str, *, task_type=None, course=None) -> list:
    if db is None or not user_id:
        return []
    query = {"user_id": user_id, "status": {"$in": list(OPEN_STATUSES)}}
    if task_type:
        query["task_type"] = task_type
    tasks = list(db.tasks.find(query))
    if course:
        from utils.academic import get_user_academic_context, match_course, base_course
        try:
            ctx = get_user_academic_context(db, user_id)
            target = match_course(course, ctx.get("courses", []), ctx.get("aliases", {}))
            needle = base_course(target or course).lower()
            tasks = [
                t for t in tasks
                if needle in base_course(str(t.get("parsed_course") or "")).lower()
                or needle == str(t.get("parsed_course") or "").lower()
            ]
        except Exception:
            lowered = course.lower()
            tasks = [
                t for t in tasks
                if lowered in str(t.get("parsed_course") or "").lower()
            ]
    return tasks


def resolve_target_tasks(
    db,
    user_id: str,
    *,
    scope: str,
    filter_type=None,
    filter_course=None,
    last_task_ids=None,
) -> list:
    """Pick candidate tasks for an action. Never looks at another user's rows."""
    if scope == "all":
        return list_open_tasks(db, user_id)
    if scope == "reference":
        ids = [i for i in (last_task_ids or []) if i]
        if not ids:
            return []
        oids = []
        for raw in ids:
            try:
                oids.append(ObjectId(str(raw)))
            except Exception:
                continue
        if not oids:
            return []
        return list(db.tasks.find({
            "_id": {"$in": oids},
            "user_id": user_id,
            "status": {"$in": list(OPEN_STATUSES)},
        }))
    return list_open_tasks(db, user_id, task_type=filter_type, course=filter_course)


def complete_tasks(db, user_id: str, tasks: list) -> list:
    """Mark the given open tasks completed. Returns the docs that actually changed."""
    if db is None or not user_id or not tasks:
        return []
    ids = [t["_id"] for t in tasks if t.get("user_id") == user_id and t.get("status") in OPEN_STATUSES]
    if not ids:
        return []
    result = db.tasks.update_many(
        {
            "_id": {"$in": ids},
            "user_id": user_id,
            "status": {"$in": list(OPEN_STATUSES)},
        },
        {"$set": {"status": "completed", "needs_review": False, "updated_at": _utc_now()}},
    )
    if not result.modified_count:
        return []
    return list(db.tasks.find({"_id": {"$in": ids}, "user_id": user_id, "status": "completed"}))


def delete_tasks(db, user_id: str, tasks: list) -> int:
    if db is None or not user_id or not tasks:
        return 0
    ids = [t["_id"] for t in tasks if t.get("user_id") == user_id]
    if not ids:
        return 0
    result = db.tasks.delete_many({"_id": {"$in": ids}, "user_id": user_id})
    return int(result.deleted_count or 0)


def reschedule_tasks(db, user_id: str, tasks: list, due_date: datetime) -> list:
    if db is None or not user_id or not tasks or due_date is None:
        return []
    ids = [t["_id"] for t in tasks if t.get("user_id") == user_id]
    if not ids:
        return []
    result = db.tasks.update_many(
        {"_id": {"$in": ids}, "user_id": user_id},
        {
            "$set": {
                "parsed_due_date": due_date,
                "date_uncertain": False,
                "needs_review": False,
                "status": "pending",
                "updated_at": _utc_now(),
            }
        },
    )
    if not result.modified_count:
        return []
    return list(db.tasks.find({"_id": {"$in": ids}, "user_id": user_id}))


def confirm_completed(updated: list) -> str:
    if not updated:
        return "You don't have any pending tasks to complete."
    if len(updated) == 1:
        return f"Done — I marked {task_label(updated[0])} as completed."
    lines = "\n".join(f"• {task_label(t)}" for t in updated)
    return f"Done — I marked {len(updated)} tasks as completed:\n{lines}"


def confirm_deleted(count: int, labels: list) -> str:
    if count <= 0:
        return "I couldn't delete that — nothing was changed."
    if count == 1 and labels:
        return f"Deleted {labels[0]}."
    return f"Deleted {count} tasks."


def confirm_rescheduled(updated: list, due_date: datetime) -> str:
    due_str = _fmt_due(due_date) or "the new time"
    if not updated:
        return "I couldn't update the due date — nothing was changed."
    if len(updated) == 1:
        return f"Moved {task_label(updated[0])} to {due_str}."
    return f"Moved {len(updated)} tasks to {due_str}."


def ask_which_task(action: str, tasks: list) -> str:
    verb = {
        "complete": "mark as completed",
        "delete": "delete",
        "reschedule": "reschedule",
    }.get(action, "update")
    lines = "\n".join(f"{i}. {task_label(t)}" for i, t in enumerate(tasks, 1))
    return f"Which one should I {verb}? You have more than one match:\n{lines}"


def serialize_draft(draft: dict) -> dict:
    """JSON-safe draft for session storage."""
    out = dict(draft or {})
    due = out.get("due_date")
    if hasattr(due, "isoformat"):
        out["due_date"] = due.isoformat()
    return out


def deserialize_draft(draft: dict) -> dict:
    out = dict(draft or {})
    due = out.get("due_date")
    if isinstance(due, str):
        try:
            parsed = datetime.fromisoformat(due.replace("Z", "+00:00"))
            out["due_date"] = parsed
        except ValueError:
            out["due_date"] = None
    return out
