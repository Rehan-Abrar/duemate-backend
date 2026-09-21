"""
NLU (Natural Language Understanding) module for DueMate.

Two-call LLM architecture — see docs/backend-audit-15-09-2026/09-llm-nlu-architecture.md.

  LLM #1 (understand) — strict JSON routing params; NEVER emits facts
  Backend (execute)   — pure Python; sole source of academic/task facts
  LLM #2 (respond)    — optional rephrasing of the grounded deterministic text;
                         always has a deterministic fallback

Feature flags (env vars, checked at call time so they can flip without redeploy):
  NLU_LLM_ROUTING_ENABLED  (default "false") — enable the LLM #1 path
  NLU_LLM_RESPONSE_ENABLED (default "false") — enable LLM #2 naturalization
  NLU_LLM_TIMEOUT_SECONDS  (default "8")     — per-call timeout
  GROQ_MODEL               (default "openai/gpt-oss-20b") — shared model slug

The deterministic fallback classifier (_fallback_classify) mirrors the current
keyword logic in agent.py so behavior is never worse than today when LLM #1 fails.
"""

from __future__ import annotations

import json
import logging
import os
import re
import textwrap
from datetime import datetime, timedelta, timezone
from typing import Optional

from utils.config import DASHBOARD_URL
from utils.groq_config import get_groq_model
from utils.llm_client import complete_chat

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_PKT = timezone(timedelta(hours=5))

# Valid values for schema clamping (prevents unconstrained model output from leaking)
_VALID_INTENTS = frozenset({
    "schedule_query", "task_query", "save_task", "task_action",
    "greeting", "help", "out_of_scope", "section_set", "dashboard_required",
})
_VALID_TASK_TYPES = frozenset({"quiz", "assignment", "project", "exam", "lab", "other"})
_VALID_TASK_ACTIONS = frozenset({"complete", "delete", "reschedule", "cancel"})
_VALID_TASK_SCOPE = frozenset({"all", "matching", "reference"})
_VALID_MISSING = frozenset({"course", "due_date", "due_time", "target"})
_VALID_QUERY_TYPES = frozenset({
    "next_class", "day_schedule", "course_schedule", "teacher", "full_timetable", "free_check",
})
_VALID_DAYS = frozenset({
    "today", "tomorrow", "monday", "tuesday", "wednesday", "thursday", "friday",
})
_VALID_DUE = frozenset({"today", "tomorrow", "this_week", "overdue"})
_VALID_LANGUAGES = frozenset({"en", "ur", "mixed"})
_VALID_OOS_KINDS = frozenset({"casual", "internal", "unrelated", "dashboard_required"})
_TIME_RE = re.compile(r"^\d{2}:\d{2}$")
_OOS_TOPIC_RE = re.compile(r"^[a-z]+(?:[ -][a-z]+){0,2}$")
# Genuine new-request cues — not course names. Used only to avoid treating
# a real query as a pending-create field fill.
_PENDING_INTERRUPT_RE = re.compile(
    r"(?:[?؟]|"
    r"\b(?:when|what|what's|whats|which|who|where|how)\b|"
    r"\b(?:show|tell|list)\b|"
    r"\b(?:schedule|timetable)\b|"
    r"\b(?:classes|lectures|class|lecture)\b|"
    r"\b(?:free|teacher|teaches)\b|"
    r"\b(?:kab|kya|mera|mere)\b|"
    r"\b(?:tasks?|assignments?)\b|"
    r"\b(?:cancel|nevermind|never mind)\b"
    r")",
    re.IGNORECASE,
)
_PENDING_INTENT_INTERRUPTS = frozenset({
    "greeting", "help", "out_of_scope", "task_action",
})
_OOS_TOPIC_BLOCKED = frozenset({
    "prompt", "prompts", "instruction", "instructions", "system", "backend",
    "secret", "secrets", "password", "token", "key", "api", "internal",
})

# ── Config helpers ────────────────────────────────────────────────────────────

def _groq_model() -> str:
    return get_groq_model()

def _nlu_timeout() -> float:
    try:
        return float(os.getenv("NLU_LLM_TIMEOUT_SECONDS", "8"))
    except (ValueError, TypeError):
        return 8.0

def routing_enabled() -> bool:
    """True when NLU_LLM_ROUTING_ENABLED is set to a truthy value."""
    return os.getenv("NLU_LLM_ROUTING_ENABLED", "true").lower() in ("1", "true", "yes")

def response_enabled() -> bool:
    """True when NLU_LLM_RESPONSE_ENABLED is set to a truthy value."""
    return os.getenv("NLU_LLM_RESPONSE_ENABLED", "true").lower() in ("1", "true", "yes")

# ── Static replies (deterministic, no LLM) ───────────────────────────────────

GREETING_REPLY = (
    "Hey! 👋 I'm your *DueMate Assistant*. Here's what I can do:\n\n"
    "📅 *Timetable* — _\"when is my next class?\"_ / _\"kal 2 ke baad class hai?\"_\n"
    "📋 *Tasks* — _\"what do I have due?\"_ / _\"mere kya assignments hain?\"_\n"
    "📌 *Save tasks* — forward or type any deadline announcement\n\n"
    "I understand English, Roman Urdu, and Hinglish. 🇵🇰"
)

HELP_REPLY = (
    "🤖 *DueMate can help with:*\n\n"
    "📅 *Schedule questions:*\n"
    "  • _\"when is my next class?\"_\n"
    "  • _\"kal 2 bajay ke baad koi lecture hai?\"_\n"
    "  • _\"CN kab hai?\"_ / _\"bhai kal free hoon?\"_\n\n"
    "📋 *Task queries:*\n"
    "  • _\"what assignments do I have?\"_\n"
    "  • _\"kya aaj kuch due hai?\"_\n\n"
    "📌 *Save a task:* Just forward or type any deadline!\n\n"
    "I understand English, Urdu, and Hinglish. 🇵🇰"
)

OUT_OF_SCOPE_REPLY = (
    "I can only help with your timetable and academic tasks. 📚\n\n"
    "Try asking:\n"
    "• _\"when is my next class?\"_\n"
    "• _\"what do I have due this week?\"_"
)

OUT_OF_SCOPE_CASUAL = (
    "Haha, glad it's working 😄. I can help with your timetable and academic tasks."
)
OUT_OF_SCOPE_INTERNAL = (
    "I can help with your timetable and academic tasks, but I can't provide "
    "internal system instructions."
)
OUT_OF_SCOPE_UNRELATED = (
    "I can help with your timetable and academic tasks, but I can't help with "
    "questions outside that."
)
DASHBOARD_REQUIRED_REPLY = (
    "You'll need to do that from your DueMate dashboard. Open it here:\n"
    f"{DASHBOARD_URL}"
)

_DASHBOARD_REQUIRED_RE = re.compile(
    r"\b(?:upload|download|change|update|delete|manage|open|view)\b.{0,40}\b(?:timetable|pdf|file|university|degree|major|email|account|profile|dashboard)\b|"
    r"\b(?:upload|download)\b.{0,20}\b(?:timetable|pdf|file)\b|"
    r"\b(?:change|update)\b.{0,20}\b(?:university|degree|major|email|profile)\b|"
    r"\b(?:delete|close)\b.{0,20}\b(?:account|profile)\b|"
    r"\b(?:open|show|go\s+to)\b.{0,20}\b(?:dashboard|web\s+app)\b",
    flags=re.IGNORECASE,
)


def _is_dashboard_required(text: str) -> bool:
    if not text:
        return False
    t = text.lower().strip()
    if "section" in t:
        return False
    return bool(_DASHBOARD_REQUIRED_RE.search(t))

# ── Trivial-greeting fast path ────────────────────────────────────────────────
# A TINY exact-match set used only for latency/cost, NOT as a meaning classifier.
_TRIVIAL_TOKENS = frozenset({
    "hi", "hello", "hey", "salam", "assalam", "assalamualaikum", "helo", "hola",
    "yo", "sup", "ok", "okay", "thanks", "thank you", "shukriya", "jazakallah",
    "thx", "ty", "acha", "theek", "k", "start", "test", "ping", "nice", "good",
})

def _is_trivial_greeting(text: str) -> bool:
    """True only for single/two-token messages that are clearly greetings/acks."""
    t = re.sub(r"\s+", " ", (text or "").strip().lower())
    # Check full phrase first (catches multi-word tokens like "thank you")
    if t in _TRIVIAL_TOKENS:
        return True
    words = t.split()
    return 1 <= len(words) <= 2 and all(w in _TRIVIAL_TOKENS for w in words)

# ── Prompt loading (YAML block scalar; indentation is not sent to the model) ──

def _load_prompt(filename: str) -> str:
    """Load prompt_text from prompts/<filename> as a YAML |/> block scalar."""
    try:
        path = os.path.join(os.path.dirname(__file__), "..", "prompts", filename)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"^prompt_text:\s*[>|][+-]?\s*\n(.*)", content, re.DOTALL | re.MULTILINE)
        if match:
            return textwrap.dedent(match.group(1)).strip()
    except Exception as exc:
        logger.warning("nlu: failed to load prompt %s: %s", filename, exc)
    return ""

# ── Groq API call (same pattern as parse_task._parse_with_groq) ───────────────

def _call_groq(
    system_prompt: str,
    user_content: str,
    *,
    json_mode: bool = True,
    caller: str = "nlu",
    db=None,
    prompt_version: str = "nlu_v1",
    max_tokens: int = 400,
) -> str:
    """LLM transport via the shared fallback client. Raises on total failure."""
    result = complete_chat(
        system_prompt,
        user_content,
        json_mode=json_mode,
        timeout=_nlu_timeout(),
        max_tokens=max_tokens,
        db=db,
        caller=caller,
        prompt_version=prompt_version,
        parse_method="nlu",
    )
    return result.content

# ── JSON extraction (reuse the fence-tolerant version from parse_task) ────────

def _extract_json(raw: str) -> dict:
    raw = raw.strip()
    # Strip code fences
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return json.loads(raw)

# ── Schema clamping and validation ────────────────────────────────────────────

def _clamp(value, valid_set, default):
    return value if (value and value in valid_set) else default

def _validate_time(s) -> Optional[str]:
    """Return "HH:MM" string or None."""
    if s and isinstance(s, str) and _TIME_RE.match(s.strip()):
        return s.strip()
    return None


def _sanitize_oos_topic(raw) -> Optional[str]:
    """Allow a short public topic label; never keep instruction/secret wording."""
    if not raw or not isinstance(raw, str):
        return None
    topic = re.sub(r"[^a-zA-Z\s-]", "", raw).strip().lower()
    topic = re.sub(r"\s+", " ", topic)
    if not topic or not _OOS_TOPIC_RE.match(topic):
        return None
    words = topic.replace("-", " ").split()
    if any(w in _OOS_TOPIC_BLOCKED for w in words):
        return None
    return topic


def _out_of_scope_reply(request: dict) -> str:
    """Deterministic reply from LLM #1's out_of_scope kind — no extra model call."""
    intent = request.get("intent")
    oos = request.get("out_of_scope") or {}
    kind = oos.get("kind")
    topic = oos.get("topic")

    if intent == "dashboard_required" or kind == "dashboard_required":
        return DASHBOARD_REQUIRED_REPLY

    if kind == "casual":
        return OUT_OF_SCOPE_CASUAL
    if kind == "internal":
        return OUT_OF_SCOPE_INTERNAL
    if kind == "unrelated":
        if topic:
            return (
                "I can help with your timetable and academic tasks, but I can't "
                f"help with general {topic} questions."
            )
        return OUT_OF_SCOPE_UNRELATED
    return OUT_OF_SCOPE_REPLY

def _clamp_request(raw: dict) -> dict:
    """
    Validate and clamp a raw LLM #1 response to the known schema.
    Unknown/missing values get safe defaults; never raises.
    """
    intent = _clamp(raw.get("intent"), _VALID_INTENTS, "out_of_scope")
    language = _clamp(raw.get("language"), _VALID_LANGUAGES, "en")
    confidence = raw.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))

    result: dict = {
        "intent": intent,
        "language": language,
        "confidence": round(confidence, 2),
    }

    if intent == "schedule_query":
        from utils.academic import normalize_requested_section

        sched = raw.get("schedule") or {}
        course = sched.get("course") or None
        section = normalize_requested_section(sched.get("section"))
        if not section:
            promoted = normalize_requested_section(course)
            if promoted:
                section = promoted
                course = None
        elif course and normalize_requested_section(course) == section:
            course = None
        result["schedule"] = {
            "query_type": _clamp(sched.get("query_type"), _VALID_QUERY_TYPES, "next_class"),
            "course": course,
            "teacher": sched.get("teacher") or None,
            "section": section,
            "day": _clamp(
                str(sched.get("day", "") or "").lower(), _VALID_DAYS, None
            ),
            "time_after": _validate_time(sched.get("time_after")),
            "time_before": _validate_time(sched.get("time_before")),
        }

    elif intent == "task_query":
        task = raw.get("task") or {}
        result["task"] = {
            "filter_course": task.get("filter_course") or None,
            "due": _clamp(task.get("due"), _VALID_DUE, None),
        }

    elif intent == "save_task":
        draft = raw.get("save_task") or {}
        missing = draft.get("missing_fields") or []
        if not isinstance(missing, list):
            missing = []
        result["save_task"] = {
            "course": (draft.get("course") or None),
            "task_type": _clamp(draft.get("task_type"), _VALID_TASK_TYPES, None),
            "title": draft.get("title") or None,
            "due_day": _clamp(str(draft.get("due_day") or "").lower(), _VALID_DAYS, None),
            "due_time": _validate_time(draft.get("due_time")),
            "needs_clarification": bool(draft.get("needs_clarification")),
            "missing_fields": [f for f in missing if f in _VALID_MISSING],
            "correction": bool(draft.get("correction")),
        }

    elif intent == "task_action":
        ta = raw.get("task_action") or {}
        missing = ta.get("missing_fields") or []
        if not isinstance(missing, list):
            missing = []
        result["task_action"] = {
            "action": _clamp(ta.get("action"), _VALID_TASK_ACTIONS, None),
            "scope": _clamp(ta.get("scope"), _VALID_TASK_SCOPE, "matching"),
            "filter_course": ta.get("filter_course") or None,
            "filter_type": _clamp(ta.get("filter_type"), _VALID_TASK_TYPES, None),
            "reference": ta.get("reference") or None,
            "new_due": _clamp(str(ta.get("new_due") or "").lower(), _VALID_DAYS, None),
            "new_time": _validate_time(ta.get("new_time")),
            "needs_clarification": bool(ta.get("needs_clarification")),
            "missing_fields": [f for f in missing if f in _VALID_MISSING],
        }

    elif intent == "out_of_scope":
        oos = raw.get("out_of_scope") or {}
        result["out_of_scope"] = {
            "kind": _clamp(str(oos.get("kind") or "").lower(), _VALID_OOS_KINDS, None),
            "topic": _sanitize_oos_topic(oos.get("topic")),
        }

    elif intent == "section_set":
        sec = raw.get("section") or {}
        raw_text = (sec.get("raw") or "").strip()
        result["section"] = {"raw": raw_text}

    return result

# ── LLM #1: understand ────────────────────────────────────────────────────────

def understand(text: str, db=None, session: Optional[dict] = None) -> dict:
    """
    Call LLM #1 to parse the student's message into a structured routing request.
    Returns a clamped request dict, or {"intent": "_degraded", ...} on any failure.
    NEVER raises.

    `session` is pending-create / recently-listed context only — the model must
    not treat it as a routing override.
    """
    system_prompt = _load_prompt("nlu_understand_v1.yaml")
    if not system_prompt:
        logger.warning("nlu.understand: prompt not loaded, returning degraded")
        return {"intent": "_degraded", "language": "en", "confidence": 0.0}

    try:
        raw_text = _call_groq(
            system_prompt,
            _understand_user_content(text, session),
            json_mode=True,
            caller="nlu_understand",
            db=db,
            prompt_version="nlu_understand_v1",
        )
        if not raw_text:
            raise ValueError("empty model response")
        raw = _extract_json(raw_text)
        result = _clamp_request(raw)
        if result.get("intent") == "schedule_query":
            from utils.academic import normalize_requested_section
            sched = result["schedule"]
            if not sched.get("section"):
                from_text = normalize_requested_section(text)
                if from_text:
                    sched["section"] = from_text
                    if sched.get("course") and normalize_requested_section(sched["course"]) == from_text:
                        sched["course"] = None
        logger.info(
            "nlu.understand intent=%s qt=%s day=%s section=%s lang=%s conf=%.2f text=%r",
            result["intent"],
            result.get("schedule", {}).get("query_type", "-"),
            result.get("schedule", {}).get("day", "-"),
            result.get("schedule", {}).get("section", "-"),
            result["language"],
            result["confidence"],
            text[:50],
        )
        return result

    except Exception as exc:
        logger.warning("nlu.understand failed (%s), returning degraded", exc)
        return {"intent": "_degraded", "language": "en", "confidence": 0.0}


def _understand_user_content(text: str, session: Optional[dict]) -> str:
    parts = [f"Message: {text}"]
    session = session or {}
    recent = session.get("recent_messages") or []
    if recent:
        context_lines = []
        for msg in recent[-5:]:
            u = msg.get("user") or ""
            b = msg.get("bot") or ""
            if u:
                context_lines.append(f"User: {u}")
            if b:
                context_lines.append(f"Bot: {b}")
        if context_lines:
            parts.append("Recent conversation:\n" + "\n".join(context_lines))

    pending = session.get("pending_create")
    if pending:
        from utils.task_actions import deserialize_draft, missing_create_fields
        draft = deserialize_draft(pending.get("draft") or pending)
        payload = {
            "task_type": draft.get("task_type"),
            "course": draft.get("course"),
            "has_due_date": bool(draft.get("due_date")),
            "has_explicit_time": bool(draft.get("has_explicit_time")),
        }
        missing = missing_create_fields(draft)
        if missing:
            payload["awaiting"] = missing[0]
        parts.append("Pending_create: " + json.dumps(payload, ensure_ascii=True))
    pending_action = session.get("pending_action")
    if pending_action:
        parts.append("Pending_action: " + json.dumps({
            "action": pending_action.get("action"),
            "candidate_count": len(pending_action.get("candidate_ids") or []),
        }, ensure_ascii=True))
    last_labels = session.get("last_task_labels") or []
    if last_labels:
        parts.append("Recently_listed_tasks: " + json.dumps(last_labels[:8], ensure_ascii=True))
    pending_section = session.get("pending_section")
    if pending_section:
        parts.append("Pending_section: " + json.dumps({
            "awaiting_program": True,
            "raw_suffix": pending_section.get("raw_suffix", ""),
        }, ensure_ascii=True))
    return "\n".join(parts)


def _pending_awaiting_field(session: Optional[dict]) -> Optional[str]:
    pending = (session or {}).get("pending_create")
    if not pending:
        return None
    from utils.task_actions import deserialize_draft, missing_create_fields
    draft = deserialize_draft(pending.get("draft") or pending)
    missing = missing_create_fields(draft)
    return missing[0] if missing else None


def _looks_like_clock_time(text: str) -> bool:
    from utils.parse_task import QUIZ_TIME_PATTERN, TIME_RANGE_PATTERN, BEFORE_TIME_PATTERN
    t = text or ""
    return bool(
        QUIZ_TIME_PATTERN.search(t)
        or TIME_RANGE_PATTERN.search(t)
        or BEFORE_TIME_PATTERN.search(t)
    )


def _message_is_pending_interrupt(text: str, request: dict) -> bool:
    """True when THIS message is a genuine new request, not a field fill."""
    if (request or {}).get("intent") in _PENDING_INTENT_INTERRUPTS:
        return True
    return bool(_PENDING_INTERRUPT_RE.search(text or ""))


def _as_save_task(request: dict) -> dict:
    out = dict(request or {})
    out["intent"] = "save_task"
    out.pop("schedule", None)
    out.pop("task", None)
    if not isinstance(out.get("save_task"), dict):
        out["save_task"] = {"needs_clarification": True}
    return out


def _reconcile_pending_create(
    request: dict,
    text: str,
    session: Optional[dict],
    db=None,
    user_id: Optional[str] = None,
) -> dict:
    """
    After LLM #1, keep a short field-fill on the pending create.

    Does not override genuine interrupts (queries, greetings, cancel, …).
    Course resolution uses academic.match_course — no course-name keyword lists.
    """
    awaiting = _pending_awaiting_field(session)
    if not awaiting or not request or request.get("intent") == "_degraded":
        return request
    if _message_is_pending_interrupt(text, request):
        return request

    if awaiting == "course":
        try:
            from utils.academic import get_user_academic_context, match_course
            ctx = get_user_academic_context(db, user_id) if db is not None else {}
            matched = match_course(text, ctx.get("courses") or [], ctx.get("aliases") or {})
        except Exception as exc:
            logger.warning("nlu: pending course match failed (%s)", exc)
            matched = None
        if matched:
            logger.info("nlu: pending course fill matched=%r text=%r", matched, (text or "")[:40])
            return _as_save_task(request)
        return request

    if awaiting == "due_date":
        try:
            from utils.parse_task import detect_due_date, _utc_now as parse_now
            due = detect_due_date(text, parse_now())
        except Exception as exc:
            logger.warning("nlu: pending date parse failed (%s)", exc)
            due = None
        if due is not None:
            logger.info("nlu: pending date fill text=%r", (text or "")[:40])
            return _as_save_task(request)
        return request

    if awaiting == "due_time" and _looks_like_clock_time(text):
        logger.info("nlu: pending time fill text=%r", (text or "")[:40])
        return _as_save_task(request)

    return request


# ── Backend execution (pure Python — the only source of facts) ────────────────

def _parse_hhmm(s: Optional[str]) -> Optional[int]:
    """Parse "HH:MM" to minutes since midnight."""
    if not s:
        return None
    try:
        h, m = map(int, s.split(":"))
        return h * 60 + m
    except Exception:
        return None

def _resolve_day(day_str: Optional[str]) -> Optional[str]:
    """Resolve logical day string to a real weekday name."""
    if not day_str:
        return None
    dl = day_str.lower()
    if dl == "today":
        return datetime.now(_PKT).strftime("%A")
    if dl == "tomorrow":
        return (datetime.now(_PKT) + timedelta(days=1)).strftime("%A")
    cap = dl.capitalize()
    _weekdays = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"}
    return cap if cap in _weekdays else None


def _format_pending_tasks(tasks: list) -> str:
    """Format a list of task dicts into a numbered WhatsApp string."""
    from utils.parse_task import compose_task_title

    formatted = []
    for idx, t in enumerate(tasks, 1):
        course = t.get("parsed_course") or "Unknown Course"
        title = compose_task_title(
            t.get("parsed_course"),
            t.get("task_type"),
            t.get("parsed_title"),
            t.get("raw_message"),
        )
        due = t.get("parsed_due_date")
        if due:
            if due.tzinfo:
                due_pkt = due.astimezone(_PKT)
            else:
                due_pkt = due.replace(tzinfo=timezone.utc).astimezone(_PKT)
            due_str = due_pkt.strftime("%d %b at %I:%M %p")
        else:
            due_str = "No due date"
        formatted.append(f"{idx}. *{course}*: {title} — Due: {due_str}")
    return "\n".join(formatted)


def _execute_schedule(request: dict, db, user_id: str) -> dict:
    """
    Execute a schedule_query request against the user's real academic data.
    Returns {"text": str, "data": dict|None, "no_timetable": bool}.
    """
    # Lazy import to avoid circular deps; academic.py is the source of truth
    from utils.rag import retrieve_schedule_context_structured  # type: ignore

    sched = request.get("schedule", {})
    rag_request = {
        "query_type": sched.get("query_type", "next_class"),
        "course": sched.get("course"),
        "teacher": sched.get("teacher"),
        "section": sched.get("section"),
        "day": sched.get("day"),
        "time_after_min": _parse_hhmm(sched.get("time_after")),
        "time_before_min": _parse_hhmm(sched.get("time_before")),
    }
    return retrieve_schedule_context_structured(rag_request, db, user_id)


def _execute_tasks(request: dict, db, user_id: str) -> dict:
    """
    Execute a task_query request against db.tasks with optional filters.
    Returns {"text": str, "data": dict}.
    """
    from utils.academic import get_user_academic_context, match_course, base_course  # type: ignore

    task_params = request.get("task", {}) or {}
    raw_course = task_params.get("filter_course")
    due = task_params.get("due")

    # Build MongoDB filter
    query: dict = {"user_id": user_id, "status": "pending"}
    now_pkt = datetime.now(_PKT)

    if due == "today":
        day_start = datetime(now_pkt.year, now_pkt.month, now_pkt.day, tzinfo=_PKT)
        day_end = day_start + timedelta(days=1)
        query["parsed_due_date"] = {
            "$gte": day_start.astimezone(timezone.utc),
            "$lt": day_end.astimezone(timezone.utc),
        }
    elif due == "tomorrow":
        day_start = datetime(now_pkt.year, now_pkt.month, now_pkt.day, tzinfo=_PKT) + timedelta(days=1)
        day_end = day_start + timedelta(days=1)
        query["parsed_due_date"] = {
            "$gte": day_start.astimezone(timezone.utc),
            "$lt": day_end.astimezone(timezone.utc),
        }
    elif due == "this_week":
        week_end = datetime(now_pkt.year, now_pkt.month, now_pkt.day, tzinfo=_PKT) + timedelta(days=7)
        query["parsed_due_date"] = {"$lte": week_end.astimezone(timezone.utc)}
    elif due == "overdue":
        today_start = datetime(now_pkt.year, now_pkt.month, now_pkt.day, tzinfo=_PKT)
        query["parsed_due_date"] = {"$lt": today_start.astimezone(timezone.utc)}

    tasks = list(db.tasks.find(query)) if db is not None else []

    # Course filter — resolved in Python against user's real courses
    if raw_course and tasks:
        try:
            ctx = get_user_academic_context(db, user_id)
            target = match_course(raw_course, ctx.get("courses", []), ctx.get("aliases", {}))
            if target:
                target_base = base_course(target).lower()
                tasks = [
                    t for t in tasks
                    if base_course(str(t.get("parsed_course") or "")).lower() == target_base
                ]
        except Exception as exc:
            logger.warning("nlu: course filter failed (%s), showing unfiltered tasks", exc)

    if not tasks:
        if due == "today":
            text = "Nothing due today! 🎉"
        elif due == "tomorrow":
            text = "Nothing due tomorrow! 🎉"
        elif due == "overdue":
            text = "No overdue tasks! You're all caught up. ✅"
        elif raw_course:
            text = f"No pending tasks for *{raw_course}*! 🎉"
        else:
            text = "You have no pending assignments or quizzes! Great job! 🎉"
        return {"text": text, "data": {"tasks": [], "task_ids": [], "task_labels": []}}

    task_list = _format_pending_tasks(tasks)
    header = "📋 *Your Pending Tasks:*"
    if raw_course:
        header = f"📋 *{raw_course} Tasks:*"
    elif due == "today":
        header = "📋 *Due Today:*"
    elif due == "tomorrow":
        header = "📋 *Due Tomorrow:*"
    elif due == "this_week":
        header = "📋 *Due This Week:*"
    elif due == "overdue":
        header = "📋 *Overdue Tasks:*"

    text = f"{header}\n\n{task_list}\n\nView & edit on your dashboard!"
    return {
        "text": text,
        "data": {
            "task_count": len(tasks),
            "task_ids": [str(t.get("_id")) for t in tasks if t.get("_id") is not None],
            "task_labels": [_format_one_task_label(t) for t in tasks],
        },
    }


def _format_one_task_label(task: dict) -> str:
    from utils.parse_task import compose_task_title
    course = task.get("parsed_course") or "Unknown Course"
    title = compose_task_title(
        task.get("parsed_course"),
        task.get("task_type"),
        task.get("parsed_title"),
        task.get("raw_message"),
    )
    return f"{course}: {title}"


def execute(request: dict, db, user_id: str) -> dict:
    """
    Pure Python backend execution. The only source of academic/task facts.
    Returns a grounded result dict:
      {"kind": str, "text": str, "data": dict|None, "language": str, "no_timetable": bool}
    Never raises.
    """
    intent = request.get("intent", "out_of_scope")
    language = request.get("language", "en")

    result: dict = {
        "kind": intent,
        "text": OUT_OF_SCOPE_REPLY,
        "data": None,
        "language": language,
        "no_timetable": False,
    }

    try:
        if intent == "greeting":
            result["text"] = GREETING_REPLY
            return result

        if intent == "help":
            result["text"] = HELP_REPLY
            return result

        if intent in ("save_task", "_degraded"):
            result["text"] = ""
            return result

        if intent in ("out_of_scope", "dashboard_required"):
            result["text"] = _out_of_scope_reply(request)
            return result

        if intent == "schedule_query":
            sched_result = _execute_schedule(request, db, user_id)
            result["text"] = sched_result.get("text", result["text"])
            result["data"] = sched_result.get("data")
            result["no_timetable"] = sched_result.get("no_timetable", False)
            return result

        if intent == "task_query":
            if db is None:
                result["text"] = "I'm having trouble reaching the database. Please try again shortly."
                result["no_timetable"] = True
                return result
            task_result = _execute_tasks(request, db, user_id)
            result["text"] = task_result.get("text", result["text"])
            result["data"] = task_result.get("data")
            return result

        if intent == "task_action":
            result["text"] = ""
            result["data"] = request.get("task_action")
            return result

        if intent == "section_set":
            # Validation + DB write is in _handle_section_set; execute() just
            # marks this as a section action so handle_message() can route it.
            result["text"] = ""
            result["kind"] = "section_set"
            return result

    except Exception as exc:
        logger.warning("nlu.execute failed for intent=%s (%s)", intent, exc)
        result["text"] = "Something went wrong. Please try again in a moment."

    return result

# ── LLM #2: respond (optional naturalization) ─────────────────────────────────

def _containment_guard(llm_output: str, deterministic_text: str) -> bool:
    """
    Returns True if the LLM output is safe to use.
    Checks:
    1. Not empty.
    2. All time patterns (HH:MM) in LLM output are present in the deterministic text.
    3. Not suspiciously short compared to deterministic text (guards against truncation).
    """
    # DASHBOARD_URL containment rules
    if DASHBOARD_URL not in deterministic_text and DASHBOARD_URL in llm_output:
        logger.warning("nlu.respond: containment guard tripped — unnecessary dashboard URL added")
        return False
    if DASHBOARD_URL in deterministic_text and DASHBOARD_URL not in llm_output:
        logger.warning("nlu.respond: containment guard tripped — dashboard URL omitted from output")
        return False

    # Extract time tokens from both
    time_pattern = re.compile(r"\b\d{1,2}:\d{2}\b")
    llm_times = set(time_pattern.findall(llm_output))
    det_times = set(time_pattern.findall(deterministic_text))

    # Any time in LLM output that wasn't in the deterministic text → reject
    invented_times = llm_times - det_times
    if invented_times:
        logger.warning("nlu.respond: containment guard tripped — invented times %s", invented_times)
        return False

    # LLM #2 must not invent placeholder instructor punctuation ("Instructor: … 😄")
    for marker in ("…", "..."):
        if marker in llm_output and marker not in deterministic_text:
            logger.warning("nlu.respond: containment guard tripped — placeholder marker")
            return False

    # If deterministic text is substantial but LLM output is tiny, suspect truncation
    if len(deterministic_text) > 80 and len(llm_output.strip()) < len(deterministic_text) * 0.25:
        logger.warning("nlu.respond: output too short (%d vs %d)", len(llm_output), len(deterministic_text))
        return False

    return True


def respond(grounded: dict, db=None) -> str:
    """
    LLM #2: rephrase the grounded deterministic text in the user's language.
    Returns grounded["text"] (deterministic fallback) on any failure, when the
    flag is off, or when there is nothing to rephrase.
    Never raises.
    """
    deterministic_text = grounded.get("text", "")

    # Cases where we skip LLM #2 entirely
    if not response_enabled():
        return deterministic_text

    if not deterministic_text:
        return deterministic_text

    kind = grounded.get("kind", "")
    if kind in ("save_task", "task_action", "_degraded", "out_of_scope", "greeting", "help"):
        return deterministic_text  # Static/sentinel — no point rephrasing

    if grounded.get("no_timetable"):
        return deterministic_text  # Guidance messages are precise; don't rephrase

    language = grounded.get("language", "en")
    if language == "en":
        return deterministic_text  # English is already natural; skip LLM #2 cost

    system_prompt = _load_prompt("nlu_respond_v1.yaml")
    if not system_prompt:
        return deterministic_text

    user_content = (
        f"LANGUAGE: {language}\n\n"
        f"EXISTING_RESPONSE:\n{deterministic_text}"
    )

    try:
        output = _call_groq(
            system_prompt,
            user_content,
            json_mode=False,
            caller="nlu_respond",
            db=db,
            prompt_version="nlu_respond_v1",
        )

        if not _containment_guard(output, deterministic_text):
            logger.info("nlu.respond: guard failed, using deterministic text")
            return deterministic_text

        return output.strip() or deterministic_text

    except Exception as exc:
        logger.warning("nlu.respond LLM #2 failed (%s), using deterministic text", exc)
        return deterministic_text

# ── Fallback classifier (deterministic, mirrors agent.classify_intent) ────────

def _fallback_classify(text: str) -> str:
    """
    Mirror of agent.py::classify_intent. Used when LLM #1 is unavailable.
    Returns 'save_task' | 'query_schedule' | 'query_tasks' | 'greeting'.
    """
    try:
        from utils.agent import classify_intent  # type: ignore
        return classify_intent(text)
    except Exception:
        return "query_schedule"  # safest default — never silently saves garbage


def _fallback_handle(db, user_id: str, phone: str, text: str) -> dict:
    """
    Handle a message using the existing keyword-based classify_intent + handle_agent_query.
    Used when LLM #1 is degraded or routing is disabled.
    Returns the same {"action", "text"} shape.
    """
    if _is_dashboard_required(text):
        return {
            "action": "reply",
            "text": DASHBOARD_REQUIRED_REPLY,
            "intent": "dashboard_required",
        }

    try:
        from utils.agent import classify_intent, handle_agent_query  # type: ignore
        intent = classify_intent(text)
        if intent in ("greeting", "query_schedule", "query_tasks"):
            reply = handle_agent_query(db, user_id, phone, text, intent)
            return {"action": "reply", "text": reply, "intent": intent}
        if intent == "out_of_scope":
            # Conversational fallback -- simple helpful response until LLM routing
            # is enabled in Phase 1 and natural responses arrive in Phase 4.
            return {
                "action": "reply",
                "text": (
                    "I'm here to help with your timetable and assignments! "
                    "Try asking about your schedule or tasks."
                ),
                "intent": "out_of_scope",
            }
    except Exception as exc:
        logger.warning("nlu._fallback_handle failed (%s)", exc)

    # If we end up here, treat as save_task (preserves current fail-safe behavior)
    return {"action": "save_task", "intent": "save_task"}

# ── Main entry point ──────────────────────────────────────────────────────────

def handle_message(db, user_id: str, phone: str, text: str) -> dict:
    """
    Main NLU entry point for WhatsApp and the web assistant.

    Every message is understood by LLM #1 first. Pending create/action state is
    passed as context; Python then reconciles short field-fills before execute.

    Returns:
      {"action": "reply", "text": str, "intent": str}
      {"action": "save_task", "intent": "save_task"}  — degraded fallback only

    Never raises.
    """
    try:
        from utils.nlu_session import get_nlu_session, save_nlu_session

        session = get_nlu_session(db, user_id)
        has_pending = bool(session.get("pending_create") or session.get("pending_action"))

        # Fast-path greetings only when nothing is pending (otherwise "hi" must
        # still go through LLM #1 so it can be a greeting *or* ignored in context).
        if _is_trivial_greeting(text) and not has_pending:
            logger.info("nlu: fast_path greeting text=%r", text[:40])
            return {"action": "reply", "text": GREETING_REPLY, "intent": "greeting"}

        request = understand(text, db=db, session=session)

        if request.get("intent") == "_degraded":
            logger.info("nlu: degraded, using fallback classifier text=%r", text[:40])
            return _fallback_handle(db, user_id, phone, text)

        request = _reconcile_pending_create(request, text, session, db, user_id)
        intent = request["intent"]
        logger.info(
            "nlu: intent=%s lang=%s conf=%.2f text=%r",
            intent, request.get("language", "?"), request.get("confidence", 0), text[:50],
        )

        if intent == "save_task":
            return _handle_save_task(db, user_id, phone, text, request, session)

        if intent == "task_action":
            return _handle_task_action(db, user_id, phone, text, request, session)

        if intent == "section_set":
            return _handle_section_set(db, user_id, phone, text, request, session)

        grounded = execute(request, db, user_id)
        reply_text = respond(grounded, db=db)

        if intent == "task_query":
            data = grounded.get("data") or {}
            save_nlu_session(
                db, user_id, phone,
                last_task_ids=data.get("task_ids") or [],
                last_task_labels=data.get("task_labels") or [],
                pending_create=session.get("pending_create"),
                pending_action=session.get("pending_action"),
            )

        return {"action": "reply", "text": reply_text, "intent": intent}

    except Exception as exc:
        logger.error("nlu.handle_message unexpected error: %s", exc, exc_info=True)
        return {"action": "save_task", "intent": "save_task"}


def _handle_save_task(db, user_id, phone, text, request, session) -> dict:
    from utils.academic import get_user_academic_context
    from utils.parse_task import parse_task
    from utils.nlu_session import save_nlu_session, clear_pending_create
    from utils.task_actions import (
        apply_parse_to_draft,
        missing_create_fields,
        clarify_create,
        confirm_create,
        serialize_draft,
        deserialize_draft,
    )

    pending = (session or {}).get("pending_create") or {}
    draft = deserialize_draft(pending.get("draft") or {})
    ctx = get_user_academic_context(db, user_id) if db is not None else {}
    parsed = parse_task(
        text,
        course_hint=draft.get("course"),
        user_courses=ctx.get("courses"),
        overrides=ctx.get("aliases"),
    )
    draft = apply_parse_to_draft(draft, parsed)
    missing = missing_create_fields(draft)
    if missing and missing[0] == "due_time" and draft.get("due_date"):
        from utils.parse_task import QUIZ_TIME_PATTERN, _apply_explicit_time, _utc_now as parse_now
        if QUIZ_TIME_PATTERN.search(text or ""):
            draft["due_date"] = _apply_explicit_time(text, draft["due_date"], parse_now())
            draft["has_explicit_time"] = True
            missing = missing_create_fields(draft)
    if missing:
        save_nlu_session(
            db, user_id, phone,
            pending_create={"draft": serialize_draft(draft)},
            pending_action=(session or {}).get("pending_action"),
            last_task_ids=(session or {}).get("last_task_ids") or [],
            last_task_labels=(session or {}).get("last_task_labels") or [],
        )
        return {
            "action": "reply",
            "text": clarify_create(draft, missing[0]),
            "intent": "save_task",
        }

    composed = " ".join(
        p for p in (
            draft.get("course"),
            draft.get("task_type") or "task",
            text,
        ) if p
    )
    persist = _persist_complete_task(db, user_id, phone, composed, draft)
    if not persist or not persist.get("inserted_task_id"):
        if persist and persist.get("duplicate_key"):
            clear_pending_create(db, user_id)
            return {
                "action": "reply",
                "text": "That looks like a task I already have saved.",
                "intent": "save_task",
            }
        return {
            "action": "reply",
            "text": "I understood the task but couldn't save it. Please try again.",
            "intent": "save_task",
        }

    clear_pending_create(db, user_id)
    task_doc = persist.get("task_doc") or {}
    save_nlu_session(
        db, user_id, phone,
        pending_create=None,
        last_task_ids=[persist["inserted_task_id"]],
        last_task_labels=[f"{task_doc.get('parsed_course')}: {task_doc.get('parsed_title')}"],
    )
    return {
        "action": "reply",
        "text": confirm_create(task_doc),
        "intent": "save_task",
    }


def _persist_complete_task(db, user_id, phone, text, draft) -> Optional[dict]:
    try:
        from app import persist_inbound_task
    except Exception:
        logger.warning("nlu: persist_inbound_task unavailable")
        return None
    saved = persist_inbound_task(
        db,
        user_id=user_id,
        phone=phone,
        text=text,
        source_key="nlu_create",
    )
    # Re-assert grounded draft fields after insert (parse_task may have run again).
    task_doc = saved.get("task_doc") or {}
    oid = task_doc.get("_id")
    if oid is not None and draft.get("course") and db is not None:
        db.tasks.update_one(
            {"_id": oid, "user_id": user_id},
            {"$set": {
                "parsed_course": draft.get("course") or task_doc.get("parsed_course"),
                "parsed_due_date": draft.get("due_date") or task_doc.get("parsed_due_date"),
                "task_type": draft.get("task_type") or task_doc.get("task_type"),
                "has_explicit_time": True,
                "needs_review": False,
                "course_unresolved": False,
                "status": "pending",
            }},
        )
        saved["task_doc"] = db.tasks.find_one({"_id": oid, "user_id": user_id}) or task_doc
    return saved


def _handle_task_action(db, user_id, phone, text, request, session) -> dict:
    from utils.nlu_session import save_nlu_session, clear_pending_create, clear_pending_action
    from utils.task_actions import (
        resolve_target_tasks,
        complete_tasks,
        delete_tasks,
        reschedule_tasks,
        confirm_completed,
        confirm_deleted,
        confirm_rescheduled,
        ask_which_task,
        task_label,
    )
    from utils.parse_task import detect_due_date, _utc_now as parse_now

    ta = request.get("task_action") or {}
    action = ta.get("action")
    if action == "cancel":
        clear_pending_create(db, user_id)
        clear_pending_action(db, user_id)
        return {"action": "reply", "text": "Okay — I've cancelled that.", "intent": "task_action"}

    if action not in ("complete", "delete", "reschedule"):
        return {
            "action": "reply",
            "text": "I can complete, delete, or reschedule a task — which did you mean?",
            "intent": "task_action",
        }

    scope = ta.get("scope") or "matching"
    if ta.get("reference") in ("that", "it", "last", "this"):
        scope = "reference"

    last_ids = (session or {}).get("last_task_ids") or []
    pending_action = (session or {}).get("pending_action") or {}
    if pending_action.get("candidate_ids") and action == pending_action.get("action"):
        last_ids = pending_action.get("candidate_ids") or last_ids
        if scope == "matching" and not ta.get("filter_course") and not ta.get("filter_type"):
            scope = "reference"

    targets = resolve_target_tasks(
        db, user_id,
        scope=scope,
        filter_type=ta.get("filter_type"),
        filter_course=ta.get("filter_course"),
        last_task_ids=last_ids,
    )

    if not targets:
        if action == "complete" and scope == "all":
            return {
                "action": "reply",
                "text": "You don't have any pending tasks to complete.",
                "intent": "task_action",
            }
        return {
            "action": "reply",
            "text": "I couldn't find a matching pending task. Which one did you mean?",
            "intent": "task_action",
        }

    if len(targets) > 1 and scope != "all":
        save_nlu_session(
            db, user_id, phone,
            pending_create=(session or {}).get("pending_create"),
            pending_action={
                "action": action,
                "candidate_ids": [str(t["_id"]) for t in targets],
            },
            last_task_ids=[str(t["_id"]) for t in targets],
            last_task_labels=[task_label(t) for t in targets],
        )
        return {
            "action": "reply",
            "text": ask_which_task(action, targets),
            "intent": "task_action",
        }

    if action == "complete":
        updated = complete_tasks(db, user_id, targets)
        clear_pending_action(db, user_id)
        if not updated:
            return {
                "action": "reply",
                "text": "You don't have any pending tasks to complete.",
                "intent": "task_action",
            }
        return {"action": "reply", "text": confirm_completed(updated), "intent": "task_action"}

    if action == "delete":
        labels = [task_label(t) for t in targets]
        count = delete_tasks(db, user_id, targets)
        clear_pending_action(db, user_id)
        return {"action": "reply", "text": confirm_deleted(count, labels), "intent": "task_action"}

    due_date = detect_due_date(text, parse_now())
    if due_date is None:
        save_nlu_session(
            db, user_id, phone,
            pending_create=(session or {}).get("pending_create"),
            pending_action={
                "action": "reschedule",
                "candidate_ids": [str(t["_id"]) for t in targets],
            },
            last_task_ids=[str(t["_id"]) for t in targets],
        )
        return {
            "action": "reply",
            "text": "When should I move it to?",
            "intent": "task_action",
        }
    updated = reschedule_tasks(db, user_id, targets, due_date)
    clear_pending_action(db, user_id)
    return {"action": "reply", "text": confirm_rescheduled(updated, due_date), "intent": "task_action"}



def _handle_section_set(db, user_id: str, phone: str, text: str, request: dict, session: dict) -> dict:
    """
    Execute a section_set intent: validate the raw section text and either
    save it (unambiguous full section) or ask for clarification (bare/partial).
    Supports multi-turn clarification via pending_section session state.
    """
    from utils.nlu_session import save_nlu_session, clear_pending_section  # type: ignore
    from utils.academic import validate_and_resolve_section  # type: ignore

    raw_section = (request.get("section") or {}).get("raw", "").strip()

    # --- Multi-turn: combine pending suffix with clarification program --------
    pending_sec = (session or {}).get("pending_section") or {}
    raw_suffix = pending_sec.get("raw_suffix", "")
    if raw_suffix and raw_section:
        # The user just sent the program name in response to our clarification.
        # Combine: e.g. raw_suffix="7B" + raw_section="BSCS" -> try "BSCS-7B".
        combined = f"{raw_section.upper()}-{raw_suffix.upper()}"
        candidate = validate_and_resolve_section(combined, db)
        if candidate["status"] == "valid":
            raw_section = combined
        else:
            # Suffix alone as the new attempt
            raw_section = raw_section  # keep what the user just said; validate below

    if not raw_section:
        return {"action": "reply", "text": "Which section would you like to set?", "intent": "section_set"}

    result_check = validate_and_resolve_section(raw_section, db)

    if result_check["status"] == "ambiguous":
        options = result_check.get("available") or []
        suffix = result_check.get("suffix", raw_section)
        options_text = " or ".join(f"*{s}*" for s in options[:5])
        if not options_text:
            options_text = "e.g. BSCS-7A or BSSE-7A"
        # Save pending state so the next message can be combined
        save_nlu_session(
            db, user_id, phone,
            pending_section={"raw_suffix": suffix},
            pending_create=(session or {}).get("pending_create"),
            pending_action=(session or {}).get("pending_action"),
            last_task_ids=(session or {}).get("last_task_ids") or [],
            last_task_labels=(session or {}).get("last_task_labels") or [],
        )
        return {
            "action": "reply",
            "text": f"Which program is *{suffix}* for? For example, {options_text}.",
            "intent": "section_set",
        }

    if result_check["status"] == "not_found":
        clear_pending_section(db, user_id)
        return {
            "action": "reply",
            "text": (
                f"I couldn't find *{raw_section}* in the current timetable. "
                f"{result_check.get('message', 'Please check the section name.') }"
            ),
            "intent": "section_set",
        }

    if result_check["status"] == "valid":
        section = result_check["section"]
        clear_pending_section(db, user_id)
        # Persist to DB
        if db is not None and user_id:
            db.users.update_one(
                {"user_id": user_id},
                {"$set": {"settings.timetable_section": section}},
                upsert=True,
            )
            db.user_timetables.update_one(
                {"user_id": user_id},
                {"$set": {"selected_section": section}},
                upsert=True,
            )
        # Build confirmation text
        try:
            from utils.academic import get_published_section_context  # type: ignore
            from utils.rag import retrieve_schedule_context_structured  # type: ignore
            ctx = get_published_section_context(db, section)
            if ctx.get("status") == "ok":
                next_result = retrieve_schedule_context_structured(
                    {"query_type": "next_class"}, db, user_id
                )
                next_text = next_result.get("text", "")
                if next_text:
                    return {
                        "action": "reply",
                        "text": f"Done! You're set to *{section}*. \U0001f389\n\n{next_text}",
                        "intent": "section_set",
                    }
        except Exception as exc:
            logger.warning("section_set: next class lookup failed (%s)", exc)
        return {
            "action": "reply",
            "text": f"Done! You're set to *{section}*. \U0001f389",
            "intent": "section_set",
        }

    # Fallback (should not reach here)
    return {"action": "reply", "text": "Something went wrong setting your section. Please try again.", "intent": "section_set"}

def dispatch_message(db, user_id: str, phone: str, text: str, channel: str = None) -> dict:
    """
    Single AI entry point for WhatsApp and the web assistant.

    LLM #1 → execute/RAG → LLM #2 when routing is on; same fallback as WhatsApp
    when it is off or degraded. Never raises.

    `channel` is observability-only (whatsapp|web). It is attached to the existing
    llm_calls insert via context — no extra Mongo write on the user path.
    """
    import uuid
    from utils.llm_logger import llm_call_context
    from utils.rate_limiter import allow_ai_user

    if user_id and not allow_ai_user(user_id):
        logger.warning("ai_rate_limited user=%s channel=%s", user_id, channel)
        return {
            "action": "reply",
            "text": (
                "You're sending messages a bit quickly. "
                "Please wait a moment and try again."
            ),
            "intent": "rate_limited",
        }

    with llm_call_context(
        user_id=user_id,
        channel=channel,
        request_id=str(uuid.uuid4()),
    ):
        if routing_enabled():
            result = handle_message(db, user_id, phone, text)
        else:
            result = _fallback_handle(db, user_id, phone, text)

        if result and result.get("action") == "reply" and result.get("text"):
            try:
                from utils.nlu_session import append_to_recent_messages
                append_to_recent_messages(db, user_id, text, result.get("text", ""))
            except Exception as exc:
                logger.warning("failed to append to recent_messages: %s", exc)

        return result
