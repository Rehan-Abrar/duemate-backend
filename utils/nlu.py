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
from datetime import datetime, timedelta, timezone
from typing import Optional

from utils.groq_config import get_groq_model
from utils.llm_client import complete_chat

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_PKT = timezone(timedelta(hours=5))

# Valid values for schema clamping (prevents unconstrained model output from leaking)
_VALID_INTENTS = frozenset({
    "schedule_query", "task_query", "save_task", "greeting", "help", "out_of_scope",
})
_VALID_QUERY_TYPES = frozenset({
    "next_class", "day_schedule", "course_schedule", "teacher", "full_timetable", "free_check",
})
_VALID_DAYS = frozenset({
    "today", "tomorrow", "monday", "tuesday", "wednesday", "thursday", "friday",
})
_VALID_DUE = frozenset({"today", "tomorrow", "this_week", "overdue"})
_VALID_LANGUAGES = frozenset({"en", "ur", "mixed"})
_VALID_OOS_KINDS = frozenset({"casual", "internal", "unrelated"})
_TIME_RE = re.compile(r"^\d{2}:\d{2}$")
_OOS_TOPIC_RE = re.compile(r"^[a-z]+(?:[ -][a-z]+){0,2}$")
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
    return os.getenv("NLU_LLM_ROUTING_ENABLED", "false").lower() in ("1", "true", "yes")

def response_enabled() -> bool:
    """True when NLU_LLM_RESPONSE_ENABLED is set to a truthy value."""
    return os.getenv("NLU_LLM_RESPONSE_ENABLED", "false").lower() in ("1", "true", "yes")

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

# ── Prompt loading (same YAML convention as prompts/parse_task_v2.yaml) ───────

def _load_prompt(filename: str) -> str:
    """Load prompt from prompts/<filename>. Falls back to empty string on error."""
    try:
        path = os.path.join(os.path.dirname(__file__), "..", "prompts", filename)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        match = re.search(r"prompt_text:\s*>(.*)", content, re.DOTALL)
        if match:
            return match.group(1).strip()
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
) -> str:
    """LLM transport via the shared fallback client. Raises on total failure."""
    result = complete_chat(
        system_prompt,
        user_content,
        json_mode=json_mode,
        timeout=_nlu_timeout(),
        max_tokens=400,
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
    oos = request.get("out_of_scope") or {}
    kind = oos.get("kind")
    topic = oos.get("topic")
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

    elif intent == "out_of_scope":
        oos = raw.get("out_of_scope") or {}
        result["out_of_scope"] = {
            "kind": _clamp(str(oos.get("kind") or "").lower(), _VALID_OOS_KINDS, None),
            "topic": _sanitize_oos_topic(oos.get("topic")),
        }

    return result

# ── LLM #1: understand ────────────────────────────────────────────────────────

def understand(text: str, db=None) -> dict:
    """
    Call LLM #1 to parse the student's message into a structured routing request.
    Returns a clamped request dict, or {"intent": "_degraded", ...} on any failure.
    NEVER raises.
    """
    system_prompt = _load_prompt("nlu_understand_v1.yaml")
    if not system_prompt:
        logger.warning("nlu.understand: prompt not loaded, returning degraded")
        return {"intent": "_degraded", "language": "en", "confidence": 0.0}

    try:
        raw_text = _call_groq(
            system_prompt,
            f"Message: {text}",
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
        return {"text": text, "data": {"tasks": []}}

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
    return {"text": text, "data": {"task_count": len(tasks)}}


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

        if intent == "out_of_scope":
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
    if not llm_output or not llm_output.strip():
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
    if kind in ("save_task", "_degraded", "out_of_scope", "greeting", "help"):
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
    Used when LLM #1 is degraded. Returns the same {"action", "text"} shape.
    """
    try:
        from utils.agent import classify_intent, handle_agent_query  # type: ignore
        intent = classify_intent(text)
        if intent in ("greeting", "query_schedule", "query_tasks"):
            reply = handle_agent_query(db, user_id, phone, text, intent)
            return {"action": "reply", "text": reply}
    except Exception as exc:
        logger.warning("nlu._fallback_handle failed (%s)", exc)

    # If we end up here, treat as save_task (preserves current fail-safe behavior)
    return {"action": "save_task"}

# ── Main entry point ──────────────────────────────────────────────────────────

def handle_message(db, user_id: str, phone: str, text: str) -> dict:
    """
    Main NLU entry point. Called by app.py when NLU_LLM_ROUTING_ENABLED=true.

    The caller (app.py webhook or assistant_chat) is responsible for:
      - The active-conversation check (runs before this in the webhook)
      - Calling send_text_message
      - Updating summary counters

    Returns:
      {"action": "reply",     "text": str}  — send this reply, skip parse_task
      {"action": "save_task"}               — fall through to parse_task pipeline

    Never raises.
    """
    try:
        # ── Fast path: trivial greetings (skip both LLM calls) ────────────────
        if _is_trivial_greeting(text):
            logger.info("nlu: fast_path greeting text=%r", text[:40])
            return {"action": "reply", "text": GREETING_REPLY}

        # ── LLM #1: understand the message ────────────────────────────────────
        request = understand(text, db=db)

        # Degraded → fall back to the existing keyword classifier
        if request.get("intent") == "_degraded":
            logger.info("nlu: degraded, using fallback classifier text=%r", text[:40])
            return _fallback_handle(db, user_id, phone, text)

        intent = request["intent"]
        logger.info(
            "nlu: intent=%s lang=%s conf=%.2f text=%r",
            intent, request.get("language", "?"), request.get("confidence", 0), text[:50],
        )

        # save_task → return sentinel so app.py falls through to parse_task
        if intent == "save_task":
            return {"action": "save_task"}

        # ── Backend: execute against real data ────────────────────────────────
        grounded = execute(request, db, user_id)

        # ── LLM #2 (optional): naturalize response ────────────────────────────
        reply_text = respond(grounded, db=db)

        return {"action": "reply", "text": reply_text}

    except Exception as exc:
        # Belt-and-suspenders: this should never happen, but if it does we must
        # not silently drop the message. Return save_task so the message is
        # at least processed by the parse pipeline rather than lost.
        logger.error("nlu.handle_message unexpected error: %s", exc, exc_info=True)
        return {"action": "save_task"}
