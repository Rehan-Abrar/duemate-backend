"""
Schedule/timetable query engine for DueMate's WhatsApp chatbot.

Academic data comes exclusively from the user's applicable timetable via
`utils.academic.get_user_academic_context` (official published timetable first, then
the student's self-uploaded timetable). There is NO static BSCS-6B fallback and no
hardcoded course/teacher table — course matching is derived from the user's real
courses. The LLM is never the source of truth for academic facts.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from utils.academic import (
    get_user_academic_context,
    match_course,
    course_matches,
    message_for_status,
    STATUS_OK,
)

_DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_PKT = timezone(timedelta(hours=5))


def _now_pkt() -> datetime:
    return datetime.now(_PKT)


# ── Time-window helpers (used by structured / NLU entry) ──────────────────────

def _parse_hhmm(s: Optional[str]) -> Optional[int]:
    """Parse "HH:MM" → minutes since midnight, or None."""
    if not s:
        return None
    try:
        h, m = map(int, s.split(":"))
        return h * 60 + m
    except Exception:
        return None


def _min_to_12h(minutes: int) -> str:
    """Convert minutes since midnight → "H:MM AM/PM" for human display."""
    h, m = divmod(minutes, 60)
    ampm = "AM" if h < 12 else "PM"
    h12 = h % 12 or 12
    return f"{h12}:{m:02d} {ampm}"


def _within_window(
    time_str: str,
    after_min: Optional[int] = None,
    before_min: Optional[int] = None,
) -> bool:
    """
    Return True if the slot overlaps with the requested time window.
    A slot passes when it ends after `after_min` AND starts before `before_min`.
    Unknown slot time → pass (don't filter out).
    """
    start, end = _parse_slot_time(time_str)
    if start is None:
        return True
    if after_min is not None and end <= after_min:
        return False  # slot finishes before our window starts
    if before_min is not None and start >= before_min:
        return False  # slot starts after our window ends
    return True


def _resolve_day(day_str: Optional[str]) -> Optional[str]:
    """Resolve "today"/"tomorrow"/weekday-name → actual weekday string."""
    if not day_str:
        return None
    dl = str(day_str).lower()
    if dl == "today":
        return _now_pkt().strftime("%A")
    if dl == "tomorrow":
        return (_now_pkt() + timedelta(days=1)).strftime("%A")
    cap = dl.capitalize()
    return cap if cap in _DAY_ORDER else None


def _parse_slot_time(time_str: str) -> tuple[Optional[int], Optional[int]]:
    """Return (start_min, end_min) since midnight."""
    try:
        start, end = time_str.split("-")
        def _to_min(t):
            h, m = map(int, t.strip().split(":"))
            return h * 60 + m
        return _to_min(start), _to_min(end)
    except Exception:
        return None, None


def _format_time_12h(time_str: str) -> str:
    try:
        start, end = time_str.split("-")
        def t12(t):
            h, m = map(int, t.strip().split(":"))
            ampm = "AM" if h < 12 else "PM"
            h12 = h % 12 or 12
            return f"{h12}:{m:02d} {ampm}"
        return f"{t12(start)} - {t12(end)}"
    except Exception:
        return time_str


def _format_slot(slot: dict, day: str) -> str:
    instructors = slot.get("instructor", "")
    if isinstance(instructors, list):
        instructors = " & ".join(instructors)
    return (
        f"{slot['course']}\n{day}, {_format_time_12h(slot['time'])}\n"
        f"Room: {slot.get('room','?')}\nInstructor: {instructors}"
    )


# ── Handlers ──────────────────────────────────────────────────────────────────

def _get_next_class(
    timetable: dict,
    target_course: Optional[str],
    *,
    time_after_min: Optional[int] = None,
    time_before_min: Optional[int] = None,
) -> str:
    """
    Return the next (or currently ongoing) class, optionally filtered by course
    and/or a time window.  `time_after_min` / `time_before_min` are minutes since
    midnight; pass None to skip that bound.  Default None reproduces the original
    behaviour so existing callers are unaffected.
    """
    now = _now_pkt()
    current_day = now.strftime("%A")
    current_minutes = now.hour * 60 + now.minute

    schedule = timetable.get("schedule", {})
    day_index = _DAY_ORDER.index(current_day) if current_day in _DAY_ORDER else 0

    for offset in range(7):
        day = _DAY_ORDER[(day_index + offset) % len(_DAY_ORDER)]
        day_slots = schedule.get(day, [])

        valid_slots = []
        for slot in day_slots:
            if target_course and not course_matches(slot.get("course", ""), target_course):
                continue
            if not _within_window(slot.get("time", ""), time_after_min, time_before_min):
                continue
            valid_slots.append(slot)

        # Sort by start time
        valid_slots.sort(key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0)

        for slot in valid_slots:
            start_min, end_min = _parse_slot_time(slot.get("time", ""))
            if start_min is None or end_min is None:
                continue

            if offset == 0:
                if end_min <= current_minutes:
                    continue  # Passed
                if start_min <= current_minutes < end_min:
                    prefix = "Current class:" if not target_course else f"Current {slot.get('course')} class:"
                    return f"*{prefix}*\n" + _format_slot(slot, day)

            prefix = "Next class:" if not target_course else f"Next {slot.get('course')} class:"
            return f"*{prefix}*\n" + _format_slot(slot, day)

    return "No upcoming classes found in your timetable."


def _get_course_schedule(timetable: dict, target_course: str) -> str:
    schedule = timetable.get("schedule", {})
    found = []
    for day in _DAY_ORDER:
        for slot in schedule.get(day, []):
            if course_matches(slot.get("course", ""), target_course):
                found.append((day, slot))

    if not found:
        return "No classes found for that course in your timetable."

    res = "📅 *Course Schedule:*\n\n"
    for day, slot in found:
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()


def _get_teacher_info(teachers_data: dict, timetable: dict, query: str, target_course: Optional[str]) -> str:
    teacher_list = teachers_data.get("teachers", [])
    q = query.lower()

    matched_teachers = []
    for t in teacher_list:
        name = t["name"].lower()
        if any(part in q for part in name.split() if len(part) > 2):
            matched_teachers.append(t)
            continue

        # Match by the resolved course (against the teacher's actual subjects)
        if target_course:
            subjects = t.get("subjects", [])
            if any(course_matches(subj, target_course) for subj in subjects):
                if t not in matched_teachers:
                    matched_teachers.append(t)

    if not matched_teachers:
        return "I couldn't find any instructors matching your query in your timetable."

    res = ""
    for t in matched_teachers:
        res += f"👨‍🏫 *{t['name']}*\nTeaches: {', '.join(t.get('subjects', []))}\n"
        slots_found = []
        for day in _DAY_ORDER:
            for slot in timetable.get("schedule", {}).get(day, []):
                instr = (
                    " ".join(slot.get("instructor", []))
                    if isinstance(slot.get("instructor"), list)
                    else str(slot.get("instructor", ""))
                )
                if t["name"].lower() in instr.lower():
                    slots_found.append(
                        f"• {day}, {_format_time_12h(slot['time'])} ({slot['course']} in {slot.get('room','?')})"
                    )
        if slots_found:
            res += "Schedule:\n" + "\n".join(slots_found) + "\n\n"
    return res.strip()


def _get_day_schedule(
    timetable: dict,
    day: str,
    *,
    time_after_min: Optional[int] = None,
    time_before_min: Optional[int] = None,
) -> str:
    """
    Return the schedule for a specific day, optionally filtered to a time window.
    Keyword-only `time_after_min` / `time_before_min` default to None so existing
    callers that don't pass them are unaffected.
    """
    all_slots = timetable.get("schedule", {}).get(day, [])

    if time_after_min is not None or time_before_min is not None:
        slots = [s for s in all_slots if _within_window(s.get("time", ""), time_after_min, time_before_min)]
    else:
        slots = all_slots

    if not slots:
        if time_after_min is not None:
            return f"No classes on {day} after {_min_to_12h(time_after_min)}."
        return f"No classes scheduled for {day}."

    res = f"📅 *{day} Schedule:*\n\n"
    for slot in sorted(slots, key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0):
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()


def _is_free(
    timetable: dict,
    day: str,
    time_after_min: Optional[int] = None,
    time_before_min: Optional[int] = None,
) -> str:
    """
    Answer a yes/no freedom question for a given day (and optional time window).
    Returns a formatted string suitable for direct use as a WhatsApp reply.
    """
    all_slots = timetable.get("schedule", {}).get(day, [])
    conflicts = [
        s for s in all_slots
        if _within_window(s.get("time", ""), time_after_min, time_before_min)
    ]

    if not conflicts:
        if time_after_min is not None:
            return f"✅ You're free on *{day}* after {_min_to_12h(time_after_min)}!"
        return f"✅ No classes on *{day}*! You're free."

    # Has classes — list them
    if time_after_min is not None:
        header = f"📅 You have {len(conflicts)} class(es) on *{day}* after {_min_to_12h(time_after_min)}:\n\n"
    else:
        header = f"📅 You have {len(conflicts)} class(es) on *{day}*:\n\n"

    res = header
    for slot in sorted(conflicts, key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0):
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()


def _get_full_timetable(timetable: dict) -> str:
    res = "📅 *Full Weekly Timetable:*\n\n"
    for day in _DAY_ORDER:
        slots = timetable.get("schedule", {}).get(day, [])
        if slots:
            res += f"*{day}*\n"
            for slot in sorted(slots, key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0):
                res += f"• {_format_time_12h(slot['time'])}: {slot['course']} ({slot.get('room','?')})\n"
            res += "\n"
    return res.strip()


def _build_teachers_from_timetable(timetable: dict) -> dict:
    """
    Derive teacher→courses mapping dynamically from the user's actual schedule.
    Returns a dict shaped like the old teachers.json so handlers work unchanged.
    """
    teachers: dict = {}
    for day, slots in timetable.get("schedule", {}).items():
        for slot in slots:
            instr = slot.get("instructor", "")
            course = slot.get("course", "")
            if isinstance(instr, list):
                instructors = instr
            else:
                instructors = [i.strip() for i in instr.split("/") if i.strip()]
            for name in instructors:
                if not name:
                    continue
                if name not in teachers:
                    teachers[name] = set()
                teachers[name].add(course)

    return {
        "teachers": [
            {"name": name, "subjects": sorted(subjects)}
            for name, subjects in teachers.items()
        ]
    }


# ── Structured entry (used by utils/nlu.execute) ─────────────────────────────

def retrieve_schedule_context_structured(request: dict, db, user_id: Optional[str]) -> dict:
    """
    Execute a structured schedule request (produced by nlu.understand) and return
    a grounded result dict:
        {"text": str, "data": dict | None, "no_timetable": bool}

    This is the NLU-path entry.  The legacy `retrieve_schedule_context(query, ...)` is
    retained unchanged so all existing callers (keyword path, tests) are unaffected.
    """
    ctx = get_user_academic_context(db, user_id)
    if ctx["status"] != STATUS_OK:
        return {
            "text": message_for_status(ctx["status"]),
            "data": None,
            "no_timetable": True,
        }

    timetable = {"schedule": ctx["schedule"]}
    courses = ctx["courses"]
    overrides = ctx.get("aliases", {})
    teachers_data = _build_teachers_from_timetable(timetable)

    query_type = request.get("query_type", "next_class")
    raw_course = request.get("course") or None
    raw_teacher = request.get("teacher") or None
    day_str = request.get("day") or None
    time_after_min: Optional[int] = request.get("time_after_min")
    time_before_min: Optional[int] = request.get("time_before_min")

    # Resolve logical day → actual weekday name
    resolved_day = _resolve_day(day_str)

    # Resolve course text → canonical course via dynamic matching
    target_course = match_course(raw_course, courses, overrides) if raw_course else None

    # Dispatch
    if query_type == "full_timetable":
        text = _get_full_timetable(timetable)

    elif query_type == "teacher":
        lookup_text = raw_teacher or raw_course or ""
        text = _get_teacher_info(teachers_data, timetable, lookup_text, target_course)

    elif query_type == "free_check":
        effective_day = resolved_day or _now_pkt().strftime("%A")
        text = _is_free(timetable, effective_day, time_after_min, time_before_min)

    elif query_type == "day_schedule":
        effective_day = resolved_day or _now_pkt().strftime("%A")
        text = _get_day_schedule(
            timetable, effective_day,
            time_after_min=time_after_min,
            time_before_min=time_before_min,
        )

    elif query_type == "course_schedule":
        if target_course:
            text = _get_course_schedule(timetable, target_course)
        else:
            text = (
                "I couldn't identify which course you mean. "
                "Try using the full name or a common abbreviation (e.g. 'CN', 'PDC')."
            )

    else:  # next_class (default)
        text = _get_next_class(
            timetable, target_course,
            time_after_min=time_after_min,
            time_before_min=time_before_min,
        )

    return {"text": text, "data": None, "no_timetable": False}


# ── Legacy entry (keyword-path and existing tests — unchanged) ────────────────

def retrieve_schedule_context(query: str, db=None, user_id: str = None) -> str:
    # Academic data comes only from the user's applicable timetable.
    ctx = get_user_academic_context(db, user_id)
    if ctx["status"] != STATUS_OK:
        # No silent static fallback — tell the user what to do.
        return message_for_status(ctx["status"])

    timetable = {"schedule": ctx["schedule"]}
    courses = ctx["courses"]
    overrides = ctx.get("aliases", {})

    # Teachers derived from the user's actual timetable (never a static file).
    teachers_data = _build_teachers_from_timetable(timetable)

    q = query.lower()
    q_clean = re.sub(r'[^a-z0-9\s]', ' ', q)

    # Resolve the query against the user's REAL courses (dynamic, deterministic).
    target_course = match_course(query, courses, overrides)

    teacher_kws = ["teach", "teaches", "teacher", "teaching", "instructor", "sir", "ma'am", "madam", "prof"]
    is_teacher_query = "who" in q_clean.split() or any(re.search(fr'\b{kw}\b', q_clean) for kw in teacher_kws)

    next_kws = ["next", "agle", "agli", "ongoing", "current", "now", "when", "class", "lecture"]
    is_next_class = any(re.search(fr'\b{kw}\b', q_clean) for kw in next_kws)

    full_schedule_phrases = ["show timetable", "full schedule", "weekly schedule", "all classes", "timetable", "schedule"]
    is_full_schedule = any(phrase in q for phrase in full_schedule_phrases)

    # Check for specific days robustly
    day_map = {d.lower(): d for d in _DAY_ORDER}
    mentioned_days = [day_map[w] for w in day_map if re.search(fr'\b{w}\b', q_clean)]

    if re.search(r'\b(today|aaj)\b', q_clean):
        today = _now_pkt().strftime("%A")
        if today in _DAY_ORDER:
            mentioned_days.append(today)
    if re.search(r'\b(tomorrow|kal)\b', q_clean):
        today = _now_pkt().strftime("%A")
        if today in _DAY_ORDER:
            idx = (_DAY_ORDER.index(today) + 1) % len(_DAY_ORDER)
            mentioned_days.append(_DAY_ORDER[idx])

    # ── Routing Logic ───────────────────────────────────────────────

    # A. Explicit Full Timetable
    if is_full_schedule:
        return _get_full_timetable(timetable)

    # B. Teacher query (Priority over next/day)
    if is_teacher_query:
        return _get_teacher_info(teachers_data, timetable, q, target_course)

    # C. Day specified (Priority over next class)
    if mentioned_days:
        res = []
        for d in set(mentioned_days):
            res.append(_get_day_schedule(timetable, d))
        return "\n\n".join(res)

    # D. "Next Class" (Triggered by 'when', 'class', 'next')
    if is_next_class:
        return _get_next_class(timetable, target_course)

    # E. Course only (e.g. "pdc") -> return full course schedule
    if target_course:
        return _get_course_schedule(timetable, target_course)

    # F. Fallback
    return (
        "I couldn't understand that schedule query. Try asking 'when is my next class', "
        "'who teaches <course>', or 'show my timetable'."
    )
