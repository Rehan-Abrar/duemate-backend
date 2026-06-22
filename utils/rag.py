"""
RAG (Retrieval-Augmented Generation) module for DueMate.

Loads timetable.json and teachers.json from the data/ directory and
returns a rich, structured context string for the LLM to answer
schedule-related questions accurately.

Key capabilities:
  - Teacher lookup: "who teaches PDC?"
  - Day schedule:   "what classes on Monday?"
  - Course lookup:  "when is ADBMS?" → all days/times for that course
  - Next class:     "when is my next class?" → time-aware (PKT)
  - Room lookup:    "where is CN lab?"
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

# ── Data loading ──────────────────────────────────────────────────────────────
_BASE_CANDIDATES = [
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data")),
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data")),
]

def _find_data_dir() -> str:
    for path in _BASE_CANDIDATES:
        if os.path.isdir(path):
            return path
    return _BASE_CANDIDATES[0]

def _load(filename: str) -> dict:
    path = os.path.join(_find_data_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# ── Alias table: short user keywords → canonical course name fragments ────────
_COURSE_ALIASES: dict[str, list[str]] = {
    "ai":             ["ai driven", "aisd", "zia", "murtaza"],
    "pdc":            ["parallel", "distributed", "pdc", "ramisha", "sheheryar"],
    "cn":             ["computer networks", "cn", "dua mahmood", "asim mansha", "networks lab"],
    "dbms":           ["database", "dbms", "adbms", "advance database", "asim mansha"],
    "automata":       ["automata", "toa", "khawar"],
    "entrepreneurship": ["entrepreneurship", "te", "tech ent", "zarmina"],
    "problem":        ["problem solving", "mateen", "ps3", "ps iii"],
}

_DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_PKT = timezone(timedelta(hours=5))


def _now_pkt() -> datetime:
    return datetime.now(_PKT)


def _parse_slot_start(time_str: str) -> Optional[int]:
    """Return slot start as minutes-since-midnight, or None."""
    try:
        start = time_str.split("-")[0].strip()
        h, m = start.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None


def _match_courses(query: str) -> list[str]:
    """Return list of alias keys whose keywords appear in the query."""
    q = query.lower()
    matched = []
    for key, keywords in _COURSE_ALIASES.items():
        if any(kw in q for kw in keywords):
            matched.append(key)
    return matched


def _course_matches_key(course_name: str, keys: list[str]) -> bool:
    cn = course_name.lower()
    for key in keys:
        for kw in _COURSE_ALIASES[key]:
            if kw in cn:
                return True
    return False


def _format_slot(slot: dict) -> str:
    instructors = slot.get("instructor", "")
    if isinstance(instructors, list):
        instructors = " & ".join(instructors)
    return f"  {slot['time']} | {slot['course']} | Room: {slot.get('room','?')} | {instructors}"


# ── Public retrieval function ─────────────────────────────────────────────────

def retrieve_schedule_context(query: str) -> str:
    """
    Entry point for the agent. Returns a rich, structured context string
    ready to be injected into the LLM system prompt.
    """
    timetable = _load("timetable.json")
    teachers_data = _load("teachers.json")
    schedule: dict[str, list] = timetable.get("schedule", {})
    teacher_list: list[dict] = teachers_data.get("teachers", [])

    q = query.lower()
    chunks: list[str] = []

    # ── Detect query type ─────────────────────────────────────────────────────
    is_teacher_query = any(w in q for w in ["who teach", "teaches", "teacher", "instructor", "sir", "ma'am", "madam", "ki class", "sahib"])
    is_next_class    = any(w in q for w in ["next class", "next lecture", "agle class", "agli class", "next session", "next slot"])
    is_today_query   = any(w in q for w in ["today", "aaj"])
    is_tomorrow_query = any(w in q for w in ["tomorrow", "kal", "parson"])
    is_room_query    = any(w in q for w in ["room", "where", "kahan", "lab", "location"])

    # Detect explicit days in query
    day_map = {d.lower(): d for d in _DAY_ORDER}
    mentioned_days = [day_map[w] for w in day_map if w in q]

    matched_keys = _match_courses(q)

    # ── 1. Teacher queries ────────────────────────────────────────────────────
    if is_teacher_query or (matched_keys and not is_next_class and not mentioned_days and not is_today_query):
        relevant = []
        for t in teacher_list:
            name = t["name"]
            subjects = t.get("subjects", [])
            # direct name mention
            if any(part.lower() in q for part in name.lower().split()):
                relevant.append(t)
                continue
            # matched via course alias
            if matched_keys and _course_matches_key(" ".join(subjects), matched_keys):
                relevant.append(t)
                continue
            # generic keyword overlap
            if any(sub.lower() in q or any(kw in sub.lower() for kw in q.split()) for sub in subjects):
                relevant.append(t)

        # Also pull timetable slots for those courses so we know days/times
        if relevant:
            teacher_block = "📋 *Teacher Information:*\n"
            for t in relevant:
                subs = ", ".join(t["subjects"])
                teacher_block += f"  • *{t['name']}* teaches: {subs}\n"

                # Find their schedule slots
                slots_found = []
                for day, slots in schedule.items():
                    for slot in slots:
                        instr = slot.get("instructor", "")
                        instr_str = " & ".join(instr) if isinstance(instr, list) else str(instr)
                        if t["name"].lower() in instr_str.lower():
                            slots_found.append(f"    - {day}: {slot['time']} | {slot['course']} | Room {slot.get('room','?')}")
                if slots_found:
                    teacher_block += "  📅 Schedule:\n" + "\n".join(slots_found) + "\n"
            chunks.append(teacher_block)

    # ── 2. Next class (time-aware) ────────────────────────────────────────────
    if is_next_class:
        now = _now_pkt()
        current_day_name = now.strftime("%A")
        current_minutes = now.hour * 60 + now.minute

        # Build an ordered list of (day, slot) tuples starting from today
        ordered = []
        day_index = _DAY_ORDER.index(current_day_name) if current_day_name in _DAY_ORDER else 0
        for offset in range(7):
            day = _DAY_ORDER[(day_index + offset) % len(_DAY_ORDER)]
            for slot in schedule.get(day, []):
                slot_start = _parse_slot_start(slot.get("time", ""))
                if slot_start is None:
                    continue
                # If it's today, only show future slots
                if offset == 0 and slot_start <= current_minutes:
                    continue
                ordered.append((day, slot))
            if ordered:
                break  # found next class on this day

        if ordered:
            block = f"⏰ *Next Upcoming Class* (current PKT time: {now.strftime('%H:%M on %A')}):\n"
            for day, slot in ordered[:3]:  # show up to 3 slots on next day
                block += _format_slot(slot) + f"  ({day})\n"
            chunks.append(block)
        else:
            chunks.append("No upcoming classes found for the rest of the week.")

    # ── 3. Specific day schedule ──────────────────────────────────────────────
    target_days = []
    if mentioned_days:
        target_days = mentioned_days
    elif is_today_query:
        now = _now_pkt()
        today = now.strftime("%A")
        if today in schedule:
            target_days = [today]
    elif is_tomorrow_query:
        now = _now_pkt()
        tomorrow_idx = (_DAY_ORDER.index(now.strftime("%A")) + 1) % len(_DAY_ORDER) if now.strftime("%A") in _DAY_ORDER else 0
        target_days = [_DAY_ORDER[tomorrow_idx]]

    if target_days:
        for day in target_days:
            day_slots = schedule.get(day, [])
            if not day_slots:
                chunks.append(f"No classes on *{day}*.")
                continue
            block = f"📅 *{day} Schedule:*\n"
            for slot in day_slots:
                block += _format_slot(slot) + "\n"
            chunks.append(block)

    # ── 4. Course-specific lookup (all days) ──────────────────────────────────
    if matched_keys and not is_teacher_query:
        course_slots: dict[str, list[str]] = {}
        for day, slots in schedule.items():
            for slot in slots:
                if _course_matches_key(slot.get("course", ""), matched_keys):
                    course_slots.setdefault(day, []).append(_format_slot(slot))

        if course_slots:
            block = "📚 *Matching Course Schedule:*\n"
            for day in _DAY_ORDER:
                if day in course_slots:
                    block += f"  *{day}:*\n" + "\n".join(course_slots[day]) + "\n"
            chunks.append(block)

    # ── 5. Fallback: send full timetable ─────────────────────────────────────
    if not chunks:
        full = "📅 *Full Weekly Timetable:*\n"
        for day in _DAY_ORDER:
            if day in schedule:
                full += f"\n*{day}:*\n"
                for slot in schedule[day]:
                    full += _format_slot(slot) + "\n"
        return full

    return "\n\n".join(chunks)
