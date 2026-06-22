import json
import os
import re
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

# ── Course Aliases ────────────────────────────────────────────────────────────
_COURSE_ALIASES = {
    "AI Driven Software Development": ["ai", "software", "development", "aisd", "zia", "murtaza", "ai driven"],
    "Parallel & Distributed Computing": ["pdc", "parallel", "distributed", "computing", "ramisha", "sheheryar"],
    "Computer Networks": ["cn", "networks", "computer", "dua mahmood", "dua", "asim", "networks lab"],
    "Advance Database Management Systems": ["dbms", "database", "adbms", "advance database", "asim", "mansha"],
    "Theory of Automata": ["automata", "toa", "khawar", "iqbal"],
    "Entrepreneurship": ["entrepreneurship", "te", "tech", "techno", "technology", "zarmina"],
    "Problem Solving III": ["problem", "solving", "mateen", "ps3", "ps iii"]
}

_DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_PKT = timezone(timedelta(hours=5))

def _now_pkt() -> datetime:
    return datetime.now(_PKT)

def _parse_slot_start(time_str: str) -> Optional[int]:
    """Return slot start as minutes-since-midnight."""
    try:
        start = time_str.split("-")[0].strip()
        h, m = start.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None

def _parse_slot_end(time_str: str) -> Optional[int]:
    """Return slot end as minutes-since-midnight."""
    try:
        end = time_str.split("-")[1].strip()
        h, m = end.split(":")
        return int(h) * 60 + int(m)
    except Exception:
        return None

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

def _resolve_courses(query: str) -> list[str]:
    """Return canonical course names based on keywords in query."""
    q = query.lower()
    # Replace punctuation
    q = re.sub(r'[^a-z0-9\s]', ' ', q)
    words = set(q.split())
    
    matched = set()
    for canonical, aliases in _COURSE_ALIASES.items():
        # Exact word match for short aliases (like "ai", "cn", "te")
        # Substring match for longer ones
        for alias in aliases:
            if len(alias) <= 3:
                if alias in words:
                    matched.add(canonical)
            else:
                if alias in q:
                    matched.add(canonical)
    return list(matched)

def _format_slot(slot: dict, day: str) -> str:
    instructors = slot.get("instructor", "")
    if isinstance(instructors, list):
        instructors = " & ".join(instructors)
    return f"{slot['course']}\n{day}, {_format_time_12h(slot['time'])}\nRoom: {slot.get('room','?')}\nInstructor: {instructors}"

# ── Handlers ──────────────────────────────────────────────────────────────────

def _get_next_class(timetable: dict, courses: list[str]) -> str:
    now = _now_pkt()
    current_day = now.strftime("%A")
    current_minutes = now.hour * 60 + now.minute
    
    schedule = timetable.get("schedule", {})
    day_index = _DAY_ORDER.index(current_day) if current_day in _DAY_ORDER else 0
    
    for offset in range(7):
        day = _DAY_ORDER[(day_index + offset) % len(_DAY_ORDER)]
        day_slots = schedule.get(day, [])
        
        # Filter slots by course if specified
        valid_slots = []
        for slot in day_slots:
            if not courses:
                valid_slots.append(slot)
            else:
                slot_course = slot.get("course", "").lower()
                if any(c.lower() in slot_course for c in courses):
                    valid_slots.append(slot)
                    
        # Sort by start time
        valid_slots.sort(key=lambda s: _parse_slot_start(s.get("time", "")) or 0)
        
        for slot in valid_slots:
            start_min = _parse_slot_start(slot.get("time", ""))
            end_min = _parse_slot_end(slot.get("time", ""))
            if start_min is None or end_min is None:
                continue
                
            if offset == 0:
                if end_min <= current_minutes:
                    continue # Already passed
                if start_min <= current_minutes < end_min:
                    # Class is currently ongoing
                    prefix = "Current class:" if not courses else f"Current {courses[0]} class:"
                    return f"*{prefix}*\n" + _format_slot(slot, day)
                
            prefix = "Next class:" if not courses else f"Next {courses[0]} class:"
            return f"*{prefix}*\n" + _format_slot(slot, day)
            
    if courses:
        return f"No upcoming classes found for {', '.join(courses)}."
    return "No upcoming classes found for the rest of the week."

def _get_course_schedule(timetable: dict, courses: list[str]) -> str:
    schedule = timetable.get("schedule", {})
    found = []
    for day in _DAY_ORDER:
        for slot in schedule.get(day, []):
            slot_course = slot.get("course", "").lower()
            if any(c.lower() in slot_course for c in courses):
                found.append((day, slot))
                
    if not found:
        return f"I couldn't find a class matching those courses."
        
    res = f"📅 *Schedule for {', '.join(courses)}:*\n\n"
    for day, slot in found:
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()

def _get_teacher_info(teachers_data: dict, timetable: dict, query: str, courses: list[str]) -> str:
    teacher_list = teachers_data.get("teachers", [])
    q = query.lower()
    
    matched_teachers = []
    for t in teacher_list:
        name = t["name"].lower()
        if any(part in q for part in name.split() if len(part) > 2):
            matched_teachers.append(t)
            continue
        
        # If we didn't match by name, see if we matched by course and they teach it
        for c in courses:
            if any(c.lower() in sub.lower() for sub in t.get("subjects", [])):
                if t not in matched_teachers:
                    matched_teachers.append(t)
                    
    if not matched_teachers:
        return "I couldn't find any instructors matching your query."
        
    res = ""
    for t in matched_teachers:
        res += f"👨‍🏫 *{t['name']}*\nTeaches: {', '.join(t.get('subjects', []))}\n"
        # Find their schedule
        slots_found = []
        for day in _DAY_ORDER:
            for slot in timetable.get("schedule", {}).get(day, []):
                instr = slot.get("instructor", "")
                instr_str = " & ".join(instr) if isinstance(instr, list) else str(instr)
                if t["name"].lower() in instr_str.lower():
                    slots_found.append(f"• {day}, {_format_time_12h(slot['time'])} ({slot['course']} in {slot.get('room','?')})")
        if slots_found:
            res += "Schedule:\n" + "\n".join(slots_found) + "\n\n"
    return res.strip()

def _get_day_schedule(timetable: dict, day: str) -> str:
    slots = timetable.get("schedule", {}).get(day, [])
    if not slots:
        return f"No classes scheduled for {day}."
        
    res = f"📅 *{day} Schedule:*\n\n"
    for slot in sorted(slots, key=lambda s: _parse_slot_start(s.get("time", "")) or 0):
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()

def _get_full_timetable(timetable: dict) -> str:
    res = "📅 *Full Weekly Timetable:*\n\n"
    for day in _DAY_ORDER:
        slots = timetable.get("schedule", {}).get(day, [])
        if slots:
            res += f"*{day}*\n"
            for slot in sorted(slots, key=lambda s: _parse_slot_start(s.get("time", "")) or 0):
                res += f"• {_format_time_12h(slot['time'])}: {slot['course']} ({slot.get('room','?')})\n"
            res += "\n"
    return res.strip()

# ── Main Entry ────────────────────────────────────────────────────────────────

def retrieve_schedule_context(query: str) -> str:
    timetable = _load("timetable.json")
    teachers_data = _load("teachers.json")
    
    q = query.lower()
    q_clean = re.sub(r'[^a-z0-9\s]', ' ', q)
    q_words = set(q_clean.split())
    courses = _resolve_courses(q)
    
    teacher_kws = {"teach", "teaches", "teacher", "teaching", "instructor", "sir", "ma'am", "madam", "prof"}
    is_teacher_query = "who" in q_words or any(kw in q_words for kw in teacher_kws)
    
    next_kws = {"next", "agle", "agli", "ongoing", "current", "now"}
    is_next_class = any(kw in q_words for kw in next_kws)
    
    full_schedule_phrases = ["show timetable", "full schedule", "weekly schedule", "all classes"]
    is_full_schedule = any(phrase in q for phrase in full_schedule_phrases)
    
    # Check for specific days robustly
    day_map = {d.lower(): d for d in _DAY_ORDER}
    mentioned_days = [day_map[w] for w in day_map if w in q_words]
    
    if "today" in q_words or "aaj" in q_words:
        today = _now_pkt().strftime("%A")
        if today in _DAY_ORDER: mentioned_days.append(today)
    if "tomorrow" in q_words or "kal" in q_words:
        today = _now_pkt().strftime("%A")
        if today in _DAY_ORDER:
            idx = (_DAY_ORDER.index(today) + 1) % len(_DAY_ORDER)
            mentioned_days.append(_DAY_ORDER[idx])
            
    # 1. Full timetable explicitly requested
    if is_full_schedule:
        return _get_full_timetable(timetable)
        
    # 2. Next class (with or without course)
    if is_next_class:
        return _get_next_class(timetable, courses)
        
    # 3. Teacher info
    if is_teacher_query:
        return _get_teacher_info(teachers_data, timetable, q, courses)
        
    # 4. Specific day
    if mentioned_days and not courses:
        res = []
        for d in set(mentioned_days):
            res.append(_get_day_schedule(timetable, d))
        return "\n\n".join(res)
        
    # 5. Specific course
    if courses:
        return _get_course_schedule(timetable, courses)
        
    # 6. Specific day fallback (if both day and course, course takes priority above, but we can combine if needed)
    if mentioned_days:
        res = []
        for d in set(mentioned_days):
            res.append(_get_day_schedule(timetable, d))
        return "\n\n".join(res)
        
    # Fallback if we really don't understand
    return "I couldn't find specific schedule information for your query. Try asking 'when is next class', 'who teaches PDC', or 'show timetable'."
