import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

def _find_data_dir() -> str:
    """
    Locate the data/ directory by checking multiple candidate paths.
    Works both locally (data lives outside duemate-backend/) and on
    Render (where only duemate-backend/ is deployed — data is inside it).
    """
    candidates = [
        # 1. data/ sitting next to this utils/ folder, inside the backend repo (PRODUCTION)
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data")),
        # 2. CWD/data — when app runs from the repo root
        os.path.abspath(os.path.join(os.getcwd(), "data")),
        # 3. data/ two levels up (local dev where data/ is at DueMate/data/)
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data")),
    ]
    for path in candidates:
        if os.path.isdir(path) and os.path.exists(os.path.join(path, "timetable.json")):
            return path
    # Fallback — will fail gracefully in _load()
    return candidates[0]

def _load(filename: str) -> dict:
    path = os.path.join(_find_data_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

# ── Course ID Architecture ──────────────────────────────────────────────────────
# Map unique IDs to all possible aliases, acronyms, and teacher names
_COURSE_MAPPINGS = {
    "aisd": ["ai driven", "aisd", "ai", "software development", "zia", "murtaza"],
    "pdc":  ["parallel", "distributed", "pdc", "computing", "ramisha", "sheheryar"],
    "cn":   ["computer networks", "cn", "networks", "dua mahmood", "dua", "asim"],
    "adbms":["advance database", "dbms", "adbms", "database", "asim", "mansha"],
    "toa":  ["automata", "toa", "theory of automata", "khawar", "iqbal"],
    "te":   ["entrepreneurship", "te", "tech", "techno", "technology", "zarmina"],
    "ps3":  ["problem solving", "ps3", "ps iii", "mateen"]
}

_DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_PKT = timezone(timedelta(hours=5))

def _now_pkt() -> datetime:
    return datetime.now(_PKT)

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

def _get_course_ids(text: str) -> list[str]:
    """Extract course IDs from any text (user query or timetable slot)."""
    text = text.lower()
    matched_ids = set()
    for cid, aliases in _COURSE_MAPPINGS.items():
        for alias in aliases:
            # Use regex boundaries for short aliases to prevent 'te' matching 'computer'
            if len(alias) <= 3:
                if re.search(fr'\b{re.escape(alias)}\b', text):
                    matched_ids.add(cid)
            else:
                if alias in text:
                    matched_ids.add(cid)
    return list(matched_ids)

def _format_slot(slot: dict, day: str) -> str:
    instructors = slot.get("instructor", "")
    if isinstance(instructors, list):
        instructors = " & ".join(instructors)
    return f"{slot['course']}\n{day}, {_format_time_12h(slot['time'])}\nRoom: {slot.get('room','?')}\nInstructor: {instructors}"

# ── Handlers ──────────────────────────────────────────────────────────────────

def _get_next_class(timetable: dict, target_ids: list[str]) -> str:
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
            slot_ids = _get_course_ids(slot.get("course", ""))
            if not target_ids or any(tid in slot_ids for tid in target_ids):
                valid_slots.append(slot)
                    
        # Sort by start time
        valid_slots.sort(key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0)
        
        for slot in valid_slots:
            start_min, end_min = _parse_slot_time(slot.get("time", ""))
            if start_min is None or end_min is None:
                continue
                
            if offset == 0:
                if end_min <= current_minutes:
                    continue # Passed
                if start_min <= current_minutes < end_min:
                    prefix = "Current class:" if not target_ids else f"Current {slot.get('course')} class:"
                    return f"*{prefix}*\n" + _format_slot(slot, day)
                
            prefix = "Next class:" if not target_ids else f"Next {slot.get('course')} class:"
            return f"*{prefix}*\n" + _format_slot(slot, day)
            
    return "No upcoming classes found. Please check your timetable mappings."

def _get_course_schedule(timetable: dict, target_ids: list[str]) -> str:
    schedule = timetable.get("schedule", {})
    found = []
    for day in _DAY_ORDER:
        for slot in schedule.get(day, []):
            slot_ids = _get_course_ids(slot.get("course", ""))
            if any(tid in slot_ids for tid in target_ids):
                found.append((day, slot))
                
    if not found:
        return "No classes found for this course. Please check the timetable."
        
    res = "📅 *Course Schedule:*\n\n"
    for day, slot in found:
        res += _format_slot(slot, day) + "\n\n"
    return res.strip()

def _get_teacher_info(teachers_data: dict, timetable: dict, query: str, target_ids: list[str]) -> str:
    teacher_list = teachers_data.get("teachers", [])
    q = query.lower()
    
    matched_teachers = []
    for t in teacher_list:
        name = t["name"].lower()
        if any(part in q for part in name.split() if len(part) > 2):
            matched_teachers.append(t)
            continue
            
        # Match by course ID
        t_subs = " ".join(t.get("subjects", []))
        t_ids = _get_course_ids(t_subs)
        if any(tid in t_ids for tid in target_ids):
            if t not in matched_teachers:
                matched_teachers.append(t)
                    
    if not matched_teachers:
        return "I couldn't find any instructors matching your query."
        
    res = ""
    for t in matched_teachers:
        res += f"👨‍🏫 *{t['name']}*\nTeaches: {', '.join(t.get('subjects', []))}\n"
        slots_found = []
        for day in _DAY_ORDER:
            for slot in timetable.get("schedule", {}).get(day, []):
                instr = " ".join(slot.get("instructor", [])) if isinstance(slot.get("instructor"), list) else str(slot.get("instructor", ""))
                if t["name"].lower() in instr.lower():
                    slots_found.append(f"• {day}, {_format_time_12h(slot['time'])} ({slot['course']} in {slot.get('room','?')})")
        if slots_found:
            res += "Schedule:\n" + "\n".join(slots_found) + "\n\n"
    return res.strip()

def _get_day_schedule(timetable: dict, day: str) -> str:
    slots = timetable.get("schedule", {}).get(day, [])
    if not slots:
        return f"No classes scheduled for {day}."
        
    res = f"📅 *{day} Schedule:*\n\n"
    for slot in sorted(slots, key=lambda s: _parse_slot_time(s.get("time", ""))[0] or 0):
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

# ── Main Entry ────────────────────────────────────────────────────────────────

def retrieve_schedule_context(query: str) -> str:
    timetable = _load("timetable.json")
    teachers_data = _load("teachers.json")
    
    q = query.lower()
    q_clean = re.sub(r'[^a-z0-9\s]', ' ', q)
    
    # 1. Extract intent constraints
    target_ids = _get_course_ids(q)
    
    teacher_kws = ["teach", "teaches", "teacher", "teaching", "instructor", "sir", "ma'am", "madam", "prof"]
    is_teacher_query = "who" in q_clean.split() or any(re.search(fr'\b{kw}\b', q_clean) for kw in teacher_kws)
    
    # Next class triggers: explicit next keywords, OR asking "when" without a specific day
    next_kws = ["next", "agle", "agli", "ongoing", "current", "now", "when", "class", "lecture"]
    is_next_class = any(re.search(fr'\b{kw}\b', q_clean) for kw in next_kws)
    
    full_schedule_phrases = ["show timetable", "full schedule", "weekly schedule", "all classes", "timetable", "schedule"]
    is_full_schedule = any(phrase in q for phrase in full_schedule_phrases)
    
    # Check for specific days robustly
    day_map = {d.lower(): d for d in _DAY_ORDER}
    mentioned_days = [day_map[w] for w in day_map if re.search(fr'\b{w}\b', q_clean)]
    
    if re.search(r'\b(today|aaj)\b', q_clean):
        today = _now_pkt().strftime("%A")
        if today in _DAY_ORDER: mentioned_days.append(today)
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
        return _get_teacher_info(teachers_data, timetable, q, target_ids)
        
    # C. Day specified (Priority over next class)
    # If they say "when is monday's class", return Monday schedule
    if mentioned_days:
        res = []
        for d in set(mentioned_days):
            res.append(_get_day_schedule(timetable, d))
        return "\n\n".join(res)
        
    # D. "Next Class" (Triggered by 'when', 'class', 'next')
    if is_next_class:
        return _get_next_class(timetable, target_ids)
        
    # E. Course only (e.g. "pdc") -> return full course schedule
    if target_ids:
        return _get_course_schedule(timetable, target_ids)
        
    # F. Fallback
    return "I couldn't understand that schedule query. Please try asking 'when is next class', 'who teaches pdc', or 'show timetable'."

