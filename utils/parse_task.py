"""
AI-powered task parser for extracting assignment/quiz details from WhatsApp messages.

Primary: Groq API (llama-3.3-70b-versatile) for intelligent parsing
Fallback: Regex + dateparser for offline/failure scenarios

The parser handles mixed English/Urdu/Hinglish messages commonly used by
Pakistani university students in WhatsApp groups.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import dateparser
from dateparser.search import search_dates

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger(__name__)

# Groq API configuration
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

COURSE_CODE_PATTERN = re.compile(r"\b([A-Z]{2,4}[-\s]?\d{2,4}[A-Z]?)\b", re.IGNORECASE)
KNOWN_COURSE_TOKENS = {
    "OOP",
    "DSA",
    "DBMS",
    "OS",
    "AI",
    "ML",
    "DL",
    "NLP",
    "CN",
    "SE",
    "HCI",
    "PF",
    "ITC",
    "MATH",
    "PHY",
    "CHEM",
    "CALC",
    "STAT",
}

# Canonical course names for current semester
SEMESTER_COURSES = [
    "AI-Driven Software Development",
    "Parallel & Distributed Computing",
    "Technology Entrepreneurship",
    "Computer Networks",
    "Advanced DBMS",
    "Theory of Automata",
]

# Map common abbreviations and variations to canonical names
COURSE_ALIASES = {
    "ai-driven software development": "AI-Driven Software Development",
    "ai driven software development": "AI-Driven Software Development",
    "ai driven": "AI-Driven Software Development",
    "ai software": "AI-Driven Software Development",
    "aisd": "AI-Driven Software Development",
    "parallel & distributed computing": "Parallel & Distributed Computing",
    "parallel and distributed computing": "Parallel & Distributed Computing",
    "parallel computing": "Parallel & Distributed Computing",
    "distributed": "Parallel & Distributed Computing",
    "pdc": "Parallel & Distributed Computing",
    "technology entrepreneurship": "Technology Entrepreneurship",
    "tech ent": "Technology Entrepreneurship",
    "entrepreneurship": "Technology Entrepreneurship",
    "te": "Technology Entrepreneurship",
    "computer networks": "Computer Networks",
    "computer network": "Computer Networks",
    "networks": "Computer Networks",
    "cn": "Computer Networks",
    "advanced dbms": "Advanced DBMS",
    "advanced db": "Advanced DBMS",
    "adbms": "Advanced DBMS",
    "dbms": "Advanced DBMS",
    "theory of automata": "Theory of Automata",
    "automata": "Theory of Automata",
    "toa": "Theory of Automata",
}

TASK_TYPE_KEYWORDS = {
    "quiz": ["quiz", "mcq", "viva", "oral test", "sessional"],
    "assignment": ["assignment", "asgn", "task", "homework", "hw", "project", "report"],
    "exam": ["exam", "midterm", "mid term", "final", "test"],
}

QUIZ_MATERIAL_PATTERN = re.compile(
    r"\b(?:chapter|chapters|ch|slides?|section|unit)\s*\d+(?:\s*[-to]{1,3}\s*\d+)?\b",
    re.IGNORECASE,
)
QUIZ_DURATION_PATTERN = re.compile(r"\b\d+\s*(?:hours?|hrs?|minutes?|mins?)\b", re.IGNORECASE)
QUIZ_TIME_PATTERN = re.compile(r"\b\d{1,2}(?::\d{2})?\s*(?:am|pm)\b", re.IGNORECASE)
WEEKDAY_TO_INDEX = {
    "monday": 0,
    "mon": 0,
    "tuesday": 1,
    "tue": 1,
    "tues": 1,
    "wednesday": 2,
    "wed": 2,
    "thursday": 3,
    "thu": 3,
    "thurs": 3,
    "friday": 4,
    "fri": 4,
    "saturday": 5,
    "sat": 5,
    "sunday": 6,
    "sun": 6,
}

NOISE_PREFIXES = [
    "forwarded",
    "fwd",
    "from:",
    "teacher:",
    "sir:",
    "madam:",
]

TITLE_STOPWORDS = {
    "for",
    "all",
    "is",
    "the",
    "a",
    "an",
    "to",
    "of",
    "and",
    "in",
    "at",
    "by",
    "this",
    "that",
    "here",
    "complete",
    "student",
    "need",
    "my",
    "office",
}

# Prepositions / common words that must not match as course codes (e.g. "on 22")
COURSE_CODE_STOPWORDS = {
    "ON", "AT", "BY", "IN", "OR", "TO", "MY", "IS", "AS", "AN", "AM", "PM",
    "NO", "SO", "UP", "IF", "IT", "WE", "HE", "BE", "DO", "GO", "OF", "US",
}

MONTH_NAME_TOKENS = {
    "JAN", "JANUARY", "FEB", "FEBRUARY", "MAR", "MARCH", "APR", "APRIL",
    "MAY", "JUN", "JUNE", "JUL", "JULY", "AUG", "AUGUST", "SEP", "SEPT",
    "SEPTEMBER", "OCT", "OCTOBER", "NOV", "NOVEMBER", "DEC", "DECEMBER",
}

NUMBERED_TASK_PATTERN = re.compile(
    r"\b(?P<label>assignment|asgn|homework|hw|lab|quiz|project|report|task)"
    r"(?:\s*(?:#|no\.?|number))?\s*(?P<num>\d+[a-z]?)\b",
    re.IGNORECASE,
)

TEXT_DATE_PATTERN = re.compile(
    r"\b\d{1,2}(?:st|nd|rd|th)?"
    r"\s+(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+\d{2,4}\b",
    re.IGNORECASE,
)

DATEPARSER_SETTINGS = {
    "PREFER_DATES_FROM": "future",
    "TIMEZONE": "UTC",
    "TO_TIMEZONE": "UTC",
    "RETURN_AS_TIMEZONE_AWARE": True,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _next_weekday(now: datetime, target_idx: int) -> datetime:
    days_ahead = target_idx - now.weekday()
    if days_ahead <= 0:
        days_ahead += 7
    return now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _dateparser_settings(now: datetime) -> dict:
    return {**DATEPARSER_SETTINGS, "RELATIVE_BASE": now}


def _is_valid_course_code_match(match: re.Match) -> bool:
    raw = match.group(1)
    letters = re.sub(r"[^A-Za-z]", "", raw.split()[0] if " " in raw else raw).upper()
    if len(letters) < 2 or letters in COURSE_CODE_STOPWORDS or letters in MONTH_NAME_TOKENS:
        return False
    if letters in KNOWN_COURSE_TOKENS:
        return True
    if " " in raw.strip():
        left = raw.strip().split()[0].upper()
        if left in COURSE_CODE_STOPWORDS or left in MONTH_NAME_TOKENS:
            return False
    normalized = raw.upper().replace(" ", "").replace("-", "")
    letter_prefix = re.match(r"^([A-Z]+)", normalized)
    if letter_prefix and letter_prefix.group(1) in MONTH_NAME_TOKENS:
        return False
    return bool(re.match(r"^[A-Z]{2,4}\d{2,4}[A-Z]?$", normalized))


def _parse_text_date(text: str, now: datetime) -> Optional[datetime]:
    match = TEXT_DATE_PATTERN.search(text)
    if not match:
        return None
    parsed = dateparser.parse(match.group(0), settings=_dateparser_settings(now))
    if not parsed or _is_suspicious_due_date(parsed, text, now):
        return None
    return _ensure_utc(parsed)


def _apply_explicit_time(text: str, dt: datetime, now: datetime) -> datetime:
    match = QUIZ_TIME_PATTERN.search(text)
    if not match:
        return dt
    parsed_time = dateparser.parse(
        match.group(0),
        settings=_dateparser_settings(now),
    )
    if not parsed_time:
        return dt
    parsed_time = _ensure_utc(parsed_time)
    return dt.replace(hour=parsed_time.hour, minute=parsed_time.minute, second=0, microsecond=0)


def _finalize_due_date(dt: datetime, now: datetime) -> datetime:
    dt = _ensure_utc(dt)
    if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
        dt = dt.replace(hour=23, minute=59, second=0, microsecond=0)
    return dt


def _is_suspicious_due_date(dt: datetime, text: str, now: datetime) -> bool:
    if dt.year < 2026:
        return True
    if dt.month == 1 and dt.day == 1:
        if not re.search(
            r"\b(?:jan(?:uary)?|1/1|01/01|1-1|jan\s*1)\b",
            text,
            re.IGNORECASE,
        ):
            return True
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if _ensure_utc(dt) < today_start:
        return True
    return False


def _dates_match(d1: Optional[datetime], d2: Optional[datetime], tolerance_hours: int = 36) -> bool:
    if d1 is None or d2 is None:
        return False
    delta = abs((_ensure_utc(d1) - _ensure_utc(d2)).total_seconds())
    return delta <= tolerance_hours * 3600


def _extract_numbered_title(text: str) -> Optional[str]:
    match = NUMBERED_TASK_PATTERN.search(text)
    if not match:
        return None
    label = match.group("label").lower()
    num = match.group("num")
    if label in {"asgn", "hw"}:
        label = "assignment" if label == "asgn" else "homework"
    return f"{label.title()} {num}"


def _normalize_course_value(course: Optional[str]) -> Optional[str]:
    if not course or not isinstance(course, str):
        return None
    cleaned = course.strip()
    if not cleaned or cleaned.lower() == "null":
        return None
    if cleaned in SEMESTER_COURSES:
        return cleaned
    for alias, canonical in COURSE_ALIASES.items():
        if cleaned.lower() == alias or cleaned == canonical:
            return canonical
    upper = cleaned.upper().replace(" ", "").replace("-", "")
    prefix_match = re.match(r"^([A-Z]+)", upper)
    if prefix_match and (
        prefix_match.group(1) in COURSE_CODE_STOPWORDS
        or prefix_match.group(1) in MONTH_NAME_TOKENS
    ):
        return None
    if upper in KNOWN_COURSE_TOKENS:
        return upper
    if re.match(r"^[A-Z]{2,4}\d{2,4}[A-Z]?$", upper):
        return upper
    return None


def _is_generic_title(title: Optional[str]) -> bool:
    if not title:
        return True
    return title.strip().lower() in {"assignment", "quiz", "task", "deadline", "exam"}


def _extract_deterministic_fields(
    message_text: str,
    course_hint: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict:
    now = now or _utc_now()
    normalized = _normalize(message_text)
    task_type = detect_task_type(normalized)
    course = detect_course(normalized)
    if course_hint and not course:
        hinted = _normalize_course_value(course_hint.strip())
        if hinted:
            course = hinted
    due_date = detect_due_date(normalized, now)
    title = extract_title(normalized, task_type, course)
    numbered = _extract_numbered_title(normalized)
    if numbered:
        title = numbered

    return {
        "task_type": task_type,
        "course": course,
        "title": title,
        "due_date": due_date,
        "quiz_material": _detect_quiz_material(normalized) if task_type == "quiz" else None,
        "quiz_duration": _detect_quiz_duration(normalized) if task_type == "quiz" else None,
        "quiz_time": _detect_quiz_time(normalized) if task_type == "quiz" else None,
        "normalized_text": normalized,
    }


def _reconcile_due_date(
    groq_date: Optional[datetime],
    det_date: Optional[datetime],
    text: str,
    now: datetime,
) -> tuple[Optional[datetime], list[str]]:
    notes: list[str] = []
    groq_ok = groq_date is not None and not _is_suspicious_due_date(groq_date, text, now)
    det_ok = det_date is not None

    if groq_ok and det_ok:
        if _dates_match(groq_date, det_date):
            if groq_date and det_date and groq_date.hour not in (0, 23) and det_date.hour in (23,):
                return groq_date, notes
            if det_date and det_date.hour not in (0, 23):
                return det_date, notes
            return groq_date, notes
        notes.append("date_mismatch_using_deterministic")
        return det_date, notes

    if det_ok:
        if groq_date is not None and not groq_ok:
            notes.append("groq_date_rejected")
        return det_date, notes

    if groq_ok:
        return groq_date, notes

    if groq_date is not None:
        notes.append("date_uncertain")
    return None, notes


def _reconcile_title(
    groq_title: Optional[str],
    det_title: Optional[str],
    text: str,
) -> Optional[str]:
    numbered = _extract_numbered_title(text)
    if numbered:
        return numbered
    if groq_title and not _is_generic_title(groq_title):
        return groq_title.strip()[:120]
    if det_title and not _is_generic_title(det_title):
        return det_title.strip()[:120]
    return groq_title or det_title


def _reconcile_course(
    groq_course: Optional[str],
    det_course: Optional[str],
) -> Optional[str]:
    groq_norm = _normalize_course_value(groq_course)
    det_norm = _normalize_course_value(det_course) if det_course else None
    if groq_norm and groq_norm in SEMESTER_COURSES:
        return groq_norm
    if det_norm:
        return det_norm
    return groq_norm


def _compute_parse_confidence(
    task_type: str,
    course: Optional[str],
    due_date: Optional[datetime],
    title: Optional[str],
    parse_method: str,
    date_notes: list[str],
    llm_confidence: float,
) -> float:
    score = 0.0
    if task_type:
        score += 0.15
    if course:
        score += 0.2
    if due_date:
        score += 0.4
        if "date_mismatch" not in " ".join(date_notes) and "groq_date_rejected" not in date_notes:
            score += 0.1
    if title and not _is_generic_title(title):
        score += 0.15
    if parse_method == "groq":
        score = max(score, min(llm_confidence, 0.85))
    else:
        score = min(score, 0.75)
    if "date_uncertain" in date_notes or due_date is None:
        score = min(score, 0.55)
    return round(max(0.0, min(1.0, score)), 2)


def _normalize(text: str) -> str:
    cleaned = (text or "").strip()
    cleaned = cleaned.replace("\r", "\n")
    cleaned = re.sub(r"\n+", "\n", cleaned)

    lines = []
    for raw_line in cleaned.split("\n"):
        line = raw_line.strip()
        if not line:
            continue
        low = line.lower()
        if any(low.startswith(prefix) for prefix in NOISE_PREFIXES):
            continue
        line = re.sub(r"^(?:>+|\*+|-+)+\s*", "", line)
        lines.append(line)

    compact = " ".join(lines)
    compact = re.sub(r"\s+", " ", compact).strip()

    # Common shorthand seen in student groups.
    compact = re.sub(r"\bsub\b", "submit", compact, flags=re.IGNORECASE)
    compact = re.sub(r"\btmr\b", "tomorrow", compact, flags=re.IGNORECASE)
    compact = re.sub(r"\bkal\b", "tomorrow", compact, flags=re.IGNORECASE)
    return compact


def detect_task_type(text: str) -> str:
    lower = text.lower()
    for task_type, keywords in TASK_TYPE_KEYWORDS.items():
        if any(re.search(rf"\b{re.escape(word)}\b", lower) for word in keywords):
            return task_type

    if any(token in lower for token in ["deadline", "submit", "due"]):
        return "assignment"

    return "assignment"


def detect_course(text: str) -> Optional[str]:
    lower = text.lower()
    for alias, canonical in COURSE_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lower):
            return canonical

    for match in COURSE_CODE_PATTERN.finditer(text):
        if _is_valid_course_code_match(match):
            return match.group(1).upper().replace(" ", "").replace("-", "")

    for token in re.findall(r"\b[A-Za-z]{2,8}\b", text):
        upper = token.upper()
        if upper in KNOWN_COURSE_TOKENS:
            return upper

    return None


def detect_due_date(text: str, now: datetime) -> Optional[datetime]:
    lower = text.lower()

    if "day after tomorrow" in lower:
        return _finalize_due_date(
            now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=2),
            now,
        )
    if any(token in lower for token in ["tomorrow", "tmr", "kal"]):
        return _finalize_due_date(
            now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=1),
            now,
        )
    if "today" in lower:
        return _finalize_due_date(now, now)

    for day_name, day_idx in WEEKDAY_TO_INDEX.items():
        if re.search(rf"\b{day_name}\b", lower):
            return _finalize_due_date(_next_weekday(now, day_idx), now)

    settings = _dateparser_settings(now)
    found_dates = search_dates(text, settings=settings)
    best: Optional[datetime] = None
    if found_dates:
        for _, candidate in found_dates:
            if not candidate:
                continue
            candidate = _ensure_utc(candidate)
            if _is_suspicious_due_date(candidate, text, now):
                continue
            if best is None or candidate > best:
                best = candidate

    if best is None:
        best = _parse_text_date(text, now)

    if best is None:
        parsed = dateparser.parse(text, settings=settings)
        if parsed and not _is_suspicious_due_date(parsed, text, now):
            best = _ensure_utc(parsed)

    if best is None:
        return None

    best = _apply_explicit_time(text, best, now)
    return _finalize_due_date(best, now)


def extract_title(text: str, task_type: str, course: Optional[str]) -> str:
    numbered = _extract_numbered_title(text)
    if numbered:
        return numbered[:120]

    title = text

    if course:
        title = re.sub(re.escape(course), "", title, flags=re.IGNORECASE)
        title = COURSE_CODE_PATTERN.sub("", title)

    for word in TASK_TYPE_KEYWORDS.get(task_type, []):
        title = re.sub(rf"\b{re.escape(word)}\b", "", title, flags=re.IGNORECASE)

    title = re.sub(
        r"\b(?:due|by|on|before|submit|submission|deadline|tomorrow|today)\b",
        "",
        title,
        flags=re.IGNORECASE,
    )
    title = QUIZ_TIME_PATTERN.sub("", title)
    title = QUIZ_MATERIAL_PATTERN.sub("", title)
    title = TEXT_DATE_PATTERN.sub("", title)
    title = re.sub(r"\b\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?\b", "", title)
    title = re.sub(r"[,;:|]+", " ", title)
    title = re.sub(r"\s+", " ", title).strip(" -")

    meaningful_tokens = [
        tok for tok in re.findall(r"\b[A-Za-z0-9]+\b", title)
        if tok.lower() not in TITLE_STOPWORDS
    ]
    if meaningful_tokens:
        title = " ".join(meaningful_tokens)
    else:
        title = ""

    if len(title) < 4:
        if course:
            title = f"{course} {task_type.title()}"
        else:
            title = task_type.title()

    return title[:120]


def _detect_quiz_material(text: str) -> Optional[str]:
    match = QUIZ_MATERIAL_PATTERN.search(text)
    return match.group(0) if match else None


def _detect_quiz_duration(text: str) -> Optional[str]:
    match = QUIZ_DURATION_PATTERN.search(text)
    return match.group(0) if match else None


def _detect_quiz_time(text: str) -> Optional[str]:
    match = QUIZ_TIME_PATTERN.search(text)
    return match.group(0) if match else None


def _build_groq_system_prompt(today: str) -> str:
    """Build the system prompt for Groq AI parsing."""
    return f"""You are a strict data extraction assistant parsing university assignments and quizzes from WhatsApp messages. 
Students send you messages in mixed English/Urdu/Hinglish. Your job is to extract structured data.

CRITICAL RULES:
- Extract ONLY what is explicitly stated or can be strongly inferred from context clues.
- DO NOT invent, hallucinate, or guess dates, titles, or courses if they aren't explicitly mentioned. 
- If a date is missing, return null for due_date. Never return "0001-01-01", "1970-01-01" or similar fallback dates.
- If the subject/course cannot be inferred, return null for course.
- If the title of the assignment/quiz is generic like "Lab 3" or "Assignment 4", extract it as the title. But do not invent a title if one isn't given.
- "kal" = tomorrow, "parso" = day after tomorrow, "agla hafte" = next week, "is hafte" = this week, "agli class" = next class
- The course/subject name is embedded naturally in the message — not as a code, but as a full name written conversationally.
- Known courses and their common abbreviations/shorthands:
    * "AI-Driven Software Development" → aisd, ai driven, ai software
    * "Parallel & Distributed Computing" → pdc, parallel computing, distributed
    * "Technology Entrepreneurship" → te, tech ent, entrepreneurship
    * "Computer Networks" → cn, networks, computer network
    * "Advanced DBMS" → adbms, advanced db, dbms
    * "Theory of Automata" → toa, automata, theory of automata
- Confidence should reflect how certain you are across all extracted fields. If you had to guess or leave fields empty (like course or due_date), set confidence low (< 0.6).
- If due_date is relative (e.g. "tomorrow", "kal"), resolve it relative to today's date provided below.
- Always return valid JSON and nothing else. No preamble, no markdown, no code fences.

Today's date: {today}

Examples:
- "computer network tomorrow class from YouTube video" → task_type: "quiz", course: "Computer Networks", due_date: tomorrow
- "PDC assignment submit karna hai friday tak" → task_type: "assignment", course: "Parallel & Distributed Computing", due_date: friday
- "kal TOA ka quiz hai chapter 3 aur 4 se" → task_type: "quiz", course: "Theory of Automata", quiz_material: "Chapter 3-4", due_date: tomorrow
- "tomorrow is quiz" → task_type: "quiz", course: null, due_date: tomorrow, confidence: 0.4, notes: "Missing course"
- "a assignment due on 1/1/19" → task_type: "assignment", course: null, due_date: "2019-01-01T23:59:00", confidence: 0.3, notes: "Past date and missing course"
- "Here is complete assignment 4, student need to submit on 22 June 2026 before 2PM in my office" → task_type: "assignment", title: "Assignment 4", course: null, due_date: "2026-06-22T14:00:00", confidence: 0.6, notes: "Missing course"

Return this exact JSON schema:
{{
  "task_type": "assignment" | "quiz",
  "course": "full canonical course name as listed above" | null,
  "title": "descriptive title inferred from message" | null,
  "due_date": "YYYY-MM-DDTHH:MM:SS" | null,
  "quiz_material": "e.g. Chapter 3-4, Slides 10-20" | null,
  "quiz_duration": "e.g. 2 hours" | null,
  "quiz_time": "HH:MM in 24h format" | null,
  "confidence": 0.0-1.0,
  "notes": "any ambiguity or uncertainty worth flagging"
}}"""


def _extract_json_from_response(raw: str) -> dict:
    """Extract JSON from Groq response, stripping markdown code fences if present."""
    # Strip markdown code fences: ```json ... ``` or ``` ... ```
    cleaned = re.sub(r'^```(?:json)?\s*', '', raw.strip())
    cleaned = re.sub(r'\s*```$', '', cleaned)
    return json.loads(cleaned)


def _normalize_due_date(
    due_date_str: Optional[str],
    text: str = "",
    now: Optional[datetime] = None,
) -> Optional[datetime]:
    """
    Convert ISO date string to datetime, defaulting midnight to end of day.

    When Groq returns a date without a specific time (e.g., "2026-04-08T00:00:00"),
    students typically mean "by end of day", not "at midnight". This prevents
    tasks from appearing overdue at 12:01 AM.
    """
    if not due_date_str:
        return None
    now = now or _utc_now()
    try:
        dt = datetime.fromisoformat(str(due_date_str).replace("Z", "+00:00"))
        dt = _ensure_utc(dt)

        if _is_suspicious_due_date(dt, text, now):
            return None

        if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
            dt = dt.replace(hour=23, minute=59, second=0, microsecond=0)
        return dt
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse due_date '{due_date_str}': {e}")
        return None


def _merge_parse_results(
    deterministic: dict,
    groq_result: Optional[dict],
    message_text: str,
    parse_method: str,
) -> dict:
    now = _utc_now()
    text = deterministic.get("normalized_text") or _normalize(message_text)
    date_notes: list[str] = []

    groq_date = None
    groq_title = None
    groq_course = None
    groq_confidence = 0.5
    groq_notes = None
    groq_raw = None
    task_type = deterministic["task_type"]
    quiz_material = deterministic.get("quiz_material")
    quiz_duration = deterministic.get("quiz_duration")
    quiz_time = deterministic.get("quiz_time")

    if groq_result:
        task_type = groq_result.get("task_type") or task_type
        if task_type not in ("assignment", "quiz"):
            task_type = "assignment"
        groq_date = groq_result.get("due_date")
        groq_title = groq_result.get("title")
        groq_course = groq_result.get("course")
        groq_confidence = groq_result.get("confidence", 0.5)
        groq_notes = groq_result.get("notes")
        groq_raw = groq_result.get("groq_raw_response")
        if task_type == "quiz":
            quiz_material = groq_result.get("quiz_material") or quiz_material
            quiz_duration = groq_result.get("quiz_duration") or quiz_duration
            quiz_time = groq_result.get("quiz_time") or quiz_time

    due_date, date_notes = _reconcile_due_date(
        groq_date,
        deterministic.get("due_date"),
        text,
        now,
    )
    title = _reconcile_title(groq_title, deterministic.get("title"), text)
    course = _reconcile_course(groq_course, deterministic.get("course"))

    confidence = _compute_parse_confidence(
        task_type,
        course,
        due_date,
        title,
        parse_method,
        date_notes,
        float(groq_confidence) if isinstance(groq_confidence, (int, float)) else 0.5,
    )

    notes_parts = [n for n in [groq_notes] if n]
    notes_parts.extend(date_notes)
    if parse_method == "regex_fallback":
        notes_parts.append("Parsed with regex fallback - AI parser unavailable")
    notes = "; ".join(dict.fromkeys(notes_parts)) if notes_parts else None

    date_uncertain = due_date is None or "date_uncertain" in date_notes or "groq_date_rejected" in date_notes
    needs_review = date_uncertain or _is_generic_title(title) or confidence < 0.7

    return {
        "task_type": task_type,
        "course": course,
        "title": title,
        "due_date": due_date,
        "quiz_material": quiz_material if task_type == "quiz" else None,
        "quiz_duration": quiz_duration if task_type == "quiz" else None,
        "quiz_time": quiz_time if task_type == "quiz" else None,
        "confidence": confidence,
        "needs_review": needs_review,
        "date_uncertain": date_uncertain,
        "notes": notes,
        "parse_method": parse_method,
        "groq_raw_response": groq_raw,
    }


def _parse_with_groq(
    message_text: str,
    normalized_text: str,
    now: datetime,
) -> dict:
    """
    Parse task using Groq AI API.

    Returns standardized result dict for merging with deterministic extraction.
    Raises exception on API failure to trigger fallback.
    """
    if not HAS_REQUESTS:
        raise RuntimeError("requests library not available")

    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        raise RuntimeError("GROQ_API_KEY not configured")

    today = now.strftime("%Y-%m-%d")
    system_prompt = _build_groq_system_prompt(today)

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Parse this message:\n\n{message_text}"},
        ],
        "temperature": 0.1,
        "max_tokens": 500,
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=15)
    response.raise_for_status()

    data = response.json()
    raw_content = data.get("choices", [{}])[0].get("message", {}).get("content", "")

    if not raw_content:
        raise ValueError("Empty response from Groq API")

    parsed = _extract_json_from_response(raw_content)

    task_type = str(parsed.get("task_type", "assignment")).lower()
    if task_type not in ("assignment", "quiz"):
        task_type = "assignment"

    course = parsed.get("course")
    if course and not isinstance(course, str):
        course = None
    elif course and course.lower() == "null":
        course = None

    title = parsed.get("title")
    if title and not isinstance(title, str):
        title = None
    elif title and title.lower() == "null":
        title = None

    due_date = _normalize_due_date(parsed.get("due_date"), normalized_text, now)

    confidence = parsed.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))

    return {
        "task_type": task_type,
        "course": course,
        "title": title,
        "due_date": due_date,
        "quiz_material": parsed.get("quiz_material") if task_type == "quiz" else None,
        "quiz_duration": parsed.get("quiz_duration") if task_type == "quiz" else None,
        "quiz_time": parsed.get("quiz_time") if task_type == "quiz" else None,
        "confidence": round(confidence, 2),
        "notes": parsed.get("notes"),
        "groq_raw_response": data,
    }


def _parse_with_regex_fallback(message_text: str, course_hint: Optional[str] = None) -> dict:
    """
    Fallback parser using regex and dateparser.

    Used when Groq API is unavailable, rate-limited, or returns errors.
    """
    deterministic = _extract_deterministic_fields(message_text, course_hint)
    return _merge_parse_results(deterministic, None, message_text, "regex_fallback")


def parse_task(message_text: str, course_hint: Optional[str] = None) -> dict:
    """
    Parse WhatsApp message into structured task details.

    Always runs deterministic extraction, optionally enriches with Groq, and
    reconciles both so dates/titles cannot silently drift.
    """
    now = _utc_now()
    deterministic = _extract_deterministic_fields(message_text, course_hint, now)

    groq_result = None
    parse_method = "regex_fallback"
    try:
        groq_result = _parse_with_groq(
            message_text,
            deterministic["normalized_text"],
            now,
        )
        parse_method = "groq"
        logger.info(
            "Groq parser succeeded with LLM confidence %.2f",
            groq_result.get("confidence", 0),
        )
    except Exception as e:
        logger.warning("Groq parser failed: %s — using deterministic extraction", e)

    result = _merge_parse_results(deterministic, groq_result, message_text, parse_method)
    logger.info(
        "Parse complete method=%s confidence=%.2f due=%s title=%r",
        result.get("parse_method"),
        result.get("confidence", 0),
        result.get("due_date"),
        result.get("title"),
    )
    return result
