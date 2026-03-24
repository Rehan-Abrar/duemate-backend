"""Heuristic-first parser for extracting task details from WhatsApp text."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import dateparser
from dateparser.search import search_dates

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

SEMESTER_COURSES = [
    "AI-Driven Software Development",
    "Parallel & Distributed Computing",
    "Technology Entrepreneurship",
    "Computer Networks",
    "Advanced DBMS",
    "Theory of Automata",
]

COURSE_ALIASES = {
    "ai-driven software development": "AI-Driven Software Development",
    "ai driven software development": "AI-Driven Software Development",
    "aisd": "AI-Driven Software Development",
    "parallel & distributed computing": "Parallel & Distributed Computing",
    "parallel and distributed computing": "Parallel & Distributed Computing",
    "pdc": "Parallel & Distributed Computing",
    "technology entrepreneurship": "Technology Entrepreneurship",
    "te": "Technology Entrepreneurship",
    "computer networks": "Computer Networks",
    "cn": "Computer Networks",
    "advanced dbms": "Advanced DBMS",
    "adbms": "Advanced DBMS",
    "theory of automata": "Theory of Automata",
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
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _next_weekday(now: datetime, target_idx: int) -> datetime:
    days_ahead = target_idx - now.weekday()
    if days_ahead <= 0:
        days_ahead += 7
    return now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)


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

    code_match = COURSE_CODE_PATTERN.search(text)
    if code_match:
        return code_match.group(1).upper().replace(" ", "").replace("-", "")

    for token in re.findall(r"\b[A-Za-z]{2,8}\b", text):
        upper = token.upper()
        if upper in KNOWN_COURSE_TOKENS:
            return upper

    return None


def detect_due_date(text: str, now: datetime) -> Optional[datetime]:
    lower = text.lower()

    if "day after tomorrow" in lower:
        return now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=2)
    if any(token in lower for token in ["tomorrow", "tmr", "kal"]):
        return now.replace(hour=9, minute=0, second=0, microsecond=0) + timedelta(days=1)
    if "today" in lower:
        return now

    for day_name, day_idx in WEEKDAY_TO_INDEX.items():
        if re.search(rf"\b{day_name}\b", lower):
            return _next_weekday(now, day_idx)

    found_dates = search_dates(
        text,
        settings={
            "PREFER_DATES_FROM": "future",
            "TIMEZONE": "UTC",
            "TO_TIMEZONE": "UTC",
            "RETURN_AS_TIMEZONE_AWARE": True,
            "RELATIVE_BASE": now,
        },
    )
    if found_dates:
        for _, candidate in found_dates:
            if candidate and candidate.tzinfo:
                return candidate

    parsed = dateparser.parse(
        text,
        settings={
            "PREFER_DATES_FROM": "future",
            "TIMEZONE": "UTC",
            "TO_TIMEZONE": "UTC",
            "RETURN_AS_TIMEZONE_AWARE": True,
            "RELATIVE_BASE": now,
        },
    )
    if parsed:
        return parsed

    return None


def extract_title(text: str, task_type: str, course: Optional[str]) -> str:
    title = text

    if course:
        title = re.sub(re.escape(course), "", title, flags=re.IGNORECASE)

    for word in TASK_TYPE_KEYWORDS.get(task_type, []):
        title = re.sub(rf"\b{re.escape(word)}\b", "", title, flags=re.IGNORECASE)

    title = re.sub(r"\b(?:due|by|on|before|submit|submission|deadline|tomorrow|today)\b", "", title, flags=re.IGNORECASE)
    title = QUIZ_TIME_PATTERN.sub("", title)
    title = QUIZ_MATERIAL_PATTERN.sub("", title)
    title = re.sub(r"\b\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?\b", "", title)
    title = re.sub(r"[,;:|]+", " ", title)
    title = re.sub(r"\s+", " ", title).strip(" -")

    meaningful_tokens = [tok for tok in re.findall(r"\b[A-Za-z0-9]+\b", title) if tok.lower() not in TITLE_STOPWORDS]
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


def _confidence(task_type: str, course: Optional[str], due_date: Optional[datetime], title: str) -> float:
    score = 0.0
    if task_type:
        score += 0.2
    if course:
        score += 0.2
    if due_date:
        score += 0.45
    if title and len(title) > 6:
        score += 0.15

    # Penalize generic filler titles.
    if title.lower() in {"assignment", "quiz", "task", "deadline"}:
        score -= 0.1

    score = max(0.0, min(1.0, score))
    return round(score, 2)


def parse_task(message_text: str, course_hint: Optional[str] = None) -> dict:
    """Parse WhatsApp text into structured task details."""
    now = _utc_now()
    normalized = _normalize(message_text)

    task_type = detect_task_type(normalized)
    course = detect_course(normalized) or (course_hint.strip().upper() if course_hint else None)
    due_date = detect_due_date(normalized, now)
    title = extract_title(normalized, task_type, course)

    quiz_material = _detect_quiz_material(normalized) if task_type == "quiz" else None
    quiz_duration = _detect_quiz_duration(normalized) if task_type == "quiz" else None
    quiz_time = _detect_quiz_time(normalized) if task_type == "quiz" else None

    confidence = _confidence(task_type, course, due_date, title)
    needs_review = confidence < 0.8

    return {
        "task_type": task_type,
        "course": course,
        "title": title,
        "due_date": due_date,
        "quiz_material": quiz_material,
        "quiz_duration": quiz_duration,
        "quiz_time": quiz_time,
        "confidence": confidence,
        "needs_review": needs_review,
    }
