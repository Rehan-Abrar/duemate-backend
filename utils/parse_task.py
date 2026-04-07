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


def _build_groq_system_prompt(today: str) -> str:
    """Build the system prompt for Groq AI parsing."""
    return f"""You are a university assignment and quiz parser. Students send you WhatsApp messages from their subject-specific WhatsApp group chats in mixed English/Urdu/Hinglish. Your job is to extract structured data.

Rules:
- Extract ONLY what is explicitly stated. Do not invent or guess fields not present.
- "kal" = tomorrow, "parso" = day after tomorrow, "agla hafte" = next week, "is hafte" = this week, "agli class" = next class
- The course/subject name is embedded naturally in the message — not as a code, but as a full name written conversationally.
- Known courses and their common abbreviations/shorthands:
    * "AI-Driven Software Development" → aisd, ai driven, ai software
    * "Parallel & Distributed Computing" → pdc, parallel computing, distributed
    * "Technology Entrepreneurship" → te, tech ent, entrepreneurship
    * "Computer Networks" → cn, networks, computer network
    * "Advanced DBMS" → adbms, advanced db, dbms
    * "Theory of Automata" → toa, automata, theory of automata
- Extract the course by identifying which subject is being discussed. Return the full canonical name (e.g. "Computer Networks", not "cn" or "networks").
- If the subject truly cannot be inferred from the message, return null and flag needs_review.
- Do not guess the course if the message gives no subject context at all (e.g. "tomorrow is quiz" with zero other clues).
- Confidence should reflect how certain you are across all extracted fields, averaged.
- If due_date is relative (e.g. "tomorrow", "kal"), resolve it relative to today's date provided below.
- For quiz tasks, extract material (chapters, slides, topics), duration, and time if mentioned.
- Always return valid JSON and nothing else. No preamble, no markdown, no code fences.

Today's date: {today}

Examples:
- "computer network tomorrow class from YouTube video" → task_type: "quiz", course: "Computer Networks", due_date: tomorrow
- "PDC assignment submit karna hai friday tak" → task_type: "assignment", course: "Parallel & Distributed Computing", due_date: friday
- "kal TOA ka quiz hai chapter 3 aur 4 se" → task_type: "quiz", course: "Theory of Automata", quiz_material: "Chapter 3-4", due_date: tomorrow
- "tomorrow is quiz" → task_type: "quiz", course: null, needs_review: true
- "ADBMS assignment 2 due next week" → task_type: "assignment", course: "Advanced DBMS", title: "Assignment 2"

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


def _normalize_due_date(due_date_str: Optional[str]) -> Optional[datetime]:
    """
    Convert ISO date string to datetime, defaulting midnight to end of day.
    
    When Groq returns a date without a specific time (e.g., "2026-04-08T00:00:00"),
    students typically mean "by end of day", not "at midnight". This prevents
    tasks from appearing overdue at 12:01 AM.
    """
    if not due_date_str:
        return None
    try:
        dt = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
        # If no time was specified (midnight = Groq default), push to end of day
        if dt.hour == 0 and dt.minute == 0 and dt.second == 0:
            dt = dt.replace(hour=23, minute=59, second=0)
        # Ensure timezone awareness
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse due_date '{due_date_str}': {e}")
        return None


def _parse_with_groq(message_text: str) -> dict:
    """
    Parse task using Groq AI API.
    
    Returns standardized result dict with parse_method='groq' and groq_raw_response
    for debugging. Raises exception on API failure to trigger fallback.
    """
    if not HAS_REQUESTS:
        raise RuntimeError("requests library not available")
    
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        raise RuntimeError("GROQ_API_KEY not configured")
    
    today = _utc_now().strftime("%Y-%m-%d")
    system_prompt = _build_groq_system_prompt(today)
    
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Parse this message:\n\n{message_text}"}
        ],
        "temperature": 0.1,  # Low temperature for consistent parsing
        "max_tokens": 500,
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
    
    # Normalize and validate the parsed result
    task_type = str(parsed.get("task_type", "assignment")).lower()
    if task_type not in ("assignment", "quiz"):
        task_type = "assignment"
    
    course = parsed.get("course")
    if course and not isinstance(course, str):
        course = None
    
    title = parsed.get("title")
    if title and not isinstance(title, str):
        title = None
    
    due_date = _normalize_due_date(parsed.get("due_date"))
    
    confidence = parsed.get("confidence", 0.5)
    if not isinstance(confidence, (int, float)):
        confidence = 0.5
    confidence = max(0.0, min(1.0, float(confidence)))
    
    # Mark for review if confidence is low or course couldn't be determined
    needs_review = confidence < 0.8 or course is None
    
    return {
        "task_type": task_type,
        "course": course,
        "title": title,
        "due_date": due_date,
        "quiz_material": parsed.get("quiz_material") if task_type == "quiz" else None,
        "quiz_duration": parsed.get("quiz_duration") if task_type == "quiz" else None,
        "quiz_time": parsed.get("quiz_time") if task_type == "quiz" else None,
        "confidence": round(confidence, 2),
        "needs_review": needs_review,
        "notes": parsed.get("notes"),
        "parse_method": "groq",
        "groq_raw_response": data,  # Store full response for debugging
    }


def _parse_with_regex_fallback(message_text: str, course_hint: Optional[str] = None) -> dict:
    """
    Fallback parser using regex and dateparser.
    
    Used when Groq API is unavailable, rate-limited, or returns errors.
    Returns results with lower confidence and parse_method='regex_fallback'.
    """
    now = _utc_now()
    normalized = _normalize(message_text)

    task_type = detect_task_type(normalized)
    course = detect_course(normalized) or (course_hint.strip().upper() if course_hint else None)
    due_date = detect_due_date(normalized, now)
    title = extract_title(normalized, task_type, course)

    quiz_material = _detect_quiz_material(normalized) if task_type == "quiz" else None
    quiz_duration = _detect_quiz_duration(normalized) if task_type == "quiz" else None
    quiz_time = _detect_quiz_time(normalized) if task_type == "quiz" else None

    # Regex fallback gets lower confidence to encourage review
    confidence = _confidence(task_type, course, due_date, title)
    confidence = min(confidence, 0.6)  # Cap at 0.6 for fallback
    needs_review = True  # Always flag regex fallback for review

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
        "notes": "Parsed with regex fallback - AI parser unavailable",
        "parse_method": "regex_fallback",
        "groq_raw_response": None,
    }


def parse_task(message_text: str, course_hint: Optional[str] = None) -> dict:
    """
    Parse WhatsApp message into structured task details.
    
    Primary: Groq AI parser for intelligent extraction
    Fallback: Regex + dateparser when Groq is unavailable
    
    Always returns a dict with the standard schema. The 'parse_method' field
    indicates which parser was used ('groq' or 'regex_fallback').
    
    Args:
        message_text: Raw WhatsApp message content
        course_hint: Optional course code from source mapping
        
    Returns:
        Dict with task_type, course, title, due_date, quiz_*, confidence,
        needs_review, parse_method, and groq_raw_response (for debugging).
    """
    # Try Groq AI parser first
    try:
        result = _parse_with_groq(message_text)
        logger.info(f"Groq parser succeeded with confidence {result.get('confidence', 0):.2f}")
        return result
    except Exception as e:
        logger.warning(f"Groq parser failed: {e} — falling back to regex")
        return _parse_with_regex_fallback(message_text, course_hint)
