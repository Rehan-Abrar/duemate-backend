"""
Shared academic-context layer for DueMate.

This is the SINGLE source of truth for a user's academic data (courses, schedule,
section, teachers, rooms). Every downstream feature (RAG chatbot, task parsing,
conversation menus, onboarding) should consume this instead of maintaining its own
hardcoded course/teacher mappings.

Resolution precedence (safest model — see docs/backend-audit-15-09-2026/08):
    1. Published + currently-effective OFFICIAL timetable for the user's section
       (official_timetables collection). Requires settings.university_id to be set,
       so a section label cannot collide across universities.
    2. Student self-uploaded timetable (user_timetables collection).
    3. No timetable.

It NEVER falls back to the static BSCS-6B data/timetable.json fixture. Academic facts
come only from the user's applicable timetable, never from an LLM or a hardcoded table.

Course matching is deterministic and derived from the user's ACTUAL courses:
    - per-user slang overrides (users.settings.course_aliases) win first,
    - then initialism (e.g. "pdc" for "Parallel & Distributed Computing"),
    - then token overlap ("parallel computing", "networks").
Ambiguous / unknown queries return None (handled gracefully by callers).
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

# ── Status codes ──────────────────────────────────────────────────────────────
STATUS_OK = "ok"
STATUS_NO_DB = "no_db"
STATUS_NO_TIMETABLE = "no_timetable"
STATUS_NO_SECTION = "no_section"
STATUS_EMPTY = "empty"
STATUS_UNKNOWN_SECTION = "unknown_section"

# Generic English structure words used only for tokenising course titles.
# These are NOT academic facts (no course/teacher/section names live here), so they
# are safe to keep as constants under the generalization rule.
_STOPWORDS = {
    "lab", "of", "and", "the", "a", "an", "for", "to", "in", "on",
    "i", "ii", "iii", "iv", "v", "&", "-",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ── Course-name helpers ─────────────────────────────────────────────────────────

def base_course(name: str) -> str:
    """'Parallel & Distributed Computing Lab' -> 'Parallel & Distributed Computing'."""
    return re.sub(r"\s+lab\s*$", "", (name or "").strip(), flags=re.IGNORECASE).strip()


def _tokens(text: str) -> set:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if t not in _STOPWORDS}


def _initialism(name: str) -> str:
    return "".join(
        w[0] for w in base_course(name).split() if w and w.lower() not in _STOPWORDS
    ).lower()


def match_course(query: str, courses, overrides: Optional[dict] = None) -> Optional[str]:
    """
    Resolve free text to ONE of the user's actual courses.

    Order: per-user override → initialism → token overlap (>= 0.5 of course tokens).
    Returns the canonical (base) course string, or None when nothing matches
    confidently (safe ambiguity handling — callers decide what to do with None).
    """
    if not courses:
        return None
    q = (query or "").lower()
    qtok = _tokens(query)
    overrides = overrides or {}

    # 1. per-user slang override wins (e.g. {"aisd": "AI Driven Software Development"})
    for alias, canonical in overrides.items():
        if alias and re.search(rf"\b{re.escape(str(alias).lower())}\b", q):
            return canonical

    # 2. initialism match (e.g. "pdc" -> "Parallel & Distributed Computing")
    for c in courses:
        ini = _initialism(c)
        if len(ini) >= 2 and re.search(rf"\b{re.escape(ini)}\b", q):
            return c

    # 3. token-overlap match (e.g. "parallel computing", "networks")
    best, best_score = None, 0.0
    for c in courses:
        ctok = _tokens(base_course(c))
        if not ctok:
            continue
        score = len(qtok & ctok) / len(ctok)
        if score > best_score:
            best, best_score = c, score
    return best if best_score >= 0.5 else None


def course_matches(slot_course: str, target_course: str) -> bool:
    """True if a timetable slot's course refers to the same course as target
    (treating 'X Lab' and 'X' as the same course)."""
    if not slot_course or not target_course:
        return False
    return base_course(slot_course).lower() == base_course(target_course).lower()


# ── Context building ────────────────────────────────────────────────────────────

def _build_context(
    status: str,
    source: Optional[str],
    section: Optional[str],
    slots: list,
    academic_term: Optional[str],
    timetable_version,
    overrides: dict,
) -> dict:
    schedule: dict = defaultdict(list)
    for s in slots or []:
        day = s.get("day")
        if day:
            schedule[day].append(s)

    courses = sorted({base_course(s.get("course", "")) for s in (slots or []) if s.get("course")})
    rooms = sorted({s.get("room", "") for s in (slots or []) if s.get("room")})

    return {
        "status": status,
        "source": source,                      # "official" | "self_upload" | None
        "section": section,
        "academic_term": academic_term,
        "timetable_version": timetable_version,
        "schedule": dict(schedule),
        "courses": courses,
        "rooms": rooms,
        "aliases": overrides or {},
        "has_timetable": status == STATUS_OK,
    }


def _empty_context(status: str, overrides: dict, section: Optional[str] = None) -> dict:
    return {
        "status": status,
        "source": None,
        "section": section,
        "academic_term": None,
        "timetable_version": None,
        "schedule": {},
        "courses": [],
        "rooms": [],
        "aliases": overrides or {},
        "has_timetable": False,
    }


def normalize_requested_section(raw: Optional[str]) -> Optional[str]:
    """
    Turn free text into a canonical section label using the PDF parser's
    section matcher (BSCS-7A, 'BSCS 7B', BSSE-7C, …). Returns None when the
    text does not contain a section token. Not a default-section fallback.
    """
    if not raw or not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    from utils.timetable_universal import _extract_sections_from_text, _norm_section

    found = list(dict.fromkeys(_extract_sections_from_text(text)))
    if found:
        return found[0]
    normalized = _norm_section(text)
    if re.fullmatch(
        r"(BSCS|BSSE|BSDS|BSIT|BSAI|BSCY|BSCGV|BSCOMP)-\d+[A-Z]?",
        normalized,
        re.I,
    ):
        return normalized
    return None


def get_published_section_context(db, section: str) -> dict:
    """
    Public official-only lookup for an explicit section label.

    Reads official_timetables only. Never reads users.settings, user_timetables,
    tasks, or any default section.
    """
    normalized = normalize_requested_section(section)
    if db is None:
        return _empty_context(STATUS_NO_DB, {}, section=normalized)
    if not normalized:
        return _empty_context(STATUS_UNKNOWN_SECTION, {}, section=None)

    now = _utc_now()
    doc = db.official_timetables.find_one(
        {
            "status": "published",
            "detected_sections": normalized,
            "effective_from": {"$lte": now},
            "$or": [{"effective_to": None}, {"effective_to": {"$gt": now}}],
        },
        sort=[("effective_from", -1), ("version", -1)],
    )
    if not doc:
        return _empty_context(STATUS_UNKNOWN_SECTION, {}, section=normalized)
    slots = (doc.get("sections") or {}).get(normalized, [])
    if not slots:
        return _empty_context(STATUS_UNKNOWN_SECTION, {}, section=normalized)
    return _build_context(
        STATUS_OK,
        "official",
        normalized,
        slots,
        doc.get("academic_term"),
        doc.get("version"),
        {},
    )


def load_course_overrides(db, user_id: str) -> dict:
    """Optional per-user slang map: users.settings.course_aliases = {alias: canonical}."""
    if db is None or not user_id:
        return {}
    user = db.users.find_one({"user_id": user_id}, {"settings.course_aliases": 1}) or {}
    aliases = ((user.get("settings") or {}).get("course_aliases")) or {}
    return aliases if isinstance(aliases, dict) else {}


def resolve_official_timetable(db, user_id: str, overrides: Optional[dict] = None) -> Optional[dict]:
    """
    Return the academic context sourced from the currently published + effective
    OFFICIAL timetable for the user's section, or None if not applicable.

    Guarded on settings.university_id so a bare section label (e.g. 'BSCS-6B')
    cannot collide across universities. academic_term further narrows when present.
    """
    if db is None or not user_id:
        return None
    user = db.users.find_one({"user_id": user_id}, {"settings": 1}) or {}
    settings = user.get("settings") or {}
    section = settings.get("timetable_section")
    university_id = settings.get("university_id")
    if not section or not university_id:
        return None

    now = _utc_now()
    query = {
        "status": "published",
        "university_id": university_id,
        "detected_sections": section,
        "effective_from": {"$lte": now},
        "$or": [{"effective_to": None}, {"effective_to": {"$gt": now}}],
    }
    academic_term = settings.get("academic_term")
    if academic_term:
        query["academic_term"] = academic_term

    doc = db.official_timetables.find_one(
        query, sort=[("effective_from", -1), ("version", -1)]
    )
    if not doc:
        return None
    slots = (doc.get("sections") or {}).get(section, [])
    if not slots:
        return None
    return _build_context(
        STATUS_OK,
        "official",
        section,
        slots,
        doc.get("academic_term"),
        doc.get("version"),
        overrides or {},
    )


def get_user_academic_context(db, user_id: str) -> dict:
    """
    Single entry point. Returns the user's academic context following the
    official → self-upload → none precedence. Never returns BSCS-6B fallback data.
    """
    if db is None or not user_id:
        return _empty_context(STATUS_NO_DB, {})

    overrides = load_course_overrides(db, user_id)

    # 1. Official published timetable (if the user is section-associated).
    official = resolve_official_timetable(db, user_id, overrides)
    if official is not None:
        return official

    # 2. Student self-uploaded timetable.
    doc = db.user_timetables.find_one({"user_id": user_id})
    if not doc:
        return _empty_context(STATUS_NO_TIMETABLE, overrides)
    if not doc.get("selected_section"):
        return _empty_context(STATUS_NO_SECTION, overrides)

    section = doc["selected_section"]
    slots = (doc.get("sections") or {}).get(section, [])
    if not slots:
        return _empty_context(STATUS_EMPTY, overrides, section=section)

    return _build_context(STATUS_OK, "self_upload", section, slots, None, None, overrides)


# ── User-facing status messages (no silent static fallback) ──────────────────────

NO_TIMETABLE_MESSAGES = {
    STATUS_NO_DB: "I'm having trouble reaching the database right now. Please try again shortly.",
    STATUS_NO_TIMETABLE: (
        "I don't have your timetable yet. Upload it (or pick your section) from the "
        "dashboard and I'll be able to answer schedule questions."
    ),
    STATUS_NO_SECTION: (
        "You've uploaded a timetable but haven't selected your section yet. "
        "Please pick your section in the dashboard first."
    ),
    STATUS_EMPTY: (
        "Your selected section doesn't have any classes yet. Try re-uploading your "
        "timetable or selecting a different section."
    ),
}


def message_for_status(status: str, section: Optional[str] = None) -> str:
    if status == STATUS_UNKNOWN_SECTION:
        if section:
            return f"I couldn't find a published timetable for {section}."
        return "I couldn't find a published timetable for that section."
    return NO_TIMETABLE_MESSAGES.get(
        status, "I don't have your timetable yet. Please set it up from the dashboard."
    )
