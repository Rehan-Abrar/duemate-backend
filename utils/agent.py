"""
Agent module for DueMate.

Intent Classification flow:
  1. Deterministic pre-filter (no API call, instant):
     - Hard-match greetings → return 'greeting'
     - Hard-match schedule keywords → return 'query_schedule'
     - Hard-match task-asking keywords → return 'query_tasks'
     - MUST contain at least one task-trigger word to proceed to LLM
  2. LLM classifier (Groq) — only called when deterministic is ambiguous
     and the message actually looks task-like.

This ensures "hi", "who teaches pdc", etc. NEVER get saved as tasks
even if the Groq API is down or rate-limited.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from utils.rag import retrieve_schedule_context

logger = logging.getLogger(__name__)

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
_PKT = timezone(timedelta(hours=5))

# ── Deterministic keyword sets ────────────────────────────────────────────────

# These words in the message → definite GREETING (no further processing)
_GREETING_EXACT = {
    "hi", "hello", "hey", "salam", "assalam", "assalamualaikum", "helo",
    "hola", "yo", "sup", "start", "test", "ping", "k", "ok", "okay",
    "thanks", "thank you", "shukriya", "jazakallah", "nice", "good",
    "acha", "theek", "thx", "ty",
}

# These PATTERNS in the message → definite GREETING
_GREETING_PATTERNS = [
    r"^hi+$", r"^he+y+$", r"^hello+$", r"^(as)?salam\w*$",
    r"^good\s?(morning|evening|afternoon|night)$",
    r"^how\s?are\s?you", r"^kya haal", r"^kaise ho",
]

# Words that MUST be present for a message to be a task → save_task
_TASK_TRIGGER_WORDS = {
    "assignment", "homework", "quiz", "lab", "project", "viva",
    "submit", "submission", "due", "deadline", "remind", "sessional",
    "exam", "test", "mids", "midterm", "final", "presentation",
    "report", "task", "jama", "submit karna", "karwana", "bhejni",
}

# Keywords that signal the user is ASKING about their saved tasks
_MY_TASKS_WORDS = {
    "my tasks", "my assignments", "my quiz", "mere tasks", "mere assignments",
    "pending tasks", "pending assignments", "what do i have", "show my",
    "list my", "kya karna", "kitne", "how many tasks", "upcoming tasks",
    "due today", "due tomorrow",
    # 'what X do i have' patterns
    "do i have", "kya hai mere", "assignments do i", "quizzes do i",
    "tasks do i", "what homework", "what quiz", "what assignment",
}

# Keywords that signal a schedule / timetable question
_SCHEDULE_WORDS = {
    "who teaches", "who is the teacher", "teacher", "instructor", "teaches",
    "sir", "ma'am", "madam", "prof", "professor", "lecture", "class",
    "timetable", "schedule", "timing", "when is", "where is", "room",
    "lab room", "next class", "today class", "what time", "kab hai",
    "kahan hai", "which room", "agli class", "agle class", "aaj class",
    "pdc class", "cn class", "ai class", "dbms class", "toa class",
    "automata class", "entrepreneurship class",
}

# Course/teacher names that strongly signal a schedule question
_SCHEDULE_ENTITY_PATTERNS = [
    r"\bwho\b.*(teach|sir|madam|prof|instructor)",
    r"\bwhen\b.*(class|lecture|lab|session)",
    r"\bwhere\b.*(class|lab|room)",
    r"\b(pdc|cn|adbms|toa|aisd|te)\b.*(class|teacher|room|time|when|where)",
    r"\b(teaches?|instructor)\b",
    r"next class",
    r"(aaj|kal|monday|tuesday|wednesday|thursday|friday).*(class|schedule)",
]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _is_greeting(text: str) -> bool:
    t = _normalize(text)
    # Exact single-word or very short match
    words = t.split()
    if len(words) <= 2 and all(w in _GREETING_EXACT for w in words):
        return True
    # Pattern match
    for pattern in _GREETING_PATTERNS:
        if re.match(pattern, t):
            return True
    return False


def _is_schedule_query(text: str) -> bool:
    t = _normalize(text)
    # Keyword match
    if any(kw in t for kw in _SCHEDULE_WORDS):
        return True
    # Regex entity patterns
    for pattern in _SCHEDULE_ENTITY_PATTERNS:
        if re.search(pattern, t):
            return True
    return False


def _is_my_tasks_query(text: str) -> bool:
    t = _normalize(text)
    return any(kw in t for kw in _MY_TASKS_WORDS)


def _has_task_trigger(text: str) -> bool:
    t = _normalize(text)
    return any(kw in t for kw in _TASK_TRIGGER_WORDS)


# ── Groq API helpers ──────────────────────────────────────────────────────────

def _call_groq(system_prompt: str, user_prompt: str, json_format: bool = False) -> str:
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        raise RuntimeError("GROQ_API_KEY not configured")

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 400,
    }
    if json_format:
        payload["response_format"] = {"type": "json_object"}

    headers = {
        "Authorization": f"Bearer {groq_api_key}",
        "Content-Type": "application/json",
    }
    response = requests.post(GROQ_API_URL, json=payload, headers=headers, timeout=15)
    response.raise_for_status()
    data = response.json()
    return data.get("choices", [{}])[0].get("message", {}).get("content", "")


# ── Public: classify_intent ───────────────────────────────────────────────────

def classify_intent(message_text: str) -> str:
    """
    Classify incoming WhatsApp message intent.
    Returns: 'save_task' | 'query_schedule' | 'query_tasks' | 'greeting'

    Priority order:
      1. Deterministic pre-filter (instant, no API call)
      2. LLM classifier (only if message looks task-like AND is ambiguous)
    """
    # ── STEP 1: Deterministic pre-filter ─────────────────────────────────────
    if _is_greeting(message_text):
        logger.info("deterministic_intent: greeting text=%r", message_text[:50])
        return "greeting"

    if _is_schedule_query(message_text):
        logger.info("deterministic_intent: query_schedule text=%r", message_text[:50])
        return "query_schedule"

    if _is_my_tasks_query(message_text):
        logger.info("deterministic_intent: query_tasks text=%r", message_text[:50])
        return "query_tasks"

    # If no task-trigger word at all, it's very unlikely to be a task.
    # Treat as a schedule query so it goes to the agent (which can explain
    # it doesn't understand) rather than silently saving garbage to the DB.
    if not _has_task_trigger(message_text):
        logger.info("deterministic_intent: no_task_trigger → query_schedule text=%r", message_text[:50])
        return "query_schedule"

    # ── STEP 2: LLM classifier (only for ambiguous task-like messages) ────────
    system_prompt = (
        "You are an intent classifier for DueMate, a university WhatsApp task-saving bot.\n"
        "Classify the message into exactly one intent:\n"
        "  save_task     – user is sharing a new assignment, quiz, project, or deadline to be saved\n"
        "  query_schedule – user is asking about class times, rooms, teachers, or timetable\n"
        "  query_tasks   – user is asking about their already-saved tasks or upcoming deadlines\n"
        "  greeting      – casual chat, hello, test, acknowledgement\n\n"
        "Rules:\n"
        "  - A message that has 'who teaches', 'when is class', 'room', 'teacher' → query_schedule\n"
        "  - A message that is just 'hi', 'hello', 'salam', 'thanks' → greeting\n"
        "  - ONLY classify as save_task when the user is clearly announcing a deadline to be recorded.\n"
        "Respond ONLY with JSON: {\"intent\": \"...\", \"reason\": \"...\"}"
    )

    try:
        response_text = _call_groq(system_prompt, f"Message: {message_text}", json_format=True)
        result = json.loads(response_text)
        intent = result.get("intent", "save_task")
        if intent not in ("save_task", "query_schedule", "query_tasks", "greeting"):
            intent = "save_task"
        logger.info("llm_intent: %s reason=%s", intent, result.get("reason", ""))
        return intent
    except Exception as e:
        # If LLM fails AND we know there's a task trigger word, save the task
        logger.warning("LLM intent classification failed: %s — falling back to save_task", e)
        return "save_task"


# ── Public: handle_agent_query ────────────────────────────────────────────────

def handle_agent_query(db, user_id: str, phone: str, message_text: str, intent: str) -> str:
    """
    Execute the appropriate tool and generate a reply based on intent.
    """
    # ── GREETING ──────────────────────────────────────────────────────────────
    if intent == "greeting":
        return (
            "Hey! 👋 I'm your *DueMate Assistant*. Here's what you can do:\n\n"
            "📌 *Save tasks* — just forward or type an assignment/quiz announcement\n"
            "📅 *Ask about your timetable* — e.g. _\"when is PDC class?\"_ or _\"who teaches CN?\"_\n"
            "📋 *Check your tasks* — e.g. _\"what assignments do I have?\"_\n\n"
            "Try sending an assignment announcement to get started!"
        )

    # ── SCHEDULE QUERY (RAG) ──────────────────────────────────────────────────
    elif intent == "query_schedule":
        now_pkt = datetime.now(_PKT)
        context = retrieve_schedule_context(message_text)

        system_prompt = (
            f"You are the DueMate Academic Assistant. The current Pakistan Standard Time is "
            f"{now_pkt.strftime('%I:%M %p on %A, %d %B %Y')}.\n\n"
            "Answer the student's question concisely and accurately using ONLY the provided context.\n"
            "Format your reply for WhatsApp: use *bold* for names and times, keep it under 5 lines.\n"
            "If teacher names are listed, always name ALL of them.\n"
            "If the information is not in the context, say so politely.\n\n"
            f"Context:\n{context}"
        )
        try:
            return _call_groq(system_prompt, f"Question: {message_text}")
        except Exception as e:
            logger.error("RAG generation failed: %s", e)
            # Return raw context as fallback so the user still gets an answer
            return f"Here's what I found:\n\n{context}"

    # ── MY TASKS QUERY (DB) ───────────────────────────────────────────────────
    elif intent == "query_tasks":
        tasks = list(db.tasks.find({"user_id": user_id, "status": "pending"}))

        if not tasks:
            return "You have no pending assignments or quizzes! Great job! 🎉"

        now_pkt = datetime.now(_PKT)
        formatted = []
        for idx, t in enumerate(tasks, 1):
            course = t.get("parsed_course") or "Unknown Course"
            title = t.get("parsed_title") or "Task"
            due = t.get("parsed_due_date")
            if due:
                # Convert UTC → PKT for display
                if due.tzinfo:
                    due_pkt = due.astimezone(_PKT)
                else:
                    due_pkt = due
                due_str = due_pkt.strftime("%d %b at %I:%M %p")
            else:
                due_str = "No due date"
            formatted.append(f"{idx}. *{course}*: {title} — Due: {due_str}")

        task_list = "\n".join(formatted)
        system_prompt = (
            "You are the DueMate Assistant. Present the following pending tasks to the student "
            "in a warm, encouraging WhatsApp message. Mention the dashboard for details. "
            "Keep it short.\n\nTasks:\n" + task_list
        )
        try:
            return _call_groq(system_prompt, "Show my tasks.")
        except Exception:
            return f"📋 *Your Pending Tasks:*\n\n{task_list}\n\nView & edit them on your dashboard!"

    return "I'm not sure how to help with that. Try asking about your timetable or assignments!"
