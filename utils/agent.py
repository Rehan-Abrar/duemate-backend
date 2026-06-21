import json
import logging
import os
import requests
from datetime import datetime, timezone
from utils.rag import retrieve_schedule_context

logger = logging.getLogger(__name__)

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"

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

def classify_intent(message_text: str) -> str:
    """
    Classify the incoming WhatsApp message intent using Groq LLM.
    Returns: 'save_task', 'query_schedule', 'query_tasks', or 'greeting'
    """
    system_prompt = """You are an intent classification assistant for DueMate, a university WhatsApp bot.
Classify the user's message into one of these 4 intents:
1. 'save_task': User is announcing, submitting, or forwarding a new assignment, quiz, project, or sessional announcement to be saved.
   (e.g., "submit PDC assignment by friday", "kal Automata ka quiz hai", "CN project deadline 30 June", "assignent number 4 due on Monday")
2. 'query_schedule': User is asking questions about the university class schedule, timetables, course timings, classroom numbers, or instructors/teachers.
   (e.g., "when is CN lab?", "who teaches Automata?", "room of PDC lab?", "what class is at 11am on Wednesday?", "zia sahib ki class kab hai?")
3. 'query_tasks': User is asking about their saved tasks, list of assignments, upcoming tests, or sessional deadlines.
   (e.g., "what assignments do I have?", "show my pending tasks", "do I have any quiz tomorrow?", "mere complete sessional check karo")
4. 'greeting': User is saying hello, hi, salam, testing, or starting a simple chat.
   (e.g., "hi", "salam", "hello bot", "hey", "start")

Respond ONLY with a JSON object containing the 'intent' field and a brief 'reason' field.
JSON format: {"intent": "save_task" | "query_schedule" | "query_tasks" | "greeting", "reason": "why"}"""

    try:
        response_text = _call_groq(system_prompt, f"Message: {message_text}", json_format=True)
        result = json.loads(response_text)
        intent = result.get("intent", "save_task")
        if intent not in ("save_task", "query_schedule", "query_tasks", "greeting"):
            intent = "save_task"
        return intent
    except Exception as e:
        logger.warning(f"Intent classification failed: {e}. Defaulting to 'save_task'")
        return "save_task"

def handle_agent_query(db, user_id: str, phone: str, message_text: str, intent: str) -> str:
    """
    Runs the agent workflow based on intent, executes tools (RAG / DB search), and generates the final reply.
    """
    if intent == "greeting":
        return "Hey! 👋 I am your DueMate Assistant. You can:\n\n1. *Forward assignments/quizzes* to me and I will save them.\n2. Ask me about *deadlines* (e.g. \"what assignments do I have?\").\n3. Ask me about your *timetable & teachers* (e.g. \"when is PDC lab?\" or \"who teaches Automata?\")."

    elif intent == "query_schedule":
        # 1. Execute RAG Retrieval tool
        context = retrieve_schedule_context(message_text)
        
        # 2. Generate final answer with injected context
        system_prompt = f"""You are the DueMate Academic Assistant. Answer the student's question accurately using only the provided timetable and teacher context.
Keep your response short, conversational, and direct (max 3 sentences). Highlight rooms, times, and teacher names in bold.
If the information is not in the context, politely state you don't know.

Context:
{context}"""
        try:
            return _call_groq(system_prompt, f"Question: {message_text}")
        except Exception as e:
            logger.error(f"RAG generation failed: {e}")
            return "Sorry, I couldn't access the timetable right now. Please try again later."

    elif intent == "query_tasks":
        # 1. Execute DB Search tool
        tasks = list(db.tasks.find({"user_id": user_id, "status": "pending"}))
        
        if not tasks:
            return "You have no pending assignments or quizzes! Great job! 🎉"
            
        # 2. Format task list
        formatted_tasks = []
        for idx, t in enumerate(tasks, 1):
            course = t.get("parsed_course") or "Unknown Course"
            title = t.get("title") or t.get("parsed_title") or "Task"
            due_date = t.get("parsed_due_date")
            due_str = due_date.strftime("%d %B (%I:%M %p)") if due_date else "No due date"
            
            # Format nicely
            formatted_tasks.append(f"{idx}. *{course}*: {title} (Due: {due_str})")
            
        task_list_str = "\n".join(formatted_tasks)
        
        system_prompt = f"""You are the DueMate Assistant. Present the user's pending tasks back to them in a friendly, encouraging way.
Highlight deadlines and tell them they can view or edit these on their dashboard.

Tasks list:
{task_list_str}"""
        try:
            return _call_groq(system_prompt, "Show me my tasks.")
        except Exception as e:
            logger.error(f"Task query generation failed: {e}")
            return f"Here are your pending tasks:\n\n{task_list_str}\n\nCheck your dashboard for details!"

    return "I'm not sure how to handle that request. Please try again."
