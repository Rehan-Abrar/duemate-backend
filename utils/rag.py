import json
import os
import re
from typing import Optional

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

def load_json_file(filename: str) -> dict:
    filepath = os.path.join(DATA_DIR, filename)
    if not os.path.exists(filepath):
        # Fallback if inside duemate-backend
        filepath = os.path.join(os.path.dirname(__file__), "..", "data", filename)
        if not os.path.exists(filepath):
            return {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def retrieve_schedule_context(query: str) -> str:
    """
    RAG Retrieval: Extracts relevant sections of timetable and teachers based on query keywords.
    """
    timetable = load_json_file("timetable.json")
    teachers = load_json_file("teachers.json")
    
    query_lower = query.lower()
    
    # Days of the week keywords
    days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
    matched_days = [day for day in days if day in query_lower]
    
    # Course alias mappings to help match short queries
    course_keywords = {
        "ai": ["ai", "software", "development", "aisd", "murtaza"],
        "pdc": ["pdc", "parallel", "distributed", "computing", "ramisha", "sheheryar"],
        "cn": ["cn", "networks", "computer", "dua", "asim"],
        "dbms": ["dbms", "database", "database", "adbms", "asim"],
        "automata": ["automata", "toa", "khawar"],
        "entrepreneurship": ["entrepreneurship", "te", "tech", "ent", "zarmina"],
        "problem": ["problem", "solving", "mateen"]
    }
    
    matched_courses = []
    for course_key, keywords in course_keywords.items():
        if any(kw in query_lower for kw in keywords):
            matched_courses.append(course_key)
            
    context_chunks = []
    
    # 1. Retrieve teacher info
    teacher_list = teachers.get("teachers", [])
    relevant_teachers = []
    for t in teacher_list:
        name = t.get("name", "")
        subjects = t.get("subjects", [])
        # If query asks about a teacher directly or a course they teach
        if name.lower() in query_lower or any(any(kw in sub.lower() for kw in query_lower.split()) for sub in subjects):
            relevant_teachers.append(t)
        # Or if we matched the course key
        else:
            for course_key in matched_courses:
                for sub in subjects:
                    if course_key in sub.lower() or (course_key == "ai" and "ai" in sub.lower()):
                        if t not in relevant_teachers:
                            relevant_teachers.append(t)
                            
    if relevant_teachers:
        context_chunks.append("### Matched Instructor Info:\n" + json.dumps(relevant_teachers, indent=2))
        
    # 2. Retrieve timetable entries
    schedule = timetable.get("schedule", {})
    relevant_schedule = {}
    
    # If the user specifically queried a day, grab that whole day's schedule
    for day in matched_days:
        title_day = day.capitalize()
        if title_day in schedule:
            relevant_schedule[title_day] = schedule[title_day]
            
    # Also filter slots across other days that match the course keywords
    for day, slots in schedule.items():
        if day in relevant_schedule:
            continue # already added
        matching_slots = []
        for slot in slots:
            course_name = slot.get("course", "").lower()
            instructor_name = str(slot.get("instructor", "")).lower()
            
            # Check if course or instructor matches matched_courses
            matches = False
            for course_key in matched_courses:
                if course_key in course_name or course_key in instructor_name:
                    matches = True
                    break
            if name.lower() in query_lower:
                matches = True
                
            if matches:
                matching_slots.append(slot)
        if matching_slots:
            relevant_schedule[day] = matching_slots
            
    if relevant_schedule:
        context_chunks.append("### Matched Timetable slots:\n" + json.dumps(relevant_schedule, indent=2))
        
    if not context_chunks:
        # Fallback: send the entire timetable summary
        return "No specific course or day matched. Here is the general schedule context:\n" + json.dumps(timetable, indent=1)
        
    return "\n\n".join(context_chunks)
