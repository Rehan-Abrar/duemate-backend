"""
Fingerprint generation and duplicate detection for DueMate tasks.

Generates SHA-256 fingerprints from normalized task data to detect
potential duplicates before storing. This prevents users from
accidentally submitting the same assignment/quiz multiple times.
"""

import hashlib
import re
from datetime import datetime
from typing import Optional


def normalize_text(text: Optional[str]) -> str:
    """
    Normalize text for fingerprint comparison.
    
    - Lowercase
    - Remove non-alphanumeric characters
    - Collapse whitespace
    """
    if not text:
        return ""
    # Convert to lowercase and keep only alphanumeric
    return re.sub(r'[^a-z0-9]', '', text.lower().strip())


def make_fingerprint(
    user_id: str,
    course: Optional[str],
    title: Optional[str],
    due_date: Optional[datetime]
) -> str:
    """
    Generate a SHA-256 fingerprint for duplicate detection.
    
    The fingerprint is based on:
    - user_id (exact match)
    - course (normalized)
    - title (normalized)
    - due_date (YYYYMMDD format, or empty if None)
    
    Args:
        user_id: User identifier
        course: Course name (will be normalized)
        title: Task title (will be normalized)
        due_date: Due date datetime object
        
    Returns:
        64-character hex SHA-256 hash
    """
    # Format date as YYYYMMDD or empty string
    date_str = due_date.strftime("%Y%m%d") if due_date else ""
    
    # Build fingerprint source string
    parts = [
        user_id,
        normalize_text(course),
        normalize_text(title),
        date_str
    ]
    raw = "|".join(parts)
    
    return hashlib.sha256(raw.encode()).hexdigest()


def check_duplicate(db, user_id: str, fingerprint: str, exclude_task_id: Optional[str] = None) -> bool:
    """
    Check if a task with this fingerprint already exists.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        fingerprint: Task fingerprint to check
        exclude_task_id: Optional task ID to exclude (for updates)
        
    Returns:
        True if a duplicate exists
    """
    query = {
        "user_id": user_id,
        "fingerprint": fingerprint,
        "status": {"$ne": "completed"}  # Don't flag completed tasks as duplicates
    }
    
    if exclude_task_id:
        from bson import ObjectId
        query["_id"] = {"$ne": ObjectId(exclude_task_id)}
    
    return db.tasks.count_documents(query, limit=1) > 0


def find_similar_tasks(
    db,
    user_id: str,
    course: Optional[str],
    title: Optional[str],
    due_date: Optional[datetime],
    limit: int = 5
) -> list:
    """
    Find similar tasks that might be duplicates.
    
    Uses a combination of exact fingerprint match and fuzzy matching
    on individual fields to surface potential duplicates.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        course: Course name to match
        title: Title to match
        due_date: Due date to match
        limit: Maximum results to return
        
    Returns:
        List of potentially similar task documents
    """
    from datetime import timedelta
    
    # Build query for similar tasks
    query = {
        "user_id": user_id,
        "status": {"$ne": "completed"}
    }
    
    # Match by course if provided
    if course:
        # Case-insensitive regex match
        query["parsed_course"] = {"$regex": f"^{re.escape(course)}$", "$options": "i"}
    
    # Match within a date range if due_date provided
    if due_date:
        query["parsed_due_date"] = {
            "$gte": due_date - timedelta(days=1),
            "$lte": due_date + timedelta(days=1)
        }
    
    cursor = db.tasks.find(query).limit(limit)
    return list(cursor)
