"""
Database connection and schema management for DueMate.

This module handles MongoDB connectivity, index creation, and provides
utility functions for database operations.

Collections:
- users: User accounts with phone numbers and settings
- tasks: Assignments and quizzes parsed from WhatsApp messages
- otp_sessions: Temporary OTP storage for authentication
- refresh_tokens: JWT refresh token tracking
- reminders_sent: Reminder delivery tracking
- archived_tasks: Completed tasks older than 30 days
- archived_reminders_sent: Old reminders older than 60 days
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

from pymongo import MongoClient
from pymongo.database import Database

logger = logging.getLogger(__name__)

_mongo_client: Optional[MongoClient] = None
_indexes_ready = False


def get_env(primary: str, *aliases: str, default: str = "") -> str:
    """Read environment value using a primary key with optional aliases."""
    for key in (primary, *aliases):
        value = os.getenv(key)
        if value:
            return value
    return default


def get_mongo_client() -> Optional[MongoClient]:
    """Create and cache MongoDB client if URI is configured."""
    global _mongo_client
    if _mongo_client is not None:
        return _mongo_client

    mongo_uri = get_env("MONGODB_URI", "MONGO_URI")
    if not mongo_uri:
        logger.warning("MongoDB URI not configured")
        return None

    _mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=3000)
    return _mongo_client


def get_db() -> Optional[Database]:
    """Get the DueMate database instance."""
    client = get_mongo_client()
    if client is None:
        return None
    return client.get_database("duemate")


def ensure_indexes() -> None:
    """Create all required MongoDB indexes on startup."""
    global _indexes_ready
    if _indexes_ready:
        return

    db = get_db()
    if db is None:
        return

    logger.info("Creating MongoDB indexes...")

    # Users collection
    db.users.create_index("user_id", unique=True)
    db.users.create_index("phone_number", unique=True, sparse=True)

    # Tasks collection - optimized for common queries
    db.tasks.create_index([("user_id", 1), ("status", 1)])
    db.tasks.create_index("fingerprint")
    db.tasks.create_index("parsed_due_date")
    db.tasks.create_index("needs_review")
    db.tasks.create_index("source_message_id", unique=True, sparse=True)

    # OTP sessions - auto-expire with TTL index
    db.otp_sessions.create_index("expires_at", expireAfterSeconds=0)
    db.otp_sessions.create_index("phone_number")

    # Refresh tokens - auto-expire with TTL index
    db.refresh_tokens.create_index("expires_at", expireAfterSeconds=0)
    db.refresh_tokens.create_index("user_id")
    db.refresh_tokens.create_index("token_hash", unique=True)

    # Reminders tracking
    db.reminders_sent.create_index([("task_id", 1), ("user_id", 1)])
    db.reminders_sent.create_index("sent_at")

    # Push subscriptions
    db.push_subscriptions.create_index("user_id")
    db.push_subscriptions.create_index("endpoint", unique=True)

    # Webhook events (idempotency)
    db.webhook_events.create_index("event_key", unique=True)
    db.webhook_events.create_index("processed_at")

    # Course source mappings
    db.course_source_mappings.create_index([("user_id", 1), ("source_key", 1)], unique=True)

    _indexes_ready = True
    logger.info("MongoDB indexes created successfully")


def check_connectivity() -> tuple[bool, str]:
    """Check MongoDB connectivity and return status with error hint if failed."""
    try:
        client = get_mongo_client()
        if client is None:
            return False, "mongo_uri_missing"
        client.admin.command("ping")
        return True, ""
    except Exception as exc:
        return False, exc.__class__.__name__


def utc_now() -> datetime:
    """Get current UTC timestamp with timezone info."""
    return datetime.now(timezone.utc)
