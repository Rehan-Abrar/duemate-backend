"""
Web Push notification sender for DueMate.

Uses pywebpush with VAPID authentication to send push notifications
to subscribed browsers. Used for deadline reminders when the user
has enabled push notifications in the dashboard.

Setup:
1. Generate VAPID keys: vapid --gen
2. Set VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT in environment
"""

import json
import logging
import os
from typing import Optional

from pywebpush import webpush, WebPushException

logger = logging.getLogger(__name__)


def get_vapid_keys() -> tuple[str, str, str]:
    """
    Get VAPID keys from environment.
    
    Returns:
        Tuple of (public_key, private_key, subject)
    """
    public_key = os.getenv("VAPID_PUBLIC_KEY", "")
    private_key = os.getenv("VAPID_PRIVATE_KEY", "")
    subject = os.getenv("VAPID_SUBJECT", "")
    
    return public_key, private_key, subject


def is_configured() -> bool:
    """Check if VAPID keys are configured."""
    public, private, subject = get_vapid_keys()
    return bool(public and private and subject)


def send_push_notification(
    subscription: dict,
    title: str,
    body: str,
    url: Optional[str] = None,
    icon: Optional[str] = None,
    badge: Optional[str] = None,
    tag: Optional[str] = None,
    data: Optional[dict] = None,
    ttl: int = 86400
) -> dict:
    """
    Send a web push notification to a subscribed client.
    
    Args:
        subscription: Push subscription object from browser
            Must contain: endpoint, keys.p256dh, keys.auth
        title: Notification title
        body: Notification body text
        url: URL to open when notification is clicked
        icon: URL to notification icon
        badge: URL to badge icon (mobile)
        tag: Tag to group/replace notifications
        data: Additional data to include
        ttl: Time to live in seconds (default: 24 hours)
        
    Returns:
        Dict with keys:
        - sent: bool
        - error: str (if failed)
        - error_code: str (if failed, e.g., 'gone' for unsubscribed)
    """
    public_key, private_key, subject = get_vapid_keys()
    
    if not all([public_key, private_key, subject]):
        logger.warning("VAPID keys not configured, skipping push notification")
        return {"sent": False, "error": "vapid_not_configured"}
    
    # Build notification payload
    payload = {
        "notification": {
            "title": title,
            "body": body,
            "icon": icon or "/icon-192.png",
            "badge": badge or "/badge-72.png",
            "tag": tag,
            "requireInteraction": True,
            "actions": [
                {"action": "open", "title": "Open Dashboard"},
                {"action": "dismiss", "title": "Dismiss"}
            ],
            "data": {
                "url": url or "/",
                **(data or {})
            }
        }
    }
    
    vapid_claims = {
        "sub": subject
    }
    
    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps(payload),
            vapid_private_key=private_key,
            vapid_claims=vapid_claims,
            ttl=ttl
        )
        
        logger.info(f"Push notification sent: {title}")
        return {"sent": True}
        
    except WebPushException as e:
        error_msg = str(e)
        error_code = "unknown"
        
        # Parse specific error codes
        if "410" in error_msg or "gone" in error_msg.lower():
            error_code = "gone"  # Subscription expired/unsubscribed
            logger.info(f"Push subscription expired: {error_msg}")
        elif "401" in error_msg or "unauthorized" in error_msg.lower():
            error_code = "unauthorized"
            logger.error(f"Push auth failed (check VAPID keys): {error_msg}")
        elif "404" in error_msg:
            error_code = "not_found"
            logger.warning(f"Push endpoint not found: {error_msg}")
        elif "429" in error_msg:
            error_code = "rate_limited"
            logger.warning(f"Push rate limited: {error_msg}")
        else:
            logger.error(f"Push failed: {error_msg}")
        
        return {
            "sent": False,
            "error": error_msg,
            "error_code": error_code
        }
    except Exception as e:
        logger.error(f"Push error: {e}")
        return {"sent": False, "error": str(e), "error_code": "exception"}


def send_task_reminder(
    subscription: dict,
    task_type: str,
    title: str,
    course: Optional[str],
    due_date: str,
    hours_until_due: int,
    task_id: str,
    dashboard_url: str
) -> dict:
    """
    Send a task deadline reminder push notification.
    
    Args:
        subscription: Push subscription object
        task_type: "assignment" or "quiz"
        title: Task title
        course: Course name
        due_date: Formatted due date
        hours_until_due: Hours remaining
        task_id: Task ID for tracking
        dashboard_url: Base dashboard URL
        
    Returns:
        Result dict from send_push_notification
    """
    course_part = f" ({course})" if course else ""
    
    if hours_until_due <= 1:
        notification_title = f"⏰ {task_type.title()} due NOW!"
        urgency = "final"
    elif hours_until_due <= 6:
        notification_title = f"🔴 {task_type.title()} due in {hours_until_due}h"
        urgency = "urgent"
    elif hours_until_due <= 24:
        notification_title = f"🟡 {task_type.title()} due today"
        urgency = "today"
    else:
        days = hours_until_due // 24
        notification_title = f"📌 {task_type.title()} due in {days} day{'s' if days > 1 else ''}"
        urgency = "reminder"
    
    body = f"{title}{course_part}\nDue: {due_date}"
    
    return send_push_notification(
        subscription=subscription,
        title=notification_title,
        body=body,
        url=f"{dashboard_url}?task={task_id}",
        tag=f"task-{task_id}",
        data={
            "task_id": task_id,
            "urgency": urgency,
            "hours_remaining": hours_until_due
        }
    )


def cleanup_invalid_subscription(db, endpoint: str) -> bool:
    """
    Remove an invalid/expired push subscription from database.
    
    Called when a push fails with 'gone' or 'not_found' error.
    
    Args:
        db: MongoDB database instance
        endpoint: Push subscription endpoint URL
        
    Returns:
        True if subscription was removed
    """
    result = db.push_subscriptions.delete_one({"endpoint": endpoint})
    if result.deleted_count > 0:
        logger.info(f"Removed invalid push subscription: {endpoint[:50]}...")
        return True
    return False


def save_push_subscription(db, user_id: str, subscription: dict) -> bool:
    """
    Save or update a push subscription for a user.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        subscription: Push subscription object from browser
        
    Returns:
        True if saved successfully
    """
    from datetime import datetime, timezone
    
    endpoint = subscription.get("endpoint", "")
    if not endpoint:
        return False
    
    try:
        db.push_subscriptions.update_one(
            {"endpoint": endpoint},
            {
                "$set": {
                    "user_id": user_id,
                    "subscription": subscription,
                    "updated_at": datetime.now(timezone.utc)
                },
                "$setOnInsert": {
                    "created_at": datetime.now(timezone.utc)
                }
            },
            upsert=True
        )
        logger.info(f"Saved push subscription for user {user_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to save push subscription: {e}")
        return False


def get_user_subscriptions(db, user_id: str) -> list[dict]:
    """
    Get all push subscriptions for a user.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        
    Returns:
        List of subscription objects
    """
    cursor = db.push_subscriptions.find(
        {"user_id": user_id},
        {"subscription": 1, "_id": 0}
    )
    return [doc["subscription"] for doc in cursor if "subscription" in doc]
