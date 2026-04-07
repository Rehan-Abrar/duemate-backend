"""
WhatsApp Cloud API integration for DueMate.

Provides functions to send messages via Meta's WhatsApp Business API.
Used for:
- OTP delivery during authentication
- Task acknowledgment replies
- Reminder notifications (if enabled by user)

Note: Sending messages requires the user to have initiated contact
within the last 24 hours (WhatsApp's service window policy).
"""

import logging
import os
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GRAPH_API_VERSION = "v22.0"
GRAPH_API_BASE = f"https://graph.facebook.com/{GRAPH_API_VERSION}"


def get_env(primary: str, *aliases: str, default: str = "") -> str:
    """Read environment value using a primary key with optional aliases."""
    for key in (primary, *aliases):
        value = os.getenv(key)
        if value:
            return value
    return default


def get_phone_number_id() -> str:
    """Get WhatsApp phone number ID from environment."""
    return get_env("META_PHONE_NUMBER_ID", "META_PHONE_ID", "WHATSAPP_PHONE_ID")


def get_access_token() -> str:
    """Get WhatsApp API access token from environment."""
    return get_env("META_BEARER_TOKEN", "META_ACCESS_TOKEN", "WHATSAPP_TOKEN")


def send_text_message(
    to_number: str,
    message_body: str,
    preview_url: bool = False
) -> dict:
    """
    Send a plain text message via WhatsApp.
    
    Args:
        to_number: Recipient phone number (E.164 format without +)
        message_body: Message text content
        preview_url: Whether to generate link previews
        
    Returns:
        Dict with keys:
        - sent: bool
        - message_id: str (if successful)
        - error: str (if failed)
        - response: dict (raw API response)
    """
    phone_id = get_phone_number_id()
    access_token = get_access_token()
    
    if not phone_id or not access_token:
        logger.error("WhatsApp API credentials not configured")
        return {"sent": False, "error": "whatsapp_not_configured"}
    
    # Normalize phone number (remove + and spaces)
    to_number = "".join(c for c in str(to_number) if c.isdigit())
    
    url = f"{GRAPH_API_BASE}/{phone_id}/messages"
    
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": to_number,
        "type": "text",
        "text": {
            "body": message_body,
            "preview_url": preview_url
        }
    }
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=15)
        data = response.json()
        
        if response.ok:
            message_id = data.get("messages", [{}])[0].get("id", "")
            logger.info(f"WhatsApp message sent to {to_number[-4:]}: {message_id}")
            return {
                "sent": True,
                "message_id": message_id,
                "response": data
            }
        else:
            error_msg = data.get("error", {}).get("message", "Unknown error")
            logger.warning(f"WhatsApp send failed: {error_msg}")
            return {
                "sent": False,
                "error": error_msg,
                "status_code": response.status_code,
                "response": data
            }
            
    except requests.Timeout:
        logger.error("WhatsApp API timeout")
        return {"sent": False, "error": "timeout"}
    except requests.RequestException as e:
        logger.error(f"WhatsApp API error: {e}")
        return {"sent": False, "error": str(e)}


def send_otp_message(to_number: str, otp: str) -> dict:
    """
    Send OTP verification message.
    
    Args:
        to_number: Recipient phone number
        otp: 6-digit OTP code
        
    Returns:
        Result dict with success status
    """
    message = (
        f"🔐 Your DueMate verification code is: *{otp}*\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you didn't request this, ignore this message."
    )
    result = send_text_message(to_number, message)
    return {"success": result.get("sent", False), **result}


def send_task_acknowledgment(
    to_phone: str,
    task_type: str,
    course: Optional[str],
    due_date: Optional[str],
    confidence: float,
    is_duplicate: bool = False,
    needs_review: bool = False,
    dashboard_url: str = ""
) -> dict:
    """
    Send task parsing acknowledgment message.
    
    Args:
        to_phone: Recipient phone number
        task_type: "assignment" or "quiz"
        course: Parsed course name (or None)
        due_date: Formatted due date string or datetime (or None)
        confidence: Parse confidence 0.0-1.0
        is_duplicate: Whether this appears to be a duplicate
        needs_review: Whether the task needs manual review
        dashboard_url: URL to the dashboard
        
    Returns:
        Result dict with success status
    """
    # Format due date if it's a datetime object
    if due_date and hasattr(due_date, 'strftime'):
        due_date = due_date.strftime("%b %d, %Y")
    
    if is_duplicate:
        message = (
            f"🔁 This looks like something you already sent.\n\n"
            f"Check your dashboard to confirm:\n{dashboard_url}"
        )
    elif confidence >= 0.8 and not needs_review:
        course_part = f" for *{course}*" if course else ""
        due_part = f" due *{due_date}*" if due_date else ""
        message = (
            f"✅ Got it! {task_type.title()}{course_part}{due_part}.\n\n"
            f"Track it here:\n{dashboard_url}"
        )
    elif confidence > 0:
        message = (
            f"⚠️ Saved but I'm not sure I got all the details right.\n\n"
            f"Please review here:\n{dashboard_url}"
        )
    else:
        message = (
            f"❌ I received your message but couldn't extract the details.\n\n"
            f"Open your dashboard to fill them in:\n{dashboard_url}"
        )
    
    result = send_text_message(to_phone, message)
    return {"success": result.get("sent", False), **result}


def send_reminder(
    to_number: str,
    task_type: str,
    title: str,
    course: Optional[str],
    due_date: str,
    hours_until_due: int,
    dashboard_url: str
) -> dict:
    """
    Send deadline reminder message.
    
    Args:
        to_number: Recipient phone number
        task_type: "assignment" or "quiz"
        title: Task title
        course: Course name
        due_date: Formatted due date
        hours_until_due: Hours remaining until deadline
        dashboard_url: URL to dashboard
        
    Returns:
        Result dict from send_text_message
    """
    course_part = f" ({course})" if course else ""
    
    if hours_until_due <= 1:
        urgency = "⏰ *FINAL REMINDER*"
        time_text = "less than an hour"
    elif hours_until_due <= 6:
        urgency = "🔴 *Urgent*"
        time_text = f"{hours_until_due} hours"
    elif hours_until_due <= 24:
        urgency = "🟡 *Due Today*"
        time_text = f"{hours_until_due} hours"
    else:
        days = hours_until_due // 24
        urgency = "📌 *Reminder*"
        time_text = f"{days} day{'s' if days > 1 else ''}"
    
    message = (
        f"{urgency}\n\n"
        f"*{task_type.title()}*: {title}{course_part}\n"
        f"Due in {time_text} ({due_date})\n\n"
        f"View details:\n{dashboard_url}"
    )
    
    return send_text_message(to_number, message)
