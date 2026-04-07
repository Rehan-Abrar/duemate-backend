"""
APScheduler-based job scheduler for DueMate.

Handles:
- Deadline reminder checks (every 15 minutes)
- Weekly data archival (old completed tasks and reminders)

Known limitation: APScheduler runs in-process. If Render restarts the
dyno, scheduled jobs re-register on startup but any reminder that should
have fired during the restart window is missed. Mitigation: cron-job.org
keep-alive pings reduce restart frequency. Accepted for MVP.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_scheduler: Optional[BackgroundScheduler] = None


def get_scheduler() -> BackgroundScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = BackgroundScheduler(
            timezone="UTC",
            job_defaults={
                "coalesce": True,  # Combine missed runs into one
                "max_instances": 1,  # Only one instance at a time
                "misfire_grace_time": 300,  # 5 minute grace for missed jobs
            }
        )
    return _scheduler


def utc_now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


def check_reminders(db) -> dict:
    """
    Check for upcoming deadlines and send reminders.
    
    Queries for tasks due within the user's reminder window (default 24h)
    and sends push notifications and/or WhatsApp reminders based on
    user preferences.
    
    Returns:
        Summary dict with counts of reminders sent
    """
    from utils.push_sender import send_task_reminder, get_user_subscriptions, cleanup_invalid_subscription
    from utils.whatsapp_sender import send_reminder as send_wa_reminder
    
    now = utc_now()
    
    # Get reminder settings - check tasks due in next 24 hours by default
    reminder_hours = int(os.getenv("REMINDER_HOURS_BEFORE", "24"))
    reminder_window = now + timedelta(hours=reminder_hours)
    
    # Find pending tasks due within the window that haven't had reminders sent recently
    pipeline = [
        {
            "$match": {
                "status": {"$in": ["pending", "needs_review"]},
                "parsed_due_date": {
                    "$gte": now,
                    "$lte": reminder_window
                }
            }
        },
        {
            "$lookup": {
                "from": "reminders_sent",
                "let": {"task_id": {"$toString": "$_id"}},
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    {"$eq": ["$task_id", "$$task_id"]},
                                    {"$gte": ["$sent_at", now - timedelta(hours=6)]}
                                ]
                            }
                        }
                    }
                ],
                "as": "recent_reminders"
            }
        },
        {
            "$match": {
                "recent_reminders": {"$size": 0}  # No recent reminders
            }
        },
        {"$limit": 100}  # Process in batches
    ]
    
    try:
        tasks = list(db.tasks.aggregate(pipeline))
    except Exception as e:
        logger.error(f"Reminder query failed: {e}")
        return {"error": str(e)}
    
    summary = {
        "tasks_checked": len(tasks),
        "push_sent": 0,
        "push_failed": 0,
        "whatsapp_sent": 0,
        "whatsapp_failed": 0,
        "skipped": 0
    }
    
    dashboard_url = os.getenv("DASHBOARD_URL", "https://duemate.vercel.app")
    
    for task in tasks:
        task_id = str(task["_id"])
        user_id = task.get("user_id", "")
        
        if not user_id:
            summary["skipped"] += 1
            continue
        
        # Get user settings
        user = db.users.find_one({"user_id": user_id})
        if not user:
            summary["skipped"] += 1
            continue
        
        settings = user.get("settings", {})
        
        # Calculate hours until due
        due_date = task.get("parsed_due_date")
        if not due_date:
            summary["skipped"] += 1
            continue
        
        hours_until_due = max(0, int((due_date - now).total_seconds() / 3600))
        
        # Format due date for display
        due_date_str = due_date.strftime("%b %d, %I:%M %p")
        
        task_type = task.get("task_type", "assignment")
        title = task.get("parsed_title", "Untitled")
        course = task.get("parsed_course")
        
        # Send push notification if user has subscriptions
        push_sent = False
        subscriptions = get_user_subscriptions(db, user_id)
        for sub in subscriptions:
            result = send_task_reminder(
                subscription=sub,
                task_type=task_type,
                title=title,
                course=course,
                due_date=due_date_str,
                hours_until_due=hours_until_due,
                task_id=task_id,
                dashboard_url=dashboard_url
            )
            
            if result.get("sent"):
                push_sent = True
                summary["push_sent"] += 1
            elif result.get("error_code") in ("gone", "not_found"):
                # Clean up invalid subscription
                cleanup_invalid_subscription(db, sub.get("endpoint", ""))
            else:
                summary["push_failed"] += 1
        
        # Send WhatsApp reminder if enabled and user has phone number
        wa_sent = False
        if settings.get("whatsapp_reminders_enabled"):
            phone = user.get("phone_number")
            if phone:
                result = send_wa_reminder(
                    to_number=phone,
                    task_type=task_type,
                    title=title,
                    course=course,
                    due_date=due_date_str,
                    hours_until_due=hours_until_due,
                    dashboard_url=dashboard_url
                )
                
                if result.get("sent"):
                    wa_sent = True
                    summary["whatsapp_sent"] += 1
                else:
                    summary["whatsapp_failed"] += 1
        
        # Record reminder sent
        if push_sent or wa_sent:
            channels = []
            if push_sent:
                channels.append("web_push")
            if wa_sent:
                channels.append("whatsapp")
            
            db.reminders_sent.insert_one({
                "user_id": user_id,
                "task_id": task_id,
                "channels": channels,
                "sent_at": now,
                "success": True,
                "hours_before_due": hours_until_due
            })
    
    logger.info(f"Reminder check complete: {summary}")
    return summary


def archive_old_data(db) -> dict:
    """
    Archive completed tasks older than 30 days and old reminders.
    
    - Moves completed tasks older than 30 days to archived_tasks
    - Keeps last 50 completed tasks per user regardless of age
    - Moves reminders_sent older than 60 days to archived_reminders_sent
    
    Returns:
        Summary dict with counts of archived records
    """
    now = utc_now()
    cutoff_tasks = now - timedelta(days=30)
    cutoff_reminders = now - timedelta(days=60)
    
    summary = {
        "tasks_archived": 0,
        "reminders_archived": 0,
        "errors": []
    }
    
    try:
        # Archive old completed tasks
        # First, get all users with completed tasks
        users = db.tasks.distinct("user_id", {"status": "completed"})
        
        for user_id in users:
            # Get completed tasks for this user, sorted by date
            completed_tasks = list(db.tasks.find({
                "user_id": user_id,
                "status": "completed"
            }).sort("created_at", -1))
            
            # Keep the 50 most recent, archive the rest if older than cutoff
            tasks_to_archive = []
            for i, task in enumerate(completed_tasks):
                if i >= 50:  # Beyond the keep threshold
                    created = task.get("created_at")
                    if created and created < cutoff_tasks:
                        tasks_to_archive.append(task)
            
            # Move to archive
            for task in tasks_to_archive:
                task["archived_at"] = now
                try:
                    db.archived_tasks.insert_one(task)
                    db.tasks.delete_one({"_id": task["_id"]})
                    summary["tasks_archived"] += 1
                except Exception as e:
                    summary["errors"].append(f"Task archive error: {e}")
        
        # Archive old reminders
        old_reminders = list(db.reminders_sent.find({
            "sent_at": {"$lt": cutoff_reminders}
        }))
        
        for reminder in old_reminders:
            reminder["archived_at"] = now
            try:
                db.archived_reminders_sent.insert_one(reminder)
                db.reminders_sent.delete_one({"_id": reminder["_id"]})
                summary["reminders_archived"] += 1
            except Exception as e:
                summary["errors"].append(f"Reminder archive error: {e}")
        
    except Exception as e:
        summary["errors"].append(f"Archive job error: {e}")
        logger.error(f"Archive job failed: {e}")
    
    logger.info(f"Archive complete: {summary}")
    return summary


def start_scheduler(db_getter) -> BackgroundScheduler:
    """
    Start the scheduler with all jobs configured.
    
    Args:
        db_getter: Callable that returns the MongoDB database instance
        
    Returns:
        The started scheduler instance
    """
    scheduler = get_scheduler()
    
    if scheduler.running:
        logger.info("Scheduler already running")
        return scheduler
    
    # Reminder check job - every 15 minutes
    def reminder_job():
        db = db_getter()
        if db:
            check_reminders(db)
    
    scheduler.add_job(
        reminder_job,
        trigger=IntervalTrigger(minutes=15),
        id="check_reminders",
        name="Check upcoming deadlines and send reminders",
        replace_existing=True
    )
    
    # Weekly archive job - Sunday at 3 AM UTC
    def archive_job():
        db = db_getter()
        if db:
            archive_old_data(db)
    
    scheduler.add_job(
        archive_job,
        trigger=CronTrigger(day_of_week="sun", hour=3, minute=0),
        id="archive_old_data",
        name="Archive old completed tasks and reminders",
        replace_existing=True
    )
    
    scheduler.start()
    logger.info("Scheduler started with reminder and archive jobs")
    
    return scheduler


def stop_scheduler():
    """Stop the scheduler if running."""
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
