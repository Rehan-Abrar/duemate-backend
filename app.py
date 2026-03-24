import os
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import json
import logging
import secrets
import uuid
from typing import Optional

from flask import Flask, jsonify, request
from flask_cors import CORS
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import requests
from werkzeug.security import check_password_hash, generate_password_hash

from utils.parse_task import SEMESTER_COURSES, parse_task


_mongo_client: Optional[MongoClient] = None
_indexes_ready = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_unix_timestamp(value: Optional[str]) -> datetime:
    if not value:
        return _utc_now()
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError):
        return _utc_now()


def _serialize_for_json(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, list):
        return [_serialize_for_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize_for_json(val) for key, val in value.items()}
    return value


def _parse_object_id(value: str) -> Optional[ObjectId]:
    try:
        return ObjectId(value)
    except Exception:
        return None


def _parse_due_date_value(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _build_user_id(phone_number: str) -> str:
    return f"wa:{phone_number}"


def _normalize_phone_number(value: str) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return digits


def _parse_bool_arg(name: str) -> Optional[bool]:
    raw_value = request.args.get(name, "").strip().lower()
    if raw_value in {"true", "false"}:
        return raw_value == "true"
    return None


def _extract_session_token() -> str:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return request.headers.get("X-Session-Token", "").strip()


def _hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _session_ttl_days() -> int:
    raw_value = get_env("SESSION_TTL_DAYS", default="14").strip()
    try:
        days = int(raw_value)
    except ValueError:
        days = 14
    return max(1, min(days, 60))


def _create_user_session(db, user_id: str) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(36)
    now = _utc_now()
    expires_at = now + timedelta(days=_session_ttl_days())
    db.user_sessions.insert_one(
        {
            "user_id": user_id,
            "token_hash": _hash_session_token(token),
            "created_at": now,
            "last_seen": now,
            "expires_at": expires_at,
            "revoked_at": None,
        }
    )
    return token, expires_at


def _resolve_authenticated_user(db):
    token = _extract_session_token()
    if not token:
        return None, None

    session = db.user_sessions.find_one(
        {
            "token_hash": _hash_session_token(token),
            "revoked_at": None,
            "expires_at": {"$gt": _utc_now()},
        }
    )
    if not session:
        return None, None

    user = db.users.find_one({"user_id": session.get("user_id")})
    if not user:
        return None, None

    db.user_sessions.update_one(
        {"_id": session["_id"]},
        {"$set": {"last_seen": _utc_now()}},
    )
    return user, session


def _task_filter_query_for_request(user_id: str) -> tuple[dict, int]:
    query = {"user_id": user_id}

    task_type = request.args.get("type", "").strip().lower()
    if task_type in {"assignment", "quiz", "exam"}:
        query["task_type"] = task_type

    status = request.args.get("status", "").strip().lower()
    if status in {"pending", "completed", "needs_review"}:
        query["status"] = status

    needs_review = _parse_bool_arg("needs_review")
    if needs_review is not None:
        query["needs_review"] = needs_review

    course_unresolved = _parse_bool_arg("course_unresolved")
    if course_unresolved is not None:
        query["course_unresolved"] = course_unresolved

    try:
        limit = int(request.args.get("limit", "50"))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    return query, limit


def _task_sort_key(task: dict):
    status_value = str(task.get("status") or "pending")
    completed_rank = 1 if status_value == "completed" else 0
    unresolved_rank = 0 if bool(task.get("course_unresolved")) else 1
    review_rank = 0 if bool(task.get("needs_review")) else 1

    due_value = task.get("parsed_due_date")
    due_rank = 1
    due_sort_value = datetime.max.replace(tzinfo=timezone.utc)
    if isinstance(due_value, datetime):
        due_rank = 0
        due_sort_value = due_value

    created_value = task.get("created_at")
    created_timestamp = 0.0
    if isinstance(created_value, datetime):
        created_timestamp = created_value.timestamp()

    return (completed_rank, unresolved_rank, review_rank, due_rank, due_sort_value, -created_timestamp)


def _serialize_user_profile(user: dict) -> dict:
    return {
        "user_id": user.get("user_id", ""),
        "phone_number": user.get("phone_number", ""),
        "last_seen": _serialize_for_json(user.get("last_seen")),
        "created_at": _serialize_for_json(user.get("created_at")),
        "settings": _serialize_for_json(user.get("settings", {})),
    }


def _get_admin_key() -> str:
    return get_env("ADMIN_API_KEY", "ADMIN_KEY", default="")


def _verify_admin_key() -> tuple[bool, Optional[tuple]]:
    admin_key = _get_admin_key()
    if not admin_key:
        return False, (jsonify({"error": "admin_key_not_configured"}), 503)

    auth_header = request.headers.get("X-Admin-Key", "").strip()
    if not auth_header or auth_header != admin_key:
        return False, (jsonify({"error": "forbidden"}), 403)

    return True, None


def _derive_source_key(message: dict) -> tuple[str, bool, str]:
    context = message.get("context", {}) if isinstance(message, dict) else {}
    is_forwarded = bool(context.get("forwarded"))
    forwarded_from = str(context.get("forwarded_from") or "").strip()

    if is_forwarded and forwarded_from:
        return f"forwarded:{forwarded_from}", True, forwarded_from
    if is_forwarded:
        return "forwarded:unknown", True, ""
    return "direct", False, ""


def _resolve_course_from_mapping(db, user_id: str, source_key: str) -> Optional[str]:
    if not user_id or not source_key:
        return None

    mapping = db.course_source_mappings.find_one({"user_id": user_id, "source_key": source_key}, {"_id": 0, "course_code": 1})
    if mapping:
        return str(mapping.get("course_code") or "").strip().upper() or None
    return None


def _is_course_unresolved(parsed_course: Optional[str], source_key: str) -> bool:
    if not parsed_course:
        return True
    if source_key == "forwarded:unknown":
        return True
    return False


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
        return None

    _mongo_client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
    return _mongo_client


def get_mongo_db():
    client = get_mongo_client()
    if client is None:
        return None
    return client.get_database("duemate")


def ensure_mongo_indexes() -> None:
    global _indexes_ready
    if _indexes_ready:
        return

    db = get_mongo_db()
    if db is None:
        return

    db.webhook_events.create_index("event_key", unique=True)
    db.webhook_events.create_index("processed_at")
    db.messages.create_index("message_id", unique=True)
    db.messages.create_index("received_at")
    db.messages.create_index("from")
    db.contacts.create_index("wa_id", unique=True)
    db.users.create_index("user_id", unique=True)
    db.users.create_index("phone_number", unique=True)
    db.users.create_index("password_set")
    db.user_sessions.create_index("token_hash", unique=True)
    db.user_sessions.create_index("user_id")
    db.user_sessions.create_index("expires_at")
    db.user_sessions.create_index("revoked_at")
    db.tasks.create_index("user_id")
    db.tasks.create_index("status")
    db.tasks.create_index("needs_review")
    db.tasks.create_index("course_unresolved")
    db.tasks.create_index("parsed_due_date")
    db.tasks.create_index("created_at")
    db.tasks.create_index("source_message_id", unique=True)
    db.tasks.create_index("source_key")
    db.course_source_mappings.create_index([("user_id", 1), ("source_key", 1)], unique=True)
    db.course_source_mappings.create_index("course_code")
    db.reminders_sent.create_index("user_id")
    db.reminders_sent.create_index("task_id")
    _indexes_ready = True


def check_mongo_connectivity() -> bool:
    """Ping MongoDB to verify network/auth connectivity."""
    ok, _ = get_mongo_connectivity_status()
    return ok


def get_mongo_connectivity_status() -> tuple[bool, str]:
    """Return mongo connectivity status and a safe error hint for diagnostics."""
    try:
        client = get_mongo_client()
        if client is None:
            return False, "mongo_uri_missing"
        client.admin.command("ping")
        return True, ""
    except Exception as exc:
        # Keep the error safe and compact for health/debugging without leaking secrets.
        return False, exc.__class__.__name__


def verify_webhook_signature(request_body: bytes, signature: str) -> bool:
    """Verify X-Hub-Signature-256 from Meta webhook."""
    app_secret = get_env("META_APP_SECRET", "WHATSAPP_APP_SECRET", "APP_SECRET")
    if not app_secret or not signature:
        return False

    expected_signature = hmac.HMAC(
        app_secret.encode(),
        request_body,
        hashlib.sha256
    ).hexdigest()

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(f"sha256={expected_signature}", signature)


def build_event_key(prefix: str, payload: dict, fallback_fields: Optional[list[str]] = None) -> str:
    if fallback_fields:
        parts = [str(payload.get(field, "")) for field in fallback_fields]
        if all(parts):
            return f"{prefix}:{':'.join(parts)}"

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{prefix}:hash:{digest}"


def log_webhook_event(db, event_key: str, event_type: str, payload: dict, request_id: str) -> bool:
    try:
        db.webhook_events.insert_one(
            {
                "event_key": event_key,
                "event_type": event_type,
                "payload": payload,
                "request_id": request_id,
                "processed_at": _utc_now(),
            }
        )
        return True
    except DuplicateKeyError:
        return False


def send_whatsapp_text_message(to_number: str, message_body: str) -> dict:
    phone_id = get_env("META_PHONE_ID")
    access_token = get_env("META_BEARER_TOKEN", "META_ACCESS_TOKEN")

    if not phone_id or not access_token:
        return {"sent": False, "reason": "meta_credentials_missing"}

    url = f"https://graph.facebook.com/v22.0/{phone_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": to_number,
        "type": "text",
        "text": {"body": message_body},
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.ok:
            return {"sent": True, "response": response.json()}
        return {
            "sent": False,
            "status_code": response.status_code,
            "response": response.text[:800],
        }
    except requests.RequestException as exc:
        return {"sent": False, "error": str(exc)}


def process_webhook_payload(data: dict, request_id: str) -> dict:
    db = get_mongo_db()
    ensure_mongo_indexes()

    summary = {
        "inbound_messages": 0,
        "status_updates": 0,
        "duplicates": 0,
        "acked": 0,
        "ack_failures": 0,
        "tasks_created": 0,
        "tasks_needs_review": 0,
        "tasks_missing_course_mapping": 0,
    }

    if db is None:
        return {**summary, "storage": "unavailable"}

    for entry in data.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            metadata = value.get("metadata", {})

            contacts_map = {
                contact.get("wa_id"): contact for contact in value.get("contacts", []) if contact.get("wa_id")
            }

            for message in value.get("messages", []):
                message_id = message.get("id")
                event_key = build_event_key("message", message, ["id"])

                was_logged = log_webhook_event(db, event_key, "inbound_message", message, request_id)
                if not was_logged:
                    summary["duplicates"] += 1
                    continue

                sender = message.get("from")
                user_id = _build_user_id(sender) if sender else ""
                sender_profile = contacts_map.get(sender, {}).get("profile", {}).get("name", "")
                message_type = message.get("type", "unknown")
                text_body = ""
                if message_type == "text":
                    text_body = message.get("text", {}).get("body", "")
                elif message_type in message and isinstance(message.get(message_type), dict):
                    text_body = json.dumps(message.get(message_type), ensure_ascii=True)

                source_key, is_forwarded, forwarded_from = _derive_source_key(message)

                message_doc = {
                    "message_id": message_id,
                    "from": sender,
                    "to": metadata.get("display_phone_number", ""),
                    "wa_phone_id": metadata.get("phone_number_id", ""),
                    "type": message_type,
                    "text": text_body,
                    "timestamp": _parse_unix_timestamp(message.get("timestamp")),
                    "received_at": _utc_now(),
                    "delivery_status": "received",
                    "source_key": source_key,
                    "is_forwarded": is_forwarded,
                    "forwarded_from": forwarded_from,
                    "raw": message,
                    "request_id": request_id,
                }

                try:
                    db.messages.insert_one(message_doc)
                except DuplicateKeyError:
                    summary["duplicates"] += 1
                    continue

                if sender:
                    db.contacts.update_one(
                        {"wa_id": sender},
                        {
                            "$set": {
                                "wa_id": sender,
                                "profile_name": sender_profile,
                                "last_seen": _utc_now(),
                                "updated_at": _utc_now(),
                            }
                        },
                        upsert=True,
                    )

                    db.users.update_one(
                        {"user_id": user_id},
                        {
                            "$set": {
                                "phone_number": sender,
                                "last_seen": _utc_now(),
                                "updated_at": _utc_now(),
                            },
                            "$setOnInsert": {
                                "user_id": user_id,
                                "created_at": _utc_now(),
                                "settings": {
                                    "timezone": "UTC",
                                    "reminder_enabled": True,
                                    "notification_preference": "all",
                                },
                            },
                        },
                        upsert=True,
                    )

                mapped_course = _resolve_course_from_mapping(db, user_id, source_key) if user_id else None
                parse_result = parse_task(text_body, course_hint=mapped_course)
                task_status = "needs_review" if parse_result["needs_review"] else "pending"
                course_unresolved = _is_course_unresolved(parse_result.get("course"), source_key)
                course_resolution_method = "mapped" if mapped_course else ("heuristic" if parse_result.get("course") else "unresolved")
                task_doc = {
                    "user_id": user_id,
                    "phone_number": sender,
                    "task_type": parse_result["task_type"],
                    "raw_message": text_body,
                    "parsed_course": parse_result["course"],
                    "parsed_title": parse_result["title"],
                    "parsed_due_date": parse_result["due_date"],
                    "quiz_material": parse_result["quiz_material"],
                    "quiz_duration": parse_result["quiz_duration"],
                    "quiz_time": parse_result["quiz_time"],
                    "parse_confidence": parse_result["confidence"],
                    "needs_review": parse_result["needs_review"] or course_unresolved,
                    "status": task_status,
                    "course_unresolved": course_unresolved,
                    "course_resolution_method": course_resolution_method,
                    "source_key": source_key,
                    "is_forwarded": is_forwarded,
                    "forwarded_from": forwarded_from,
                    "course_mapped_from_source": bool(mapped_course),
                    "source_message_id": message_id,
                    "source_request_id": request_id,
                    "created_at": _utc_now(),
                    "updated_at": _utc_now(),
                }

                try:
                    db.tasks.insert_one(task_doc)
                    summary["tasks_created"] += 1
                except DuplicateKeyError:
                    summary["duplicates"] += 1

                if parse_result["needs_review"]:
                    summary["tasks_needs_review"] += 1
                if course_unresolved:
                    summary["tasks_missing_course_mapping"] += 1

                summary["inbound_messages"] += 1

                dashboard_url = get_env("DASHBOARD_URL", default="")
                ack_template = get_env("ACK_MESSAGE_TEMPLATE", default="DueMate: Task saved.")
                review_template = get_env(
                    "ACK_REVIEW_TEMPLATE",
                    default="DueMate: Please review parsed details on dashboard.",
                )
                if dashboard_url:
                    review_template = f"{review_template} {dashboard_url}"

                ack_message = review_template if parse_result["needs_review"] else ack_template
                send_result = send_whatsapp_text_message(sender, ack_message) if sender else {"sent": False}
                if send_result.get("sent"):
                    summary["acked"] += 1
                else:
                    summary["ack_failures"] += 1

            for status in value.get("statuses", []):
                event_key = build_event_key("status", status, ["id", "status", "timestamp"])
                was_logged = log_webhook_event(db, event_key, "status_update", status, request_id)
                if not was_logged:
                    summary["duplicates"] += 1
                    continue

                status_value = status.get("status", "unknown")
                message_id = status.get("id")
                if message_id:
                    db.messages.update_one(
                        {"message_id": message_id},
                        {
                            "$set": {
                                "delivery_status": status_value,
                                "status_timestamp": _parse_unix_timestamp(status.get("timestamp")),
                                "updated_at": _utc_now(),
                            }
                        },
                    )

                summary["status_updates"] += 1

    return {**summary, "storage": "ok"}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = get_env("FLASK_SECRET_KEY", "SECRET_KEY", default="dev-secret-change-me")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    CORS(app)

    @app.get("/")
    def index():
        return jsonify(
            {
                "service": "duemate-backend",
                "message": "DueMate backend is running",
                "status": "ok",
            }
        )

    @app.get("/health")
    def health():
        mongo_uri = get_env("MONGODB_URI", "MONGO_URI")
        webhook_secret = get_env("META_APP_SECRET", "WHATSAPP_APP_SECRET", "APP_SECRET")
        mongo_connected, mongo_error = (
            get_mongo_connectivity_status() if mongo_uri else (False, "mongo_uri_missing")
        )
        return jsonify(
            {
                "status": "ok",
                "utc_time": datetime.now(timezone.utc).isoformat(),
                "mongo_configured": bool(mongo_uri),
                "mongo_connected": mongo_connected,
                "mongo_error": "" if mongo_connected else mongo_error,
                "meta_configured": bool(get_env("META_BEARER_TOKEN", "META_ACCESS_TOKEN")),
                "webhook_signature_ready": bool(webhook_secret),
            }
        )

    def resolve_authenticated_user_or_401(db):
        user, session = _resolve_authenticated_user(db)
        if user is None or session is None:
            return None, None, (jsonify({"error": "unauthorized"}), 401)
        return user, session, None

    @app.post("/api/auth/signup")
    def auth_signup():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        data = request.get_json(silent=True) or {}
        phone_number = _normalize_phone_number(data.get("phone_number", ""))
        password = str(data.get("password", ""))

        if not phone_number:
            return jsonify({"error": "phone_number_required"}), 400
        if len(password) < 8:
            return jsonify({"error": "password_too_short", "minimum_length": 8}), 400

        ensure_mongo_indexes()
        user_id = _build_user_id(phone_number)
        existing = db.users.find_one({"user_id": user_id})
        if existing and existing.get("password_hash"):
            return jsonify({"error": "account_already_exists"}), 409

        now = _utc_now()
        password_hash = generate_password_hash(password)
        db.users.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "phone_number": phone_number,
                    "password_hash": password_hash,
                    "password_set": True,
                    "updated_at": now,
                    "last_seen": now,
                },
                "$setOnInsert": {
                    "created_at": now,
                    "settings": {
                        "timezone": "UTC",
                        "reminder_enabled": True,
                        "notification_preference": "all",
                        "whatsapp_reminders_enabled": False,
                    },
                },
            },
            upsert=True,
        )

        user = db.users.find_one({"user_id": user_id})
        token, expires_at = _create_user_session(db, user_id)
        return jsonify(
            {
                "token": token,
                "expires_at": _serialize_for_json(expires_at),
                "user": _serialize_user_profile(user or {}),
            }
        ), 201

    @app.post("/api/auth/login")
    def auth_login():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        data = request.get_json(silent=True) or {}
        phone_number = _normalize_phone_number(data.get("phone_number", ""))
        password = str(data.get("password", ""))

        if not phone_number or not password:
            return jsonify({"error": "credentials_required"}), 400

        user = db.users.find_one({"user_id": _build_user_id(phone_number)})
        password_hash = str((user or {}).get("password_hash") or "")
        if not user or not password_hash or not check_password_hash(password_hash, password):
            return jsonify({"error": "invalid_credentials"}), 401

        token, expires_at = _create_user_session(db, user.get("user_id", ""))
        return jsonify(
            {
                "token": token,
                "expires_at": _serialize_for_json(expires_at),
                "user": _serialize_user_profile(user),
            }
        )

    @app.post("/api/auth/logout")
    def auth_logout():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        _, session, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        db.user_sessions.update_one(
            {"_id": session["_id"]},
            {"$set": {"revoked_at": _utc_now(), "updated_at": _utc_now()}},
        )
        return jsonify({"ok": True})

    @app.get("/api/auth/me")
    def auth_me():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, session, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        return jsonify(
            {
                "user": _serialize_user_profile(user),
                "session": {
                    "expires_at": _serialize_for_json(session.get("expires_at")),
                    "last_seen": _serialize_for_json(session.get("last_seen")),
                },
            }
        )

    @app.get("/api/messages/recent")
    def recent_messages():
        ok, error_response = _verify_admin_key()
        if not ok:
            return error_response

        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        try:
            limit = int(request.args.get("limit", "20"))
        except ValueError:
            limit = 20
        limit = max(1, min(limit, 100))
        try:
            ensure_mongo_indexes()
            cursor = db.messages.find({}, {"_id": 0}).sort("received_at", -1).limit(limit)
            items = [_serialize_for_json(doc) for doc in cursor]
            return jsonify({"items": items, "count": len(items)})
        except Exception as exc:
            app.logger.exception("recent_messages_failed error=%s", str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.get("/api/delivery-status")
    def delivery_status():
        ok, error_response = _verify_admin_key()
        if not ok:
            return error_response

        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        try:
            ensure_mongo_indexes()
            pipeline = [
                {"$group": {"_id": "$delivery_status", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            summary = [
                {"status": row.get("_id") or "unknown", "count": row.get("count", 0)}
                for row in db.messages.aggregate(pipeline)
            ]

            recent_events_cursor = (
                db.webhook_events.find({"event_type": "status_update"}, {"_id": 0, "payload": 1, "processed_at": 1})
                .sort("processed_at", -1)
                .limit(20)
            )
            events = []
            for event in recent_events_cursor:
                payload = event.get("payload", {})
                events.append(
                    {
                        "message_id": payload.get("id", ""),
                        "status": payload.get("status", "unknown"),
                        "recipient_id": payload.get("recipient_id", ""),
                        "timestamp": _parse_unix_timestamp(payload.get("timestamp")).isoformat(),
                        "processed_at": _serialize_for_json(event.get("processed_at")),
                    }
                )

            return jsonify({"summary": summary, "recent_events": events})
        except Exception as exc:
            app.logger.exception("delivery_status_failed error=%s", str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.get("/api/tasks/<user_id>")
    def get_tasks_for_user(user_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error
        if str(user.get("user_id") or "") != user_id:
            return jsonify({"error": "forbidden"}), 403

        try:
            ensure_mongo_indexes()
            query = {"user_id": user_id}

            task_type = request.args.get("type", "").strip().lower()
            if task_type in {"assignment", "quiz", "exam"}:
                query["task_type"] = task_type

            status = request.args.get("status", "").strip().lower()
            if status in {"pending", "completed", "needs_review"}:
                query["status"] = status

            needs_review_param = request.args.get("needs_review", "").strip().lower()
            if needs_review_param in {"true", "false"}:
                query["needs_review"] = needs_review_param == "true"

            course_unresolved_param = request.args.get("course_unresolved", "").strip().lower()
            if course_unresolved_param in {"true", "false"}:
                query["course_unresolved"] = course_unresolved_param == "true"

            items = [
                _serialize_for_json(doc)
                for doc in db.tasks.find(query).sort([("parsed_due_date", 1), ("created_at", -1)])
            ]
            return jsonify({"items": items, "count": len(items)})
        except Exception as exc:
            app.logger.exception("get_tasks_for_user_failed user_id=%s error=%s", user_id, str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.get("/api/tasks")
    def list_tasks():
        ok, error_response = _verify_admin_key()
        if not ok:
            return error_response

        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        try:
            ensure_mongo_indexes()
            query = {}

            user_id = request.args.get("user_id", "").strip()
            if user_id:
                query["user_id"] = user_id

            needs_review_param = request.args.get("needs_review", "").strip().lower()
            if needs_review_param in {"true", "false"}:
                query["needs_review"] = needs_review_param == "true"

            course_unresolved_param = request.args.get("course_unresolved", "").strip().lower()
            if course_unresolved_param in {"true", "false"}:
                query["course_unresolved"] = course_unresolved_param == "true"

            try:
                limit = int(request.args.get("limit", "50"))
            except ValueError:
                limit = 50
            limit = max(1, min(limit, 200))

            items = [
                _serialize_for_json(doc)
                for doc in db.tasks.find(query).sort([("created_at", -1)]).limit(limit)
            ]
            return jsonify({"items": items, "count": len(items)})
        except Exception as exc:
            app.logger.exception("list_tasks_failed error=%s", str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.get("/api/student/tasks")
    def list_student_tasks():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        try:
            ensure_mongo_indexes()
            query, limit = _task_filter_query_for_request(user.get("user_id", ""))
            raw_items = list(db.tasks.find(query))
            raw_items.sort(key=_task_sort_key)
            items = [_serialize_for_json(doc) for doc in raw_items[:limit]]

            return jsonify(
                {
                    "items": items,
                    "count": len(items),
                    "scope": "student",
                    "user_id": user.get("user_id", ""),
                }
            )
        except Exception as exc:
            app.logger.exception("list_student_tasks_failed error=%s", str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.patch("/api/student/tasks/<task_id>/status")
    def update_student_task_status(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        new_status = str(data.get("status", "")).strip().lower()
        if new_status not in {"pending", "completed", "needs_review"}:
            return jsonify({"error": "invalid_status"}), 400

        result = db.tasks.update_one(
            {"_id": oid, "user_id": user.get("user_id", "")},
            {
                "$set": {
                    "status": new_status,
                    "needs_review": new_status == "needs_review",
                    "updated_at": _utc_now(),
                }
            },
        )
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid, "user_id": user.get("user_id", "")})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.patch("/api/student/tasks/<task_id>")
    def update_student_task(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        allowed_fields = {
            "task_type",
            "parsed_course",
            "parsed_title",
            "quiz_material",
            "quiz_duration",
            "quiz_time",
            "status",
            "needs_review",
        }
        update_doc = {key: data[key] for key in allowed_fields if key in data}

        if "parsed_due_date" in data:
            parsed_due_date = _parse_due_date_value(str(data.get("parsed_due_date", "")))
            if str(data.get("parsed_due_date", "")).strip() and parsed_due_date is None:
                return jsonify({"error": "invalid_parsed_due_date"}), 400
            update_doc["parsed_due_date"] = parsed_due_date

        if not update_doc:
            return jsonify({"error": "no_updatable_fields"}), 400

        update_doc["corrected_at"] = _utc_now()
        update_doc["updated_at"] = _utc_now()
        if "needs_review" not in update_doc:
            update_doc["needs_review"] = False
        if "status" not in update_doc and not update_doc["needs_review"]:
            update_doc["status"] = "pending"

        result = db.tasks.update_one(
            {"_id": oid, "user_id": user.get("user_id", "")},
            {"$set": update_doc},
        )
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid, "user_id": user.get("user_id", "")})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.post("/api/student/tasks/<task_id>/confirm")
    def confirm_student_task(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        result = db.tasks.update_one(
            {"_id": oid, "user_id": user.get("user_id", "")},
            {
                "$set": {
                    "needs_review": False,
                    "status": "pending",
                    "course_unresolved": False,
                    "course_resolution_method": "manual",
                    "corrected_at": _utc_now(),
                    "updated_at": _utc_now(),
                }
            },
        )
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid, "user_id": user.get("user_id", "")})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.post("/api/student/tasks/<task_id>/assign-course")
    def assign_student_task_course(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        course_code = str(data.get("course_code", "")).strip().upper()
        apply_to_source = bool(data.get("apply_to_source", False))
        if not course_code:
            return jsonify({"error": "course_code_required"}), 400

        task = db.tasks.find_one({"_id": oid, "user_id": user.get("user_id", "")})
        if not task:
            return jsonify({"error": "task_not_found"}), 404

        db.tasks.update_one(
            {"_id": oid, "user_id": user.get("user_id", "")},
            {
                "$set": {
                    "parsed_course": course_code,
                    "course_unresolved": False,
                    "course_resolution_method": "manual",
                    "needs_review": False,
                    "status": "pending",
                    "corrected_at": _utc_now(),
                    "updated_at": _utc_now(),
                }
            },
        )

        mapping_saved = False
        source_key = str(task.get("source_key") or "")
        user_id = str(user.get("user_id") or "")
        if apply_to_source and source_key and source_key != "forwarded:unknown" and user_id:
            db.course_source_mappings.update_one(
                {"user_id": user_id, "source_key": source_key},
                {
                    "$set": {
                        "user_id": user_id,
                        "source_key": source_key,
                        "course_code": course_code,
                        "updated_at": _utc_now(),
                    },
                    "$setOnInsert": {"created_at": _utc_now()},
                },
                upsert=True,
            )
            mapping_saved = True

        updated = db.tasks.find_one({"_id": oid, "user_id": user.get("user_id", "")})
        return jsonify({"item": _serialize_for_json(updated), "mapping_saved": mapping_saved})

    @app.get("/api/student/course-mappings")
    def get_student_course_mappings():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        user_id = str(user.get("user_id") or "")
        items = [
            _serialize_for_json(doc)
            for doc in db.course_source_mappings.find({"user_id": user_id}, {"_id": 0}).sort("updated_at", -1)
        ]
        return jsonify({"items": items, "count": len(items)})

    @app.post("/api/student/course-mappings")
    def upsert_student_course_mapping():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        data = request.get_json(silent=True) or {}
        source_key = str(data.get("source_key", "")).strip()
        course_code = str(data.get("course_code", "")).strip().upper()
        if not source_key:
            return jsonify({"error": "source_key_required"}), 400
        if not course_code:
            return jsonify({"error": "course_code_required"}), 400

        user_id = str(user.get("user_id") or "")
        doc = {
            "user_id": user_id,
            "source_key": source_key,
            "course_code": course_code,
            "updated_at": _utc_now(),
        }
        db.course_source_mappings.update_one(
            {"user_id": user_id, "source_key": source_key},
            {"$set": doc, "$setOnInsert": {"created_at": _utc_now()}},
            upsert=True,
        )
        return jsonify({"item": _serialize_for_json(doc)})

    @app.delete("/api/student/course-mappings")
    def delete_student_course_mapping():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        source_key = request.args.get("source_key", "").strip()
        if not source_key:
            return jsonify({"error": "source_key_required"}), 400

        user_id = str(user.get("user_id") or "")
        result = db.course_source_mappings.delete_one({"user_id": user_id, "source_key": source_key})
        return jsonify({"deleted": result.deleted_count > 0, "source_key": source_key})

    @app.get("/api/student/reminders")
    def list_student_reminders():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error

        now = _utc_now()
        soon_boundary = now + timedelta(hours=48)
        query = {
            "user_id": user.get("user_id", ""),
            "status": {"$ne": "completed"},
            "parsed_due_date": {"$gte": now, "$lte": soon_boundary},
        }
        items = [
            _serialize_for_json(doc)
            for doc in db.tasks.find(query).sort([("parsed_due_date", 1), ("created_at", -1)]).limit(25)
        ]
        return jsonify({"items": items, "count": len(items), "window_hours": 48})

    @app.get("/api/courses/default")
    def default_courses():
        return jsonify({"items": SEMESTER_COURSES, "count": len(SEMESTER_COURSES)})

    @app.patch("/api/tasks/<task_id>/status")
    def update_task_status(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        new_status = str(data.get("status", "")).strip().lower()
        if new_status not in {"pending", "completed", "needs_review"}:
            return jsonify({"error": "invalid_status"}), 400

        update_doc = {
            "status": new_status,
            "needs_review": new_status == "needs_review",
            "updated_at": _utc_now(),
        }

        result = db.tasks.update_one({"_id": oid}, {"$set": update_doc})
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.patch("/api/tasks/<task_id>")
    def update_task(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        allowed_fields = {
            "task_type",
            "parsed_course",
            "parsed_title",
            "quiz_material",
            "quiz_duration",
            "quiz_time",
            "status",
            "needs_review",
        }
        update_doc = {key: data[key] for key in allowed_fields if key in data}

        if "parsed_due_date" in data:
            parsed_due_date = _parse_due_date_value(str(data.get("parsed_due_date", "")))
            if str(data.get("parsed_due_date", "")).strip() and parsed_due_date is None:
                return jsonify({"error": "invalid_parsed_due_date"}), 400
            update_doc["parsed_due_date"] = parsed_due_date

        if not update_doc:
            return jsonify({"error": "no_updatable_fields"}), 400

        update_doc["corrected_at"] = _utc_now()
        update_doc["updated_at"] = _utc_now()

        if "needs_review" not in update_doc:
            update_doc["needs_review"] = False
        if "status" not in update_doc and not update_doc["needs_review"]:
            update_doc["status"] = "pending"

        result = db.tasks.update_one({"_id": oid}, {"$set": update_doc})
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.post("/api/tasks/<task_id>/confirm")
    def confirm_task(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        result = db.tasks.update_one(
            {"_id": oid},
            {
                "$set": {
                    "needs_review": False,
                    "status": "pending",
                    "course_unresolved": False,
                    "course_resolution_method": "manual",
                    "corrected_at": _utc_now(),
                    "updated_at": _utc_now(),
                }
            },
        )
        if result.matched_count == 0:
            return jsonify({"error": "task_not_found"}), 404

        updated = db.tasks.find_one({"_id": oid})
        return jsonify({"item": _serialize_for_json(updated)})

    @app.post("/api/tasks/<task_id>/assign-course")
    def assign_task_course(task_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        oid = _parse_object_id(task_id)
        if oid is None:
            return jsonify({"error": "invalid_task_id"}), 400

        data = request.get_json(silent=True) or {}
        course_code = str(data.get("course_code", "")).strip()
        apply_to_source = bool(data.get("apply_to_source", False))

        if not course_code:
            return jsonify({"error": "course_code_required"}), 400

        task = db.tasks.find_one({"_id": oid})
        if not task:
            return jsonify({"error": "task_not_found"}), 404

        update_doc = {
            "parsed_course": course_code,
            "course_unresolved": False,
            "course_resolution_method": "manual",
            "needs_review": False,
            "status": "pending",
            "corrected_at": _utc_now(),
            "updated_at": _utc_now(),
        }
        db.tasks.update_one({"_id": oid}, {"$set": update_doc})

        mapping_saved = False
        source_key = str(task.get("source_key") or "")
        user_id = str(task.get("user_id") or "")
        if apply_to_source and source_key and source_key != "forwarded:unknown" and user_id:
            db.course_source_mappings.update_one(
                {"user_id": user_id, "source_key": source_key},
                {
                    "$set": {
                        "user_id": user_id,
                        "source_key": source_key,
                        "course_code": course_code,
                        "updated_at": _utc_now(),
                    },
                    "$setOnInsert": {
                        "created_at": _utc_now(),
                    },
                },
                upsert=True,
            )
            mapping_saved = True

        updated = db.tasks.find_one({"_id": oid})
        return jsonify({"item": _serialize_for_json(updated), "mapping_saved": mapping_saved})

    @app.get("/api/course-mappings/<user_id>")
    def get_course_mappings(user_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error
        if str(user.get("user_id") or "") != user_id:
            return jsonify({"error": "forbidden"}), 403

        try:
            ensure_mongo_indexes()
            items = [
                _serialize_for_json(doc)
                for doc in db.course_source_mappings.find({"user_id": user_id}, {"_id": 0}).sort("updated_at", -1)
            ]
            return jsonify({"items": items, "count": len(items)})
        except Exception as exc:
            app.logger.exception("get_course_mappings_failed user_id=%s error=%s", user_id, str(exc))
            return jsonify({"error": "database_unavailable", "detail": exc.__class__.__name__}), 503

    @app.post("/api/course-mappings/<user_id>")
    def upsert_course_mapping(user_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error
        if str(user.get("user_id") or "") != user_id:
            return jsonify({"error": "forbidden"}), 403

        data = request.get_json(silent=True) or {}
        source_key = str(data.get("source_key", "")).strip()
        course_code = str(data.get("course_code", "")).strip().upper()

        if not source_key:
            return jsonify({"error": "source_key_required"}), 400
        if not course_code:
            return jsonify({"error": "course_code_required"}), 400

        doc = {
            "user_id": user_id,
            "source_key": source_key,
            "course_code": course_code,
            "updated_at": _utc_now(),
        }
        db.course_source_mappings.update_one(
            {"user_id": user_id, "source_key": source_key},
            {
                "$set": doc,
                "$setOnInsert": {
                    "created_at": _utc_now(),
                },
            },
            upsert=True,
        )
        return jsonify({"item": _serialize_for_json(doc)})

    @app.delete("/api/course-mappings/<user_id>")
    def delete_course_mapping(user_id: str):
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        user, _, auth_error = resolve_authenticated_user_or_401(db)
        if auth_error:
            return auth_error
        if str(user.get("user_id") or "") != user_id:
            return jsonify({"error": "forbidden"}), 403

        source_key = request.args.get("source_key", "").strip()
        if not source_key:
            return jsonify({"error": "source_key_required"}), 400

        result = db.course_source_mappings.delete_one({"user_id": user_id, "source_key": source_key})
        return jsonify({"deleted": result.deleted_count > 0, "source_key": source_key})

    @app.get("/webhook")
    @app.get("/webhook/messages")
    def webhook_verify():
        """Handle webhook verification from Meta."""
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        
        verify_token = get_env("META_VERIFY_TOKEN", "WEBHOOK_VERIFY_TOKEN")
        
        if mode == "subscribe" and token == verify_token:
            return challenge, 200
        else:
            return "Unauthorized", 403

    @app.post("/webhook")
    @app.post("/webhook/messages")
    def webhook_receive():
        """Handle incoming WhatsApp messages from Meta."""
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        # Verify signature
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(request.data, signature):
            app.logger.warning(
                "webhook_signature_invalid request_id=%s signature_present=%s secret_configured=%s",
                request_id,
                bool(signature),
                bool(get_env("META_APP_SECRET", "WHATSAPP_APP_SECRET", "APP_SECRET")),
            )
            return jsonify({"error": "Invalid signature"}), 401

        try:
            data = request.get_json(silent=True)
            if not isinstance(data, dict):
                return jsonify({"error": "Invalid JSON payload"}), 400

            app.logger.info(
                "webhook_received request_id=%s body_bytes=%s",
                request_id,
                len(request.data),
            )

            result = process_webhook_payload(data, request_id=request_id)
            app.logger.info("webhook_processed request_id=%s result=%s", request_id, result)

            return jsonify({"status": "received", "request_id": request_id, "result": result}), 200
        except Exception as e:
            app.logger.exception("webhook_processing_failed request_id=%s error=%s", request_id, str(e))
            return jsonify({"error": "Internal server error", "request_id": request_id}), 500

    return app


app = create_app()

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_mode)
