import os
from datetime import datetime, timezone
import hmac
import hashlib
import json
import logging
import uuid
from typing import Optional

from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import requests


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
    if isinstance(value, list):
        return [_serialize_for_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _serialize_for_json(val) for key, val in value.items()}
    return value


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
    _indexes_ready = True


def check_mongo_connectivity() -> bool:
    """Ping MongoDB to verify network/auth connectivity."""
    try:
        client = get_mongo_client()
        if client is None:
            return False
        client.admin.command("ping")
        return True
    except Exception:
        return False


def verify_webhook_signature(request_body: bytes, signature: str) -> bool:
    """Verify X-Hub-Signature-256 from Meta webhook."""
    app_secret = get_env("META_APP_SECRET")
    if not app_secret:
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
                sender_profile = contacts_map.get(sender, {}).get("profile", {}).get("name", "")
                message_type = message.get("type", "unknown")
                text_body = ""
                if message_type == "text":
                    text_body = message.get("text", {}).get("body", "")
                elif message_type in message and isinstance(message.get(message_type), dict):
                    text_body = json.dumps(message.get(message_type), ensure_ascii=True)

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

                summary["inbound_messages"] += 1

                ack_template = get_env(
                    "ACK_MESSAGE_TEMPLATE",
                    default="DueMate: Message received. We will process your request shortly.",
                )
                send_result = send_whatsapp_text_message(sender, ack_template) if sender else {"sent": False}
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
        mongo_connected = check_mongo_connectivity() if mongo_uri else False
        return jsonify(
            {
                "status": "ok",
                "utc_time": datetime.now(timezone.utc).isoformat(),
                "mongo_configured": bool(mongo_uri),
                "mongo_connected": mongo_connected,
                "meta_configured": bool(get_env("META_BEARER_TOKEN", "META_ACCESS_TOKEN")),
            }
        )

    @app.get("/api/messages/recent")
    def recent_messages():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

        ensure_mongo_indexes()
        try:
            limit = int(request.args.get("limit", "20"))
        except ValueError:
            limit = 20
        limit = max(1, min(limit, 100))

        cursor = db.messages.find({}, {"_id": 0}).sort("received_at", -1).limit(limit)
        items = [_serialize_for_json(doc) for doc in cursor]
        return jsonify({"items": items, "count": len(items)})

    @app.get("/api/delivery-status")
    def delivery_status():
        db = get_mongo_db()
        if db is None:
            return jsonify({"error": "database_not_configured"}), 503

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
            app.logger.warning("webhook_signature_invalid request_id=%s", request_id)
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
