import os
from datetime import datetime, timezone
import hmac
import hashlib
import json

from flask import Flask, jsonify, request


def verify_webhook_signature(request_body: bytes, signature: str) -> bool:
    """Verify X-Hub-Signature-256 from Meta webhook."""
    app_secret = os.getenv("META_APP_SECRET", "")
    if not app_secret:
        return False
    
    expected_signature = hmac.new(
        app_secret.encode(),
        request_body,
        hashlib.sha256
    ).hexdigest()
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(f"sha256={expected_signature}", signature)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me"))

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
        return jsonify(
            {
                "status": "ok",
                "utc_time": datetime.now(timezone.utc).isoformat(),
                "mongo_configured": bool(os.getenv("MONGO_URI")),
                "meta_configured": bool(os.getenv("META_ACCESS_TOKEN")),
            }
        )

    @app.get("/webhook")
    @app.get("/webhook/messages")
    def webhook_verify():
        """Handle webhook verification from Meta."""
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        
        verify_token = os.getenv("WEBHOOK_VERIFY_TOKEN", "")
        
        if mode == "subscribe" and token == verify_token:
            return challenge, 200
        else:
            return "Unauthorized", 403

    @app.post("/webhook")
    @app.post("/webhook/messages")
    def webhook_receive():
        """Handle incoming WhatsApp messages from Meta."""
        # Verify signature
        signature = request.headers.get("X-Hub-Signature-256", "")
        if not verify_webhook_signature(request.data, signature):
            return jsonify({"error": "Invalid signature"}), 401
        
        try:
            data = request.get_json()
            print(f"[WEBHOOK] Received: {json.dumps(data, indent=2)}")
            
            # TODO: Parse message and store in MongoDB
            # TODO: Send immediate feedback reply via WhatsApp
            
            return jsonify({"status": "received"}), 200
        except Exception as e:
            print(f"[ERROR] Webhook processing failed: {e}")
            return jsonify({"error": str(e)}), 500

    return app


app = create_app()

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_mode)
