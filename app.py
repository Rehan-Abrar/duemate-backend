import os
from datetime import datetime, timezone

from flask import Flask, jsonify


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

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
                "mongo_configured": bool(os.getenv("MONGODB_URI")),
                "meta_configured": bool(os.getenv("META_BEARER_TOKEN")),
            }
        )

    return app


app = create_app()

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug_mode)
