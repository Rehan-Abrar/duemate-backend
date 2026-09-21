"""
End-to-end: the LATEST RSCI timetable PDF must upload successfully through the
real API endpoint (this is the user-facing path that was broken - the parser's
layout gate rejected the file, so uploads returned 422 unsupported_layout).

POST /api/student/timetable/upload -> validate_layout() -> parse_all() -> Mongo.
"""

import io
import os
import sys
from datetime import datetime, timedelta, timezone

import jwt
import mongomock
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import app as appmod  # noqa: E402

SECRET = "test-jwt-secret"


@pytest.fixture
def ctx(monkeypatch):
    db = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: db)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)
    db.users.insert_one({"user_id": "wa:7", "settings": {}})
    application = appmod.create_app()
    application.testing = True
    return application.test_client(), db


def _token(user_id):
    return jwt.encode(
        {
            "sub": user_id,
            "user_id": user_id,
            "type": "access",  # required by utils.auth.verify_access_token
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        SECRET,
        algorithm="HS256",
    )


def test_latest_pdf_upload_succeeds(ctx, latest_timetable_pdf):
    client, db = ctx
    with open(latest_timetable_pdf, "rb") as f:
        pdf_bytes = f.read()

    resp = client.post(
        "/api/student/timetable/upload",
        data={"file": (io.BytesIO(pdf_bytes), "Latest-Timetable.pdf")},
        headers={"Authorization": f"Bearer {_token('wa:7')}"},
        content_type="multipart/form-data",
    )

    assert resp.status_code == 200, resp.get_data(as_text=True)

    # The endpoint returns the list of detected section names (for the picker).
    sections = resp.get_json()["sections"]
    assert isinstance(sections, list), sections
    assert "BSCS-7B" in sections, sections[:10]
    assert len(sections) >= 30, f"only {len(sections)} sections detected"

    # The full slots are persisted under the same shape parse_all() produced.
    stored = db.user_timetables.find_one({"user_id": "wa:7"})
    assert stored is not None
    assert len(stored["sections"]["BSCS-7B"]) == 7
    assert stored["pdf_name"] == "Latest-Timetable.pdf"
    assert stored["selected_section"] is None


def test_upload_requires_auth(ctx):
    client, _ = ctx
    resp = client.post("/api/student/timetable/upload")
    assert resp.status_code == 401
