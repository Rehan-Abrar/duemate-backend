"""
Integration tests for the admin-managed official timetable system:
  - authorization (only admins can publish; students cannot)
  - publish gate (refuses empty/invalid parses)
  - draft → publish → student auto-uses official (no re-upload)
  - versions list / review diff
  - rollback re-activates a prior version
  - idempotency (double publish rejected)

The PDF parsing path is exercised separately; here we seed drafts directly so the
tests are deterministic and don't require a real Riphah-format PDF.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import mongomock
import jwt
import pytest

TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

import app as appmod
from utils.academic import get_user_academic_context

SECRET = "test-jwt-secret"


def _slot(day, time, course, section, instr="Dr X"):
    start, end = time.split("-")
    return {
        "day": day, "start_time": start, "end_time": end, "time": time,
        "course": course, "instructor": instr, "room": "R1", "section": section,
    }


@pytest.fixture
def ctx(monkeypatch):
    db = mongomock.MongoClient().db
    monkeypatch.setenv("JWT_SECRET", SECRET)  # used by utils.auth.verify_access_token
    monkeypatch.setattr(appmod, "get_mongo_db", lambda: db)
    monkeypatch.setattr(appmod, "JWT_SECRET", SECRET)  # used by admin_auth_required
    db.users.insert_one({
        "user_id": "admin:system", "username": "admin",
        "settings": {"is_admin": True},
    })
    application = appmod.create_app()
    application.testing = True
    return application.test_client(), db


def _token(user_id, secret=SECRET):
    return jwt.encode(
        {
            "sub": user_id,
            "user_id": user_id,
            "type": "access",  # required by utils.auth.verify_access_token
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        },
        secret, algorithm="HS256",
    )


def _admin_headers():
    return {"Authorization": f"Bearer {_token('admin:system')}"}


def _seed_draft(db, version, course, section="BSDS-4A"):
    doc = {
        "timetable_id": "riphah-fall-2026",
        "university_id": "riphah",
        "academic_term": "Fall 2026",
        "version": version,
        "status": "draft",
        "detected_sections": [section],
        "effective_from": None,
        "effective_to": None,
        "sections": {section: [_slot("Monday", "08:00-10:00", course, section)]},
    }
    return db.official_timetables.insert_one(doc).inserted_id


def _seed_student(db, user_id="wa:2", section="BSDS-4A"):
    db.users.insert_one({
        "user_id": user_id,
        "settings": {
            "timetable_section": section,
            "university_id": "riphah",
            "academic_term": "Fall 2026",
        },
    })


# ── authorization ─────────────────────────────────────────────────────────────

def test_publish_requires_auth(ctx):
    client, db = ctx
    vid = _seed_draft(db, 1, "Operating Systems")
    resp = client.post(f"/api/admin/timetable/{vid}/publish")
    assert resp.status_code == 401


def test_publish_forbidden_for_non_admin(ctx):
    client, db = ctx
    db.users.insert_one({"user_id": "wa:99", "settings": {}})
    vid = _seed_draft(db, 1, "Operating Systems")
    resp = client.post(
        f"/api/admin/timetable/{vid}/publish",
        headers={"Authorization": f"Bearer {_token('wa:99')}"},
    )
    assert resp.status_code == 403


# ── publish flow + student auto-use ─────────────────────────────────────────────

def test_publish_then_student_uses_official(ctx):
    client, db = ctx
    vid = _seed_draft(db, 1, "Operating Systems")
    _seed_student(db)

    resp = client.post(f"/api/admin/timetable/{vid}/publish", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "published"

    # Student never uploaded anything, yet gets the official timetable.
    sctx = get_user_academic_context(db, "wa:2")
    assert sctx["source"] == "official"
    assert sctx["timetable_version"] == 1
    assert "Operating Systems" in sctx["courses"]


def test_double_publish_rejected(ctx):
    client, db = ctx
    vid = _seed_draft(db, 1, "Operating Systems")
    client.post(f"/api/admin/timetable/{vid}/publish", headers=_admin_headers())
    resp = client.post(f"/api/admin/timetable/{vid}/publish", headers=_admin_headers())
    assert resp.status_code == 409


def test_publish_gate_rejects_empty(ctx):
    client, db = ctx
    doc = {
        "timetable_id": "riphah-fall-2026", "university_id": "riphah",
        "academic_term": "Fall 2026", "version": 1, "status": "draft",
        "detected_sections": [], "sections": {}, "effective_from": None, "effective_to": None,
    }
    vid = db.official_timetables.insert_one(doc).inserted_id
    resp = client.post(f"/api/admin/timetable/{vid}/publish", headers=_admin_headers())
    assert resp.status_code == 422


# ── new version supersedes; student auto-updates ─────────────────────────────────

def test_new_published_version_supersedes(ctx):
    client, db = ctx
    _seed_student(db)
    v1 = _seed_draft(db, 1, "Operating Systems")
    client.post(f"/api/admin/timetable/{v1}/publish", headers=_admin_headers())

    v2 = _seed_draft(db, 2, "Machine Learning")
    client.post(f"/api/admin/timetable/{v2}/publish", headers=_admin_headers())

    sctx = get_user_academic_context(db, "wa:2")
    assert sctx["timetable_version"] == 2
    assert "Machine Learning" in sctx["courses"]
    assert "Operating Systems" not in sctx["courses"]


def test_rollback_reactivates_prior_version(ctx):
    client, db = ctx
    _seed_student(db)
    v1 = _seed_draft(db, 1, "Operating Systems")
    client.post(f"/api/admin/timetable/{v1}/publish", headers=_admin_headers())
    v2 = _seed_draft(db, 2, "Machine Learning")
    client.post(f"/api/admin/timetable/{v2}/publish", headers=_admin_headers())

    resp = client.post(f"/api/admin/timetable/{v1}/rollback", headers=_admin_headers())
    assert resp.status_code == 200

    sctx = get_user_academic_context(db, "wa:2")
    assert sctx["timetable_version"] == 1
    assert "Operating Systems" in sctx["courses"]


# ── versions list / review ───────────────────────────────────────────────────

def test_versions_and_review(ctx):
    client, db = ctx
    vid = _seed_draft(db, 1, "Operating Systems")

    vresp = client.get("/api/admin/timetable/versions", headers=_admin_headers())
    assert vresp.status_code == 200
    items = vresp.get_json()["items"]
    assert any(i["version"] == 1 for i in items)

    rresp = client.get(f"/api/admin/timetable/{vid}/review", headers=_admin_headers())
    assert rresp.status_code == 200
    body = rresp.get_json()
    assert body["detected_sections"] == ["BSDS-4A"]
    assert "diff" in body


# ── onboarding discovery endpoints ──────────────────────────────────────────────

def test_timetable_available_endpoint(ctx):
    client, db = ctx
    _seed_student(db)
    v1 = _seed_draft(db, 1, "Operating Systems")
    client.post(f"/api/admin/timetable/{v1}/publish", headers=_admin_headers())

    resp = client.get(
        "/api/timetable/available?section=BSDS-4A&university_id=riphah&term=Fall 2026",
        headers={"Authorization": f"Bearer {_token('wa:2')}"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["available"] is True

    resp2 = client.get(
        "/api/timetable/available?section=NOPE-9Z",
        headers={"Authorization": f"Bearer {_token('wa:2')}"},
    )
    assert resp2.get_json()["available"] is False


def _student_headers(user_id="wa:2"):
    return {"Authorization": f"Bearer {_token(user_id)}"}


def _seed_published_sections(db, sections_map, academic_term="Fall 2026"):
    now = datetime.now(timezone.utc) - timedelta(days=1)
    db.official_timetables.insert_one({
        "timetable_id": "riphah-fall-2026",
        "university_id": "riphah",
        "academic_term": academic_term,
        "version": 1,
        "status": "published",
        "detected_sections": sorted(sections_map.keys()),
        "effective_from": now,
        "effective_to": None,
        "sections": sections_map,
    })


# ── Change class (official vs self-upload) ─────────────────────────────────────

def test_official_user_changes_section_without_user_timetables(ctx):
    client, db = ctx
    _seed_published_sections(db, {
        "BSCS-6A": [_slot("Monday", "08:00-10:00", "Operating Systems", "BSCS-6A")],
        "BSCS-6B": [_slot("Tuesday", "09:00-11:00", "Machine Learning", "BSCS-6B")],
    })
    _seed_student(db, user_id="wa:2", section="BSCS-6A")
    assert db.user_timetables.find_one({"user_id": "wa:2"}) is None

    before = client.get("/api/student/timetable", headers=_student_headers())
    assert before.status_code == 200
    assert any(s["course"] == "Operating Systems" for s in before.get_json())

    resp = client.post(
        "/api/student/timetable/select",
        json={"section": "BSCS-6B"},
        headers=_student_headers(),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["source"] == "official"
    assert body["section"] == "BSCS-6B"
    assert body["university_id"] == "riphah"
    assert body["academic_term"] == "Fall 2026"

    # No self-upload document is created.
    assert db.user_timetables.find_one({"user_id": "wa:2"}) is None

    user = db.users.find_one({"user_id": "wa:2"})
    settings = user["settings"]
    assert settings["timetable_section"] == "BSCS-6B"
    assert settings["university_id"] == "riphah"
    assert settings["academic_term"] == "Fall 2026"
    assert settings["program"] == "BSCS"
    assert settings["semester"] == 6

    after = client.get("/api/student/timetable", headers=_student_headers())
    courses = [s["course"] for s in after.get_json()]
    assert "Machine Learning" in courses
    assert "Operating Systems" not in courses

    ctx_after = get_user_academic_context(db, "wa:2")
    assert ctx_after["source"] == "official"
    assert ctx_after["section"] == "BSCS-6B"


def test_official_select_accepts_university_from_body(ctx):
    """Picker sends university_id + term so a student can bind without a PDF."""
    client, db = ctx
    _seed_published_sections(db, {
        "BSDS-4A": [_slot("Monday", "08:00-10:00", "Operating Systems", "BSDS-4A")],
        "BSDS-4B": [_slot("Wednesday", "10:00-12:00", "Data Mining", "BSDS-4B")],
    })
    db.users.insert_one({"user_id": "wa:3", "settings": {}})  # no university yet
    assert db.user_timetables.find_one({"user_id": "wa:3"}) is None

    resp = client.post(
        "/api/student/timetable/select",
        json={
            "section": "BSDS-4B",
            "university_id": "riphah",
            "academic_term": "Fall 2026",
        },
        headers=_student_headers("wa:3"),
    )
    assert resp.status_code == 200
    assert resp.get_json()["source"] == "official"
    assert db.user_timetables.find_one({"user_id": "wa:3"}) is None

    slots = client.get("/api/student/timetable", headers=_student_headers("wa:3")).get_json()
    assert any(s["course"] == "Data Mining" for s in slots)


def test_self_upload_select_unchanged_even_if_official_exists(ctx):
    """Classic PDF users (no university_id) keep the self-upload path."""
    client, db = ctx
    _seed_published_sections(db, {
        "BSCS-6B": [_slot("Tuesday", "09:00-11:00", "Machine Learning", "BSCS-6B")],
    })
    db.users.insert_one({"user_id": "wa:5", "settings": {}})
    db.user_timetables.insert_one({
        "user_id": "wa:5",
        "selected_section": "BSCS-6A",
        "sections": {
            "BSCS-6A": [_slot("Monday", "08:00-10:00", "Operating Systems", "BSCS-6A")],
            "BSCS-6B": [_slot("Tuesday", "09:00-11:00", "Computer Networks", "BSCS-6B")],
        },
    })

    resp = client.post(
        "/api/student/timetable/select",
        json={"section": "BSCS-6B"},
        headers=_student_headers("wa:5"),
    )
    assert resp.status_code == 200
    assert resp.get_json()["source"] == "self_upload"

    doc = db.user_timetables.find_one({"user_id": "wa:5"})
    assert doc["selected_section"] == "BSCS-6B"

    user = db.users.find_one({"user_id": "wa:5"})
    assert user["settings"]["timetable_section"] == "BSCS-6B"
    assert not user["settings"].get("university_id")

    slots = client.get("/api/student/timetable", headers=_student_headers("wa:5")).get_json()
    courses = [s["course"] for s in slots]
    assert "Computer Networks" in courses
    assert "Machine Learning" not in courses
    assert "Operating Systems" not in courses


def test_self_upload_select_still_requires_uploaded_pdf(ctx):
    client, db = ctx
    db.users.insert_one({"user_id": "wa:6", "settings": {}})
    resp = client.post(
        "/api/student/timetable/select",
        json={"section": "BSCS-6B"},
        headers=_student_headers("wa:6"),
    )
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "no_timetable_uploaded"
