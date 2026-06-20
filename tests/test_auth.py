import os
import sys
from datetime import timedelta

import mongomock
import pytest

# Make duemate-backend/utils importable: add duemate-backend to sys.path
TEST_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TEST_ROOT not in sys.path:
    sys.path.insert(0, TEST_ROOT)

from utils import auth


def setup_module(module):
    # Ensure predictable JWT secret for tests
    os.environ["JWT_SECRET"] = "test-jwt-secret"


def test_generate_and_hash_otp():
    otp = auth.generate_otp()
    assert isinstance(otp, str) and otp.isdigit() and len(otp) == 6

    otp_hash = auth.hash_otp(otp)
    assert isinstance(otp_hash, str) and otp_hash

    assert auth._verify_otp_hash(otp, otp_hash) is True
    assert auth._verify_otp_hash("000000", otp_hash) is False


def test_create_and_verify_otp_session_success_and_expiry():
    client = mongomock.MongoClient()
    db = client.testdb

    phone = "+15551234567"
    otp, expires_at = auth.create_otp_session(db, phone)
    assert isinstance(otp, str) and len(otp) == 6

    # Successful verification
    ok, err = auth.verify_otp_session(db, phone, otp)
    assert ok is True and err == ""

    # Create another OTP then force expiry
    otp2, _ = auth.create_otp_session(db, phone)

    # Manually set expires_at in DB to past
    db.otp_sessions.update_one({"phone_number": phone, "used": False}, {"$set": {"expires_at": auth.utc_now() - timedelta(minutes=1)}})

    ok2, err2 = auth.verify_otp_session(db, phone, otp2)
    assert ok2 is False
    assert err2 in ("otp_expired", "otp_invalid")


def test_access_and_refresh_token_lifecycle():
    client = mongomock.MongoClient()
    db = client.testdb

    user_id = "user123"

    # Access token
    token = auth.create_access_token(user_id)
    assert isinstance(token, str) and token

    payload = auth.verify_access_token(token)
    assert payload and payload.get("user_id") == user_id

    # Refresh token creation and verification
    raw, expires_at = auth.create_refresh_token(db, user_id)
    assert isinstance(raw, str) and raw

    found_user = auth.verify_refresh_token(db, raw)
    assert found_user == user_id

    # Revoke single token
    revoked = auth.revoke_refresh_token(db, raw)
    assert revoked is True

    # After revoke, verification should fail
    assert auth.verify_refresh_token(db, raw) is None

    # Create multiple tokens and revoke all for user
    t1, _ = auth.create_refresh_token(db, user_id)
    t2, _ = auth.create_refresh_token(db, user_id)
    count = auth.revoke_all_user_tokens(db, user_id)
    assert count >= 2
    assert auth.verify_refresh_token(db, t1) is None
    assert auth.verify_refresh_token(db, t2) is None
