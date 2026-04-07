"""
JWT and OTP authentication utilities for DueMate.

Provides:
- OTP generation, hashing, and verification
- JWT access token creation and validation
- Refresh token management
- Helper decorators for protected routes

Security notes:
- OTPs are bcrypt-hashed before storage (10-minute TTL)
- Access tokens are short-lived (15 minutes)
- Refresh tokens are long-lived (30 days by default), stored hashed
- All tokens use constant-time comparison
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Callable, Optional

import bcrypt
import jwt
from flask import g, jsonify, request, Response

logger = logging.getLogger(__name__)


def _get_refresh_token_expiry_days() -> int:
    """Get refresh token TTL in days from env with safe bounds."""
    raw = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS", os.getenv("SESSION_TTL_DAYS", "30")).strip()
    try:
        days = int(raw)
    except ValueError:
        days = 30
    return max(1, min(days, 90))

# JWT configuration
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 15
REFRESH_TOKEN_EXPIRY_DAYS = _get_refresh_token_expiry_days()


def get_jwt_secret() -> str:
    """Get JWT secret from environment."""
    secret = os.getenv("JWT_SECRET", "")
    if not secret:
        logger.error("JWT_SECRET not configured!")
        raise ValueError("JWT_SECRET environment variable is required")
    return secret


def get_jwt_refresh_secret() -> str:
    """Get JWT refresh secret from environment (falls back to JWT_SECRET)."""
    return os.getenv("JWT_REFRESH_SECRET", os.getenv("JWT_SECRET", ""))


def utc_now() -> datetime:
    """Get current UTC timestamp with timezone info."""
    return datetime.now(timezone.utc)


# ============================================================================
# OTP Functions
# ============================================================================

def generate_otp(length: int = 6) -> str:
    """
    Generate a cryptographically secure numeric OTP.
    
    Args:
        length: Number of digits (default: 6)
        
    Returns:
        String of random digits
    """
    return "".join(secrets.choice("0123456789") for _ in range(length))


def hash_otp(otp: str) -> str:
    """
    Hash an OTP using bcrypt for secure storage.
    
    Args:
        otp: Plain text OTP
        
    Returns:
        bcrypt hash string
    """
    return bcrypt.hashpw(otp.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_otp_hash(otp: str, otp_hash: str) -> bool:
    """
    Verify an OTP against its bcrypt hash.
    
    Args:
        otp: Plain text OTP to verify
        otp_hash: bcrypt hash from database
        
    Returns:
        True if OTP matches, False otherwise
    """
    try:
        return bcrypt.checkpw(otp.encode("utf-8"), otp_hash.encode("utf-8"))
    except Exception as e:
        logger.warning(f"OTP verification error: {e}")
        return False


def create_otp_session(db, phone_number: str) -> tuple[str, datetime]:
    """
    Generate OTP and store hashed in database.
    
    Invalidates any existing OTP for this phone number.
    
    Args:
        db: MongoDB database instance
        phone_number: E.164 formatted phone number
        
    Returns:
        Tuple of (plain_text_otp, expires_at)
    """
    now = utc_now()
    expires_at = now + timedelta(minutes=10)
    otp = generate_otp()
    
    # Invalidate existing sessions
    db.otp_sessions.update_many(
        {"phone_number": phone_number, "used": False},
        {"$set": {"used": True}}
    )
    
    # Create new session
    db.otp_sessions.insert_one({
        "phone_number": phone_number,
        "otp_hash": hash_otp(otp),
        "expires_at": expires_at,
        "used": False,
        "created_at": now,
    })
    
    logger.info(f"Created OTP session for phone ending in {phone_number[-4:]}")
    return otp, expires_at


def verify_otp_session(db, phone_number: str, otp: str) -> tuple[bool, str]:
    """
    Verify OTP against stored session.
    
    Marks session as used on success. Returns error code on failure.
    
    Args:
        db: MongoDB database instance
        phone_number: E.164 formatted phone number
        otp: Plain text OTP to verify
        
    Returns:
        Tuple of (success: bool, error_code: str)
        Error codes: "", "otp_expired", "otp_invalid", "otp_already_used"
    """
    now = utc_now()
    
    # Find valid session
    session = db.otp_sessions.find_one({
        "phone_number": phone_number,
        "used": False,
        "expires_at": {"$gt": now},
    })
    
    if not session:
        # Check if there was an expired session
        expired = db.otp_sessions.find_one({
            "phone_number": phone_number,
            "used": False,
            "expires_at": {"$lte": now},
        })
        if expired:
            return False, "otp_expired"
        return False, "otp_invalid"
    
    # Verify OTP
    if not _verify_otp_hash(otp, session["otp_hash"]):
        return False, "otp_invalid"
    
    # Mark as used
    db.otp_sessions.update_one(
        {"_id": session["_id"]},
        {"$set": {"used": True}}
    )
    
    logger.info(f"OTP verified for phone ending in {phone_number[-4:]}")
    return True, ""


# ============================================================================
# Convenience wrappers (for app.py import compatibility)
# ============================================================================

def create_otp(db, phone_number: str) -> tuple[str, datetime]:
    """Wrapper for create_otp_session for simpler import."""
    return create_otp_session(db, phone_number)


def verify_otp(db, phone_number: str, otp: str) -> tuple[bool, str]:
    """Wrapper for verify_otp_session for simpler import."""
    return verify_otp_session(db, phone_number, otp)


def create_access_token(user_id: str, extra_claims: Optional[dict] = None) -> str:
    """
    Create a short-lived JWT access token.
    
    Args:
        user_id: User identifier
        extra_claims: Optional additional JWT claims
        
    Returns:
        JWT token string
    """
    now = utc_now()
    expires_at = now + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
    
    payload = {
        "sub": user_id,  # Standard JWT subject claim
        "user_id": user_id,  # For backwards compatibility
        "type": "access",
        "iat": now,
        "exp": expires_at,
        **(extra_claims or {})
    }
    
    token = jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)
    return token


def create_refresh_token(db, user_id: str) -> tuple[str, datetime]:
    """
    Create a long-lived refresh token and store hash in database.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        
    Returns:
        Tuple of (token_string, expires_at)
    """
    now = utc_now()
    expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    
    # Generate opaque token
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    # Store in database
    db.refresh_tokens.insert_one({
        "user_id": user_id,
        "token_hash": token_hash,
        "expires_at": expires_at,
        "revoked": False,
        "created_at": now,
    })
    
    return raw_token, expires_at


def verify_access_token(token: str) -> Optional[dict]:
    """
    Verify and decode a JWT access token.
    
    Args:
        token: JWT token string
        
    Returns:
        Payload dict if valid, None if invalid
    """
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        
        if payload.get("type") != "access":
            return None
        
        return payload
        
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def verify_refresh_token(db, token: str) -> Optional[str]:
    """
    Verify a refresh token against database.
    
    Args:
        db: MongoDB database instance
        token: Raw refresh token
        
    Returns:
        user_id if valid, None if invalid
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = utc_now()
    
    record = db.refresh_tokens.find_one({"token_hash": token_hash})
    
    if not record:
        return None
    
    if record.get("revoked"):
        return None
    
    if record.get("expires_at", now) <= now:
        return None
    
    return record.get("user_id")


def revoke_refresh_token(db, token: str) -> bool:
    """
    Revoke a refresh token.
    
    Args:
        db: MongoDB database instance
        token: Raw refresh token
        
    Returns:
        True if token was found and revoked
    """
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    result = db.refresh_tokens.update_one(
        {"token_hash": token_hash},
        {"$set": {"revoked": True}}
    )
    return result.modified_count > 0


def revoke_all_user_tokens(db, user_id: str) -> int:
    """
    Revoke all refresh tokens for a user.
    
    Args:
        db: MongoDB database instance
        user_id: User identifier
        
    Returns:
        Number of tokens revoked
    """
    result = db.refresh_tokens.update_many(
        {"user_id": user_id, "revoked": False},
        {"$set": {"revoked": True}}
    )
    return result.modified_count


# ============================================================================
# Route Decorators
# ============================================================================

def extract_bearer_token() -> Optional[str]:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


def jwt_required(f: Callable) -> Callable:
    """
    Decorator to require valid JWT access token.
    
    Sets g.user_id and g.jwt_payload on success.
    Returns 401 error on failure.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = extract_bearer_token()
        
        if not token:
            return jsonify({
                "error": "unauthorized",
                "message": "You need to be logged in to do that. Please sign in again."
            }), 401
        
        payload = verify_access_token(token)
        if not payload:
            return jsonify({
                "error": "unauthorized",
                "message": "Invalid authentication. Please sign in again."
            }), 401
        
        g.user_id = payload.get("user_id")
        g.jwt_payload = payload
        
        return f(*args, **kwargs)
    return wrapper


def admin_required(f: Callable) -> Callable:
    """
    Decorator to require valid admin JWT token.
    
    Checks for admin flag in JWT payload or validates admin user.
    Sets g.user_id and g.is_admin on success.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = extract_bearer_token()
        
        if not token:
            # Check for Basic Auth fallback
            auth = request.authorization
            if auth:
                admin_username = os.getenv("ADMIN_USERNAME", "admin")
                admin_password = os.getenv("ADMIN_PASSWORD", "")
                
                if auth.username == admin_username and auth.password == admin_password:
                    g.user_id = "admin:system"
                    g.is_admin = True
                    return f(*args, **kwargs)
            
            response = jsonify({
                "error": "unauthorized",
                "message": "Admin access required."
            })
            response.headers["WWW-Authenticate"] = 'Basic realm="DueMate Admin"'
            return response, 401
        
        payload = verify_access_token(token)
        if not payload:
            return jsonify({
                "error": "unauthorized",
                "message": "Invalid admin credentials."
            }), 401
        
        # Check admin flag in token
        if payload.get("type") != "admin" and not payload.get("is_admin"):
            return jsonify({
                "error": "forbidden",
                "message": "Admin access required."
            }), 403
        
        g.user_id = payload.get("user_id")
        g.is_admin = True
        
        return f(*args, **kwargs)
    return wrapper
