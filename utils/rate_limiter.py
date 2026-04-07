"""
In-memory rate limiting for DueMate API endpoints.

Implements per-IP and per-phone-number rate limiting using a simple
in-memory store with automatic expiry. Suitable for single-instance
deployment on Render.com.

Known limitation: State is lost on server restart. Acceptable for MVP
since Render restarts are infrequent with keep-alive pings.
"""

import logging
import time
from dataclasses import dataclass, field
from functools import wraps
from threading import Lock
from typing import Callable, Optional

from flask import jsonify, request, Response

logger = logging.getLogger(__name__)


@dataclass
class RateLimitEntry:
    """Tracks request counts for a single key within a time window."""
    count: int = 0
    window_start: float = field(default_factory=time.time)
    
    def reset_if_window_expired(self, window_seconds: int) -> None:
        """Reset counter if the time window has passed."""
        now = time.time()
        if now - self.window_start >= window_seconds:
            self.count = 0
            self.window_start = now
    
    def increment(self) -> int:
        """Increment and return new count."""
        self.count += 1
        return self.count
    
    def seconds_until_reset(self, window_seconds: int) -> int:
        """Calculate seconds until the rate limit window resets."""
        elapsed = time.time() - self.window_start
        return max(1, int(window_seconds - elapsed))


class RateLimiter:
    """
    Thread-safe in-memory rate limiter.
    
    Tracks request counts per key within sliding time windows.
    Automatically cleans up stale entries to prevent memory growth.
    """
    
    def __init__(self, cleanup_interval: int = 300):
        self._store: dict[str, RateLimitEntry] = {}
        self._lock = Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = cleanup_interval
    
    def _cleanup_stale_entries(self, max_age_seconds: int = 600) -> None:
        """Remove entries older than max_age_seconds."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        stale_keys = [
            key for key, entry in self._store.items()
            if now - entry.window_start > max_age_seconds
        ]
        for key in stale_keys:
            del self._store[key]
        
        self._last_cleanup = now
        if stale_keys:
            logger.debug(f"Cleaned up {len(stale_keys)} stale rate limit entries")
    
    def is_allowed(
        self,
        key: str,
        max_requests: int,
        window_seconds: int
    ) -> tuple[bool, int, int]:
        """
        Check if a request is allowed for the given key.
        
        Args:
            key: Unique identifier (e.g., IP address, phone number)
            max_requests: Maximum allowed requests in the window
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (allowed: bool, current_count: int, retry_after_seconds: int)
        """
        with self._lock:
            self._cleanup_stale_entries()
            
            if key not in self._store:
                self._store[key] = RateLimitEntry()
            
            entry = self._store[key]
            entry.reset_if_window_expired(window_seconds)
            
            current = entry.increment()
            retry_after = entry.seconds_until_reset(window_seconds)
            
            return current <= max_requests, current, retry_after
    
    def get_remaining(self, key: str, max_requests: int, window_seconds: int) -> int:
        """Get remaining requests allowed for a key."""
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return max_requests
            
            entry.reset_if_window_expired(window_seconds)
            return max(0, max_requests - entry.count)


# Global rate limiter instance
_limiter = RateLimiter()


def make_rate_limit_error_response(retry_after: int) -> tuple[Response, int]:
    """Create a human-friendly rate limit error response."""
    return jsonify({
        "error": "too_many_requests",
        "message": "You're sending requests too quickly. Please wait a moment and try again.",
        "retry_after_seconds": retry_after
    }), 429


def get_client_ip() -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (set by Render/load balancers)
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Take the first IP in the chain (original client)
        return forwarded.split(",")[0].strip()
    
    # Fall back to direct connection IP
    return request.remote_addr or "unknown"


def rate_limit_ip(
    max_requests: int = 30,
    window_seconds: int = 60
) -> Callable:
    """
    Decorator to apply per-IP rate limiting.
    
    Args:
        max_requests: Maximum requests allowed per window (default: 30)
        window_seconds: Time window in seconds (default: 60)
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = get_client_ip()
            key = f"ip:{ip}"
            
            allowed, count, retry_after = _limiter.is_allowed(
                key, max_requests, window_seconds
            )
            
            if not allowed:
                logger.warning(
                    f"Rate limit exceeded for IP {ip}: {count}/{max_requests} "
                    f"in {window_seconds}s window"
                )
                return make_rate_limit_error_response(retry_after)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def rate_limit_phone(
    limit: int = 5,
    window_minutes: int = 10,
    phone_param: str = "phone_number"
) -> Callable:
    """
    Decorator to apply per-phone-number rate limiting.
    
    Extracts phone_number from JSON request body.
    
    Args:
        limit: Maximum requests allowed per window (default: 5)
        window_minutes: Time window in minutes (default: 10)
        phone_param: Name of the JSON field containing phone number
    """
    window_seconds = window_minutes * 60
    
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True) or {}
            phone = str(data.get(phone_param, "")).strip()
            
            if not phone:
                # Can't rate limit without phone, let the endpoint handle validation
                return f(*args, **kwargs)
            
            # Normalize phone number to digits only
            phone_digits = "".join(c for c in phone if c.isdigit())
            key = f"phone:{phone_digits}"
            
            allowed, count, retry_after = _limiter.is_allowed(
                key, limit, window_seconds
            )
            
            if not allowed:
                logger.warning(
                    f"Rate limit exceeded for phone {phone_digits[-4:] if len(phone_digits) >= 4 else 'XXXX'}: "
                    f"{count}/{limit} in {window_minutes} min window"
                )
                return make_rate_limit_error_response(retry_after)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def check_webhook_rate_limit() -> Optional[tuple[Response, int]]:
    """
    Check rate limit for webhook endpoint (60 req/min per IP).
    
    Returns None if allowed, or (error_response, status_code) if rate limited.
    Called directly in webhook handler before signature validation.
    """
    ip = get_client_ip()
    key = f"webhook:{ip}"
    
    allowed, count, retry_after = _limiter.is_allowed(key, 60, 60)
    
    if not allowed:
        logger.warning(f"Webhook rate limit exceeded for IP {ip}: {count}/60 per minute")
        return make_rate_limit_error_response(retry_after)
    
    return None
