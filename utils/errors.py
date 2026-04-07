"""
Centralized error handling for DueMate API.

Provides:
- Consistent error response schema
- Human-friendly error messages
- Flask error handlers
- Exception logging
"""

import logging
from functools import wraps
from typing import Callable, Optional

from flask import Flask, jsonify, Response

logger = logging.getLogger(__name__)


# Human-friendly error messages mapped to error codes
ERROR_MESSAGES = {
    # Authentication errors
    "unauthorized": "You need to be logged in to do that. Please sign in again.",
    "forbidden": "You don't have permission to access this resource.",
    "invalid_credentials": "That username or password doesn't match our records. Please try again.",
    "token_expired": "Your session has expired. Please sign in again.",
    "token_invalid": "Invalid authentication. Please sign in again.",
    
    # OTP errors
    "otp_expired": "That code has expired. Request a new one and try again.",
    "otp_invalid": "That code doesn't match. Double-check and try again — you have a few attempts left.",
    "otp_already_used": "That code has already been used. Request a new one.",
    "otp_rate_limited": "Too many OTP requests. Please wait a few minutes before trying again.",
    
    # Rate limiting
    "too_many_requests": "You're sending requests too quickly. Please wait a moment and try again.",
    
    # Webhook errors
    "invalid_signature": "This request didn't come from WhatsApp. Ignoring it.",
    "webhook_processing_failed": "We had trouble processing that message. Please try sending it again.",
    
    # Task errors
    "task_not_found": "We couldn't find that task. It may have been deleted.",
    "invalid_task_id": "That task ID doesn't look right. Please check and try again.",
    "no_updatable_fields": "Nothing to update. Please provide at least one field to change.",
    "invalid_status": "That's not a valid status. Use 'pending', 'completed', or 'needs_review'.",
    "invalid_parsed_due_date": "That date format doesn't look right. Please use ISO format (YYYY-MM-DD).",
    
    # Parsing errors
    "parse_failed": "We received your message but couldn't read the details. Open your dashboard to fill them in manually.",
    "groq_unavailable": "Our AI parser is temporarily unavailable. Your message was saved but may need manual review.",
    
    # Resource errors
    "course_code_required": "Please select or enter a course for this task.",
    "source_key_required": "A source identifier is required for this mapping.",
    "phone_number_required": "Please enter your WhatsApp number to continue.",
    "password_too_short": "Password must be at least 8 characters long.",
    "account_already_exists": "An account with this phone number already exists. Try logging in instead.",
    
    # System errors
    "database_not_configured": "Database connection is not available. Please try again later.",
    "database_unavailable": "We're having trouble connecting to the database. Please try again in a moment.",
    "internal_error": "Something went wrong on our end. Please try again in a moment.",
    "service_unavailable": "This service is temporarily unavailable. Please try again later.",
    
    # Validation errors
    "invalid_json": "The request data couldn't be processed. Please check the format.",
    "missing_required_field": "A required field is missing. Please check your input.",
}


def make_error_response(
    error_code: str,
    message: Optional[str] = None,
    details: Optional[dict] = None,
    status_code: int = 400
) -> tuple[Response, int]:
    """
    Create a standardized error response.
    
    Args:
        error_code: Snake_case error identifier
        message: Human-readable message (defaults to ERROR_MESSAGES lookup)
        details: Optional additional structured data
        status_code: HTTP status code
        
    Returns:
        Tuple of (Flask Response, status_code)
    """
    response_body = {
        "error": error_code,
        "message": message or ERROR_MESSAGES.get(error_code, "An error occurred.")
    }
    
    if details:
        response_body["details"] = details
    
    return jsonify(response_body), status_code


def register_error_handlers(app: Flask) -> None:
    """
    Register Flask error handlers for common exceptions.
    
    Should be called during app initialization.
    """
    
    @app.errorhandler(400)
    def bad_request(error):
        logger.warning(f"Bad request: {error}")
        return make_error_response("invalid_request", str(error.description) if hasattr(error, 'description') else None, status_code=400)
    
    @app.errorhandler(401)
    def unauthorized(error):
        return make_error_response("unauthorized", status_code=401)
    
    @app.errorhandler(403)
    def forbidden(error):
        return make_error_response("forbidden", status_code=403)
    
    @app.errorhandler(404)
    def not_found(error):
        return make_error_response("not_found", "The requested resource was not found.", status_code=404)
    
    @app.errorhandler(429)
    def rate_limited(error):
        return make_error_response("too_many_requests", status_code=429)
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.exception(f"Internal server error: {error}")
        return make_error_response("internal_error", status_code=500)
    
    @app.errorhandler(503)
    def service_unavailable(error):
        return make_error_response("service_unavailable", status_code=503)
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Catch-all handler for unhandled exceptions."""
        logger.exception(f"Unhandled exception: {error}")
        
        # In development, include error details
        import os
        if os.getenv("FLASK_ENV") == "development":
            return make_error_response(
                "internal_error",
                details={"exception": str(error), "type": error.__class__.__name__},
                status_code=500
            )
        
        return make_error_response("internal_error", status_code=500)


def handle_db_error(f: Callable) -> Callable:
    """
    Decorator to handle database errors consistently.
    
    Catches database exceptions and returns appropriate error responses.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            error_type = e.__class__.__name__
            logger.exception(f"Database error in {f.__name__}: {error_type}")
            
            if "timeout" in str(e).lower():
                return make_error_response(
                    "database_unavailable",
                    details={"retry_after_seconds": 5},
                    status_code=503
                )
            
            return make_error_response(
                "database_unavailable",
                details={"error_type": error_type},
                status_code=503
            )
    return wrapper
