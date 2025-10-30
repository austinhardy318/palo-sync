from typing import Optional, Dict, Any
from flask import jsonify


def ok(payload: Dict[str, Any], status: int = 200):
    """Return a plain JSON payload with HTTP status (keeps existing contracts)."""
    return jsonify(payload), status


def fail(
    message: str,
    status: int = 400,
    code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
    extra_top: Optional[Dict[str, Any]] = None,
):
    """Return a standardized error envelope, with optional extra data.

    extra: merged into error.details (deprecated; prefer details)
    extra_top: merged at top-level for backward-compatible shapes
    """
    error_obj: Dict[str, Any] = {"message": message}
    if code:
        error_obj["code"] = code
    if details:
        error_obj["details"] = details
    elif extra:  # backward-compat
        error_obj["details"] = extra

    body: Dict[str, Any] = {"success": False, "error": error_obj}
    if extra_top:
        body.update(extra_top)
    return jsonify(body), status


def unauthorized(message: str = "Authentication required"):
    return fail(message, status=401, code="UNAUTHORIZED")


def forbidden(message: str = "Forbidden"):
    return fail(message, status=403, code="FORBIDDEN")


def not_found(message: str = "Not found"):
    return fail(message, status=404, code="NOT_FOUND")


def validation_error(message: str = "Invalid input", details: Optional[Dict[str, Any]] = None):
    return fail(message, status=400, code="VALIDATION_FAILED", details=details)


