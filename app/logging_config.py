"""
Structured logging configuration with correlation IDs
Provides request tracing and structured JSON logging
"""

import logging
import os
import sys
from typing import Any, Dict

import structlog
from structlog.stdlib import LoggerFactory


def configure_logging(json_logs: bool = None, log_level: str = None) -> None:
    """
    Configure structured logging with correlation IDs
    
    Args:
        json_logs: Whether to output JSON logs (default: auto-detect from LOG_FORMAT)
        log_level: Logging level (default: string from LOG_LEVEL env var or INFO)
    """
    # Determine log format
    if json_logs is None:
        log_format = os.getenv('LOG_FORMAT', 'text').lower()
        json_logs = log_format == 'json'
    
    # Determine log level
    if log_level is None:
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level, logging.INFO)
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )
    
    # Configure structlog processors
    processors = [
        structlog.contextvars.merge_contextvars,  # Merge context variables (correlation IDs)
        structlog.stdlib.add_log_level,  # Add log level
        structlog.stdlib.add_logger_name,  # Add logger name
        structlog.processors.TimeStamper(fmt="iso"),  # Add ISO timestamp
        structlog.processors.StackInfoRenderer(),  # Add stack info for exceptions
        structlog.processors.format_exc_info,  # Format exceptions
    ]
    
    if json_logs:
        # JSON output for production/log aggregation
        processors.append(structlog.processors.JSONRenderer())
    else:
        # Human-readable output for development
        processors.extend([
            structlog.dev.ConsoleRenderer(colors=True)  # Pretty console output
        ])
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger instance
    
    Args:
        name: Logger name (default: calling module name)
    
    Returns:
        Structured logger instance
    """
    if name is None:
        # Get calling module name
        import inspect
        frame = inspect.currentframe().f_back
        name = frame.f_globals.get('__name__', 'app')
    
    return structlog.get_logger(name)


def bind_request_id(request_id: str) -> None:
    """
    Bind request ID to current context for correlation
    
    Args:
        request_id: Unique request identifier
    """
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)


def bind_user(username: str = None) -> None:
    """
    Bind user information to current context
    
    Args:
        username: Username (will be hashed if LOG_SALT is set)
    """
    if username:
        # Hash username for privacy if LOG_SALT is set
        import hashlib
        salt = os.getenv('LOG_SALT')
        if salt:
            hashed = hashlib.sha256((username + salt).encode()).hexdigest()[:16]
            structlog.contextvars.bind_contextvars(user=hashed)
        else:
            structlog.contextvars.bind_contextvars(user=username)
    else:
        structlog.contextvars.bind_contextvars(user='anonymous')


def clear_context() -> None:
    """Clear all context variables"""
    structlog.contextvars.clear_contextvars()

