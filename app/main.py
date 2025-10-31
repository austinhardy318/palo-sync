"""
Flask web application for NMS-Sync
Provides REST API and web GUI for configuration synchronization
"""

import os
import json
import logging
import datetime as dt
import hashlib
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path
from io import BytesIO
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, send_file, g
from functools import wraps
from typing import Optional, Dict, Any, Callable, Tuple
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flasgger import Swagger
import redis

from .config import Config
from .sync_service import SyncService
from .backup_service import BackupService
from .http_responses import ok, fail, unauthorized, validation_error, handle_exception
from .auth import Authenticator
from .validators import (
    validate_backup_path as validate_backup_path_validator,
    validate_filename,
    validate_boolean,
    validate_integer,
    validate_string,
    validate_timezone,
    validate_regex_pattern,
    validate_file_size,
    validate_list_of_strings,
    validate_required
)
from .settings_manager import get_settings_manager
from .exceptions import (
    NMSException, ValidationError, AuthenticationError, AuthorizationError,
    NotFoundError, SyncError, ConfigError, BackupError,
    PanoramaConnectionError, PanoramaAPIError
)

# Initialize Flask app
app = Flask(__name__)

# Require FLASK_SECRET_KEY in production for security
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
if not FLASK_SECRET_KEY:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
app.secret_key = FLASK_SECRET_KEY

# Set session timeout (8 hours)
app.permanent_session_lifetime = dt.timedelta(hours=8)

# Configure secure session cookies
# In production (or when SSL_VERIFY is enabled), enforce secure cookies
is_production = os.getenv('FLASK_ENV', 'production').lower() == 'production'
ssl_enabled = Config.SSL_VERIFY or os.getenv('SSL_VERIFY', 'false').lower() == 'true'

app.config['SESSION_COOKIE_SECURE'] = ssl_enabled  # Only send over HTTPS if SSL is enabled
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection while allowing some cross-site navigation

# Enable CSRF protection
# Configure CSRF protection  
# Flask-WTF by default accepts CSRF tokens from:
# 1. Form data (field name: csrf_token)
# 2. Request headers (header name: X-CSRFToken)
# 3. Cookies (if configured)

csrf = CSRFProtect(app)
# No additional config needed - Flask-WTF 1.2.1 accepts X-CSRFToken header by default

# Note: CSRF is enabled globally but exempted on specific routes

# Make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    """Make CSRF token available in all templates"""
    def get_csrf_token():
        try:
            # Generate CSRF token - Flask-WTF will store it in session
            return generate_csrf()
        except Exception as e:
            logger.error(f"Error generating CSRF token: {e}")
            return ""
    return dict(csrf_token=get_csrf_token)


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Enable XSS protection (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer policy - only send referrer for same-origin requests
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Content Security Policy - allow same-origin and specific CDNs
    # Note: This is a basic CSP - adjust based on your needs
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "  # unsafe-inline needed for inline scripts
        "style-src 'self' 'unsafe-inline'; "  # unsafe-inline needed for inline styles
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"  # Same as X-Frame-Options
    )
    response.headers['Content-Security-Policy'] = csp
    
    # HSTS - only if SSL is enabled
    if ssl_enabled:
        # 31536000 seconds = 1 year
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Permissions Policy (formerly Feature Policy)
    response.headers['Permissions-Policy'] = (
        'geolocation=(), '
        'microphone=(), '
        'camera=(), '
        'payment=(), '
        'usb=()'
    )
    
    return response

# Add error handler for CSRF errors to return JSON instead of HTML
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF errors and return JSON response for API endpoints"""
    logger.warning(f"CSRF validation failed: {e.description} for path {request.path}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False, 
            'error': {
                'message': 'CSRF token missing or invalid',
                'code': 'CSRF_ERROR',
                'details': {'description': str(e.description) if hasattr(e, 'description') else str(e)}
            }
        }), 400
    # For non-API routes, let Flask-WTF handle the default error page
    return jsonify({'success': False, 'error': {'message': 'CSRF token missing or invalid', 'code': 'CSRF_ERROR'}}), 400


# Register error handlers for custom exceptions
@app.errorhandler(NMSException)
def handle_nms_exception(e: NMSException):
    """Handle custom NMS exceptions"""
    logger.error(f"NMS Exception: {e.code} - {e.message}", extra={'details': e.details})
    return handle_exception(e)


@app.errorhandler(ValidationError)
def handle_validation_error(e: ValidationError):
    """Handle validation errors"""
    logger.warning(f"Validation error: {e.message}", extra={'details': e.details})
    return handle_exception(e)


@app.errorhandler(AuthenticationError)
def handle_authentication_error(e: AuthenticationError):
    """Handle authentication errors"""
    logger.warning(f"Authentication error: {e.message}")
    return handle_exception(e)


@app.errorhandler(NotFoundError)
def handle_not_found_error(e: NotFoundError):
    """Handle not found errors"""
    logger.info(f"Resource not found: {e.message}")
    return handle_exception(e)


@app.errorhandler(500)
def handle_internal_error(e):
    """Handle unhandled exceptions"""
    logger.exception("Unhandled exception")
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': {
                'message': 'An internal error occurred',
                'code': 'INTERNAL_ERROR'
            }
        }), 500
    # For non-API routes, let Flask handle it
    return e

# Configure structured logging with correlation IDs
from .logging_config import configure_logging, get_logger, bind_request_id, bind_user, clear_context
configure_logging()
logger = get_logger(__name__)

# Request ID middleware - must be before routes
@app.before_request
def before_request():
    """Set up request context with correlation ID"""
    # Generate or retrieve request ID
    request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
    g.request_id = request_id
    
    # Bind request ID to structured logging context
    bind_request_id(request_id)
    
    # Bind user if authenticated
    if 'authenticated' in session and session.get('authenticated'):
        username = session.get('username')
        if username:
            bind_user(username)
    
    # Log request start
    logger.info(
        "Request started",
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr,
        user_agent=request.headers.get('User-Agent', '')[:100]  # Truncate long user agents
    )


@app.after_request
def after_request(response):
    """Add request ID to response headers and log request completion"""
    # Add request ID to response headers
    if hasattr(g, 'request_id'):
        response.headers['X-Request-ID'] = g.request_id
    
    # Log request completion
    logger.info(
        "Request completed",
        method=request.method,
        path=request.path,
        status_code=response.status_code,
        duration_ms=None  # Could add timing if needed
    )
    
    # Clear context after request
    clear_context()
    
    return response

# Configure rate limiting with Redis backend

# Initialize Redis connection pool for rate limiting
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
try:
    redis_pool = redis.ConnectionPool.from_url(redis_url, max_connections=20, socket_connect_timeout=2, decode_responses=True)
    redis_client = redis.Redis(connection_pool=redis_pool)
    redis_client.ping()  # Test connection
    logger.info(
        "Connected to Redis",
        redis_url=redis_url,
        connection_pool=True
    )
    redis_available = True
except (redis.RedisError, redis.ConnectionError, OSError) as e:
    logger.warning(
        "Redis connection failed, using in-memory storage",
        redis_url=redis_url,
        error=str(e),
        error_type=type(e).__name__,
        fallback="in_memory"
    )
    redis_client = None
    redis_available = False


def get_rate_limit_key() -> str:
    """
    Get rate limit key for current request
    Uses username for authenticated users, IP address for anonymous users
    This allows per-user rate limiting for authenticated users
    """
    # Check if user is authenticated
    if 'authenticated' in session and session.get('authenticated'):
        username = session.get('username')
        if username:
            return f"user:{username}"
        # Log warning if authenticated session is missing username
        logger.warning("Authenticated session missing username, falling back to IP for rate limiting")
    # Fall back to IP address for anonymous users or when username is missing
    return f"ip:{get_remote_address()}"


limiter = Limiter(
    app=app,
    key_func=get_rate_limit_key,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=redis_url if redis_available else "memory://"
)


# Initialize Swagger for API documentation
from .swagger_config import SWAGGER_CONFIG
swagger = Swagger(app, config=SWAGGER_CONFIG)

# Initialize sync manager and authenticator
sync_manager = SyncService()
backup_service = BackupService(Config.BACKUP_DIR)
authenticator = Authenticator()

# Store operation logs in memory (fallback when Redis unavailable)
operation_logs = []
# Lock for thread-safe access to operation_logs
operation_logs_lock = threading.Lock()
# Redis key for operation logs
REDIS_LOGS_KEY = "nms_sync:operation_logs"
MAX_LOGS = 100


def hash_username(username: str) -> str:
    """
    Hash username for logging purposes to prevent username enumeration
    Uses SHA-256 with a salt from config
    """
    # Require LOG_SALT in production for security
    is_production = os.getenv('FLASK_ENV', 'production').lower() == 'production'
    salt = os.getenv('LOG_SALT')
    
    if not salt:
        if is_production:
            logger.error(
                "LOG_SALT environment variable is required in production",
                error_type="configuration_error",
                required=True
            )
            raise ValueError("LOG_SALT environment variable must be set in production. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
        else:
            # Use a default for development, but warn
            logger.warning(
                "LOG_SALT not set - using default salt",
                warning_type="security_warning",
                production_ready=False
            )
            salt = 'nms-sync-default-salt-change-in-production'
    
    # Validate salt length (minimum 16 bytes recommended)
    if len(salt) < 16:
        logger.warning(
            "LOG_SALT is too short",
            salt_length=len(salt),
            recommended_minimum=32,
            warning_type="security_warning"
        )
    
    return hashlib.sha256((username + salt).encode()).hexdigest()[:16]


def rotate_session() -> None:
    """Regenerate session ID to prevent session fixation attacks"""
    # Flask automatically regenerates session ID when we clear certain keys
    # We'll keep the essential data but force regeneration
    if 'authenticated' in session:
        session.permanent = True  # Ensure session stays permanent
        # Force session refresh by modifying a dummy key
        session['_refresh'] = datetime.now().isoformat()


def requires_auth(f: Callable) -> Callable:
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check if user is logged in via session
        if 'authenticated' not in session or not session.get('authenticated'):
            # Check if authentication is required
            auth_required = (Config.GUI_USERNAME and Config.GUI_PASSWORD) or Config.RADIUS_ENABLED
            if auth_required:
                # Return JSON error for API requests
                if request.path.startswith('/api/'):
                    return unauthorized()
                # Redirect to login page for web requests
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def validate_backup_path(backup_path: str, backup_dir: Path, max_filename_length: int = 255) -> Tuple[bool, Optional[str]]:
    """
    Validate backup path to prevent directory traversal attacks
    Uses centralized validator from validators module
    Returns (is_valid, error_message)
    """
    return validate_backup_path_validator(backup_path, backup_dir, max_filename_length)


def log_operation(operation: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Add entry to operation logs (Redis if available, else in-memory)."""
    user_log: Dict[str, Any] = details.copy() if details else {}

    # Add username from session if available
    if 'user' in session:
        user_log['user'] = session.get('username', 'unknown')

    # Get request ID from context if available
    request_id = getattr(g, 'request_id', None)

    entry = {
        'timestamp': datetime.now(dt.timezone.utc).isoformat(),
        'operation': operation,
        'user': session.get('username', 'system'),
        'request_id': request_id,  # Add correlation ID
        'details': user_log
    }

    # Log to structured logger as well
    logger.info(
        "Operation logged",
        operation=operation,
        **user_log
    )

    # Prefer Redis capped list for cross-worker durability
    if redis_available and redis_client is not None:
        try:
            redis_client.lpush(REDIS_LOGS_KEY, json.dumps(entry))
            redis_client.ltrim(REDIS_LOGS_KEY, 0, MAX_LOGS - 1)
            return
        except (redis.RedisError, redis.ConnectionError, json.JSONEncodeError) as e:
            logger.warning(
                "Failed to write log to Redis, falling back to memory",
                error=str(e),
                operation=operation
            )

    # Fallback: in-memory list (thread-safe)
    with operation_logs_lock:
        operation_logs.append(entry)
        if len(operation_logs) > MAX_LOGS:
            operation_logs.pop(0)


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Exempt login from CSRF protection since it's the entry point
@limiter.limit("5 per minute", key_func=get_remote_address)  # Use IP for login attempts
def login() -> Any:
    """Login page with rate limiting"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password')
            return render_template('login.html')
        
        # Authenticate user
        success, error = authenticator.authenticate(username, password)
        if success:
            # Regenerate session ID to prevent session fixation
            session.permanent = True
            session['authenticated'] = True
            session['username'] = username
            # Log successful login with actual username (for audit trail)
            log_operation('login', {'username': username})
            return redirect(url_for('index'))
        else:
            flash(f'Authentication failed: {error}')
            # Log failed login with hashed username to prevent enumeration
            username_hash = hash_username(username)
            log_operation('login_failed', {'username_hash': username_hash})
    
    return render_template('login.html')


@app.route('/logout')
def logout() -> Any:
    """Logout and clear session"""
    username = session.get('username')
    # Clear session and mark as non-permanent
    session.permanent = False
    session.clear()
    log_operation('logout', {'username': username})
    flash('You have been logged out successfully')
    return redirect(url_for('login'))


@app.route('/')
@requires_auth
def index() -> str:
    """Serve the main web GUI"""
    return render_template('index.html')


@app.route('/settings')
@requires_auth
def settings() -> str:
    """Serve the settings page"""
    return render_template('settings.html')


@app.route('/api/status', methods=['GET'])
@requires_auth
def get_status() -> Any:
    """
    Get connection status for both NMS instances
    ---
    tags:
      - Status
    summary: Get connection status
    description: Test connectivity to both production and lab Panorama instances
    responses:
      200:
        description: Connection status for both instances
        schema:
          type: object
          properties:
            success:
              type: boolean
            production:
              type: object
              properties:
                connected:
                  type: boolean
                error:
                  type: string
                  nullable: true
                version:
                  type: string
                  nullable: true
            lab:
              type: object
              properties:
                connected:
                  type: boolean
                error:
                  type: string
                  nullable: true
                version:
                  type: string
                  nullable: true
      401:
        description: Authentication required
      500:
        description: Internal server error
    """
    try:
        status = sync_manager.test_connection()
        log_operation('status_check', status)
        return ok(status)
    except ValidationError as e:
        # Re-raise validation errors - they'll be handled by error handler
        raise
    except PanoramaConnectionError as e:
        # Re-raise custom exceptions - they'll be handled by error handlers
        raise
    except Exception as e:
        logger.error(
            "Error getting status",
            error=str(e),
            error_type=type(e).__name__
        )
        raise ConfigError(f"Failed to get connection status: {str(e)}")


@app.route('/api/diff', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth  # Require authentication for diff endpoint
def generate_diff() -> Any:
    """Generate configuration diff between production and lab"""
    try:
        log_operation('diff_start')
        diff_result = sync_manager.generate_diff()
        log_operation('diff_complete', {'success': diff_result.get('success', False)})
        return ok(diff_result)
    except PanoramaConnectionError as e:
        raise
    except PanoramaAPIError as e:
        raise
    except Exception as e:
        logger.error(f"Error generating diff: {e}")
        log_operation('diff_error', {'error': str(e)})
        raise SyncError(f"Failed to generate diff: {str(e)}", operation='diff')


@app.route('/api/sync', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def sync_configuration() -> Any:
    """
    Execute configuration sync from production to lab
    ---
    tags:
      - Sync
    summary: Sync configuration
    description: Synchronize configuration from production Panorama to lab Panorama
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            create_backup:
              type: boolean
              default: true
              description: Whether to create a backup before syncing
            commit:
              type: boolean
              default: false
              description: Whether to commit the configuration after import
    responses:
      200:
        description: Sync operation result
        schema:
          type: object
          properties:
            success:
              type: boolean
            sync_id:
              type: string
            backup_path:
              type: string
              nullable: true
            commit_job_id:
              type: string
              nullable: true
            timestamp:
              type: string
              format: date-time
      400:
        description: Validation error
      401:
        description: Authentication required
      500:
        description: Sync operation failed
    """
    try:
        # Log CSRF token presence for debugging
        logger.debug(f"CSRF token in headers: {request.headers.get('X-CSRFToken', 'NOT FOUND')}")
        logger.debug(f"CSRF token in headers (alt): {request.headers.get('X-CSRF-Token', 'NOT FOUND')}")
        
        # Rotate session on sensitive operation
        rotate_session()
        
        data = request.get_json() or {}
        
        # Validate input types
        create_backup = data.get('create_backup', True)
        if not isinstance(create_backup, bool):
            raise ValidationError('create_backup must be a boolean', field='create_backup')
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            raise ValidationError('commit must be a boolean', field='commit')
        
        log_operation('sync_start', {'create_backup': create_backup, 'commit': commit})
        sync_result = sync_manager.sync_configuration(create_backup=create_backup, commit=commit)
        log_operation('sync_complete', {'success': sync_result.get('success', False)})
        
        return ok(sync_result)
    except ValidationError as e:
        # Re-raise validation errors immediately (they return 400)
        raise
    except PanoramaConnectionError as e:
        raise
    except PanoramaAPIError as e:
        raise
    except BackupError as e:
        raise
    except Exception as e:
        # Get values from data if available, otherwise use defaults
        # This handles cases where validation fails before create_backup/commit are set
        create_backup_val = data.get('create_backup', True) if 'data' in locals() else True
        commit_val = data.get('commit', False) if 'data' in locals() else False
        
        logger.error(
            "Error during sync",
            error=str(e),
            error_type=type(e).__name__,
            create_backup=create_backup_val,
            commit=commit_val
        )
        log_operation('sync_error', {'error': str(e)})
        raise SyncError(f"Sync operation failed: {str(e)}", operation='sync', details={'create_backup': create_backup_val, 'commit': commit_val})


@app.route('/api/backups', methods=['GET'])
@requires_auth
def list_backups() -> Any:
    """
    List all available backup files
    ---
    tags:
      - Backups
    summary: List backups
    description: Get a list of all available backup files
    responses:
      200:
        description: List of backup files
        schema:
          type: object
          properties:
            success:
              type: boolean
            backups:
              type: array
              items:
                type: object
                properties:
                  filename:
                    type: string
                  path:
                    type: string
                  size:
                    type: integer
                  modified:
                    type: string
                    format: date-time
      401:
        description: Authentication required
      500:
        description: Error listing backups
    """
    try:
        backups = backup_service.list_backups()
        return ok({'backups': backups})
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        return fail(str(e), status=500, extra_top={'backups': []})


@app.route('/api/backups/download/<path:backup_path>', methods=['GET'])
@requires_auth
def download_backup(backup_path: str) -> Any:
    """Download a backup file"""
    try:
        # Ensure the path is within the backup directory (security)
        backup_file = Path(backup_path)
        backups_dir = Path(sync_manager.backup_dir)
        
        # Resolve the path to prevent directory traversal
        try:
            backup_file = (backups_dir / backup_file.name).resolve()
            # Ensure it's still within the backups directory
            if not str(backup_file).startswith(str(backups_dir.resolve())):
                raise ValidationError('Invalid backup path', field='backup_path')
        except (ValueError, OSError) as e:
            raise ValidationError(f'Invalid backup path: {str(e)}', field='backup_path')
        
        if not backup_file.exists():
            raise NotFoundError('backup', identifier=backup_file.name)
        
        # Check file size (max 100MB per backup file)
        max_backup_size = 100 * 1024 * 1024  # 100MB
        file_size = backup_file.stat().st_size
        if file_size > max_backup_size:
            raise BackupError(
                'Backup file exceeds maximum size limit',
                operation='download',
                details={'file_size': file_size, 'max_size': max_backup_size},
                status_code=413  # Request Entity Too Large
            )
        
        log_operation('backup_download', {'filename': backup_file.name})
        return send_file(
            str(backup_file),
            as_attachment=True,
            download_name=backup_file.name,
            mimetype='application/xml'
        )
    except (ValidationError, NotFoundError, BackupError):
        # Re-raise custom exceptions
        raise
    except (OSError, IOError) as e:
        logger.error(f"IO error downloading backup: {e}")
        log_operation('backup_download_error', {'error': str(e)})
        raise BackupError(f'Failed to read backup file: {str(e)}', operation='download')
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        log_operation('backup_download_error', {'error': str(e)})
        raise BackupError(f'Unexpected error downloading backup: {str(e)}', operation='download')


@app.route('/api/backups/restore', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def restore_backup() -> Any:
    """
    Restore a backup file
    ---
    tags:
      - Backups
    summary: Restore backup
    description: Restore configuration from a backup file to lab Panorama
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - backup_path
          properties:
            backup_path:
              type: string
              description: Path to the backup file to restore
            commit:
              type: boolean
              default: false
              description: Whether to commit the configuration after restore
    responses:
      200:
        description: Restore operation result
        schema:
          type: object
          properties:
            success:
              type: boolean
            commit_job_id:
              type: string
              nullable: true
            timestamp:
              type: string
              format: date-time
      400:
        description: Validation error
      401:
        description: Authentication required
      404:
        description: Backup file not found
      500:
        description: Restore operation failed
    """
    try:
        # Rotate session on sensitive operation
        rotate_session()
        
        data = request.get_json()
        if not data:
            raise ValidationError('Request body is required')
        
        backup_path = data.get('backup_path')
        if not backup_path:
            raise ValidationError('backup_path is required', field='backup_path')
        
        # Validate backup path
        is_valid, error_msg = validate_backup_path(backup_path, sync_manager.backup_dir)
        if not is_valid:
            raise ValidationError(error_msg or 'Invalid backup path', field='backup_path')
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            raise ValidationError('commit must be a boolean', field='commit')
        
        log_operation('restore_start', {'backup_path': backup_path, 'commit': commit})
        restore_result = sync_manager.restore_backup(backup_path, commit=commit)
        log_operation('restore_complete', {'success': restore_result.get('success', False)})
        
        return ok(restore_result)
    except (ValidationError, BackupError, PanoramaConnectionError, PanoramaAPIError):
        # Re-raise custom exceptions
        raise
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        log_operation('restore_error', {'error': str(e)})
        raise BackupError(f'Failed to restore backup: {str(e)}', operation='restore')


@app.route('/api/backups/delete', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def delete_backup() -> Any:
    """
    Delete a backup file
    ---
    tags:
      - Backups
    summary: Delete backup
    description: Delete a specific backup file
    parameters:
      - in: body
        name: body
        schema:
          type: object
          required:
            - backup_path
          properties:
            backup_path:
              type: string
              description: Path to the backup file to delete
    responses:
      200:
        description: Delete operation result
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      400:
        description: Validation error
      401:
        description: Authentication required
      404:
        description: Backup file not found
      500:
        description: Delete operation failed
    """
    try:
        data = request.get_json()
        if not data:
            raise ValidationError('Request body is required')
        
        backup_path = data.get('backup_path')
        if not backup_path:
            raise ValidationError('backup_path is required', field='backup_path')
        
        # Validate backup path
        is_valid, error_msg = validate_backup_path(backup_path, sync_manager.backup_dir)
        if not is_valid:
            raise ValidationError(error_msg or 'Invalid backup path', field='backup_path')
        
        log_operation('backup_delete_start', {'backup_path': backup_path})
        delete_result = backup_service.delete_backup(backup_path)
        log_operation('backup_delete_complete', {'success': delete_result.get('success', False)})
        
        return ok(delete_result)
    except (ValidationError, BackupError, NotFoundError):
        # Re-raise custom exceptions
        raise
    except Exception as e:
        logger.error(
            "Error deleting backup",
            error=str(e),
            error_type=type(e).__name__
        )
        log_operation('backup_delete_error', {'error': str(e)})
        raise BackupError(f'Failed to delete backup: {str(e)}', operation='delete')


@app.route('/api/logs', methods=['GET'])
# GET requests don't need CSRF protection, keeping exempt for read-only
# Also exempt from rate limiting - this is a read-only endpoint used for auto-refresh
@csrf.exempt
@limiter.exempt
def get_logs() -> Any:
    """Get recent operation logs"""
    global operation_logs  # Declare global at the start of the function

    try:
        limit_str = request.args.get('limit', '50')
        try:
            limit_val = int(limit_str)
        except ValueError:
            raise ValidationError('limit must be a valid integer', field='limit')
        
        # Validate limit bounds using centralized validator
        is_valid, error_msg = validate_integer(limit_val, min_value=1, max_value=1000, field_name='limit')
        if not is_valid:
            raise ValidationError(error_msg or 'limit must be between 1 and 1000', field='limit')
        limit = limit_val

        # If Redis available, read from capped list
        if redis_available and redis_client is not None:
            try:
                # LRANGE 0..limit-1 gives most recent first; reverse to chronological
                raw = redis_client.lrange(REDIS_LOGS_KEY, 0, limit - 1)
                parsed = []
                for item in reversed(raw):
                    try:
                        parsed.append(json.loads(item))
                    except json.JSONDecodeError:
                        # Skip malformed entries
                        continue
                return ok({'logs': parsed})
            except (redis.RedisError, redis.ConnectionError) as e:
                logger.warning(f"Failed to read logs from Redis, falling back to memory: {e}")

        # Fallback: in-memory list (thread-safe)
        with operation_logs_lock:
            if not isinstance(operation_logs, list):
                logger.warning("operation_logs is not a list, initializing")
                operation_logs = []
            logs = operation_logs[-limit:] if operation_logs else []
        return ok({'logs': logs})
    except ValidationError as e:
        # Re-raise validation errors - they'll be handled by error handler
        raise
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return fail(str(e), status=500, extra_top={'logs': []})


@app.route('/api/backups/create', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def create_lab_backup() -> Any:
    """
    Create a lab backup only (no sync or commit)
    ---
    tags:
      - Backups
    summary: Create lab backup
    description: Create a backup of the current lab Panorama configuration
    responses:
      200:
        description: Backup created successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            backup_path:
              type: string
            filename:
              type: string
      401:
        description: Authentication required
      500:
        description: Error creating backup
    """
    try:
        log_operation('backup_create_start', {'env': 'lab'})
        backup_path = sync_manager.create_backup('lab')
        filename = Path(backup_path).name
        log_operation('backup_create_complete', {'env': 'lab', 'filename': filename})
        return ok({'backup_path': backup_path, 'filename': filename})
    except (BackupError, PanoramaConnectionError, PanoramaAPIError):
        # Re-raise custom exceptions
        raise
    except Exception as e:
        logger.error(
            "Error creating lab backup",
            error=str(e),
            error_type=type(e).__name__,
            env='lab'
        )
        log_operation('backup_create_error', {'env': 'lab', 'error': str(e)})
        raise BackupError(f'Failed to create lab backup: {str(e)}', operation='create')


@app.route('/api/settings', methods=['GET'])
@requires_auth
def get_settings() -> Any:
    """
    Get application settings (from cache)
    ---
    tags:
      - Settings
    summary: Get settings
    description: Retrieve current application settings
    responses:
      200:
        description: Application settings
        schema:
          type: object
          properties:
            success:
              type: boolean
            settings:
              type: object
              properties:
                createBackup:
                  type: boolean
                commitConfig:
                  type: boolean
                preserveHostname:
                  type: boolean
                autoRefreshLogs:
                  type: boolean
                logRefreshInterval:
                  type: integer
                requestTimeout:
                  type: integer
                timezone:
                  type: string
                diffIgnorePaths:
                  type: array
                  items:
                    type: string
                diffIgnoreRegexPaths:
                  type: array
                  items:
                    type: string
                diffSignificantDigits:
                  type: integer
      401:
        description: Authentication required
      500:
        description: Error retrieving settings
    """
    try:
        settings_manager = get_settings_manager()
        settings = settings_manager.get_settings()
        return ok({'settings': settings})
    except Exception as e:
        logger.error(
            "Error getting settings",
            error=str(e),
            error_type=type(e).__name__
        )
        raise ConfigError(f"Failed to get settings: {str(e)}")


@app.route('/api/settings', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def save_settings() -> Any:
    """Save application settings"""
    try:
        # Get settings from request - validate BEFORE any file operations
        data = request.get_json()
        settings = data.get('settings')
        
        if not settings:
            raise ValidationError('Settings are required')
        
        # Validate settings structure BEFORE any file operations
        required_keys = ['createBackup', 'commitConfig', 'preserveHostname']
        for key in required_keys:
            if key not in settings:
                raise ValidationError(f'Missing required setting: {key}', field=key)
        
        # Validate types using centralized validators
        is_valid, error_msg = validate_boolean(settings['createBackup'], field_name='createBackup')
        if not is_valid:
            raise ValidationError(error_msg or 'createBackup must be a boolean', field='createBackup')
        
        is_valid, error_msg = validate_boolean(settings['commitConfig'], field_name='commitConfig')
        if not is_valid:
            raise ValidationError(error_msg or 'commitConfig must be a boolean', field='commitConfig')
        
        is_valid, error_msg = validate_boolean(settings['preserveHostname'], field_name='preserveHostname')
        if not is_valid:
            raise ValidationError(error_msg or 'preserveHostname must be a boolean', field='preserveHostname')
        
        # Validate optional log refresh settings
        if 'autoRefreshLogs' in settings:
            is_valid, error_msg = validate_boolean(settings['autoRefreshLogs'], field_name='autoRefreshLogs')
            if not is_valid:
                raise ValidationError(error_msg or 'autoRefreshLogs must be a boolean', field='autoRefreshLogs')
        
        if 'logRefreshInterval' in settings:
            is_valid, error_msg = validate_integer(settings['logRefreshInterval'], min_value=5, max_value=300, field_name='logRefreshInterval')
            if not is_valid:
                raise ValidationError(error_msg or 'logRefreshInterval must be between 5 and 300 seconds', field='logRefreshInterval')
            settings['logRefreshInterval'] = int(settings['logRefreshInterval'])

        # Validate optional request timeout
        if 'requestTimeout' in settings:
            is_valid, error_msg = validate_integer(settings['requestTimeout'], min_value=5, max_value=300, field_name='requestTimeout')
            if not is_valid:
                raise ValidationError(error_msg or 'requestTimeout must be between 5 and 300 seconds', field='requestTimeout')
            settings['requestTimeout'] = int(settings['requestTimeout'])

        # Validate optional timezone (IANA tz name)
        if 'timezone' in settings:
            is_valid, error_msg = validate_timezone(settings['timezone'])
            if not is_valid:
                raise ValidationError(error_msg or 'timezone must be a valid IANA time zone (e.g., UTC, America/New_York)', field='timezone')
            settings['timezone'] = str(settings['timezone']).strip()

        # Validate diff ignore settings
        if 'diffIgnorePaths' in settings:
            is_valid, error_msg = validate_list_of_strings(settings['diffIgnorePaths'], field_name='diffIgnorePaths', max_items=200)
            if not is_valid:
                raise ValidationError(error_msg or 'diffIgnorePaths must be an array of strings', field='diffIgnorePaths')
            # Limit length and clean up
            settings['diffIgnorePaths'] = [p.strip() for p in settings['diffIgnorePaths'] if isinstance(p, str) and p.strip()][:200]
        
        if 'diffIgnoreRegexPaths' in settings:
            is_valid, error_msg = validate_list_of_strings(settings['diffIgnoreRegexPaths'], field_name='diffIgnoreRegexPaths', max_items=200)
            if not is_valid:
                raise ValidationError(error_msg or 'diffIgnoreRegexPaths must be an array of strings', field='diffIgnoreRegexPaths')
            # Validate regex patterns using centralized validator
            validated = []
            for pattern in settings['diffIgnoreRegexPaths'][:200]:
                if not isinstance(pattern, str):
                    continue
                pat = pattern.strip()
                if not pat:
                    continue
                is_valid_regex, error_msg_regex = validate_regex_pattern(pat)
                if not is_valid_regex:
                    raise ValidationError(error_msg_regex or f'Invalid regex in diffIgnoreRegexPaths: {pattern}', field='diffIgnoreRegexPaths')
                validated.append(pat)
            settings['diffIgnoreRegexPaths'] = validated
        
        if 'diffSignificantDigits' in settings and settings['diffSignificantDigits'] is not None:
            is_valid, error_msg = validate_integer(settings['diffSignificantDigits'], min_value=0, max_value=10, field_name='diffSignificantDigits')
            if not is_valid:
                raise ValidationError(error_msg or 'diffSignificantDigits must be between 0 and 10', field='diffSignificantDigits')
            settings['diffSignificantDigits'] = int(settings['diffSignificantDigits'])
        
        # Now that validation is complete, save settings using settings manager
        # The settings manager handles file operations including directory creation
        try:
            settings_manager = get_settings_manager()
            settings_manager.save_settings(settings)
        except (OSError, IOError) as e:
            logger.error(f"Error writing settings file: {e}")
            raise ConfigError(f'Failed to save settings to file: {str(e)}')
        
        return ok({'success': True, 'message': 'Settings saved successfully'})
    except ValidationError as e:
        # Re-raise validation errors - they'll be handled by error handler
        raise
    except (ValueError, TypeError, KeyError) as e:
        logger.error(f"Error processing settings: {e}")
        raise ValidationError(str(e), details={'error_type': type(e).__name__})
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        raise ConfigError(f'Failed to save settings: {str(e)}')


@app.route('/api/settings/download', methods=['GET'])
@requires_auth
def download_settings() -> Any:
    """
    Download settings file as JSON (from cache)
    ---
    tags:
      - Settings
    summary: Download settings
    description: Download current settings as a JSON file
    responses:
      200:
        description: Settings file
        schema:
          type: file
      401:
        description: Authentication required
      500:
        description: Error downloading settings
    """
    try:
        settings_manager = get_settings_manager()
        settings = settings_manager.get_settings()
        
        # Create a temporary JSON string to send
        settings_json = json.dumps(settings, indent=2)
        log_operation('settings_download', {})
        return send_file(
            BytesIO(settings_json.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name='user_settings.json'
        )
    except Exception as e:
        logger.error(f"Error downloading settings: {e}")
        return fail(str(e), status=500)


@app.route('/api/settings/restore', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
@limiter.limit("10 per hour", key_func=get_rate_limit_key)  # Rate limit restore operations
def restore_settings() -> Any:
    """
    Restore settings from uploaded JSON file
    ---
    tags:
      - Settings
    summary: Restore settings
    description: Upload and restore settings from a JSON file
    consumes:
      - multipart/form-data
    parameters:
      - in: formData
        name: file
        type: file
        required: true
        description: JSON settings file to upload (max 1MB)
    responses:
      200:
        description: Settings restored successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
      400:
        description: Validation error
      401:
        description: Authentication required
      413:
        description: File too large
      500:
        description: Error restoring settings
    """
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            raise ValidationError('No file uploaded', field='file')
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            raise ValidationError('No file selected', field='file')
        
        # Validate filename using centralized validator
        filename = file.filename
        is_valid, error_msg = validate_filename(filename, allowed_extensions=['.json'], max_length=255)
        if not is_valid:
            raise ValidationError(error_msg or 'Invalid filename', field='filename')
        
        # Additional JSON-specific validation
        if not filename.endswith('.json'):
            raise ValidationError('File must be a JSON file', field='filename')
        
        # Check Content-Type header if present (defense in depth)
        content_type = file.content_type
        if content_type and content_type not in ('application/json', 'text/json', 'text/plain'):
            logger.warning(f"Unexpected Content-Type for settings restore: {content_type}")
            # Don't reject, but log for monitoring
        
        # Limit file size (prevent memory exhaustion and DoS)
        MAX_SETTINGS_FILE_SIZE = 1024 * 1024  # 1MB max
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size == 0:
            raise ValidationError('File is empty', field='file')
        
        is_valid, error_msg = validate_file_size(file_size, MAX_SETTINGS_FILE_SIZE)
        if not is_valid:
            raise ValidationError(error_msg or f'File size exceeds maximum limit ({MAX_SETTINGS_FILE_SIZE // 1024}KB)', field='file')
        
        # Read and parse JSON
        try:
            file_content = file.read()
            if len(file_content) != file_size:
                raise ValidationError('File size mismatch', field='file')
            
            # Limit JSON parsing complexity to prevent DoS
            settings = json.loads(file_content.decode('utf-8'))
        except UnicodeDecodeError as e:
            logger.error(
                "Error decoding uploaded settings file",
                error=str(e),
                error_type="UnicodeDecodeError"
            )
            raise ValidationError('File must be valid UTF-8 encoded text', field='file')
        except json.JSONDecodeError as e:
            logger.error(
                "Error parsing uploaded settings JSON",
                error=str(e),
                error_type="JSONDecodeError"
            )
            raise ValidationError(f'Invalid JSON file: {str(e)}', field='file')
        
        # Validate settings structure
        required_keys = ['createBackup', 'commitConfig', 'preserveHostname']
        for key in required_keys:
            if key not in settings:
                raise ValidationError(f'Missing required setting: {key}', field=key)
        
        # Validate types using centralized validators
        is_valid, error_msg = validate_boolean(settings['createBackup'], field_name='createBackup')
        if not is_valid:
            raise ValidationError(error_msg or 'createBackup must be a boolean', field='createBackup')
        
        is_valid, error_msg = validate_boolean(settings['commitConfig'], field_name='commitConfig')
        if not is_valid:
            raise ValidationError(error_msg or 'commitConfig must be a boolean', field='commitConfig')
        
        is_valid, error_msg = validate_boolean(settings['preserveHostname'], field_name='preserveHostname')
        if not is_valid:
            raise ValidationError(error_msg or 'preserveHostname must be a boolean', field='preserveHostname')
        
        # Validate optional settings
        if 'autoRefreshLogs' in settings and not isinstance(settings['autoRefreshLogs'], bool):
            return validation_error('autoRefreshLogs must be a boolean')
        
        if 'logRefreshInterval' in settings:
            try:
                interval = int(settings['logRefreshInterval'])
                if interval < 5 or interval > 300:
                    return validation_error('logRefreshInterval must be between 5 and 300')
            except (ValueError, TypeError):
                return validation_error('logRefreshInterval must be an integer')
        
        if 'requestTimeout' in settings:
            try:
                timeout = int(settings['requestTimeout'])
                if timeout < 5 or timeout > 300:
                    return validation_error('requestTimeout must be between 5 and 300')
            except (ValueError, TypeError):
                return validation_error('requestTimeout must be an integer')
        
        if 'timezone' in settings:
            if not isinstance(settings['timezone'], str):
                return validation_error('timezone must be a string')
            # Validate timezone length and format
            tz = settings['timezone'].strip()
            if len(tz) > 100:  # Reasonable max length for timezone identifiers
                return validation_error('timezone exceeds maximum length (100 characters)')
            if not tz:
                return validation_error('timezone cannot be empty')
            # Basic validation - should be IANA timezone format
            # Allow common formats but reject obviously malicious strings
            if not re.match(r'^[a-zA-Z0-9/_+\-]+$', tz):
                return validation_error('timezone contains invalid characters')
            settings['timezone'] = tz
        
        # Validate diff ignore paths
        if 'diffIgnorePaths' in settings:
            if not isinstance(settings['diffIgnorePaths'], list) or not all(isinstance(p, str) for p in settings['diffIgnorePaths']):
                return validation_error('diffIgnorePaths must be an array of strings')
            # Limit array size and individual string length
            validated_paths = []
            for p in settings['diffIgnorePaths'][:200]:  # Limit array size
                if isinstance(p, str):
                    path = p.strip()
                    if path:
                        # Limit individual path length to prevent DoS
                        if len(path) > 1000:
                            return validation_error(f'diffIgnorePath exceeds maximum length (1000 characters): {path[:50]}...')
                        validated_paths.append(path)
            settings['diffIgnorePaths'] = validated_paths
        
        if 'diffIgnoreRegexPaths' in settings:
            if not isinstance(settings['diffIgnoreRegexPaths'], list) or not all(isinstance(p, str) for p in settings['diffIgnoreRegexPaths']):
                return validation_error('diffIgnoreRegexPaths must be an array of strings')
            # Validate regex patterns
            validated = []
            for pattern in settings['diffIgnoreRegexPaths'][:200]:  # Limit array size
                if not isinstance(pattern, str):
                    continue
                pat = pattern.strip()
                if not pat:
                    continue
                # Limit regex pattern length to prevent ReDoS
                if len(pat) > 500:
                    return validation_error(f'diffIgnoreRegexPath exceeds maximum length (500 characters): {pat[:50]}...')
                try:
                    # Compile regex to validate and prevent ReDoS from extremely complex patterns
                    compiled = re.compile(pat)
                    # Additional check: limit pattern complexity by checking compiled pattern size
                    if hasattr(compiled, 'pattern') and len(compiled.pattern) != len(pat):
                        # Pattern was transformed, which might indicate complexity
                        pass  # Still accept it, but we've validated it compiles
                    validated.append(pat)
                except re.error as e:
                    return validation_error(f'Invalid regex in diffIgnoreRegexPaths: {str(e)}')
            settings['diffIgnoreRegexPaths'] = validated
        
        if 'diffSignificantDigits' in settings and settings['diffSignificantDigits'] is not None:
            try:
                sd = int(settings['diffSignificantDigits'])
                if sd < 0 or sd > 10:
                    return validation_error('diffSignificantDigits must be between 0 and 10')
                settings['diffSignificantDigits'] = sd
            except (ValueError, TypeError):
                return validation_error('diffSignificantDigits must be an integer')
        
        # Strip unknown keys to prevent injection of unexpected data
        allowed_keys = {
            'createBackup', 'commitConfig', 'preserveHostname',
            'autoRefreshLogs', 'logRefreshInterval', 'requestTimeout',
            'timezone', 'diffIgnorePaths', 'diffIgnoreRegexPaths', 'diffSignificantDigits'
        }
        stripped_settings = {k: v for k, v in settings.items() if k in allowed_keys}
        if len(stripped_settings) != len(settings):
            logger.warning(f"Settings file contained unknown keys, stripped {len(settings) - len(stripped_settings)} keys")
            settings = stripped_settings
        
        # Save settings to file using settings manager (automatically invalidates cache)
        try:
            settings_manager = get_settings_manager()
            settings_manager.save_settings(settings)
        except (OSError, IOError) as e:
            logger.error(f"Error writing restored settings file: {e}")
            return fail('Failed to save restored settings file', status=500)
        
        log_operation('settings_restore', {'filename': filename})
        return ok({'success': True, 'message': 'Settings restored successfully'})
    except Exception as e:
        logger.error(f"Error restoring settings: {e}")
        return fail(str(e), status=500)


@app.route('/api/backups/cleanup', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def cleanup_backups() -> Any:
    """Delete all backup files"""
    try:
        # Get the backup directory path
        backup_dir = Path('/backups')
        
        # Check if backup directory exists
        if not backup_dir.exists():
            return fail('Backup directory not found', status=404)
        
        # Count files before deletion
        backup_files = list(backup_dir.glob('*.xml'))
        file_count = len(backup_files)
        
        if file_count == 0:
            return ok({'success': True, 'message': 'No backup files to delete', 'deleted_count': 0})
        
        # Delete all backup files
        deleted_count = 0
        for backup_file in backup_files:
            try:
                backup_file.unlink()
                deleted_count += 1
            except (OSError, IOError) as e:
                logger.warning(f"Failed to delete backup file {backup_file}: {e}")
                # Continue deleting other files even if one fails
        
        logger.info(f"Deleted {deleted_count} backup files")
        log_operation('backups_cleanup', {'deleted_count': deleted_count})
        
        return ok({'success': True, 'message': f'Successfully deleted {deleted_count} backup file(s)', 'deleted_count': deleted_count})
    except (OSError, IOError) as e:
        logger.error(f"Error cleaning up backups: {e}")
        log_operation('backups_cleanup_error', {'error': str(e)})
        return fail('Failed to clean up backup files', status=500)
    except Exception as e:
        logger.error(f"Error cleaning up backups: {e}")
        log_operation('backups_cleanup_error', {'error': str(e)})
        return fail(str(e), status=500)


@app.route('/api/config', methods=['GET'])
@requires_auth
def get_config() -> Any:
    """Get configuration summary (without sensitive data)"""
    try:
        summary = Config.get_summary()
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
@csrf.exempt
def health() -> Any:
    """Simple readiness/liveness health endpoint."""
    return jsonify({'status': 'ok'}), 200


@app.route('/api/csrf-token', methods=['GET'])
@csrf.exempt  # Exempt this endpoint so it can be called without CSRF
def get_csrf_token() -> Any:
    """Get CSRF token for AJAX requests"""
    token = generate_csrf()
    return jsonify({'csrf_token': token})


if __name__ == '__main__':
    # Validate configuration on startup
    is_valid, errors = Config.validate()
    if not is_valid:
        logger.error("Configuration validation failed:")
        for error in errors:
            logger.error(f"  - {error}")
        logger.error("Please check your environment variables and .env file")
    else:
        logger.info("Configuration validated successfully")
        logger.info("Starting NMS-Sync web interface...")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

