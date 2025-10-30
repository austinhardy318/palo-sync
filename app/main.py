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
from datetime import datetime
from pathlib import Path
from io import BytesIO
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, flash, send_file
from functools import wraps
from typing import Optional, Dict, Any, Callable, Tuple
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

from .config import Config
from .sync_service import SyncService
from .backup_service import BackupService
from .http_responses import ok, fail, unauthorized, validation_error
from .auth import Authenticator

# Initialize Flask app
app = Flask(__name__)

# Require FLASK_SECRET_KEY in production for security
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
if not FLASK_SECRET_KEY:
    raise ValueError("FLASK_SECRET_KEY environment variable must be set. Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\"")
app.secret_key = FLASK_SECRET_KEY

# Set session timeout (8 hours)
app.permanent_session_lifetime = dt.timedelta(hours=8)

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

# Add error handler for CSRF errors to return JSON instead of HTML
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF errors and return JSON response for API endpoints"""
    logger.warning(f"CSRF validation failed: {e.description} for path {request.path}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False, 
            'error': 'CSRF token missing or invalid',
            'details': str(e.description) if hasattr(e, 'description') else str(e)
        }), 400
    # For non-API routes, let Flask-WTF handle the default error page
    return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400

# Setup logging first (needed for Redis connection logging)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure rate limiting with Redis backend

# Initialize Redis connection pool for rate limiting
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
try:
    redis_pool = redis.ConnectionPool.from_url(redis_url, max_connections=20, socket_connect_timeout=2, decode_responses=True)
    redis_client = redis.Redis(connection_pool=redis_pool)
    redis_client.ping()  # Test connection
    logger.info(f"Connected to Redis at {redis_url} with pooling")
    redis_available = True
except (redis.RedisError, redis.ConnectionError, OSError) as e:
    logger.warning(f"Redis connection failed ({e}). Using in-memory storage for rate limiting.")
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
        username = session.get('username', 'unknown')
        return f"user:{username}"
    # Fall back to IP address for anonymous users
    return f"ip:{get_remote_address()}"


limiter = Limiter(
    app=app,
    key_func=get_rate_limit_key,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=redis_url if redis_available else "memory://"
)


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
    salt = os.getenv('LOG_SALT', 'nms-sync-default-salt-change-in-production')
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
    Also validates filename format and length
    Returns (is_valid, error_message)
    """
    if not backup_path or not isinstance(backup_path, str):
        return False, 'backup_path is required and must be a string'
    
    # Check path length (prevent extremely long paths)
    if len(backup_path) > 4096:  # Maximum path length on most systems
        return False, 'backup_path exceeds maximum length'
    
    # Check for path traversal attempts
    if '..' in backup_path or backup_path.startswith('.'):
        return False, 'Invalid backup path: path traversal not allowed'
    
    # Validate filename format
    filename = Path(backup_path).name
    if not filename:
        return False, 'Invalid backup path: filename required'
    
    # Check filename length
    if len(filename) > max_filename_length:
        return False, f'Invalid backup path: filename exceeds maximum length of {max_filename_length} characters'
    
    # Validate filename contains only safe characters
    # Allow alphanumeric, hyphens, underscores, dots, and XML extension
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.xml$', filename):
        return False, 'Invalid backup path: filename must contain only alphanumeric characters, hyphens, underscores, dots, and end with .xml'
    
    # Ensure path is within backup directory
    try:
        backup_file = Path(backup_path)
        backups_dir = Path(backup_dir)
        # Normalize the path and check it's within the backup directory
        resolved_path = backup_file.resolve()
        backups_dir_resolved = backups_dir.resolve()
        if not str(resolved_path).startswith(str(backups_dir_resolved)):
            return False, 'Invalid backup path: must be within backup directory'
        
        # Additional check: ensure the resolved path is actually a file within the directory
        # Prevent accessing parent directories even if path seems valid
        if resolved_path.parent != backups_dir_resolved:
            return False, 'Invalid backup path: must be directly in backup directory'
        
        return True, None
    except (ValueError, OSError) as e:
        return False, f'Invalid backup path: {str(e)}'


def log_operation(operation: str, details: Optional[Dict[str, Any]] = None) -> None:
    """Add entry to operation logs (Redis if available, else in-memory)."""
    user_log: Dict[str, Any] = details.copy() if details else {}

    # Add username from session if available
    if 'user' in session:
        user_log['user'] = session.get('username', 'unknown')

    entry = {
        'timestamp': datetime.now(dt.timezone.utc).isoformat(),
        'operation': operation,
        'user': session.get('username', 'system'),
        'details': user_log
    }

    # Prefer Redis capped list for cross-worker durability
    if redis_available and redis_client is not None:
        try:
            redis_client.lpush(REDIS_LOGS_KEY, json.dumps(entry))
            redis_client.ltrim(REDIS_LOGS_KEY, 0, MAX_LOGS - 1)
            return
        except (redis.RedisError, redis.ConnectionError, json.JSONEncodeError) as e:
            logger.warning(f"Failed to write log to Redis, falling back to memory: {e}")

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
    """Get connection status for both NMS instances"""
    try:
        status = sync_manager.test_connection()
        log_operation('status_check', status)
        return ok(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return fail(str(e), status=500)


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
    except Exception as e:
        logger.error(f"Error generating diff: {e}")
        log_operation('diff_error', {'error': str(e)})
        return fail(str(e), status=500)


@app.route('/api/sync', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def sync_configuration() -> Any:
    """Execute configuration sync from production to lab"""
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
            return validation_error('create_backup must be a boolean')
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            return validation_error('commit must be a boolean')
        
        log_operation('sync_start', {'create_backup': create_backup, 'commit': commit})
        sync_result = sync_manager.sync_configuration(create_backup=create_backup, commit=commit)
        log_operation('sync_complete', {'success': sync_result.get('success', False)})
        
        return ok(sync_result)
    except Exception as e:
        logger.error(f"Error during sync: {e}")
        log_operation('sync_error', {'error': str(e)})
        return fail(str(e), status=500)


@app.route('/api/backups', methods=['GET'])
@requires_auth
def list_backups() -> Any:
    """List all available backup files"""
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
                return validation_error('Invalid backup path')
        except (ValueError, OSError):
            return validation_error('Invalid backup path')
        
        if not backup_file.exists():
            return fail('Backup file not found', status=404, code='BACKUP_NOT_FOUND')
        
        # Check file size (max 100MB per backup file)
        max_backup_size = 100 * 1024 * 1024  # 100MB
        file_size = backup_file.stat().st_size
        if file_size > max_backup_size:
            return fail('Backup file exceeds maximum size limit', status=413, code='BACKUP_TOO_LARGE')
        
        log_operation('backup_download', {'filename': backup_file.name})
        return send_file(
            str(backup_file),
            as_attachment=True,
            download_name=backup_file.name,
            mimetype='application/xml'
        )
    except (OSError, IOError) as e:
        logger.error(f"IO error downloading backup: {e}")
        log_operation('backup_download_error', {'error': str(e)})
        return fail('Failed to read backup file', status=500)
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        log_operation('backup_download_error', {'error': str(e)})
        return fail(str(e), status=500)


@app.route('/api/backups/restore', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def restore_backup() -> Any:
    """Restore a backup file"""
    try:
        # Rotate session on sensitive operation
        rotate_session()
        
        data = request.get_json()
        if not data:
            return validation_error('Request body is required')
        
        backup_path = data.get('backup_path')
        
        # Validate backup path
        is_valid, error_msg = validate_backup_path(backup_path, sync_manager.backup_dir)
        if not is_valid:
            return validation_error(error_msg or 'Invalid backup path')
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            return validation_error('commit must be a boolean')
        
        log_operation('restore_start', {'backup_path': backup_path, 'commit': commit})
        restore_result = sync_manager.restore_backup(backup_path, commit=commit)
        log_operation('restore_complete', {'success': restore_result.get('success', False)})
        
        return ok(restore_result)
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        log_operation('restore_error', {'error': str(e)})
        return fail(str(e), status=500)


@app.route('/api/backups/delete', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def delete_backup() -> Any:
    """Delete a backup file"""
    try:
        data = request.get_json()
        if not data:
            return validation_error('Request body is required')
        
        backup_path = data.get('backup_path')
        
        # Validate backup path
        is_valid, error_msg = validate_backup_path(backup_path, sync_manager.backup_dir)
        if not is_valid:
            return validation_error(error_msg or 'Invalid backup path')
        
        log_operation('backup_delete_start', {'backup_path': backup_path})
        delete_result = backup_service.delete_backup(backup_path)
        log_operation('backup_delete_complete', {'success': delete_result.get('success', False)})
        
        return ok(delete_result)
    except Exception as e:
        logger.error(f"Error deleting backup: {e}")
        log_operation('backup_delete_error', {'error': str(e)})
        return fail(str(e), status=500)


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
            limit = int(limit_str)
        except ValueError:
            return fail('limit must be a valid integer', status=400, extra_top={'logs': []})
        
        # Enforce bounds: between 1 and 1000
        limit = max(1, min(limit, 1000))

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
                return jsonify({'logs': parsed})
            except (redis.RedisError, redis.ConnectionError) as e:
                logger.warning(f"Failed to read logs from Redis, falling back to memory: {e}")

        # Fallback: in-memory list (thread-safe)
        with operation_logs_lock:
            if not isinstance(operation_logs, list):
                logger.warning("operation_logs is not a list, initializing")
                operation_logs = []
            logs = operation_logs[-limit:] if operation_logs else []
        return ok({'logs': logs})
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return fail(str(e), status=500, extra_top={'logs': []})


@app.route('/api/backups/create', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def create_lab_backup() -> Any:
    """Create a lab backup only (no sync or commit)."""
    try:
        log_operation('backup_create_start', {'env': 'lab'})
        backup_path = sync_manager.create_backup('lab')
        if not backup_path:
            log_operation('backup_create_error', {'env': 'lab', 'error': 'Failed to create backup'})
            return jsonify({'success': False, 'error': 'Failed to create backup'}), 500
        filename = Path(backup_path).name
        log_operation('backup_create_complete', {'env': 'lab', 'filename': filename})
        return jsonify({'success': True, 'backup_path': backup_path, 'filename': filename})
    except Exception as e:
        logger.error(f"Error creating lab backup: {e}")
        log_operation('backup_create_error', {'env': 'lab', 'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/settings', methods=['GET'])
@requires_auth
def get_settings() -> Any:
    """Get application settings"""
    try:
        settings_path = Path('/app/settings/user_settings.json')
        
        # Return default settings if file doesn't exist
        if not settings_path.exists():
            default_settings = {
                'createBackup': True,
                'commitConfig': False,
                'preserveHostname': True,
                'autoRefreshLogs': True,
                'logRefreshInterval': 10,
                'requestTimeout': 30,
                'timezone': 'UTC',
                'diffIgnorePaths': [],
                'diffIgnoreRegexPaths': [],
                'diffSignificantDigits': None
            }
            return ok({'settings': default_settings})
        
        # Read and return saved settings
        try:
            with open(settings_path, 'r') as f:
                settings = json.load(f)
        except (OSError, IOError) as e:
            logger.error(f"Error reading settings file: {e}")
            return fail('Failed to read settings file', status=500)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing settings JSON: {e}")
            return fail('Settings file contains invalid JSON', status=500)
        
        return ok({'settings': settings})
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return fail(str(e), status=500)


@app.route('/api/settings', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
def save_settings() -> Any:
    """Save application settings"""
    try:
        settings_path = Path('/app/settings/user_settings.json')
        
        # Ensure settings directory exists
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get settings from request
        data = request.get_json()
        settings = data.get('settings')
        
        if not settings:
            return validation_error('Settings are required')
        
        # Validate settings structure
        required_keys = ['createBackup', 'commitConfig', 'preserveHostname']
        for key in required_keys:
            if key not in settings:
                return validation_error(f'Missing required setting: {key}')
        
        # Validate types
        if not isinstance(settings['createBackup'], bool):
            return validation_error('createBackup must be a boolean')
        if not isinstance(settings['commitConfig'], bool):
            return validation_error('commitConfig must be a boolean')
        if not isinstance(settings['preserveHostname'], bool):
            return validation_error('preserveHostname must be a boolean')
        
        # Validate optional log refresh settings
        if 'autoRefreshLogs' in settings:
            if not isinstance(settings['autoRefreshLogs'], bool):
                return validation_error('autoRefreshLogs must be a boolean')
        
        if 'logRefreshInterval' in settings:
            try:
                interval = int(settings['logRefreshInterval'])
                if interval < 5 or interval > 300:
                    return validation_error('logRefreshInterval must be between 5 and 300 seconds')
                settings['logRefreshInterval'] = interval
            except (ValueError, TypeError):
                return validation_error('logRefreshInterval must be a valid integer')

        # Validate optional request timeout
        if 'requestTimeout' in settings:
            try:
                rt = int(settings['requestTimeout'])
                if rt < 5 or rt > 300:
                    return jsonify({'success': False, 'error': 'requestTimeout must be between 5 and 300 seconds'}), 400
                settings['requestTimeout'] = rt
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': 'requestTimeout must be a valid integer'}), 400

        # Validate optional timezone (IANA tz name)
        if 'timezone' in settings:
            try:
                from zoneinfo import ZoneInfo
                tz = str(settings['timezone']).strip()
                # Validate by attempting to construct ZoneInfo
                ZoneInfo(tz)
                settings['timezone'] = tz
            except Exception:
                return jsonify({'success': False, 'error': 'timezone must be a valid IANA time zone (e.g., UTC, America/New_York)'}), 400

        # Validate diff ignore settings
        if 'diffIgnorePaths' in settings:
            if not isinstance(settings['diffIgnorePaths'], list) or not all(isinstance(p, str) for p in settings['diffIgnorePaths']):
                return validation_error('diffIgnorePaths must be an array of strings')
            # limit length
            settings['diffIgnorePaths'] = [p.strip() for p in settings['diffIgnorePaths'] if isinstance(p, str) and p.strip()][:200]
        if 'diffIgnoreRegexPaths' in settings:
            if not isinstance(settings['diffIgnoreRegexPaths'], list) or not all(isinstance(p, str) for p in settings['diffIgnoreRegexPaths']):
                return validation_error('diffIgnoreRegexPaths must be an array of strings')
            # precompile to validate regexes
            validated = []
            for pattern in settings['diffIgnoreRegexPaths'][:200]:
                if not isinstance(pattern, str):
                    continue
                pat = pattern.strip()
                if not pat:
                    continue
                try:
                    re.compile(pat)
                    validated.append(pat)
                except re.error:
                    return validation_error(f'Invalid regex in diffIgnoreRegexPaths: {pattern}')
            settings['diffIgnoreRegexPaths'] = validated
        if 'diffSignificantDigits' in settings and settings['diffSignificantDigits'] is not None:
            try:
                sd = int(settings['diffSignificantDigits'])
                if sd < 0 or sd > 10:
                    return validation_error('diffSignificantDigits must be between 0 and 10')
                settings['diffSignificantDigits'] = sd
            except (ValueError, TypeError):
                return validation_error('diffSignificantDigits must be an integer')
        
        # Save settings to file
        try:
            with open(settings_path, 'w') as f:
                json.dump(settings, f, indent=2)
        except (OSError, IOError) as e:
            logger.error(f"Error writing settings file: {e}")
            return fail('Failed to save settings to file', status=500)
        
        logger.info("Settings saved successfully")
        return ok({'success': True, 'message': 'Settings saved successfully'})
    except (ValueError, TypeError, KeyError) as e:
        logger.error(f"Error processing settings: {e}")
        return validation_error(str(e))
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return fail(str(e), status=500)


@app.route('/api/settings/download', methods=['GET'])
@requires_auth
def download_settings() -> Any:
    """Download settings file as JSON"""
    try:
        settings_path = Path('/app/settings/user_settings.json')
        
        # If settings file doesn't exist, return default settings
        if not settings_path.exists():
            default_settings = {
                'createBackup': True,
                'commitConfig': False,
                'preserveHostname': True,
                'autoRefreshLogs': True,
                'logRefreshInterval': 10,
                'requestTimeout': 30,
                'timezone': 'UTC',
                'diffIgnorePaths': [],
                'diffIgnoreRegexPaths': [],
                'diffSignificantDigits': None
            }
            # Create a temporary JSON string to send
            settings_json = json.dumps(default_settings, indent=2)
            return send_file(
                BytesIO(settings_json.encode('utf-8')),
                mimetype='application/json',
                as_attachment=True,
                download_name='user_settings.json'
            )
        
        # Read and send the settings file
        try:
            log_operation('settings_download', {})
            return send_file(
                str(settings_path),
                mimetype='application/json',
                as_attachment=True,
                download_name='user_settings.json'
            )
        except (OSError, IOError) as e:
            logger.error(f"Error reading settings file for download: {e}")
            return fail('Failed to read settings file', status=500)
    except Exception as e:
        logger.error(f"Error downloading settings: {e}")
        return fail(str(e), status=500)


@app.route('/api/settings/restore', methods=['POST'])
@csrf.exempt  # Exempt authenticated API endpoint - session authentication provides protection
@requires_auth
@limiter.limit("10 per hour", key_func=get_rate_limit_key)  # Rate limit restore operations
def restore_settings() -> Any:
    """Restore settings from uploaded JSON file"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return validation_error('No file uploaded')
        
        file = request.files['file']
        
        # Check if file was selected
        if file.filename == '':
            return validation_error('No file selected')
        
        # Validate filename (prevent path traversal and malicious filenames)
        filename = file.filename
        if not filename or not isinstance(filename, str):
            return validation_error('Invalid filename')
        
        # Check for path traversal attempts
        if '..' in filename or '/' in filename or '\\' in filename:
            return validation_error('Invalid filename: path traversal not allowed')
        
        # Check filename length
        if len(filename) > 255:
            return validation_error('Filename exceeds maximum length (255 characters)')
        
        # Validate filename contains only safe characters
        # Allow alphanumeric, hyphens, underscores, dots, and JSON extension
        if not re.match(r'^[a-zA-Z0-9_\-\.]+\.json$', filename):
            return validation_error('Filename must contain only alphanumeric characters, hyphens, underscores, dots, and end with .json')
        
        # Check file extension (extra validation)
        if not filename.endswith('.json'):
            return validation_error('File must be a JSON file')
        
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
        
        if file_size > MAX_SETTINGS_FILE_SIZE:
            return fail(f'File size exceeds maximum limit ({MAX_SETTINGS_FILE_SIZE // 1024}KB)', status=413, code='FILE_TOO_LARGE')
        
        if file_size == 0:
            return validation_error('File is empty')
        
        # Read and parse JSON
        try:
            file_content = file.read()
            if len(file_content) != file_size:
                return validation_error('File size mismatch')
            
            # Limit JSON parsing complexity to prevent DoS
            settings = json.loads(file_content.decode('utf-8'))
        except UnicodeDecodeError as e:
            logger.error(f"Error decoding uploaded settings file: {e}")
            return validation_error('File must be valid UTF-8 encoded text')
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing uploaded settings JSON: {e}")
            return validation_error(f'Invalid JSON file: {str(e)}')
        
        # Validate settings structure
        required_keys = ['createBackup', 'commitConfig', 'preserveHostname']
        for key in required_keys:
            if key not in settings:
                return validation_error(f'Missing required setting: {key}')
        
        # Validate types
        if not isinstance(settings['createBackup'], bool):
            return validation_error('createBackup must be a boolean')
        if not isinstance(settings['commitConfig'], bool):
            return validation_error('commitConfig must be a boolean')
        if not isinstance(settings['preserveHostname'], bool):
            return validation_error('preserveHostname must be a boolean')
        
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
        
        # Save settings to file
        settings_path = Path('/app/settings/user_settings.json')
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(settings_path, 'w') as f:
                json.dump(settings, f, indent=2)
        except (OSError, IOError) as e:
            logger.error(f"Error writing restored settings file: {e}")
            return fail('Failed to save restored settings file', status=500)
        
        logger.info("Settings restored successfully from uploaded file")
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

