"""
Flask web application for Palo-Sync
Provides REST API and web GUI for configuration synchronization
"""

import os
import json
import logging
import datetime as dt
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session, flash
from functools import wraps

from .config import Config
from .panorama_sync import PanoramaSync
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
from flask_wtf.csrf import CSRFProtect, CSRFError
csrf = CSRFProtect(app)

# Note: CSRF is enabled globally but exempted on specific routes

# Setup logging first (needed for Redis connection logging)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configure rate limiting with Redis backend
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Initialize Redis connection for rate limiting
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379/0')
try:
    redis_client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
    redis_client.ping()  # Test connection
    logger.info(f"Connected to Redis at {redis_url}")
    redis_available = True
except Exception as e:
    logger.warning(f"Redis connection failed ({e}). Using in-memory storage for rate limiting.")
    redis_client = None
    redis_available = False

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=redis_url if redis_available else "memory://"
)


# Initialize sync manager and authenticator
sync_manager = PanoramaSync()
authenticator = Authenticator()

# Store operation logs in memory
operation_logs = []


def requires_auth(f):
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
                    return jsonify({'error': 'Authentication required'}), 401
                # Redirect to login page for web requests
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def log_operation(operation: str, details: dict = None):
    """Add entry to operation logs"""
    # Add username from session if available
    user_log = details.copy() if details else {}
    if 'user' in session:
        user_log['user'] = session.get('username', 'unknown')
    
    entry = {
        'timestamp': datetime.now().isoformat(),
        'operation': operation,
        'user': session.get('username', 'system'),
        'details': user_log
    }
    operation_logs.append(entry)
    # Keep only last 100 logs
    if len(operation_logs) > 100:
        operation_logs.pop(0)


@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Exempt login from CSRF protection since it's the entry point
@limiter.limit("5 per minute")
def login():
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
            session['authenticated'] = True
            session['username'] = username
            log_operation('login', {'username': username})
            return redirect(url_for('index'))
        else:
            flash(f'Authentication failed: {error}')
            log_operation('login_failed', {'username': username})
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session"""
    username = session.get('username')
    session.clear()
    log_operation('logout', {'username': username})
    flash('You have been logged out successfully')
    return redirect(url_for('login'))


@app.route('/')
@requires_auth
def index():
    """Serve the main web GUI"""
    return render_template('index.html')


@app.route('/settings')
@requires_auth
def settings():
    """Serve the settings page"""
    return render_template('settings.html')


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get connection status for both Panorama instances"""
    try:
        status = sync_manager.test_connection()
        log_operation('status_check', status)
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/diff', methods=['POST'])
@csrf.exempt
def generate_diff():
    """Generate configuration diff between production and lab"""
    try:
        log_operation('diff_start')
        diff_result = sync_manager.generate_diff()
        log_operation('diff_complete', {'success': diff_result.get('success', False)})
        return jsonify(diff_result)
    except Exception as e:
        logger.error(f"Error generating diff: {e}")
        log_operation('diff_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/sync', methods=['POST'])
@csrf.exempt
def sync_configuration():
    """Execute configuration sync from production to lab"""
    try:
        data = request.get_json() or {}
        
        # Validate input types
        create_backup = data.get('create_backup', True)
        if not isinstance(create_backup, bool):
            return jsonify({'success': False, 'error': 'create_backup must be a boolean'}), 400
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            return jsonify({'success': False, 'error': 'commit must be a boolean'}), 400
        
        log_operation('sync_start', {'create_backup': create_backup, 'commit': commit})
        sync_result = sync_manager.sync_configuration(create_backup=create_backup, commit=commit)
        log_operation('sync_complete', {'success': sync_result.get('success', False)})
        
        return jsonify(sync_result)
    except Exception as e:
        logger.error(f"Error during sync: {e}")
        log_operation('sync_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backups', methods=['GET'])
def list_backups():
    """List all available backup files"""
    try:
        backups = sync_manager.list_backups()
        return jsonify({'backups': backups})
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/backups/download/<path:backup_path>', methods=['GET'])
def download_backup(backup_path):
    """Download a backup file"""
    try:
        from pathlib import Path
        from flask import send_file
        
        # Ensure the path is within the backup directory (security)
        backup_file = Path(backup_path)
        backups_dir = Path(sync_manager.backup_dir)
        
        # Resolve the path to prevent directory traversal
        try:
            backup_file = (backups_dir / backup_file.name).resolve()
            # Ensure it's still within the backups directory
            if not str(backup_file).startswith(str(backups_dir.resolve())):
                return jsonify({'error': 'Invalid backup path'}), 400
        except (ValueError, OSError):
            return jsonify({'error': 'Invalid backup path'}), 400
        
        if not backup_file.exists():
            return jsonify({'error': 'Backup file not found'}), 404
        
        log_operation('backup_download', {'filename': backup_file.name})
        return send_file(
            str(backup_file),
            as_attachment=True,
            download_name=backup_file.name,
            mimetype='application/xml'
        )
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        log_operation('backup_download_error', {'error': str(e)})
        return jsonify({'error': str(e)}), 500


@app.route('/api/backups/restore', methods=['POST'])
@csrf.exempt
def restore_backup():
    """Restore a backup file"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400
        
        backup_path = data.get('backup_path')
        if not backup_path or not isinstance(backup_path, str):
            return jsonify({'success': False, 'error': 'backup_path is required and must be a string'}), 400
        
        # Validate backup_path - allow full paths within backups directory
        # Check for path traversal attempts
        if '..' in backup_path or backup_path.startswith('.'):
            return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        
        # Ensure path is within backup directory
        try:
            backup_file = Path(backup_path)
            backups_dir = Path(sync_manager.backup_dir)
            # Normalize the path and check it's within the backup directory
            resolved_path = backup_file.resolve()
            if not str(resolved_path).startswith(str(backups_dir.resolve())):
                return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        except (ValueError, OSError):
            return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        
        commit = data.get('commit', False)
        if not isinstance(commit, bool):
            return jsonify({'success': False, 'error': 'commit must be a boolean'}), 400
        
        log_operation('restore_start', {'backup_path': backup_path, 'commit': commit})
        restore_result = sync_manager.restore_backup(backup_path, commit=commit)
        log_operation('restore_complete', {'success': restore_result.get('success', False)})
        
        return jsonify(restore_result)
    except Exception as e:
        logger.error(f"Error restoring backup: {e}")
        log_operation('restore_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backups/delete', methods=['POST'])
@csrf.exempt
def delete_backup():
    """Delete a backup file"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Request body is required'}), 400
        
        backup_path = data.get('backup_path')
        if not backup_path or not isinstance(backup_path, str):
            return jsonify({'success': False, 'error': 'backup_path is required and must be a string'}), 400
        
        # Validate backup_path - allow full paths within backups directory
        # Check for path traversal attempts
        if '..' in backup_path or backup_path.startswith('.'):
            return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        
        # Ensure path is within backup directory
        try:
            backup_file = Path(backup_path)
            backups_dir = Path(sync_manager.backup_dir)
            # Normalize the path and check it's within the backup directory
            resolved_path = backup_file.resolve()
            if not str(resolved_path).startswith(str(backups_dir.resolve())):
                return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        except (ValueError, OSError):
            return jsonify({'success': False, 'error': 'Invalid backup path'}), 400
        
        log_operation('backup_delete_start', {'backup_path': backup_path})
        delete_result = sync_manager.delete_backup(backup_path)
        log_operation('backup_delete_complete', {'success': delete_result.get('success', False)})
        
        return jsonify(delete_result)
    except Exception as e:
        logger.error(f"Error deleting backup: {e}")
        log_operation('backup_delete_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/logs', methods=['GET'])
@csrf.exempt
def get_logs():
    """Get recent operation logs"""
    try:
        limit_str = request.args.get('limit', '50')
        try:
            limit = int(limit_str)
        except ValueError:
            return jsonify({'error': 'limit must be a valid integer'}), 400
        
        # Enforce bounds: between 1 and 1000
        limit = max(1, min(limit, 1000))
        
        logs = operation_logs[-limit:]
        return jsonify({'logs': logs})
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/settings', methods=['GET'])
def get_settings():
    """Get application settings"""
    try:
        settings_path = Path('/app/settings/user_settings.json')
        
        # Return default settings if file doesn't exist
        if not settings_path.exists():
            default_settings = {
                'createBackup': True,
                'commitConfig': False,
                'preserveHostname': True
            }
            return jsonify({'settings': default_settings})
        
        # Read and return saved settings
        with open(settings_path, 'r') as f:
            settings = json.load(f)
        
        return jsonify({'settings': settings})
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/settings', methods=['POST'])
@csrf.exempt
def save_settings():
    """Save application settings"""
    try:
        settings_path = Path('/app/settings/user_settings.json')
        
        # Ensure settings directory exists
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Get settings from request
        data = request.get_json()
        settings = data.get('settings')
        
        if not settings:
            return jsonify({'success': False, 'error': 'Settings are required'}), 400
        
        # Validate settings structure
        required_keys = ['createBackup', 'commitConfig', 'preserveHostname']
        for key in required_keys:
            if key not in settings:
                return jsonify({'success': False, 'error': f'Missing required setting: {key}'}), 400
        
        # Validate types
        if not isinstance(settings['createBackup'], bool):
            return jsonify({'success': False, 'error': 'createBackup must be a boolean'}), 400
        if not isinstance(settings['commitConfig'], bool):
            return jsonify({'success': False, 'error': 'commitConfig must be a boolean'}), 400
        if not isinstance(settings['preserveHostname'], bool):
            return jsonify({'success': False, 'error': 'preserveHostname must be a boolean'}), 400
        
        # Save settings to file
        with open(settings_path, 'w') as f:
            json.dump(settings, f, indent=2)
        
        logger.info("Settings saved successfully")
        return jsonify({'success': True, 'message': 'Settings saved successfully'})
    except Exception as e:
        logger.error(f"Error saving settings: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/backups/cleanup', methods=['POST'])
@csrf.exempt
def cleanup_backups():
    """Delete all backup files"""
    try:
        # Get the backup directory path
        backup_dir = Path('/backups')
        
        # Check if backup directory exists
        if not backup_dir.exists():
            return jsonify({'success': False, 'error': 'Backup directory not found'}), 404
        
        # Count files before deletion
        backup_files = list(backup_dir.glob('*.xml'))
        file_count = len(backup_files)
        
        if file_count == 0:
            return jsonify({'success': True, 'message': 'No backup files to delete', 'deleted_count': 0})
        
        # Delete all backup files
        for backup_file in backup_files:
            backup_file.unlink()
        
        logger.info(f"Deleted {file_count} backup files")
        log_operation('backups_cleanup', {'deleted_count': file_count})
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {file_count} backup file(s)',
            'deleted_count': file_count
        })
    except Exception as e:
        logger.error(f"Error cleaning up backups: {e}")
        log_operation('backups_cleanup_error', {'error': str(e)})
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get configuration summary (without sensitive data)"""
    try:
        summary = Config.get_summary()
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({'error': str(e)}), 500


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
        logger.info("Starting Palo-Sync web interface...")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

