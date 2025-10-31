"""
Shared test fixtures and configuration
Standardizes test setup across all test files
"""

import os
import pytest
import xml.etree.ElementTree as ET
from unittest.mock import Mock
from pathlib import Path


def pytest_collection_modifyitems(config, items):
    """Reorder tests to run import-dependent tests first."""
    # Tests that need to run before app.main is imported
    early_tests = [
        'test_log_salt_warning_in_development',
        'test_log_salt_validation'
    ]
    
    # Separate early tests from others
    early_items = []
    other_items = []
    
    for item in items:
        if any(test_name in item.name for test_name in early_tests):
            early_items.append(item)
        else:
            other_items.append(item)
    
    # Reorder: early tests first, then others
    items[:] = early_items + other_items


# Set up test environment variables at module level
# These are defaults that can be overridden with monkeypatch in individual tests
os.environ.setdefault("FLASK_SECRET_KEY", "test_secret_key_for_pytest")
os.environ.setdefault("REDIS_URL", "redis://localhost:6380/0")
os.environ.setdefault("FLASK_ENV", "testing")

# Minimal NMS credentials to satisfy Config on import
os.environ.setdefault("PROD_NMS_HOST", "prod-panorama.example.com")
os.environ.setdefault("PROD_NMS_USERNAME", "admin")
os.environ.setdefault("PROD_NMS_PASSWORD", "test_password")
os.environ.setdefault("LAB_NMS_HOST", "lab-panorama.example.com")
os.environ.setdefault("LAB_NMS_USERNAME", "admin")
os.environ.setdefault("LAB_NMS_PASSWORD", "test_password")

# Test-specific settings
os.environ.setdefault("LOG_SALT", "test_salt_for_pytest_12345")
os.environ.setdefault("SSL_VERIFY", "false")


@pytest.fixture(scope="session")
def flask_app():
    """Create Flask application instance for testing
    
    Note: This fixture is lazy - it only imports app.main when first requested.
    Tests that need to import app.main themselves should run first.
    """
    # Ensure all required env vars are set before importing
    import os
    import sys
    from pathlib import Path
    
    # Set environment variables before any imports
    os.environ['FLASK_SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'test_secret_key_for_pytest')
    os.environ['LOG_SALT'] = os.environ.get('LOG_SALT', 'test_salt_for_pytest_12345')
    os.environ['FLASK_ENV'] = 'testing'
    
    # Use temp directories for backups and logs in tests
    import tempfile
    temp_backup = tempfile.mkdtemp()
    temp_log = tempfile.mkdtemp()
    
    os.environ['BACKUP_DIR'] = temp_backup
    os.environ['LOG_DIR'] = temp_log
    
    # Ensure directories exist
    Path(temp_backup).mkdir(parents=True, exist_ok=True)
    Path(temp_log).mkdir(parents=True, exist_ok=True)
    
    # Mock Redis connection pool to avoid connection issues
    try:
        import redis
        from unittest.mock import patch, MagicMock
        
        # Patch Redis connection before app.main import
        mock_pool = MagicMock()
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_client.lpush = MagicMock()
        mock_client.ltrim = MagicMock()
        mock_client.lrange = MagicMock(return_value=[])
        
        # Store the original Redis
        original_redis = redis.Redis
        
        # Temporarily patch during import
        redis.Redis = MagicMock(return_value=mock_client)
        redis.ConnectionPool.from_url = MagicMock(return_value=mock_pool)
    except ImportError:
        pass
    
    try:
        # Import after setting up environment
        from app.main import app as flask_app
        flask_app.testing = True
    finally:
        # Restore original Redis if we patched it
        if 'original_redis' in locals():
            redis.Redis = original_redis
    
    return flask_app


@pytest.fixture
def client(flask_app):
    """Create Flask test client"""
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def authenticated_client(client):
    """Create authenticated Flask test client"""
    with client.session_transaction() as session:
        session['authenticated'] = True
        session['username'] = 'testuser'
        session.permanent = True
    return client


@pytest.fixture
def mock_panorama_xml_response():
    """Fixture that provides valid Panorama XML responses"""
    
    def create_success_response(message="Success", result_text=None, extra_elements=None):
        """Create a success XML response"""
        root = ET.Element('response', {'status': 'success'})
        msg_elem = ET.SubElement(root, 'msg')
        msg_elem.text = message
        if result_text:
            result_elem = ET.SubElement(root, 'result')
            result_elem.text = result_text
        if extra_elements:
            for tag, text in extra_elements.items():
                elem = ET.SubElement(root, tag)
                elem.text = text
        return ET.tostring(root, encoding='unicode')
    
    def create_config_export_xml():
        """Create a sample configuration export XML"""
        root = ET.Element('config')
        system = ET.SubElement(root, 'system')
        hostname = ET.SubElement(system, 'hostname')
        hostname.text = 'panorama-device'
        timezone = ET.SubElement(system, 'timezone')
        timezone.text = 'America/New_York'
        return ET.tostring(root, encoding='unicode')
    
    def create_error_response(message="Error occurred", code="401"):
        """Create an error XML response"""
        root = ET.Element('response', {'status': 'error', 'code': code})
        msg_elem = ET.SubElement(root, 'msg')
        msg_elem.text = message
        return ET.tostring(root, encoding='unicode')
    
    def create_api_key_response(api_key="test_api_key_12345"):
        """Create an API key generation response"""
        root = ET.Element('response', {'status': 'success'})
        result = ET.SubElement(root, 'result')
        key_elem = ET.SubElement(result, 'key')
        key_elem.text = api_key
        return ET.tostring(root, encoding='unicode')
    
    def create_commit_response(job_id="12345"):
        """Create a commit job response"""
        root = ET.Element('response', {'status': 'success'})
        result = ET.SubElement(root, 'result')
        job_elem = ET.SubElement(result, 'job')
        job_elem.text = job_id
        return ET.tostring(root, encoding='unicode')
    
    def create_system_info_response(hostname="lab-panorama"):
        """Create a system info response"""
        root = ET.Element('response', {'status': 'success'})
        system = ET.SubElement(root, 'system')
        hostname_elem = ET.SubElement(system, 'hostname')
        hostname_elem.text = hostname
        version = ET.SubElement(system, 'sw-version')
        version.text = '10.0.0'
        return ET.tostring(root, encoding='unicode')
    
    return {
        'success': create_success_response,
        'config_export': create_config_export_xml,
        'error': create_error_response,
        'api_key': create_api_key_response,
        'commit': create_commit_response,
        'system_info': create_system_info_response
    }


@pytest.fixture
def mock_http_client(mock_panorama_xml_response):
    """Fixture that provides a mocked HTTP client for Panorama API calls"""
    
    def mock_get(url, **kwargs):
        """Mock GET requests"""
        response = Mock()
        response.status_code = 200
        response.headers = {}
        
        if 'type=export' in url:
            # Configuration export
            response.text = mock_panorama_xml_response['config_export']()
        elif 'type=keygen' in url:
            # API key generation
            response.text = mock_panorama_xml_response['api_key']()
        else:
            response.text = mock_panorama_xml_response['success']()
        
        response.raise_for_status = Mock()
        return response
    
    def mock_post(url, **kwargs):
        """Mock POST requests"""
        response = Mock()
        response.status_code = 200
        response.headers = {}
        
        # Check the type parameter from data or params
        data = kwargs.get('data', {}) or kwargs.get('params', {})
        cmd = data.get('cmd', '') if isinstance(data, dict) else ''
        
        if 'type=op' in str(data) or 'type=op' in str(kwargs.get('params', {})):
            # Operational command
            if 'system><info' in cmd or 'show><system' in cmd:
                # System info command
                response.text = mock_panorama_xml_response['system_info']()
            else:
                response.text = mock_panorama_xml_response['success']()
        elif 'type=import' in str(data) or 'type=import' in str(kwargs.get('params', {})):
            # Import operation
            response.text = mock_panorama_xml_response['success'](result_text='config.xml')
        elif 'type=commit' in str(data) or 'load' in cmd:
            # Load or commit operation
            if 'load' in cmd:
                response.text = mock_panorama_xml_response['success']()
            else:
                response.text = mock_panorama_xml_response['commit'](job_id='12345')
        else:
            response.text = mock_panorama_xml_response['success']()
        
        response.raise_for_status = Mock()
        return response
    
    client = Mock()
    client.get = Mock(side_effect=mock_get)
    client.post = Mock(side_effect=mock_post)
    
    return client


@pytest.fixture
def temp_settings_file(tmp_path, monkeypatch):
    """Create a temporary settings file for testing
    
    Returns:
        tuple: (settings_file, settings_dir) - Path to settings file and directory
    """
    settings_dir = tmp_path / "settings"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "user_settings.json"
    
    # Set cache TTL to 1 second for faster testing
    monkeypatch.setenv("SETTINGS_CACHE_TTL_SECONDS", "1")
    
    return settings_file, settings_dir


@pytest.fixture
def temp_settings_file_with_manager(tmp_path, monkeypatch):
    """Create a temporary settings file with SettingsManager instance for testing
    
    This is a more complete fixture that also creates the SettingsManager instance.
    Use this when you need the manager object, not just the file path.
    
    Returns:
        tuple: (settings_file, manager) - Path to settings file and SettingsManager instance
    """
    settings_dir = tmp_path / "settings"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "user_settings.json"
    
    # Set cache TTL to 1 second for faster testing
    monkeypatch.setenv("SETTINGS_CACHE_TTL_SECONDS", "1")
    
    # Import after setting env var
    from app.settings_manager import SettingsManager
    
    # Reset the global instance
    import app.settings_manager
    app.settings_manager._settings_manager = None
    
    # Create settings manager with temp path
    manager = SettingsManager(settings_path=str(settings_file), cache_ttl_seconds=1)
    
    return settings_file, manager


@pytest.fixture
def temp_backup_dir(tmp_path):
    """Create a temporary backup directory for testing"""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


@pytest.fixture
def mock_sync_service(temp_backup_dir):
    """Create a mocked SyncService instance
    
    This fixture patches sync_manager with a mock that has proper defaults.
    If you need a custom backup directory, use temp_backup_dir fixture.
    
    Args:
        temp_backup_dir: Temporary backup directory (optional)
    """
    from unittest.mock import Mock, patch, MagicMock
    from pathlib import Path
    
    with patch('app.main.sync_manager') as mock_service:
        # Use provided temp_backup_dir or default
        backup_path = str(temp_backup_dir / "lab_backup_20240101_120000.xml") if temp_backup_dir else '/backups/lab_backup_20240101_120000.xml'
        
        mock_service.test_connection = Mock(return_value={
            'production': {'connected': True, 'version': '10.0.0'},
            'lab': {'connected': True, 'version': '10.0.0'}
        })
        mock_service.generate_diff = Mock(return_value={
            'success': True,
            'timestamp': '2024-01-01T12:00:00',
            'differences': {
                'items_added': 1,
                'items_removed': 0,
                'values_changed': 1,
                'items_moved': 0
            },
            'raw_diff': '{}',
            'diff_json': '{}'
        })
        mock_service.sync_configuration = Mock(return_value={
            'success': True,
            'sync_id': '20240101_120000',
            'timestamp': '2024-01-01T12:00:00',
            'backup_created': True,
            'backup_path': backup_path,
            'commit_job_id': None
        })
        mock_service.restore_backup = Mock(return_value={
            'success': True,
            'timestamp': '2024-01-01T12:00:00',
            'commit_job_id': None
        })
        mock_service.backup_dir = temp_backup_dir if temp_backup_dir else Path('/backups')
        mock_service.export_config = Mock(return_value='<config>test</config>')
        mock_service.create_backup = Mock(return_value=backup_path)
        
        yield mock_service


@pytest.fixture
def mock_backup_service():
    """Create a mocked BackupService instance"""
    from unittest.mock import Mock
    from app.backup_service import BackupService
    
    mock_service = Mock(spec=BackupService)
    mock_service.list_backups = Mock(return_value=[])
    mock_service.delete_backup = Mock(return_value={'success': True, 'message': 'Deleted'})
    mock_service.create_lab_backup = Mock(return_value='/backups/test_backup.xml')
    
    return mock_service
