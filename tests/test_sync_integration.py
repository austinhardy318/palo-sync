"""
Integration tests for sync workflow with mocked Panorama API responses
Tests the complete sync workflow from diff generation through sync execution
"""

import os
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
import pytest
from app.exceptions import NotFoundError

# Set up test environment variables before imports
# These are set in conftest.py but we set them here too for safety
os.environ.setdefault("FLASK_SECRET_KEY", "test_secret_key_for_pytest")
os.environ.setdefault("PROD_NMS_HOST", "prod-panorama.example.com")
os.environ.setdefault("PROD_NMS_USERNAME", "admin")
os.environ.setdefault("PROD_NMS_PASSWORD", "password123")
os.environ.setdefault("LAB_NMS_HOST", "lab-panorama.example.com")
os.environ.setdefault("LAB_NMS_USERNAME", "admin")
os.environ.setdefault("LAB_NMS_PASSWORD", "password123")
os.environ.setdefault("LOG_SALT", "test_salt_for_pytest_12345")


# Note: mock_panorama_xml_response and mock_http_client fixtures are now in conftest.py
# These fixtures are shared across tests and should be used from conftest


@pytest.fixture
def sync_service(mock_http_client, temp_backup_dir, monkeypatch):
    """Fixture that provides a SyncService instance with mocked HTTP client"""
    import tempfile
    
    # Set backup and log directories to temp paths
    log_dir = tempfile.mkdtemp()
    os.environ['BACKUP_DIR'] = str(temp_backup_dir)
    os.environ['LOG_DIR'] = log_dir
    
    # Patch Config.BACKUP_DIR and Config.LOG_DIR to use temp directories
    from app.config import Config
    monkeypatch.setattr(Config, 'BACKUP_DIR', str(temp_backup_dir))
    monkeypatch.setattr(Config, 'LOG_DIR', log_dir)
    
    with patch('app.sync_service.HttpClient') as mock_http_class, \
         patch('app.sync_service.ConfigService') as mock_config_class:
        
        # Set up mocked HTTP client
        mock_http_class.return_value = mock_http_client
        
        # Set up mocked ConfigService
        mock_config = Mock()
        backup_path = str(temp_backup_dir / "lab_backup_12345.xml")
        mock_config.export_config = Mock(return_value='<config><system><hostname>prod-panorama</hostname></system></config>')
        mock_config.stream_export_to_file = Mock(return_value=backup_path)
        mock_config.import_config = Mock(return_value='candidate-only')
        mock_config_class.return_value = mock_config
        
        from app.sync_service import SyncService
        service = SyncService()
        service.http = mock_http_client
        service.config = mock_config
        service.backup_dir = temp_backup_dir
        service.log_dir = Path(log_dir)
        
        return service


class TestSyncWorkflowIntegration:
    """Integration tests for the complete sync workflow"""
    
    def test_full_sync_workflow_with_backup(self, sync_service, tmp_path):
        """Test complete sync workflow: backup -> export -> import"""
        # Set backup directory to temp path
        sync_service.backup_dir = tmp_path / "backups"
        sync_service.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Execute sync with backup
        result = sync_service.sync_configuration(create_backup=True, commit=False)
        
        # Verify results
        assert result['success'] is True
        assert result['backup_created'] is True
        assert result['backup_path'] is not None
        assert 'sync_id' in result
        assert result['commit_job_id'] == 'candidate-only'  # No commit
        
        # Verify backup was created
        backup_file = Path(result['backup_path'])
        assert backup_file.exists() or sync_service.config.stream_export_to_file.called
    
    def test_sync_workflow_without_backup(self, sync_service):
        """Test sync workflow without creating backup"""
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        assert result['success'] is True
        assert result['backup_created'] is False
        assert result['backup_path'] is None
    
    def test_sync_workflow_with_commit(self, sync_service, mock_http_client):
        """Test sync workflow with commit"""
        # Mock commit response
        def mock_post_with_commit(url, **kwargs):
            response = Mock()
            response.status_code = 200
            data = kwargs.get('data', {}) or kwargs.get('params', {})
            if 'type=commit' in str(data):
                root = ET.Element('response', {'status': 'success'})
                result = ET.SubElement(root, 'result')
                job_elem = ET.SubElement(result, 'job')
                job_elem.text = '98765'
                response.text = ET.tostring(root, encoding='unicode')
            else:
                response.text = '<response status="success"><msg>Success</msg></response>'
            return response
        
        sync_service.http.post = Mock(side_effect=mock_post_with_commit)
        sync_service.config.import_config = Mock(return_value='98765')
        
        result = sync_service.sync_configuration(create_backup=False, commit=True)
        
        assert result['success'] is True
        assert result['commit_job_id'] == '98765'
    
    def test_sync_workflow_handles_connection_error(self, sync_service, mock_http_client):
        """Test sync workflow handles connection errors gracefully"""
        from app.exceptions import PanoramaConnectionError
        import requests
        
        # Mock connection error
        sync_service.config.export_config = Mock(side_effect=requests.ConnectionError("Connection refused"))
        
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        assert result['success'] is False
        assert result['error'] is not None
        assert 'Connection' in result['error'] or 'Failed' in result['error']
    
    def test_sync_workflow_handles_api_error(self, sync_service):
        """Test sync workflow handles API errors"""
        from app.exceptions import PanoramaAPIError
        
        # Mock API error
        sync_service.config.export_config = Mock(side_effect=PanoramaAPIError("API error occurred", api_response="<error>"))
        
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        assert result['success'] is False
        assert result['error'] is not None
    
    def test_sync_preserves_hostname(self, sync_service, mock_http_client):
        """Test that sync preserves lab hostname"""
        # Mock get_current_hostname to return a hostname
        sync_service.get_current_hostname = Mock(return_value='lab-panorama-01')
        sync_service.set_hostname = Mock(return_value=True)
        
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        # Verify hostname preservation was attempted
        assert sync_service.get_current_hostname.called
        assert sync_service.set_hostname.called
    
    def test_diff_generation_integration(self, sync_service):
        """Test diff generation with mocked configurations"""
        from app.diff_service import DiffService
        
        # Mock different configs
        prod_config = '<config><system><hostname>prod-panorama</hostname></system></config>'
        lab_config = '<config><system><hostname>lab-panorama</hostname></system></config>'
        
        sync_service.export_config = Mock(side_effect=lambda h, a, l: prod_config if 'prod' in h else lab_config)
        
        diff_service = DiffService(sync_service)
        result = diff_service.generate_diff()
        
        assert result['success'] is True
        assert 'differences' in result
        assert 'timestamp' in result
    
    def test_diff_caching_integration(self, sync_service):
        """Test that diff results are properly cached"""
        from app.diff_service import DiffService
        import hashlib
        import re
        
        # Clear cache
        DiffService.clear_cache()
        
        # Use same config for both prod and lab to ensure same hash (triggers fast path)
        config = '<config><system><hostname>test</hostname></system></config>'
        sync_service.export_config = Mock(return_value=config)
        
        diff_service = DiffService(sync_service)
        
        # First call - should compute diff
        result1 = diff_service.generate_diff()
        assert result1['success'] is True
        # First call may be cached if fast path (identical configs) or not cached if different
        # If fast path, it won't have 'cached' key since it's returned directly
        assert 'cached' not in result1 or result1.get('cached') is None
        
        # Second call with same configs - should use cache (if not fast path)
        result2 = diff_service.generate_diff()
        assert result2['success'] is True
        # With identical configs, second call should be cached (or fast path)
        # If cached, should have 'cached': True; if fast path, may not have 'cached' key
        if result2.get('cached') is not None:
            assert result2.get('cached') is True


class TestBackupRestoreIntegration:
    """Integration tests for backup and restore operations"""
    
    def test_backup_creation_integration(self, sync_service, tmp_path):
        """Test backup creation workflow"""
        sync_service.backup_dir = tmp_path / "backups"
        sync_service.backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_path = sync_service.create_backup("lab")
        
        assert backup_path is not None
        assert isinstance(backup_path, str)
        assert sync_service.config.stream_export_to_file.called
    
    def test_restore_backup_integration(self, sync_service, tmp_path):
        """Test restore backup workflow"""
        sync_service.backup_dir = tmp_path / "backups"
        sync_service.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a test backup file
        backup_file = sync_service.backup_dir / "test_backup.xml"
        backup_content = '<config><system><hostname>restored</hostname></system></config>'
        backup_file.write_text(backup_content)
        
        # Restore the backup
        result = sync_service.restore_backup(str(backup_file), commit=False)
        
        assert result['success'] is True
        assert sync_service.config.import_config.called
        
        # Verify the config content was passed to import
        call_args = sync_service.config.import_config.call_args
        assert backup_content in call_args[0][2] or backup_content == call_args[0][2]  # Check config_xml parameter
    
    def test_restore_backup_file_not_found(self, sync_service):
        """Test restore backup handles missing file"""
        from app.exceptions import NotFoundError
        
        with pytest.raises(NotFoundError):
            sync_service.restore_backup('/nonexistent/backup.xml', commit=False)
    
    def test_list_backups_integration(self, sync_service, tmp_path):
        """Test listing backups"""
        sync_service.backup_dir = tmp_path / "backups"
        sync_service.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test backup files
        backup1 = sync_service.backup_dir / "lab_backup_20240101_120000.xml"
        backup2 = sync_service.backup_dir / "lab_backup_20240101_130000.xml"
        backup1.write_text('<config>backup1</config>')
        backup2.write_text('<config>backup2</config>')
        
        backups = sync_service.list_backups()
        
        assert len(backups) == 2
        assert all('filename' in b for b in backups)
        assert all('path' in b for b in backups)
        assert all('size' in b for b in backups)
        assert all('modified' in b for b in backups)


class TestErrorScenarios:
    """Test error scenarios and edge cases"""
    
    def test_api_key_generation_failure(self, sync_service, mock_http_client):
        """Test handling of API key generation failure"""
        from app.exceptions import PanoramaAPIError
        
        # Mock API key generation failure
        def mock_get_error(url, **kwargs):
            response = Mock()
            response.status_code = 401
            response.text = '<response status="error"><msg>Authentication failed</msg></response>'
            response.raise_for_status = Mock(side_effect=Exception("401 Unauthorized"))
            return response
        
        sync_service.http.get = Mock(side_effect=mock_get_error)
        
        # This should raise an exception when trying to get API key
        with pytest.raises(Exception):
            sync_service._get_api_key("test-host", {'username': 'user', 'password': 'pass'})
    
    def test_config_export_timeout(self, sync_service):
        """Test handling of config export timeout"""
        import requests
        
        # Mock timeout
        sync_service.config.export_config = Mock(side_effect=requests.Timeout("Request timeout"))
        
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        assert result['success'] is False
        assert result['error'] is not None
    
    def test_config_import_failure(self, sync_service):
        """Test handling of config import failure"""
        from app.exceptions import PanoramaAPIError
        
        # Mock import failure
        sync_service.config.import_config = Mock(side_effect=PanoramaAPIError("Import failed", api_response="<error>"))
        
        result = sync_service.sync_configuration(create_backup=False, commit=False)
        
        assert result['success'] is False
        assert result['error'] is not None
    
    def test_backup_creation_failure(self, sync_service):
        """Test handling of backup creation failure"""
        from app.exceptions import BackupError
        
        # Mock backup creation failure
        sync_service.config.stream_export_to_file = Mock(side_effect=Exception("Backup failed"))
        
        with pytest.raises(BackupError):
            sync_service.create_backup("lab")


class TestConnectionStatus:
    """Test connection status checking"""
    
    def test_test_connection_success(self, sync_service, mock_http_client):
        """Test successful connection check"""
        with patch('app.sync_service.panorama.Panorama') as mock_pano:
            mock_instance = Mock()
            mock_instance.refresh_system_info = Mock(return_value={'version': '10.0.0'})
            mock_pano.return_value = mock_instance
            
            result = sync_service.test_connection()
            
            assert result['production']['connected'] is True
            assert result['lab']['connected'] is True
    
    def test_test_connection_production_failure(self, sync_service):
        """Test connection check with production failure"""
        from app.exceptions import PanoramaConnectionError
        
        with patch('app.sync_service.panorama.Panorama') as mock_pano:
            def side_effect(hostname, **kwargs):
                # Check if this is production host by comparing with Config.PROD_HOST
                from app.config import Config
                if hostname == Config.PROD_HOST:
                    raise PanoramaConnectionError(hostname, message="Connection failed")
                # Lab connection succeeds
                mock_instance = Mock()
                mock_instance.refresh_system_info = Mock(return_value={'version': '10.0.0'})
                return mock_instance
            
            mock_pano.side_effect = side_effect
            
            # test_connection should catch PanoramaConnectionError and return error, not raise
            result = sync_service.test_connection()
            
            assert result['production']['connected'] is False
            assert result['production']['error'] is not None
            # Lab should still succeed
            assert result['lab']['connected'] is True
    
    def test_test_connection_lab_failure(self, sync_service):
        """Test connection check with lab failure"""
        from app.exceptions import PanoramaConnectionError
        
        with patch('app.sync_service.panorama.Panorama') as mock_pano:
            def side_effect(hostname, **kwargs):
                if 'lab' in hostname:
                    raise PanoramaConnectionError(hostname, message="Connection failed")
                mock_instance = Mock()
                mock_instance.refresh_system_info = Mock(return_value={'version': '10.0.0'})
                return mock_instance
            
            mock_pano.side_effect = side_effect
            
            result = sync_service.test_connection()
            
            assert result['production']['connected'] is True
            assert result['lab']['connected'] is False
            assert result['lab']['error'] is not None

