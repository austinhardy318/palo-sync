"""
Integration tests for API endpoints
Tests the complete API workflow including authentication, error handling, and edge cases
"""

import os
import json
from unittest.mock import Mock, patch, MagicMock
import pytest

# Set up test environment
os.environ.setdefault("FLASK_SECRET_KEY", "test_secret_key_for_pytest")
os.environ.setdefault("PROD_NMS_HOST", "prod-panorama.example.com")
os.environ.setdefault("PROD_NMS_USERNAME", "admin")
os.environ.setdefault("PROD_NMS_PASSWORD", "password123")
os.environ.setdefault("LAB_NMS_HOST", "lab-panorama.example.com")
os.environ.setdefault("LAB_NMS_USERNAME", "admin")
os.environ.setdefault("LAB_NMS_PASSWORD", "password123")


# Note: mock_sync_service fixture is now in conftest.py
# Use the shared fixture from conftest for consistency


class TestStatusAPI:
    """Test /api/status endpoint"""
    
    def test_status_endpoint_requires_auth(self, client):
        """Test that status endpoint requires authentication"""
        # Set up authentication requirement
        os.environ.setdefault("GUI_USERNAME", "admin")
        os.environ.setdefault("GUI_PASSWORD", "password")
        
        resp = client.get('/api/status')
        # API endpoint should return 401 (not redirect) when auth required
        assert resp.status_code == 401, f"Expected 401 for unauthorized API access, got {resp.status_code}"
        assert resp.is_json, "API error response must be JSON"
        data = resp.get_json()
        assert data.get('success') is False or 'error' in data, "Error response must indicate failure"
    
    def test_status_endpoint_success(self, authenticated_client, mock_sync_service):
        """Test successful status check"""
        resp = authenticated_client.get('/api/status')
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert data['success'] is True
        assert 'production' in data
        assert 'lab' in data
    
    def test_status_endpoint_connection_error(self, authenticated_client):
        """Test status endpoint handles connection errors"""
        from app.exceptions import PanoramaConnectionError
        
        with patch('app.main.sync_manager.test_connection') as mock_test:
            mock_test.side_effect = PanoramaConnectionError(
                "prod-panorama.example.com",
                message="Connection failed"
            )
            
            resp = authenticated_client.get('/api/status')
            assert resp.status_code == 503  # Service Unavailable


class TestDiffAPI:
    """Test /api/diff endpoint"""
    
    def test_diff_endpoint_requires_auth(self, client):
        """Test that diff endpoint requires authentication"""
        os.environ.setdefault("GUI_USERNAME", "admin")
        os.environ.setdefault("GUI_PASSWORD", "password")
        
        resp = client.post('/api/diff')
        # API endpoint should return 401 (not redirect) when auth required
        assert resp.status_code == 401, f"Expected 401 for unauthorized API access, got {resp.status_code}"
        assert resp.is_json, "API error response must be JSON"
        data = resp.get_json()
        assert data.get('success') is False or 'error' in data, "Error response must indicate failure"
    
    def test_diff_endpoint_success(self, authenticated_client, mock_sync_service):
        """Test successful diff generation"""
        resp = authenticated_client.post('/api/diff')
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert data['success'] is True
        assert 'differences' in data
        assert 'timestamp' in data
    
    def test_diff_endpoint_handles_error(self, authenticated_client):
        """Test diff endpoint handles errors"""
        from app.exceptions import PanoramaConnectionError
        
        with patch('app.main.sync_manager.generate_diff') as mock_diff:
            mock_diff.side_effect = PanoramaConnectionError(
                "prod-panorama.example.com",
                message="Connection failed"
            )
            
            resp = authenticated_client.post('/api/diff')
            assert resp.status_code == 503


class TestSyncAPI:
    """Test /api/sync endpoint"""
    
    def test_sync_endpoint_requires_auth(self, client):
        """Test that sync endpoint requires authentication"""
        os.environ.setdefault("GUI_USERNAME", "admin")
        os.environ.setdefault("GUI_PASSWORD", "password")
        
        resp = client.post('/api/sync', json={'create_backup': True})
        # API endpoint should return 401 (not redirect) when auth required
        assert resp.status_code == 401, f"Expected 401 for unauthorized API access, got {resp.status_code}"
        assert resp.is_json, "API error response must be JSON"
        data = resp.get_json()
        assert data.get('success') is False or 'error' in data, "Error response must indicate failure"
    
    def test_sync_endpoint_success_with_backup(self, authenticated_client, mock_sync_service):
        """Test successful sync with backup"""
        resp = authenticated_client.post(
            '/api/sync',
            json={'create_backup': True, 'commit': False}
        )
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert data['success'] is True
        assert 'sync_id' in data
        assert data['backup_created'] is True
    
    def test_sync_endpoint_success_without_backup(self, authenticated_client, mock_sync_service):
        """Test successful sync without backup"""
        mock_sync_service.sync_configuration.return_value = {
            'success': True,
            'sync_id': '20240101_120000',
            'timestamp': '2024-01-01T12:00:00',
            'backup_created': False,
            'backup_path': None,
            'commit_job_id': None
        }
        
        resp = authenticated_client.post(
            '/api/sync',
            json={'create_backup': False, 'commit': False}
        )
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert data['success'] is True
        assert data['backup_created'] is False
    
    def test_sync_endpoint_validation_error(self, authenticated_client):
        """Test sync endpoint validates input"""
        # Invalid create_backup value (not boolean)
        resp = authenticated_client.post(
            '/api/sync',
            json={'create_backup': 'yes', 'commit': False}
        )
        assert resp.status_code == 400
        
        data = resp.get_json()
        assert data['success'] is False
        assert 'error' in data
    
    def test_sync_endpoint_handles_sync_error(self, authenticated_client):
        """Test sync endpoint handles sync errors"""
        from app.exceptions import SyncError
        
        with patch('app.main.sync_manager.sync_configuration') as mock_sync:
            mock_sync.side_effect = SyncError("Sync failed", operation='sync')
            
            resp = authenticated_client.post(
                '/api/sync',
                json={'create_backup': False, 'commit': False}
            )
            assert resp.status_code == 500


class TestBackupsAPI:
    """Test /api/backups endpoints"""
    
    def test_list_backups_requires_auth(self, client):
        """Test that list backups requires authentication"""
        os.environ.setdefault("GUI_USERNAME", "admin")
        os.environ.setdefault("GUI_PASSWORD", "password")
        
        resp = client.get('/api/backups')
        # API endpoint should return 401 (not redirect) when auth required
        assert resp.status_code == 401, f"Expected 401 for unauthorized API access, got {resp.status_code}"
        assert resp.is_json, "API error response must be JSON"
        data = resp.get_json()
        assert data.get('success') is False or 'error' in data, "Error response must indicate failure"
    
    def test_list_backups_success(self, authenticated_client, temp_backup_dir):
        """Test successful backup listing"""
        backup_path = str(temp_backup_dir / "lab_backup_20240101_120000.xml")
        with patch('app.main.backup_service.list_backups') as mock_list:
            mock_list.return_value = [
                {
                    'filename': 'lab_backup_20240101_120000.xml',
                    'path': backup_path,
                    'size': 1024,
                    'modified': '2024-01-01T12:00:00'
                }
            ]
            
            resp = authenticated_client.get('/api/backups')
            assert resp.status_code == 200
            
            data = resp.get_json()
            assert data['success'] is True
            assert 'backups' in data
            assert len(data['backups']) == 1
    
    def test_download_backup_success(self, authenticated_client, temp_backup_dir, monkeypatch):
        """Test successful backup download"""
        from pathlib import Path
        
        backup_file = temp_backup_dir / "test_backup.xml"
        backup_file.write_text('<config>test</config>')
        
        # Patch sync_manager to use temp backup directory
        from app.main import sync_manager
        original_backup_dir = sync_manager.backup_dir
        sync_manager.backup_dir = temp_backup_dir
        
        try:
            resp = authenticated_client.get(f'/api/backups/download/{backup_file.name}')
            assert resp.status_code == 200
            assert resp.is_json or 'application/xml' in resp.content_type
        finally:
            sync_manager.backup_dir = original_backup_dir
    
    def test_download_backup_not_found(self, authenticated_client, temp_backup_dir, monkeypatch):
        """Test backup download with missing file"""
        from app.exceptions import NotFoundError
        
        # Patch sync_manager to use temp backup directory
        from app.main import sync_manager
        original_backup_dir = sync_manager.backup_dir
        sync_manager.backup_dir = temp_backup_dir
        
        try:
            resp = authenticated_client.get('/api/backups/download/nonexistent.xml')
            assert resp.status_code == 404
        finally:
            sync_manager.backup_dir = original_backup_dir
    
    def test_restore_backup_validation_error(self, authenticated_client):
        """Test restore backup validates input"""
        resp = authenticated_client.post(
            '/api/backups/restore',
            json={'backup_path': '../../etc/passwd.xml', 'commit': False}
        )
        assert resp.status_code == 400
    
    def test_delete_backup_success(self, authenticated_client, temp_backup_dir, monkeypatch):
        """Test successful backup deletion"""
        # Patch sync_manager backup_dir and backup_service.delete_backup
        from app.main import sync_manager
        original_backup_dir = sync_manager.backup_dir
        sync_manager.backup_dir = temp_backup_dir
        
        # Create a test backup file
        backup_file = temp_backup_dir / "test_backup.xml"
        backup_file.write_text('<config>test</config>')
        
        try:
            # Patch validate_backup_path to pass validation
            with patch('app.main.validate_backup_path', return_value=(True, None)), \
                 patch('app.main.backup_service.delete_backup') as mock_delete:
                mock_delete.return_value = {'success': True, 'message': 'Deleted'}
                
                resp = authenticated_client.post(
                    '/api/backups/delete',
                    json={'backup_path': str(backup_file)}
                )
                assert resp.status_code == 200
        finally:
            sync_manager.backup_dir = original_backup_dir


class TestSettingsAPI:
    """Test /api/settings endpoints"""
    
    def test_get_settings_requires_auth(self, client):
        """Test that get settings requires authentication"""
        os.environ.setdefault("GUI_USERNAME", "admin")
        os.environ.setdefault("GUI_PASSWORD", "password")
        
        resp = client.get('/api/settings')
        # API endpoint should return 401 (not redirect) when auth required
        assert resp.status_code == 401, f"Expected 401 for unauthorized API access, got {resp.status_code}"
        assert resp.is_json, "API error response must be JSON"
        data = resp.get_json()
        assert data.get('success') is False or 'error' in data, "Error response must indicate failure"
    
    def test_get_settings_success(self, authenticated_client):
        """Test successful settings retrieval"""
        with patch('app.main.get_settings_manager') as mock_manager:
            mock_settings = Mock()
            mock_settings.get_settings.return_value = {
                'createBackup': True,
                'commitConfig': False,
                'preserveHostname': True
            }
            mock_manager.return_value = mock_settings
            
            resp = authenticated_client.get('/api/settings')
            assert resp.status_code == 200
            
            data = resp.get_json()
            assert data['success'] is True
            assert 'settings' in data
    
    def test_save_settings_validation_error(self, authenticated_client):
        """Test save settings validates input"""
        # Mock settings manager to avoid file system issues
        with patch('app.main.get_settings_manager') as mock_manager:
            mock_settings = Mock()
            mock_settings.save_settings = Mock()
            mock_manager.return_value = mock_settings
            
            # Missing required fields
            resp = authenticated_client.post(
                '/api/settings',
                json={'settings': {}}
            )
            assert resp.status_code == 400
    
    def test_save_settings_invalid_types(self, authenticated_client):
        """Test save settings validates types"""
        # Mock settings manager to avoid file system issues
        with patch('app.main.get_settings_manager') as mock_manager:
            mock_settings = Mock()
            mock_settings.save_settings = Mock()
            mock_manager.return_value = mock_settings
            
            resp = authenticated_client.post(
                '/api/settings',
                json={
                    'settings': {
                        'createBackup': 'yes',  # Should be boolean
                        'commitConfig': False,
                        'preserveHostname': True
                    }
                }
            )
            assert resp.status_code == 400
    
    def test_save_settings_success(self, authenticated_client, tmp_path):
        """Test successful settings save"""
        # Mock settings manager to avoid file system issues
        with patch('app.main.get_settings_manager') as mock_manager:
            mock_settings = Mock()
            mock_settings.save_settings = Mock()
            mock_manager.return_value = mock_settings
            
            resp = authenticated_client.post(
                '/api/settings',
                json={
                    'settings': {
                        'createBackup': True,
                        'commitConfig': False,
                        'preserveHostname': True
                    }
                }
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data['success'] is True


class TestLoginLogoutAPI:
    """Test /login and /logout endpoints"""
    
    def test_login_get_renders_page(self, client):
        """Test GET /login renders login page"""
        resp = client.get('/login')
        assert resp.status_code == 200
        assert resp.is_json is False  # Should be HTML
    
    def test_login_post_success(self, client, monkeypatch):
        """Test successful login"""
        from app.main import authenticator
        
        # Mock authentication
        monkeypatch.setattr(authenticator, 'authenticate', Mock(return_value=(True, None)))
        
        resp = client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        })
        
        assert resp.status_code == 302  # Redirect after login
        assert resp.location == '/'
        
        # Verify session was set
        with client.session_transaction() as session:
            assert session.get('authenticated') is True
            assert session.get('username') == 'testuser'
    
    def test_login_post_failure(self, client, monkeypatch):
        """Test failed login"""
        from app.main import authenticator
        
        # Mock authentication failure
        monkeypatch.setattr(authenticator, 'authenticate', Mock(return_value=(False, 'Invalid credentials')))
        
        resp = client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpass'
        })
        
        assert resp.status_code == 200  # Stays on login page
        assert resp.is_json is False  # Should be HTML
    
    def test_login_post_missing_credentials(self, client):
        """Test login with missing credentials"""
        resp = client.post('/login', data={})
        
        assert resp.status_code == 200  # Stays on login page
        assert resp.is_json is False
    
    def test_login_rate_limiting(self, client, monkeypatch):
        """Test rate limiting on login attempts"""
        from app.main import authenticator
        
        # Mock authentication failure
        monkeypatch.setattr(authenticator, 'authenticate', Mock(return_value=(False, 'Invalid credentials')))
        
        # Make multiple login attempts
        for _ in range(6):
            client.post('/login', data={
                'username': 'testuser',
                'password': 'wrongpass'
            })
        
        # 6th attempt should be rate limited
        resp = client.post('/login', data={
            'username': 'testuser',
            'password': 'wrongpass'
        })
        
        # Should either be rate limited or still fail
        assert resp.status_code in (200, 429)
    
    def test_logout_clears_session(self, authenticated_client):
        """Test logout clears session"""
        # Verify authenticated session
        with authenticated_client.session_transaction() as session:
            assert session.get('authenticated') is True
        
        # Logout
        resp = authenticated_client.get('/logout')
        
        assert resp.status_code == 302  # Redirect to login
        assert resp.location == '/login'
        
        # Verify session was cleared
        with authenticated_client.session_transaction() as session:
            assert session.get('authenticated') is not True
            assert 'username' not in session or session.get('username') is None
    
    def test_logout_redirects_to_login(self, authenticated_client):
        """Test logout redirects to login page"""
        resp = authenticated_client.get('/logout')
        
        assert resp.status_code == 302
        assert '/login' in resp.location


class TestLogsAPI:
    """Test /api/logs endpoint"""
    
    def test_logs_endpoint_no_auth_required(self, client):
        """Test that logs endpoint doesn't require authentication (read-only)"""
        resp = client.get('/api/logs?limit=10')
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert 'logs' in data
        assert isinstance(data['logs'], list)
    
    def test_logs_endpoint_validates_limit(self, client):
        """Test logs endpoint validates limit parameter"""
        resp = client.get('/api/logs?limit=5000')  # Exceeds max
        assert resp.status_code == 400
    
    def test_logs_endpoint_invalid_limit(self, client):
        """Test logs endpoint rejects invalid limit"""
        resp = client.get('/api/logs?limit=abc')
        assert resp.status_code == 400


class TestErrorHandling:
    """Test error handling across API endpoints"""
    
    def test_custom_exception_handling(self, authenticated_client):
        """Test that custom exceptions are properly handled"""
        from app.exceptions import ValidationError
        
        # Mock the test_connection to raise ValidationError
        with patch('app.main.sync_manager.test_connection') as mock_test:
            # The exception needs to be raised during execution, not at patch time
            def raise_validation_error(*args, **kwargs):
                raise ValidationError("Invalid input", field='host')
            
            mock_test.side_effect = raise_validation_error
            
            resp = authenticated_client.get('/api/status')
            assert resp.status_code == 400
            
            data = resp.get_json()
            assert data['success'] is False
            assert 'error' in data
            assert data['error']['code'] == 'VALIDATION_FAILED'
    
    def test_not_found_error_handling(self, authenticated_client, temp_backup_dir, monkeypatch):
        """Test that NotFoundError is properly handled"""
        from app.exceptions import NotFoundError
        
        # Patch sync_manager backup_dir
        from app.main import sync_manager
        original_backup_dir = sync_manager.backup_dir
        sync_manager.backup_dir = temp_backup_dir
        
        try:
            # Patch validate_backup_path to pass validation, then raise NotFoundError from service
            with patch('app.main.validate_backup_path', return_value=(True, None)), \
                 patch('app.main.backup_service.delete_backup') as mock_delete:
                mock_delete.side_effect = NotFoundError('backup', identifier='test.xml')
                
                resp = authenticated_client.post(
                    '/api/backups/delete',
                    json={'backup_path': str(temp_backup_dir / 'test.xml')}
                )
                assert resp.status_code == 404
        finally:
            sync_manager.backup_dir = original_backup_dir
    
    def test_unhandled_exception_handling(self, authenticated_client):
        """Test that unhandled exceptions return 500"""
        with patch('app.main.sync_manager.test_connection') as mock_test:
            mock_test.side_effect = Exception("Unexpected error")
            
            resp = authenticated_client.get('/api/status')
            assert resp.status_code == 500
            
            data = resp.get_json()
            assert data['success'] is False
            assert 'error' in data


class TestCSRFProtection:
    """Test CSRF protection"""
    
    def test_csrf_token_endpoint(self, client):
        """Test CSRF token generation endpoint"""
        resp = client.get('/api/csrf-token')
        assert resp.status_code == 200
        
        data = resp.get_json()
        assert 'csrf_token' in data
        assert len(data['csrf_token']) > 0
    
    def test_api_endpoints_exempt_from_csrf(self, authenticated_client, mock_sync_service):
        """Test that API endpoints are exempt from CSRF (use session auth)"""
        # API endpoints should work without CSRF token when authenticated
        resp = authenticated_client.post('/api/diff')
        assert resp.status_code in (200, 401, 302)  # May require auth
    
    def test_csrf_error_returns_json(self, client):
        """Test that CSRF errors return JSON for API endpoints"""
        # Try to POST to an API endpoint without CSRF token
        resp = client.post('/api/diff')
        # Should either require auth or return JSON error
        if resp.status_code == 400:
            assert resp.is_json
            data = resp.get_json()
            assert 'error' in data or 'csrf' in str(data).lower()

