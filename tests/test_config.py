"""
Tests for config module
Tests hostname validation, authentication method selection, and configuration validation
"""

import os
import pytest
from unittest.mock import patch


@pytest.fixture
def reset_config():
    """Reset config module after each test"""
    yield
    # Reload config module to reset environment variables
    import importlib
    import app.config
    importlib.reload(app.config)


class TestHostnameValidation:
    """Test hostname validation functions"""
    
    def test_is_valid_hostname_with_valid_hostname(self):
        """Test valid hostname"""
        from app.config import Config
        
        assert Config.is_valid_hostname('example.com') is True
        assert Config.is_valid_hostname('panorama.example.com') is True
        assert Config.is_valid_hostname('panorama-01.example.com') is True
    
    def test_is_valid_hostname_with_valid_ip(self):
        """Test valid IP address"""
        from app.config import Config
        
        assert Config.is_valid_hostname('192.168.1.1') is True
        assert Config.is_valid_hostname('10.0.0.1') is True
        assert Config.is_valid_hostname('2001:db8::1') is True
    
    def test_is_valid_hostname_with_invalid_hostname(self):
        """Test invalid hostname"""
        from app.config import Config
        
        assert Config.is_valid_hostname('') is False
        assert Config.is_valid_hostname('host@name') is False
        assert Config.is_valid_hostname('-invalid.example.com') is False
        assert Config.is_valid_hostname('invalid-.example.com') is False
    
    def test_is_valid_hostname_with_long_hostname(self):
        """Test hostname exceeding max length"""
        from app.config import Config
        
        long_hostname = 'a' * 254 + '.com'
        assert Config.is_valid_hostname(long_hostname) is False
    
    def test_validate_hostname_with_valid_hostname(self):
        """Test hostname validation with valid hostname"""
        from app.config import Config
        
        is_valid, error = Config.validate_hostname('example.com', 'TEST_HOST')
        assert is_valid is True
        assert error is None
    
    def test_validate_hostname_with_empty_hostname(self):
        """Test hostname validation with empty hostname"""
        from app.config import Config
        
        is_valid, error = Config.validate_hostname('', 'TEST_HOST')
        assert is_valid is False
        assert error is not None
        assert 'required' in error.lower()
    
    def test_validate_hostname_with_invalid_hostname(self):
        """Test hostname validation with invalid hostname"""
        from app.config import Config
        
        is_valid, error = Config.validate_hostname('host@name', 'TEST_HOST')
        assert is_valid is False
        assert error is not None
        assert 'valid' in error.lower() or 'hostname' in error.lower()


class TestAuthenticationMethodSelection:
    """Test authentication method selection"""
    
    def test_get_prod_auth_with_api_key(self, monkeypatch):
        """Test production auth prioritizes API key"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_API_KEY', 'api_key_123')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        auth = app.config.Config.get_prod_auth()
        assert 'api_key' in auth
        assert auth['api_key'] == 'api_key_123'
        assert 'username' not in auth
        assert 'password' not in auth
    
    def test_get_prod_auth_with_password(self, monkeypatch):
        """Test production auth falls back to username/password"""
        import app.config
        
        monkeypatch.delenv('PROD_NMS_API_KEY', raising=False)
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        auth = app.config.Config.get_prod_auth()
        assert 'username' in auth
        assert 'password' in auth
        assert auth['username'] == 'user'
        assert auth['password'] == 'pass'
        assert 'api_key' not in auth
    
    def test_get_prod_auth_with_no_credentials(self, monkeypatch):
        """Test production auth raises error when no credentials"""
        from app.config import Config
        
        # Save original values
        original_api_key = Config.PROD_API_KEY
        original_username = Config.PROD_USERNAME
        original_password = Config.PROD_PASSWORD
        
        try:
            # Clear credentials using monkeypatch
            monkeypatch.setattr(Config, 'PROD_API_KEY', None)
            monkeypatch.setattr(Config, 'PROD_USERNAME', None)
            monkeypatch.setattr(Config, 'PROD_PASSWORD', None)
            
            with pytest.raises(ValueError, match="No valid authentication"):
                Config.get_prod_auth()
        finally:
            # Restore original values
            monkeypatch.setattr(Config, 'PROD_API_KEY', original_api_key)
            monkeypatch.setattr(Config, 'PROD_USERNAME', original_username)
            monkeypatch.setattr(Config, 'PROD_PASSWORD', original_password)
    
    def test_get_lab_auth_with_api_key(self, monkeypatch):
        """Test lab auth prioritizes API key"""
        import app.config
        
        monkeypatch.setenv('LAB_NMS_API_KEY', 'api_key_456')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        auth = app.config.Config.get_lab_auth()
        assert 'api_key' in auth
        assert auth['api_key'] == 'api_key_456'
        assert 'username' not in auth
        assert 'password' not in auth
    
    def test_get_lab_auth_with_password(self, monkeypatch):
        """Test lab auth falls back to username/password"""
        import app.config
        
        monkeypatch.delenv('LAB_NMS_API_KEY', raising=False)
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        auth = app.config.Config.get_lab_auth()
        assert 'username' in auth
        assert 'password' in auth
        assert auth['username'] == 'user'
        assert auth['password'] == 'pass'
        assert 'api_key' not in auth
    
    def test_get_lab_auth_with_no_credentials(self, monkeypatch):
        """Test lab auth raises error when no credentials"""
        from app.config import Config
        
        # Save original values
        original_api_key = Config.LAB_API_KEY
        original_username = Config.LAB_USERNAME
        original_password = Config.LAB_PASSWORD
        
        try:
            # Clear credentials using monkeypatch
            monkeypatch.setattr(Config, 'LAB_API_KEY', None)
            monkeypatch.setattr(Config, 'LAB_USERNAME', None)
            monkeypatch.setattr(Config, 'LAB_PASSWORD', None)
            
            with pytest.raises(ValueError, match="No valid authentication"):
                Config.get_lab_auth()
        finally:
            # Restore original values
            monkeypatch.setattr(Config, 'LAB_API_KEY', original_api_key)
            monkeypatch.setattr(Config, 'LAB_USERNAME', original_username)
            monkeypatch.setattr(Config, 'LAB_PASSWORD', original_password)


class TestConfigurationValidation:
    """Test configuration validation"""
    
    def test_validate_with_valid_config(self, monkeypatch):
        """Test validation with valid configuration"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', 'prod.example.com')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        monkeypatch.setenv('LAB_NMS_HOST', 'lab.example.com')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        is_valid, errors = app.config.Config.validate()
        assert is_valid is True
        assert len(errors) == 0
    
    def test_validate_with_invalid_prod_host(self, monkeypatch):
        """Test validation with invalid production host"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', '')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        monkeypatch.setenv('LAB_NMS_HOST', 'lab.example.com')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        is_valid, errors = app.config.Config.validate()
        assert is_valid is False
        assert len(errors) > 0
        assert any('PROD_NMS_HOST' in error for error in errors)
    
    def test_validate_with_missing_prod_credentials(self, monkeypatch):
        """Test validation with missing production credentials"""
        from app.config import Config
        
        # Save original values
        original_prod_host = Config.PROD_HOST
        original_prod_api_key = Config.PROD_API_KEY
        original_prod_username = Config.PROD_USERNAME
        original_prod_password = Config.PROD_PASSWORD
        original_lab_host = Config.LAB_HOST
        original_lab_username = Config.LAB_USERNAME
        original_lab_password = Config.LAB_PASSWORD
        
        try:
            # Set production host but clear credentials
            monkeypatch.setattr(Config, 'PROD_HOST', 'prod.example.com')
            monkeypatch.setattr(Config, 'PROD_API_KEY', None)
            monkeypatch.setattr(Config, 'PROD_USERNAME', None)
            monkeypatch.setattr(Config, 'PROD_PASSWORD', None)
            # Set lab credentials
            monkeypatch.setattr(Config, 'LAB_HOST', 'lab.example.com')
            monkeypatch.setattr(Config, 'LAB_USERNAME', 'user')
            monkeypatch.setattr(Config, 'LAB_PASSWORD', 'pass')
            
            is_valid, errors = Config.validate()
            assert is_valid is False
            assert len(errors) > 0
            assert any('Production NMS' in error or 'PROD' in error for error in errors)
        finally:
            # Restore original values
            monkeypatch.setattr(Config, 'PROD_HOST', original_prod_host)
            monkeypatch.setattr(Config, 'PROD_API_KEY', original_prod_api_key)
            monkeypatch.setattr(Config, 'PROD_USERNAME', original_prod_username)
            monkeypatch.setattr(Config, 'PROD_PASSWORD', original_prod_password)
            monkeypatch.setattr(Config, 'LAB_HOST', original_lab_host)
            monkeypatch.setattr(Config, 'LAB_USERNAME', original_lab_username)
            monkeypatch.setattr(Config, 'LAB_PASSWORD', original_lab_password)
    
    def test_validate_with_invalid_lab_host(self, monkeypatch):
        """Test validation with invalid lab host"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', 'prod.example.com')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        monkeypatch.setenv('LAB_NMS_HOST', '')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        
        import importlib
        importlib.reload(app.config)
        
        is_valid, errors = app.config.Config.validate()
        assert is_valid is False
        assert len(errors) > 0
        assert any('LAB_NMS_HOST' in error for error in errors)
    
    def test_validate_with_missing_lab_credentials(self, monkeypatch):
        """Test validation with missing lab credentials"""
        from app.config import Config
        
        # Save original values
        original_prod_host = Config.PROD_HOST
        original_prod_username = Config.PROD_USERNAME
        original_prod_password = Config.PROD_PASSWORD
        original_lab_host = Config.LAB_HOST
        original_lab_api_key = Config.LAB_API_KEY
        original_lab_username = Config.LAB_USERNAME
        original_lab_password = Config.LAB_PASSWORD
        
        try:
            # Set production credentials
            monkeypatch.setattr(Config, 'PROD_HOST', 'prod.example.com')
            monkeypatch.setattr(Config, 'PROD_USERNAME', 'user')
            monkeypatch.setattr(Config, 'PROD_PASSWORD', 'pass')
            # Set lab host but clear credentials
            monkeypatch.setattr(Config, 'LAB_HOST', 'lab.example.com')
            monkeypatch.setattr(Config, 'LAB_API_KEY', None)
            monkeypatch.setattr(Config, 'LAB_USERNAME', None)
            monkeypatch.setattr(Config, 'LAB_PASSWORD', None)
            
            is_valid, errors = Config.validate()
            assert is_valid is False
            assert len(errors) > 0
            assert any('Lab NMS' in error or 'LAB' in error for error in errors)
        finally:
            # Restore original values
            monkeypatch.setattr(Config, 'PROD_HOST', original_prod_host)
            monkeypatch.setattr(Config, 'PROD_USERNAME', original_prod_username)
            monkeypatch.setattr(Config, 'PROD_PASSWORD', original_prod_password)
            monkeypatch.setattr(Config, 'LAB_HOST', original_lab_host)
            monkeypatch.setattr(Config, 'LAB_API_KEY', original_lab_api_key)
            monkeypatch.setattr(Config, 'LAB_USERNAME', original_lab_username)
            monkeypatch.setattr(Config, 'LAB_PASSWORD', original_lab_password)


class TestConfigurationSummary:
    """Test configuration summary generation"""
    
    def test_get_summary_with_api_key(self, monkeypatch):
        """Test summary with API key authentication"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', 'prod.example.com')
        monkeypatch.setenv('PROD_NMS_API_KEY', 'api_key_123')
        monkeypatch.setenv('LAB_NMS_HOST', 'lab.example.com')
        monkeypatch.setenv('LAB_NMS_API_KEY', 'api_key_456')
        monkeypatch.delenv('PROD_NMS_USERNAME', raising=False)
        monkeypatch.delenv('PROD_NMS_PASSWORD', raising=False)
        monkeypatch.delenv('LAB_NMS_USERNAME', raising=False)
        monkeypatch.delenv('LAB_NMS_PASSWORD', raising=False)
        
        import importlib
        importlib.reload(app.config)
        
        summary = app.config.Config.get_summary()
        
        assert 'production' in summary
        assert 'lab' in summary
        assert summary['production']['has_api_key'] is True
        assert summary['production']['auth_method'] == 'API Key'
        assert summary['lab']['has_api_key'] is True
        assert summary['lab']['auth_method'] == 'API Key'
        # Note: has_password reflects whether password is set, not whether it's being used
        # If both API key and password are set, has_password will be True
    
    def test_get_summary_with_password(self, monkeypatch):
        """Test summary with password authentication"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', 'prod.example.com')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'pass')
        monkeypatch.setenv('LAB_NMS_HOST', 'lab.example.com')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'pass')
        monkeypatch.delenv('PROD_NMS_API_KEY', raising=False)
        monkeypatch.delenv('LAB_NMS_API_KEY', raising=False)
        
        import importlib
        importlib.reload(app.config)
        
        summary = app.config.Config.get_summary()
        
        assert summary['production']['has_api_key'] is False
        assert summary['production']['has_password'] is True
        assert summary['production']['auth_method'] == 'Username/Password'
        assert summary['lab']['has_api_key'] is False
        assert summary['lab']['has_password'] is True
        assert summary['lab']['auth_method'] == 'Username/Password'
    
    def test_get_summary_no_passwords(self, monkeypatch):
        """Test that summary doesn't include passwords"""
        import app.config
        
        monkeypatch.setenv('PROD_NMS_HOST', 'prod.example.com')
        monkeypatch.setenv('PROD_NMS_USERNAME', 'user')
        monkeypatch.setenv('PROD_NMS_PASSWORD', 'secret_password')
        monkeypatch.setenv('LAB_NMS_HOST', 'lab.example.com')
        monkeypatch.setenv('LAB_NMS_USERNAME', 'user')
        monkeypatch.setenv('LAB_NMS_PASSWORD', 'secret_password')
        
        import importlib
        importlib.reload(app.config)
        
        summary = app.config.Config.get_summary()
        
        # Verify passwords are not in summary
        summary_str = str(summary)
        assert 'secret_password' not in summary_str
        assert summary['production']['has_password'] is True  # Indicates presence, not value
        assert summary['lab']['has_password'] is True


class TestSSLConfiguration:
    """Test SSL configuration"""
    
    def test_ssl_verify_default(self):
        """Test SSL verify default"""
        from app.config import Config
        
        # Default should be True
        assert isinstance(Config.SSL_VERIFY, bool)
    
    def test_ssl_cert_path(self, monkeypatch):
        """Test SSL certificate path configuration"""
        import app.config
        
        monkeypatch.setenv('SSL_CERT_PATH', '/path/to/cert.pem')
        
        import importlib
        importlib.reload(app.config)
        
        assert app.config.Config.SSL_CERT_PATH == '/path/to/cert.pem'


class TestRADIUSConfiguration:
    """Test RADIUS configuration"""
    
    def test_radius_enabled_default(self):
        """Test RADIUS enabled default"""
        from app.config import Config
        
        # Default should be False
        assert Config.RADIUS_ENABLED is False
    
    def test_radius_configuration(self, monkeypatch):
        """Test RADIUS configuration values"""
        import app.config
        
        monkeypatch.setenv('RADIUS_ENABLED', 'true')
        monkeypatch.setenv('RADIUS_SERVER', 'radius.example.com')
        monkeypatch.setenv('RADIUS_PORT', '1813')
        monkeypatch.setenv('RADIUS_SECRET', 'secret123')
        monkeypatch.setenv('RADIUS_TIMEOUT', '10')
        
        import importlib
        importlib.reload(app.config)
        
        assert app.config.Config.RADIUS_ENABLED is True
        assert app.config.Config.RADIUS_SERVER == 'radius.example.com'
        assert app.config.Config.RADIUS_PORT == 1813
        assert app.config.Config.RADIUS_SECRET == 'secret123'
        assert app.config.Config.RADIUS_TIMEOUT == 10

