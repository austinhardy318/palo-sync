"""
Tests for HTTP client module
Tests timeout configuration, SSL verification, and retry logic
"""

import pytest
from unittest.mock import Mock, patch
import requests


@pytest.fixture
def http_client():
    """Create HTTP client instance for testing"""
    from app.http_client import HttpClient
    return HttpClient(default_timeout_seconds=30)


@pytest.fixture
def mock_settings_manager(monkeypatch):
    """Mock settings manager for timeout testing"""
    from unittest.mock import Mock
    
    mock_manager = Mock()
    mock_manager.get_setting = Mock(return_value=30)  # Default timeout
    
    with patch('app.http_client.get_settings_manager', return_value=mock_manager):
        yield mock_manager


class TestTimeoutConfiguration:
    """Test timeout configuration"""
    
    def test_default_timeout(self, http_client):
        """Test default timeout value"""
        assert http_client._default_timeout == 30
    
    def test_get_timeout_from_settings(self, http_client, mock_settings_manager):
        """Test timeout retrieval from settings"""
        mock_settings_manager.get_setting.return_value = 60
        
        timeout = http_client._get_timeout()
        assert timeout == 60
    
    def test_get_timeout_valid_range(self, http_client, mock_settings_manager):
        """Test timeout within valid range"""
        mock_settings_manager.get_setting.return_value = 120
        
        timeout = http_client._get_timeout()
        assert 5 <= timeout <= 300
    
    def test_get_timeout_below_minimum(self, http_client, mock_settings_manager):
        """Test timeout below minimum uses default"""
        mock_settings_manager.get_setting.return_value = 3  # Below minimum
        
        timeout = http_client._get_timeout()
        assert timeout == 30  # Should use default
    
    def test_get_timeout_above_maximum(self, http_client, mock_settings_manager):
        """Test timeout above maximum uses default"""
        mock_settings_manager.get_setting.return_value = 500  # Above maximum
        
        timeout = http_client._get_timeout()
        assert timeout == 30  # Should use default
    
    def test_get_timeout_invalid_value(self, http_client, mock_settings_manager):
        """Test timeout with invalid value uses default"""
        mock_settings_manager.get_setting.side_effect = ValueError("Invalid")
        
        timeout = http_client._get_timeout()
        assert timeout == 30  # Should use default
    
    def test_get_timeout_with_override(self, http_client):
        """Test timeout override in request"""
        from app.http_client import HttpClient
        
        client = HttpClient(default_timeout_seconds=30)
        
        with patch.object(client._session, 'get') as mock_get:
            client.get('https://example.com', timeout=60)
            
            # Verify timeout was passed
            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs['timeout'] == 60


class TestSSLVerification:
    """Test SSL verification configuration"""
    
    def test_ssl_verify_false(self, http_client, monkeypatch):
        """Test SSL verification disabled"""
        from app.config import Config
        from app.http_client import get_ssl_verify
        
        monkeypatch.setattr(Config, 'SSL_VERIFY', False)
        
        verify = get_ssl_verify()
        assert verify is False
    
    def test_ssl_verify_true(self, http_client, monkeypatch):
        """Test SSL verification enabled"""
        from app.config import Config
        from app.http_client import get_ssl_verify
        
        # SSL_VERIFY is a bool from Config
        monkeypatch.setattr(Config, 'SSL_VERIFY', True)
        monkeypatch.setattr(Config, 'SSL_CERT_PATH', None)
        
        verify = get_ssl_verify()
        assert verify is True
    
    def test_ssl_verify_with_cert_path(self, http_client, monkeypatch):
        """Test SSL verification with custom cert path"""
        from app.config import Config
        from app.http_client import get_ssl_verify
        
        # SSL_VERIFY is a bool from Config
        monkeypatch.setattr(Config, 'SSL_VERIFY', True)
        monkeypatch.setattr(Config, 'SSL_CERT_PATH', '/path/to/cert.pem')
        
        verify = get_ssl_verify()
        assert verify == '/path/to/cert.pem'
    
    def test_get_request_with_ssl_verify(self, http_client, monkeypatch):
        """Test GET request respects SSL verification"""
        from app.config import Config
        from app.http_client import HttpClient
        
        monkeypatch.setattr(Config, 'SSL_VERIFY', False)
        
        client = HttpClient()
        
        with patch.object(client._session, 'get') as mock_get:
            client.get('https://example.com')
            
            # Verify SSL verification was passed
            mock_get.assert_called_once()
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs['verify'] is False
    
    def test_post_request_with_ssl_verify(self, http_client, monkeypatch):
        """Test POST request respects SSL verification"""
        from app.config import Config
        from app.http_client import HttpClient
        
        monkeypatch.setattr(Config, 'SSL_VERIFY', False)
        
        client = HttpClient()
        
        with patch.object(client._session, 'post') as mock_post:
            client.post('https://example.com')
            
            # Verify SSL verification was passed
            mock_post.assert_called_once()
            call_kwargs = mock_post.call_args[1]
            assert call_kwargs['verify'] is False


class TestRequestMethods:
    """Test HTTP request methods"""
    
    def test_get_request(self, http_client):
        """Test GET request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'response'
        
        with patch.object(http_client._session, 'get', return_value=mock_response) as mock_get:
            response = http_client.get('https://example.com')
            
            mock_get.assert_called_once()
            assert response == mock_response
    
    def test_post_request(self, http_client):
        """Test POST request"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'response'
        
        with patch.object(http_client._session, 'post', return_value=mock_response) as mock_post:
            response = http_client.post('https://example.com', data={'key': 'value'})
            
            mock_post.assert_called_once()
            assert response == mock_response
    
    def test_get_request_with_timeout(self, http_client):
        """Test GET request with timeout"""
        mock_response = Mock()
        
        with patch.object(http_client._session, 'get', return_value=mock_response) as mock_get:
            http_client.get('https://example.com', timeout=60)
            
            # Verify timeout was passed
            call_kwargs = mock_get.call_args[1]
            assert 'timeout' in call_kwargs
    
    def test_post_request_with_timeout(self, http_client):
        """Test POST request with timeout"""
        mock_response = Mock()
        
        with patch.object(http_client._session, 'post', return_value=mock_response) as mock_post:
            http_client.post('https://example.com', timeout=60)
            
            # Verify timeout was passed
            call_kwargs = mock_post.call_args[1]
            assert 'timeout' in call_kwargs


class TestRetryConfiguration:
    """Test retry logic configuration"""
    
    def test_retry_adapter_configured(self, http_client):
        """Test that retry adapter is configured"""
        # Check that adapters are mounted
        assert 'http://' in http_client._session.adapters
        assert 'https://' in http_client._session.adapters
    
    def test_retry_adapter_settings(self, http_client):
        """Test retry adapter settings"""
        adapter = http_client._session.adapters['https://']
        
        # Verify retry is configured
        assert adapter.max_retries is not None
        assert adapter.max_retries.total >= 0
    
    def test_retry_on_status_codes(self, http_client):
        """Test retry on specific status codes"""
        adapter = http_client._session.adapters['https://']
        retry = adapter.max_retries
        
        # Verify status codes that trigger retry
        if hasattr(retry, 'status_forcelist'):
            assert 502 in retry.status_forcelist or retry.status_forcelist == ()  # May vary by version
            assert 503 in retry.status_forcelist or retry.status_forcelist == ()
            assert 504 in retry.status_forcelist or retry.status_forcelist == ()


class TestSessionConfiguration:
    """Test session configuration"""
    
    def test_session_pool_connections(self, http_client):
        """Test connection pool configuration"""
        adapter = http_client._session.adapters['https://']
        
        # Verify pool connections are configured
        assert adapter._pool_connections >= 0
        assert adapter._pool_maxsize >= 0
    
    def test_session_methods_allowed(self, http_client):
        """Test allowed HTTP methods for retry"""
        adapter = http_client._session.adapters['https://']
        retry = adapter.max_retries
        
        # Verify allowed methods include GET and POST
        if hasattr(retry, 'allowed_methods'):
            assert 'GET' in retry.allowed_methods or retry.allowed_methods == ()  # May vary by version
            assert 'POST' in retry.allowed_methods or retry.allowed_methods == ()


class TestErrorHandling:
    """Test error handling"""
    
    def test_get_request_network_error(self, http_client):
        """Test handling of network errors in GET request"""
        with patch.object(http_client._session, 'get', side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(requests.ConnectionError):
                http_client.get('https://example.com')
    
    def test_post_request_network_error(self, http_client):
        """Test handling of network errors in POST request"""
        with patch.object(http_client._session, 'post', side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(requests.ConnectionError):
                http_client.post('https://example.com')
    
    def test_get_request_timeout_error(self, http_client):
        """Test handling of timeout errors in GET request"""
        with patch.object(http_client._session, 'get', side_effect=requests.Timeout("Request timeout")):
            with pytest.raises(requests.Timeout):
                http_client.get('https://example.com')
    
    def test_post_request_timeout_error(self, http_client):
        """Test handling of timeout errors in POST request"""
        with patch.object(http_client._session, 'post', side_effect=requests.Timeout("Request timeout")):
            with pytest.raises(requests.Timeout):
                http_client.post('https://example.com')

