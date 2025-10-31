"""
Tests for config service module
Tests export, import, and streaming operations
"""

import os
import io
import xml.etree.ElementTree as ET
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import requests


@pytest.fixture
def config_service():
    """Create ConfigService instance for testing"""
    from app.config_service import ConfigService
    from app.http_client import HttpClient
    
    http_client = HttpClient(default_timeout_seconds=30)
    return ConfigService(http_client)


@pytest.fixture
def mock_http_response():
    """Create mock HTTP response"""
    response = Mock()
    response.status_code = 200
    response.text = '<response status="success"><result>config.xml</result></response>'
    response.raise_for_status = Mock()
    return response


class TestExportConfig:
    """Test configuration export"""
    
    def test_export_config_success(self, config_service, mock_http_response):
        """Test successful configuration export"""
        mock_http_response.text = '<config><system><hostname>test</hostname></system></config>'
        
        with patch.object(config_service.http, 'get', return_value=mock_http_response):
            config_xml = config_service.export_config('panorama.example.com', 'api_key_123')
            
            assert config_xml is not None
            assert '<config>' in config_xml
            assert '<system>' in config_xml
    
    def test_export_config_url_format(self, config_service, mock_http_response):
        """Test export URL format"""
        with patch.object(config_service.http, 'get', return_value=mock_http_response) as mock_get:
            config_service.export_config('panorama.example.com', 'api_key_123')
            
            # Verify URL format
            call_args = mock_get.call_args
            url = call_args[0][0]
            assert 'type=export' in url
            assert 'category=configuration' in url
            assert 'api_key_123' in url
    
    def test_export_config_network_error(self, config_service):
        """Test handling of network errors during export"""
        with patch.object(config_service.http, 'get', side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(Exception, match="Failed to export"):
                config_service.export_config('panorama.example.com', 'api_key_123')
    
    def test_export_config_http_error(self, config_service):
        """Test handling of HTTP errors during export"""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("404 Not Found")
        
        with patch.object(config_service.http, 'get', return_value=mock_response):
            with pytest.raises(Exception):
                config_service.export_config('panorama.example.com', 'api_key_123')


class TestImportConfig:
    """Test configuration import"""
    
    def test_import_config_without_commit(self, config_service, mock_http_response):
        """Test import configuration without commit"""
        # Mock import response
        import_response = Mock()
        import_response.status_code = 200
        import_response.text = '<response status="success"><result>config.xml</result></response>'
        import_response.raise_for_status = Mock()
        
        # Mock load response
        load_response = Mock()
        load_response.status_code = 200
        load_response.text = '<response status="success"></response>'
        load_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', side_effect=[import_response, load_response]) as mock_post:
            result = config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>', commit=False)
            
            # Should be called twice: import and load
            assert mock_post.call_count == 2
            assert result == 'candidate-only'
    
    def test_import_config_with_commit(self, config_service, mock_http_response):
        """Test import configuration with commit"""
        # Mock import response
        import_response = Mock()
        import_response.status_code = 200
        import_response.text = '<response status="success"><result>config.xml</result></response>'
        import_response.raise_for_status = Mock()
        
        # Mock load response
        load_response = Mock()
        load_response.status_code = 200
        load_response.text = '<response status="success"></response>'
        load_response.raise_for_status = Mock()
        
        # Mock commit response
        commit_response = Mock()
        commit_response.status_code = 200
        commit_response.text = '<response status="success"><result><job>12345</job></result></response>'
        commit_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', side_effect=[import_response, load_response, commit_response]) as mock_post:
            result = config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>', commit=True)
            
            # Should be called three times: import, load, and commit
            assert mock_post.call_count == 3
            assert result == '12345'
    
    def test_import_config_invalid_xml_response(self, config_service):
        """Test handling of invalid XML response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'invalid xml'
        mock_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', return_value=mock_response):
            with pytest.raises(Exception, match="Invalid XML"):
                config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>')
    
    def test_import_config_error_response(self, config_service):
        """Test handling of error response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<response status="error"><msg>Import failed</msg></response>'
        mock_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', return_value=mock_response):
            with pytest.raises(Exception, match="Import failed"):
                config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>')
    
    def test_import_config_load_failure(self, config_service):
        """Test handling of load failure"""
        # Mock import response
        import_response = Mock()
        import_response.status_code = 200
        import_response.text = '<response status="success"><result>config.xml</result></response>'
        import_response.raise_for_status = Mock()
        
        # Mock load response with error
        load_response = Mock()
        load_response.status_code = 200
        load_response.text = '<response status="error"><msg>Load failed</msg></response>'
        load_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', side_effect=[import_response, load_response]):
            with pytest.raises(Exception, match="Load to candidate failed"):
                config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>')


class TestStreamExportToFile:
    """Test streaming export to file"""
    
    def test_stream_export_success(self, config_service, tmp_path):
        """Test successful streaming export"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        
        # Mock streaming response
        def mock_iter_content(chunk_size):
            yield b'<config>'
            yield b'<system>'
            yield b'<hostname>test</hostname>'
            yield b'</system>'
            yield b'</config>'
        
        mock_response.iter_content = Mock(return_value=mock_iter_content(65536))
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        dest_path = tmp_path / 'exported.xml'
        
        with patch.object(config_service.http, 'get', return_value=mock_response):
            result = config_service.stream_export_to_file('panorama.example.com', 'api_key_123', dest_path)
            
            assert result == str(dest_path)
            assert dest_path.exists()
            assert dest_path.read_text() == '<config><system><hostname>test</hostname></system></config>'
    
    def test_stream_export_file_size_limit(self, config_service, tmp_path):
        """Test file size limit enforcement"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        
        # Mock large streaming response (exceeds 100MB)
        large_chunk = b'x' * (100 * 1024 * 1024 + 1)
        
        def mock_iter_content(chunk_size):
            yield large_chunk
        
        mock_response.iter_content = Mock(return_value=mock_iter_content(65536))
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        dest_path = tmp_path / 'exported.xml'
        
        with patch.object(config_service.http, 'get', return_value=mock_response):
            with pytest.raises(Exception, match="exceeds maximum size"):
                config_service.stream_export_to_file('panorama.example.com', 'api_key_123', dest_path)
    
    def test_stream_export_cleanup_on_error(self, config_service, tmp_path):
        """Test cleanup of temporary file on error"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        
        # Mock streaming response that raises error
        def mock_iter_content(chunk_size):
            yield b'<config>'
            raise Exception("Stream error")
        
        mock_response.iter_content = Mock(return_value=mock_iter_content(65536))
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        dest_path = tmp_path / 'exported.xml'
        tmp_file = dest_path.with_suffix(dest_path.suffix + '.tmp')
        
        with patch.object(config_service.http, 'get', return_value=mock_response):
            try:
                config_service.stream_export_to_file('panorama.example.com', 'api_key_123', dest_path)
            except Exception:
                pass
            
            # Temporary file should be cleaned up
            assert not tmp_file.exists()
    
    def test_stream_export_atomic_rename(self, config_service, tmp_path):
        """Test atomic file rename"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status = Mock()
        
        # Mock streaming response
        def mock_iter_content(chunk_size):
            yield b'<config>test</config>'
        
        mock_response.iter_content = Mock(return_value=mock_iter_content(65536))
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        
        dest_path = tmp_path / 'exported.xml'
        tmp_file = dest_path.with_suffix(dest_path.suffix + '.tmp')
        
        with patch.object(config_service.http, 'get', return_value=mock_response):
            config_service.stream_export_to_file('panorama.example.com', 'api_key_123', dest_path)
            
            # Temporary file should be renamed to final file
            assert dest_path.exists()
            assert not tmp_file.exists()
    
    def test_stream_export_network_error(self, config_service, tmp_path):
        """Test handling of network errors during streaming"""
        dest_path = tmp_path / 'exported.xml'
        
        with patch.object(config_service.http, 'get', side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(Exception, match="Failed to stream"):
                config_service.stream_export_to_file('panorama.example.com', 'api_key_123', dest_path)


class TestConfigServiceErrorHandling:
    """Test error handling in config service"""
    
    def test_export_config_io_error(self, config_service):
        """Test handling of IO errors during export"""
        with patch.object(config_service.http, 'get', side_effect=IOError("IO error")):
            with pytest.raises(IOError):
                config_service.export_config('panorama.example.com', 'api_key_123')
    
    def test_import_config_network_error(self, config_service):
        """Test handling of network errors during import"""
        with patch.object(config_service.http, 'post', side_effect=requests.ConnectionError("Connection refused")):
            with pytest.raises(Exception, match="Failed to import"):
                config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>')
    
    def test_import_config_io_error(self, config_service):
        """Test handling of IO errors during import"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '<response status="success"><result>config.xml</result></response>'
        mock_response.raise_for_status = Mock()
        
        with patch.object(config_service.http, 'post', side_effect=[mock_response, IOError("IO error")]):
            with pytest.raises(IOError):
                config_service.import_config('panorama.example.com', 'api_key_123', '<config>test</config>')

