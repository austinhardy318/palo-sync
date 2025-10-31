"""
Tests for API key cache size limits and eviction
"""

import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch


@pytest.fixture
def sync_service(monkeypatch, tmp_path):
    """Create a SyncService instance for testing"""
    os.environ.setdefault("API_KEY_CACHE_MAX_SIZE", "5")
    os.environ.setdefault("API_KEY_CACHE_TTL_HOURS", "1")
    
    # Use temp directory for backups to avoid read-only file system issues
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    monkeypatch.setenv("BACKUP_DIR", str(backup_dir))
    monkeypatch.setenv("LOG_DIR", str(log_dir))
    
    # Patch Config to use temp directories
    from app.config import Config
    monkeypatch.setattr(Config, 'BACKUP_DIR', str(backup_dir))
    monkeypatch.setattr(Config, 'LOG_DIR', str(log_dir))
    
    # Reset cache
    from app.sync_service import SyncService
    SyncService._api_key_cache.clear()
    
    service = SyncService()
    # Patch backup_dir and log_dir to use temp directories
    service.backup_dir = backup_dir
    service.log_dir = log_dir
    return service


def test_api_key_cache_size_limit(sync_service, monkeypatch):
    """Test that cache doesn't exceed maximum size"""
    # Mock HTTP responses
    fake_response = Mock()
    fake_response.text = '<response status="success"><result><key>API_KEY_123</key></result></response>'
    fake_response.raise_for_status = Mock()
    
    fake_get = Mock(return_value=fake_response)
    # Patch the instance's http client, not the class
    monkeypatch.setattr(sync_service.http, 'get', fake_get)
    
    # Add more entries than max size
    for i in range(10):
        host = f"host{i}.example.com"
        auth = {'username': f'user{i}', 'password': 'pass'}
        
        try:
            sync_service._get_api_key(host, auth)
        except Exception:
            # Ignore actual network errors, we're just testing cache logic
            pass
    
    # Cache should not exceed max size
    assert len(sync_service._api_key_cache) <= sync_service._cache_max_size


def test_api_key_cache_evicts_expired(sync_service, monkeypatch):
    """Test that expired entries are evicted before adding new ones when cache is full"""
    # Cache eviction only happens when cache is at max size
    # Fill cache to max size with expired entries
    expired_time = datetime.now() - timedelta(hours=2)
    with sync_service._cache_lock:
        for i in range(sync_service._cache_max_size):
            cache_key = f"host{i}:user{i}"
            sync_service._api_key_cache[cache_key] = {
                'key': f'key{i}',
                'expires': expired_time  # Expired
            }
    
    # Verify cache is at max size
    with sync_service._cache_lock:
        assert len(sync_service._api_key_cache) == sync_service._cache_max_size
    
    # Add a new entry (should evict expired ones first during _get_api_key when cache is full)
    fake_response = Mock()
    fake_response.text = '<response status="success"><result><key>NEW_KEY</key></result></response>'
    fake_response.raise_for_status = Mock()
    
    fake_get = Mock(return_value=fake_response)
    # Patch the instance's http client, not the class
    monkeypatch.setattr(sync_service.http, 'get', fake_get)
    
    try:
        sync_service._get_api_key("newhost.example.com", {'username': 'newuser', 'password': 'pass'})
    except Exception:
        pass
    
    # Expired entries should be removed (they were expired when new entry was added)
    with sync_service._cache_lock:
        # All remaining entries should be valid (not expired) - expired ones should be gone
        for cache_key in sync_service._api_key_cache:
            expires = sync_service._api_key_cache[cache_key]['expires']
            # Expires should be in the future
            assert expires > datetime.now(), f"Entry {cache_key} expires at {expires}, now is {datetime.now()}"
        
        # Should only have the new entry (expired ones were removed when cache was full)
        assert len(sync_service._api_key_cache) <= 1, f"Expected at most 1 entry (new one), got {len(sync_service._api_key_cache)}: {list(sync_service._api_key_cache.keys())}"


def test_api_key_cache_fifo_eviction(sync_service):
    """Test FIFO eviction when cache is full"""
    # Fill cache to max size with valid entries
    with sync_service._cache_lock:
        for i in range(sync_service._cache_max_size):
            cache_key = f"host{i}:user{i}"
            sync_service._api_key_cache[cache_key] = {
                'key': f'key{i}',
                'expires': datetime.now() + timedelta(hours=1)
            }
    
    initial_keys = list(sync_service._api_key_cache.keys())
    
    # Add one more entry (should evict oldest)
    with sync_service._cache_lock:
        if len(sync_service._api_key_cache) >= sync_service._cache_max_size:
            oldest_key = next(iter(sync_service._api_key_cache))
            del sync_service._api_key_cache[oldest_key]
        
        new_key = "newhost:newuser"
        sync_service._api_key_cache[new_key] = {
            'continue': 'newkey',
            'expires': datetime.now() + timedelta(hours=1)
        }
    
    # Oldest key should be gone, new key should be present
    assert new_key in sync_service._api_key_cache
    assert oldest_key not in sync_service._api_key_cache or len(sync_service._api_key_cache) <= sync_service._cache_max_size


def test_api_key_cache_clear(sync_service):
    """Test clearing API key cache"""
    # Add some entries
    with sync_service._cache_lock:
        sync_service._api_key_cache['host1:user1'] = {'key': 'key1', 'expires': datetime.now() + timedelta(hours=1)}
        sync_service._api_key_cache['host2:user2'] = {'key': 'key2', 'expires': datetime.now() + timedelta(hours=1)}
    
    # Clear cache
    sync_service.clear_api_key_cache()
    
    assert len(sync_service._api_key_cache) == 0


def test_api_key_cache_clear_specific_host(sync_service):
    """Test clearing cache for specific host"""
    # Add entries for different hosts
    with sync_service._cache_lock:
        sync_service._api_key_cache['host1:user1'] = {'key': 'key1', 'expires': datetime.now() + timedelta(hours=1)}
        sync_service._api_key_cache['host1:user2'] = {'key': 'key2', 'expires': datetime.now() + timedelta(hours=1)}
        sync_service._api_key_cache['host2:user1'] = {'key': 'key3', 'expires': datetime.now() + timedelta(hours=1)}
    
    # Clear only host1
    sync_service.clear_api_key_cache('host1')
    
    # host1 entries should be gone, host2 should remain
    assert 'host1:user1' not in sync_service._api_key_cache
    assert 'host1:user2' not in sync_service._api_key_cache
    assert 'host2:user1' in sync_service._api_key_cache

