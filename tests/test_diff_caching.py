"""
Tests for diff result caching
"""

import os
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock


@pytest.fixture
def diff_service(monkeypatch):
    """Create a DiffService instance for testing"""
    os.environ.setdefault("DIFF_CACHE_TTL_SECONDS", "1")  # 1 second for testing
    os.environ.setdefault("DIFF_CACHE_MAX_SIZE", "10")
    
    # Reset cache
    from app.diff_service import DiffService
    DiffService._diff_cache.clear()
    
    # Patch cache TTL to use environment variable (read at class definition)
    # Since TTL is set at class definition, we need to patch the class attribute
    original_ttl = DiffService._cache_ttl_seconds
    DiffService._cache_ttl_seconds = int(os.getenv('DIFF_CACHE_TTL_SECONDS', '1'))
    
    # Create mock sync service
    mock_sync = Mock()
    mock_sync.export_config = Mock(side_effect=lambda host, auth, label: f"<config>{label}</config>")
    mock_sync.xml_to_dict = Mock(return_value={'test': 'data'})
    
    try:
        yield DiffService(mock_sync)
    finally:
        # Restore original TTL
        DiffService._cache_ttl_seconds = original_ttl


def test_diff_cache_key_generation(diff_service):
    """Test that cache keys are generated correctly"""
    prod_hash = "abc123"
    lab_hash = "def456"
    cache_key = diff_service._get_cache_key(prod_hash, lab_hash)
    assert cache_key == "abc123:def456"


def test_diff_cache_stores_and_retrieves(diff_service):
    """Test that diff results are cached and retrieved"""
    # Create a mock result
    result = {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'differences': {'items_added': 1, 'items_removed': 0, 'values_changed': 0, 'items_moved': 0},
        'raw_diff': '{}',
        'diff_json': '{}'
    }
    
    cache_key = "test:key"
    
    # Cache the result
    diff_service._cache_diff(cache_key, result)
    
    # Retrieve it
    cached = diff_service._get_cached_diff(cache_key)
    assert cached is not None
    assert cached['differences']['items_added'] == 1
    assert cached.get('cached') is True


def test_diff_cache_expires(diff_service):
    """Test that cached diffs expire after TTL"""
    result = {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'differences': {'items_added': 1},
        'raw_diff': '{}',
        'diff_json': '{}'
    }
    
    cache_key = "test:key"
    diff_service._cache_diff(cache_key, result)
    
    # Should be cached immediately
    cached = diff_service._get_cached_diff(cache_key)
    assert cached is not None
    
    # Wait for expiration (TTL is 1 second, wait 1.5 to ensure expiration)
    import time
    time.sleep(1.5)
    
    # Should be expired now - _get_cached_diff should remove expired entries and return None
    cached = diff_service._get_cached_diff(cache_key)
    assert cached is None
    
    # Also verify the cache entry was removed
    with diff_service._cache_lock:
        assert cache_key not in diff_service._diff_cache


def test_diff_cache_size_limit(diff_service):
    """Test that cache doesn't exceed maximum size"""
    # Add more entries than max size
    for i in range(15):
        result = {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'differences': {'items_added': i},
            'raw_diff': '{}',
            'diff_json': '{}'
        }
        cache_key = f"key{i}"
        diff_service._cache_diff(cache_key, result)
    
    # Cache should not exceed max size
    assert len(diff_service._diff_cache) <= diff_service._cache_max_size


def test_diff_cache_clear(diff_service):
    """Test clearing diff cache"""
    # Add some entries
    for i in range(3):
        result = {
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'differences': {'items_added': i},
            'raw_diff': '{}',
            'diff_json': '{}'
        }
        diff_service._cache_diff(f"key{i}", result)
    
    assert len(diff_service._diff_cache) > 0
    
    # Clear cache
    diff_service.clear_cache()
    
    assert len(diff_service._diff_cache) == 0


def test_diff_cache_evicts_expired_on_add(diff_service):
    """Test that expired entries are cleaned up when adding new ones"""
    # Add expired entry manually (TTL is 1 second, make it 2 seconds old)
    expired_time = (datetime.now() - timedelta(seconds=2)).isoformat()
    with diff_service._cache_lock:
        diff_service._diff_cache['expired'] = {
            'result': {'test': 'data'},
            'cached_at': expired_time
        }
    
    # Add new entry (should clean up expired entries first)
    result = {
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'differences': {'items_added': 1},
        'raw_diff': '{}',
        'diff_json': '{}'
    }
    diff_service._cache_diff('new_key', result)
    
    # Expired entry should be gone (cleaned up during cache add)
    # The _cache_diff method should remove expired entries before adding new ones
    with diff_service._cache_lock:
        # Check that expired is not in cache
        assert 'expired' not in diff_service._diff_cache, f"Expired entry still in cache: {diff_service._diff_cache.keys()}"
        # New key should be in cache
        assert 'new_key' in diff_service._diff_cache

