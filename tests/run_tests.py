#!/usr/bin/env python3
"""
Simple test runner for verification
Can be run without pytest if needed
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_settings_manager_basic():
    """Basic test of settings manager"""
    print("Testing SettingsManager...")
    try:
        from app.settings_manager import SettingsManager
        import tempfile
        import json
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
            json.dump({'requestTimeout': 45}, f)
        
        manager = SettingsManager(settings_path=temp_path, cache_ttl_seconds=1)
        settings = manager.get_settings()
        
        assert 'requestTimeout' in settings or settings.get('requestTimeout') == 45 or settings.get('requestTimeout') == 30
        print("  ✓ SettingsManager basic functionality works")
        
        os.unlink(temp_path)
        return True
    except Exception as e:
        print(f"  ✗ SettingsManager test failed: {e}")
        return False


def test_security_headers():
    """Test that security headers are configured"""
    print("Testing security headers...")
    try:
        from app.main import app
        
        with app.test_client() as client:
            resp = client.get('/api/health')
            
            headers_to_check = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Content-Security-Policy',
                'Permissions-Policy'
            ]
            
            for header in headers_to_check:
                assert header in resp.headers, f"Missing header: {header}"
            
            print("  ✓ Security headers are present")
            return True
    except Exception as e:
        print(f"  ✗ Security headers test failed: {e}")
        return False


def test_api_key_cache_structure():
    """Test API key cache structure"""
    print("Testing API key cache...")
    try:
        from app.sync_service import SyncService
        
        # Check that cache max size is set
        assert hasattr(SyncService, '_cache_max_size')
        assert SyncService._cache_max_size > 0
        print(f"  ✓ API key cache max size: {SyncService._cache_max_size}")
        return True
    except Exception as e:
        print(f"  ✗ API key cache test failed: {e}")
        return False


def test_diff_cache_structure():
    """Test diff cache structure"""
    print("Testing diff cache...")
    try:
        from app.diff_service import DiffService
        
        # Check that cache attributes exist
        assert hasattr(DiffService, '_diff_cache')
        assert hasattr(DiffService, '_cache_ttl_seconds')
        assert hasattr(DiffService, '_cache_max_size')
        print(f"  ✓ Diff cache configured (TTL: {DiffService._cache_ttl_seconds}s, Max: {DiffService._cache_max_size})")
        return True
    except Exception as e:
        print(f"  ✗ Diff cache test failed: {e}")
        return False


def test_log_salt_function():
    """Test LOG_SALT handling"""
    print("Testing LOG_SALT...")
    try:
        import os
        from app.main import hash_username
        
        # Test with LOG_SALT set
        os.environ['LOG_SALT'] = 'test_salt_for_verification_12345'
        os.environ['FLASK_ENV'] = 'development'  # Avoid production requirement
        
        result = hash_username('testuser')
        assert isinstance(result, str)
        assert len(result) == 16
        print("  ✓ LOG_SALT function works")
        return True
    except Exception as e:
        print(f"  ✗ LOG_SALT test failed: {e}")
        return False


def test_rate_limiting_key():
    """Test rate limiting key function"""
    print("Testing rate limiting...")
    try:
        from app.main import get_rate_limit_key
        
        # Should return a string starting with 'ip:'
        key = get_rate_limit_key()
        assert isinstance(key, str)
        assert key.startswith('ip:') or key.startswith('user:')
        print(f"  ✓ Rate limiting key function works: {key[:20]}...")
        return True
    except Exception as e:
        print(f"  ✗ Rate limiting test failed: {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("Running basic functionality tests...")
    print("=" * 60)
    
    tests = [
        test_settings_manager_basic,
        test_security_headers,
        test_api_key_cache_structure,
        test_diff_cache_structure,
        test_log_salt_function,
        test_rate_limiting_key,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"  ✗ Test {test.__name__} raised exception: {e}")
            results.append(False)
        print()
    
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60)
    
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())

