#!/usr/bin/env python3
"""
Verification script to check implementation without requiring dependencies
"""

import sys
import os
import ast
import re

def check_file_exists(filepath):
    """Check if file exists"""
    if os.path.exists(filepath):
        print(f"  ✓ {filepath} exists")
        return True
    else:
        print(f"  ✗ {filepath} missing")
        return False


def check_imports(filepath, required_imports):
    """Check if file contains required imports"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            for imp in required_imports:
                if imp in content:
                    print(f"  ✓ {filepath} imports {imp}")
                    return True
            print(f"  ✗ {filepath} missing imports")
            return False
    except Exception as e:
        print(f"  ✗ Error reading {filepath}: {e}")
        return False


def check_class_exists(filepath, class_name):
    """Check if class exists in file"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            if f"class {class_name}" in content:
                print(f"  ✓ {filepath} contains class {class_name}")
                return True
            else:
                print(f"  ✗ {filepath} missing class {class_name}")
                return False
    except Exception as e:
        print(f"  ✗ Error reading {filepath}: {e}")
        return False


def check_method_exists(filepath, method_name):
    """Check if method exists in file"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            # Look for method definition
            pattern = rf'def\s+{method_name}\s*\('
            if re.search(pattern, content):
                print(f"  ✓ {filepath} contains method {method_name}")
                return True
            else:
                print(f"  ✗ {filepath} missing method {method_name}")
                return False
    except Exception as e:
        print(f"  ✗ Error reading {filepath}: {e}")
        return False


def check_config_variable(filepath, var_name):
    """Check if configuration variable exists"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            if var_name in content:
                print(f"  ✓ {filepath} contains {var_name}")
                return True
            else:
                print(f"  ✗ {filepath} missing {var_name}")
                return False
    except Exception as e:
        print(f"  ✗ Error reading {filepath}: {e}")
        return False


def main():
    """Run verification checks"""
    print("=" * 70)
    print("Verifying Implementation")
    print("=" * 70)
    print()
    
    results = []
    
    # Check 1: Settings Manager exists
    print("1. Settings Manager Implementation")
    print("-" * 70)
    results.append(check_file_exists("app/settings_manager.py"))
    results.append(check_class_exists("app/settings_manager.py", "SettingsManager"))
    results.append(check_method_exists("app/settings_manager.py", "get_settings"))
    results.append(check_method_exists("app/settings_manager.py", "invalidate_cache"))
    print()
    
    # Check 2: Settings Manager used in main
    print("2. Settings Manager Integration")
    print("-" * 70)
    results.append(check_imports("app/main.py", "settings_manager"))
    results.append(check_imports("app/http_client.py", "settings_manager"))
    results.append(check_imports("app/diff_service.py", "settings_manager"))
    print()
    
    # Check 3: API Key Cache Limits
    print("3. API Key Cache Limits")
    print("-" * 70)
    results.append(check_config_variable("app/sync_service.py", "_cache_max_size"))
    results.append(check_config_variable("app/sync_service.py", "API_KEY_CACHE_MAX_SIZE"))
    print()
    
    # Check 4: Diff Cache Implementation
    print("4. Diff Result Caching")
    print("-" * 70)
    results.append(check_config_variable("app/diff_service.py", "_diff_cache"))
    results.append(check_config_variable("app/diff_service.py", "_cache_ttl_seconds"))
    results.append(check_config_variable("app/diff_service.py", "_cache_max_size"))
    results.append(check_method_exists("app/diff_service.py", "_get_cached_diff"))
    results.append(check_method_exists("app/diff_service.py", "_cache_diff"))
    results.append(check_method_exists("app/diff_service.py", "clear_cache"))
    print()
    
    # Check 5: Security Headers
    print("5. Security Headers")
    print("-" * 70)
    results.append(check_method_exists("app/main.py", "add_security_headers"))
    results.append(check_config_variable("app/main.py", "SESSION_COOKIE_SECURE"))
    results.append(check_config_variable("app/main.py", "SESSION_COOKIE_HTTPONLY"))
    results.append(check_config_variable("app/main.py", "SESSION_COOKIE_SAMESITE"))
    print()
    
    # Check 6: LOG_SALT Security
    print("6. LOG_SALT Security")
    print("-" * 70)
    results.append(check_config_variable("app/main.py", "LOG_SALT"))
    results.append(check_method_exists("app/main.py", "hash_username"))
    print()
    
    # Check 7: Rate Limiting Fix
    print("7. Rate Limiting Edge Case Fix")
    print("-" * 70)
    results.append(check_method_exists("app/main.py", "get_rate_limit_key"))
    print()
    
    # Check 8: Validators Module
    print("8. Centralized Validators")
    print("-" * 70)
    results.append(check_file_exists("app/validators.py"))
    results.append(check_class_exists("app/validators.py", "ValidationError"))
    results.append(check_method_exists("app/validators.py", "validate_backup_path"))
    results.append(check_method_exists("app/validators.py", "validate_timezone"))
    results.append(check_method_exists("app/validators.py", "validate_regex_pattern"))
    print()
    
    # Check 9: Test Files
    print("9. Test Files Created")
    print("-" * 70)
    results.append(check_file_exists("tests/test_settings_caching.py"))
    results.append(check_file_exists("tests/test_api_key_cache_limits.py"))
    results.append(check_file_exists("tests/test_diff_caching.py"))
    results.append(check_file_exists("tests/test_security_improvements.py"))
    print()
    
    # Summary
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} checks passed ({passed*100//total}%)")
    print("=" * 70)
    
    if passed == total:
        print("\n✓ All implementation checks passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} checks failed - review output above")
        return 1


if __name__ == '__main__':
    sys.exit(main())

