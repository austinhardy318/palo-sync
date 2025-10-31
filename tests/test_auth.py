"""
Tests for authentication module
Tests local accounts, RADIUS authentication, and password management
"""

import os
import json
import bcrypt
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock


@pytest.fixture
def temp_accounts_file(tmp_path):
    """Create a temporary accounts file for testing"""
    accounts_dir = tmp_path / "settings"
    accounts_dir.mkdir(parents=True, exist_ok=True)
    accounts_file = accounts_dir / "local_accounts.json"
    
    return accounts_file, accounts_dir


@pytest.fixture
def auth_with_accounts(temp_accounts_file):
    """Create Authenticator with test accounts"""
    from app.auth import Authenticator
    
    accounts_file, _ = temp_accounts_file
    
    # Create test accounts
    hashed_password = bcrypt.hashpw('testpass123'.encode(), bcrypt.gensalt()).decode()
    accounts_data = {
        'testuser': {
            'password': hashed_password,
            'role': 'user'
        },
        'adminuser': {
            'password': hashed_password,
            'role': 'admin'
        }
    }
    
    with open(accounts_file, 'w') as f:
        json.dump(accounts_data, f)
    
    # Create authenticator and patch the file path
    authenticator = Authenticator()
    authenticator.local_accounts_file = accounts_file
    authenticator.local_accounts = authenticator._load_local_accounts()
    
    return authenticator


class TestLocalAuthentication:
    """Test local account authentication"""
    
    def test_authenticate_with_valid_credentials(self, auth_with_accounts):
        """Test authentication with valid username and password"""
        success, error = auth_with_accounts.authenticate('testuser', 'testpass123')
        assert success is True
        assert error is None
    
    def test_authenticate_with_invalid_password(self, auth_with_accounts):
        """Test authentication with invalid password"""
        success, error = auth_with_accounts.authenticate('testuser', 'wrongpassword')
        assert success is False
        assert error is not None
        assert 'Invalid' in error or 'password' in error.lower()
    
    def test_authenticate_with_invalid_username(self, auth_with_accounts):
        """Test authentication with non-existent username"""
        success, error = auth_with_accounts.authenticate('nonexistent', 'testpass123')
        assert success is False
        assert error is not None
    
    def test_authenticate_with_empty_username(self, auth_with_accounts):
        """Test authentication with empty username"""
        success, error = auth_with_accounts.authenticate('', 'testpass123')
        assert success is False
        assert error is not None
    
    def test_authenticate_with_empty_password(self, auth_with_accounts):
        """Test authentication with empty password"""
        success, error = auth_with_accounts.authenticate('testuser', '')
        assert success is False
        assert error is not None


class TestPasswordHashing:
    """Test password hashing and bcrypt functionality"""
    
    def test_check_bcrypt_password(self, auth_with_accounts):
        """Test that bcrypt password checking works"""
        # Authenticator should use bcrypt to check password
        success, error = auth_with_accounts.authenticate('testuser', 'testpass123')
        assert success is True
    
    def test_password_migration_from_plain_text(self, temp_accounts_file):
        """Test migration from plain text to bcrypt"""
        from app.auth import Authenticator
        
        accounts_file, _ = temp_accounts_file
        
        # Create account with plain text password
        accounts_data = {
            'plainuser': {
                'password': 'plaintextpass',
                'role': 'user'
            }
        }
        
        with open(accounts_file, 'w') as f:
            json.dump(accounts_data, f)
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = accounts_file
        authenticator.local_accounts = authenticator._load_local_accounts()
        
        # Authenticate should work and migrate password
        success, error = authenticator.authenticate('plainuser', 'plaintextpass')
        assert success is True
        
        # Verify password was hashed
        authenticator._load_local_accounts()
        stored_password = authenticator.local_accounts['plainuser']['password']
        assert stored_password.startswith('$2b$')  # bcrypt hash prefix
    
    def test_hash_and_save_password(self, temp_accounts_file):
        """Test password hashing and saving"""
        from app.auth import Authenticator
        
        accounts_file, _ = temp_accounts_file
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = accounts_file
        
        # Create account manually
        authenticator.local_accounts['newuser'] = {
            'password': 'plainpass',
            'role': 'user'
        }
        
        # Hash and save
        authenticator._hash_and_save_password('newuser', 'plainpass')
        
        # Verify password was hashed
        hashed_password = authenticator.local_accounts['newuser']['password']
        assert hashed_password.startswith('$2b$')
        
        # Verify file was updated
        with open(accounts_file, 'r') as f:
            saved_accounts = json.load(f)
        assert 'newuser' in saved_accounts
        assert saved_accounts['newuser']['password'].startswith('$2b$')


class TestRADIUSAuthentication:
    """Test RADIUS authentication"""
    
    def test_radius_authentication_success(self, auth_with_accounts, monkeypatch):
        """Test successful RADIUS authentication"""
        from app.auth import Authenticator
        from app.config import Config
        
        # Enable RADIUS
        monkeypatch.setattr(Config, 'RADIUS_ENABLED', True)
        monkeypatch.setattr(Config, 'RADIUS_SERVER', 'radius.example.com')
        monkeypatch.setattr(Config, 'RADIUS_PORT', 1812)
        monkeypatch.setattr(Config, 'RADIUS_SECRET', 'secret123')
        monkeypatch.setattr(Config, 'RADIUS_TIMEOUT', 5)
        
        # Mock RADIUS client with proper packet support
        from unittest.mock import MagicMock
        
        # Create a mock packet that supports dictionary-like assignment
        mock_packet = MagicMock()
        mock_packet.__getitem__ = MagicMock(return_value=None)
        mock_packet.__setitem__ = MagicMock()  # Support item assignment like request["User-Password"]
        mock_packet.PwCrypt = MagicMock(return_value='encrypted_password')
        
        # Create mock response with AccessAccept code
        mock_response = MagicMock()
        mock_response.code = 2  # AccessAccept
        
        mock_client = MagicMock()
        mock_client.CreateAuthPacket = MagicMock(return_value=mock_packet)
        mock_client.SendPacket = MagicMock(return_value=mock_response)
        
        # Mock pyrad.packet constants
        with patch('pyrad.client.Client', return_value=mock_client), \
             patch('pyrad.packet.AccessRequest', 1), \
             patch('pyrad.packet.AccessAccept', 2):
            authenticator = Authenticator()
            authenticator.local_accounts_file = auth_with_accounts.local_accounts_file
            # Use username not in local accounts to trigger RADIUS
            success, error = authenticator.authenticate('radiususer', 'radiuspass')
            assert success is True
            assert error is None
    
    def test_radius_authentication_failure(self, auth_with_accounts, monkeypatch):
        """Test failed RADIUS authentication"""
        from app.auth import Authenticator
        from app.config import Config
        
        # Enable RADIUS
        monkeypatch.setattr(Config, 'RADIUS_ENABLED', True)
        monkeypatch.setattr(Config, 'RADIUS_SERVER', 'radius.example.com')
        monkeypatch.setattr(Config, 'RADIUS_PORT', 1812)
        monkeypatch.setattr(Config, 'RADIUS_SECRET', 'secret123')
        monkeypatch.setattr(Config, 'RADIUS_TIMEOUT', 5)
        
        # Mock RADIUS client with AccessReject
        mock_packet = Mock()
        mock_response = Mock()
        mock_response.code = 3  # AccessReject
        
        mock_client = Mock()
        mock_client.CreateAuthPacket = Mock(return_value=mock_packet)
        mock_client.SendPacket = Mock(return_value=mock_response)
        
        with patch('pyrad.client.Client', return_value=mock_client):
            authenticator = Authenticator()
            authenticator.local_accounts_file = auth_with_accounts.local_accounts_file
            success, error = authenticator.authenticate('radiususer', 'wrongpass')
            assert success is False
            assert error is not None
    
    def test_radius_not_available(self, auth_with_accounts, monkeypatch):
        """Test RADIUS when library is not available"""
        from app.auth import Authenticator
        from app.config import Config
        
        # Enable RADIUS
        monkeypatch.setattr(Config, 'RADIUS_ENABLED', True)
        monkeypatch.setattr(Config, 'RADIUS_SERVER', 'radius.example.com')
        monkeypatch.setattr(Config, 'RADIUS_PORT', 1812)
        monkeypatch.setattr(Config, 'RADIUS_SECRET', 'secret123')
        monkeypatch.setattr(Config, 'RADIUS_TIMEOUT', 5)
        
        # Mock ImportError when importing pyrad.client
        original_import = __import__
        def mock_import(name, *args, **kwargs):
            if name == 'pyrad.client':
                raise ImportError("pyrad not available")
            return original_import(name, *args, **kwargs)
        
        with patch('builtins.__import__', side_effect=mock_import):
            authenticator = Authenticator()
            authenticator.local_accounts_file = auth_with_accounts.local_accounts_file
            success, error = authenticator.authenticate('radiususer', 'radiuspass')
            assert success is False
            assert 'not available' in error or 'RADIUS' in error


class TestFallbackAuthentication:
    """Test GUI username/password fallback"""
    
    def test_fallback_authentication_success(self, temp_accounts_file, monkeypatch):
        """Test fallback to GUI username/password"""
        from app.auth import Authenticator
        from app.config import Config
        
        # Set GUI credentials
        monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin')
        monkeypatch.setattr(Config, 'GUI_PASSWORD', 'adminpass')
        monkeypatch.setattr(Config, 'RADIUS_ENABLED', False)
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        # Use GUI credentials (not in local accounts)
        success, error = authenticator.authenticate('admin', 'adminpass')
        assert success is True
        assert error is None
    
    def test_fallback_authentication_failure(self, temp_accounts_file, monkeypatch):
        """Test fallback authentication with wrong password"""
        from app.auth import Authenticator
        from app.config import Config
        
        # Set GUI credentials
        monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin')
        monkeypatch.setattr(Config, 'GUI_PASSWORD', 'adminpass')
        monkeypatch.setattr(Config, 'RADIUS_ENABLED', False)
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        # Use wrong password
        success, error = authenticator.authenticate('admin', 'wrongpass')
        assert success is False
        assert error is not None


class TestAccountManagement:
    """Test account creation and management"""
    
    def test_create_local_account_success(self, temp_accounts_file):
        """Test successful account creation"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('newuser', 'newpass123', 'user')
        assert success is True
        assert error is None
        
        # Verify account was created
        authenticator._load_local_accounts()
        assert 'newuser' in authenticator.local_accounts
        assert authenticator.local_accounts['newuser']['role'] == 'user'
        
        # Verify password was hashed
        stored_password = authenticator.local_accounts['newuser']['password']
        assert stored_password.startswith('$2b$')
    
    def test_create_local_account_empty_username(self, temp_accounts_file):
        """Test account creation with empty username"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('', 'password123')
        assert success is False
        assert 'required' in error.lower()
    
    def test_create_local_account_empty_password(self, temp_accounts_file):
        """Test account creation with empty password"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('newuser', '')
        assert success is False
        assert 'required' in error.lower()
    
    def test_create_local_account_short_username(self, temp_accounts_file):
        """Test account creation with username too short"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('ab', 'password123')
        assert success is False
        assert '3' in error or 'characters' in error
    
    def test_create_local_account_long_username(self, temp_accounts_file):
        """Test account creation with username too long"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        long_username = 'a' * 51
        success, error = authenticator.create_local_account(long_username, 'password123')
        assert success is False
        assert '50' in error or 'characters' in error
    
    def test_create_local_account_invalid_characters(self, temp_accounts_file):
        """Test account creation with invalid username characters"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('user@name', 'password123')
        assert success is False
        # Error message mentions invalid characters or format
        assert 'characters' in error.lower() or 'only contain' in error.lower() or 'letters' in error.lower()
    
    def test_create_local_account_short_password(self, temp_accounts_file):
        """Test account creation with password too short"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        success, error = authenticator.create_local_account('newuser', 'short')
        assert success is False
        assert '8' in error or 'characters' in error
    
    def test_create_local_account_long_password(self, temp_accounts_file):
        """Test account creation with password too long"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        
        long_password = 'a' * 129
        success, error = authenticator.create_local_account('newuser', long_password)
        assert success is False
        assert '128' in error or 'characters' in error
    
    def test_list_accounts(self, auth_with_accounts):
        """Test listing all accounts"""
        accounts = auth_with_accounts.list_accounts()
        
        assert isinstance(accounts, list)
        assert len(accounts) >= 2  # At least testuser and adminuser
        
        # Verify passwords are not included
        for account in accounts:
            assert 'username' in account
            assert 'role' in account
            assert 'password' not in account
    
    def test_list_accounts_empty(self, temp_accounts_file):
        """Test listing accounts when none exist"""
        from app.auth import Authenticator
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = temp_accounts_file[0]
        accounts = authenticator.list_accounts()
        
        assert isinstance(accounts, list)
        assert len(accounts) == 0


class TestAccountFileHandling:
    """Test account file loading and error handling"""
    
    def test_load_accounts_from_list_format(self, temp_accounts_file):
        """Test loading accounts from list format (backward compatibility)"""
        from app.auth import Authenticator
        
        accounts_file, _ = temp_accounts_file
        
        # Create accounts in list format
        accounts_list = [
            {'username': 'user1', 'password': 'pass1', 'role': 'user'},
            {'username': 'user2', 'password': 'pass2', 'role': 'admin'}
        ]
        
        with open(accounts_file, 'w') as f:
            json.dump(accounts_list, f)
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = accounts_file
        authenticator.local_accounts = authenticator._load_local_accounts()
        
        # Should convert list to dict
        assert 'user1' in authenticator.local_accounts
        assert 'user2' in authenticator.local_accounts
    
    def test_load_accounts_missing_file(self, temp_accounts_file):
        """Test loading accounts when file doesn't exist"""
        from app.auth import Authenticator
        
        # Use a file that doesn't exist
        nonexistent_file = temp_accounts_file[0].parent / "nonexistent.json"
        authenticator = Authenticator()
        authenticator.local_accounts_file = nonexistent_file
        authenticator.local_accounts = authenticator._load_local_accounts()
        
        # Should return empty dict, not crash
        assert isinstance(authenticator.local_accounts, dict)
        assert len(authenticator.local_accounts) == 0
    
    def test_load_accounts_invalid_json(self, temp_accounts_file):
        """Test handling of invalid JSON in accounts file"""
        from app.auth import Authenticator
        
        accounts_file, _ = temp_accounts_file
        
        # Write invalid JSON
        with open(accounts_file, 'w') as f:
            f.write('{invalid json}')
        
        authenticator = Authenticator()
        authenticator.local_accounts_file = accounts_file
        authenticator.local_accounts = authenticator._load_local_accounts()
        
        # Should handle error gracefully
        assert isinstance(authenticator.local_accounts, dict)
        assert len(authenticator.local_accounts) == 0
