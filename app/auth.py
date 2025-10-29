"""
Authentication module for Palo-Sync
Supports local accounts and RADIUS authentication
"""

import logging
import bcrypt
from typing import Optional, Tuple
from pathlib import Path
import json

from .config import Config

logger = logging.getLogger(__name__)


class Authenticator:
    """Handle authentication using local accounts and/or RADIUS"""
    
    def __init__(self):
        self.local_accounts_file = Path('/app/settings/local_accounts.json')
        self.local_accounts = self._load_local_accounts()
    
    def _load_local_accounts(self) -> dict:
        """Load local accounts from file"""
        try:
            if self.local_accounts_file.exists():
                with open(self.local_accounts_file, 'r') as f:
                    accounts = json.load(f)
                    # Ensure accounts is a dict keyed by username
                    if isinstance(accounts, list):
                        return {acc['username']: acc for acc in accounts}
                    return accounts
        except Exception as e:
            logger.error(f"Error loading local accounts: {e}")
        
        return {}
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Authenticate user using local accounts and/or RADIUS
        Returns (success, error_message)
        """
        # Try local authentication first if local account exists
        if username in self.local_accounts:
            if self._check_local_password(username, password):
                logger.info(f"Local authentication successful for user: {username}")
                return True, None
            else:
                logger.warning(f"Local authentication failed for user: {username}")
                return False, "Invalid username or password"
        
        # Try RADIUS if enabled
        if Config.RADIUS_ENABLED:
            success, error = self._authenticate_radius(username, password)
            if success:
                logger.info(f"RADIUS authentication successful for user: {username}")
                return True, None
            logger.warning(f"RADIUS authentication failed for user: {username}: {error}")
            return False, error or "Invalid username or password"
        
        # Try simple GUI username/password as fallback
        if Config.GUI_USERNAME and Config.GUI_PASSWORD:
            if username == Config.GUI_USERNAME and password == Config.GUI_PASSWORD:
                logger.info(f"Fallback authentication successful for user: {username}")
                return True, None
        
        logger.warning(f"Authentication failed for user: {username} - no matching credentials")
        return False, "Invalid username or password"
    
    def _check_local_password(self, username: str, password: str) -> bool:
        """Check if the password matches for a local user"""
        user_account = self.local_accounts.get(username)
        if not user_account:
            return False
        
        stored_password = user_account.get('password')
        if not stored_password:
            return False
        
        # Check if stored password is hashed (starts with $2b$)
        if stored_password.startswith('$2b$'):
            # Compare hashed password
            try:
                return bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error checking password hash: {e}")
                return False
        else:
            # Legacy plain text password (for migration)
            is_valid = password == stored_password
            # Auto-migrate to hashed password
            if is_valid:
                logger.info(f"Migrating password to bcrypt for user: {username}")
                self._hash_and_save_password(username, password)
            return is_valid
    
    def _hash_and_save_password(self, username: str, password: str):
        """Hash a password and save it to the account file"""
        try:
            # Generate salt and hash password
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Update the account
            self.local_accounts[username]['password'] = hashed
            
            # Save to file
            with open(self.local_accounts_file, 'w') as f:
                json.dump(self.local_accounts, f, indent=2)
            
            logger.info(f"Password hashed and saved for user: {username}")
        except Exception as e:
            logger.error(f"Error hashing password: {e}")
    
    def _authenticate_radius(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Authenticate using RADIUS"""
        try:
            from pyrad.client import Client
            import pyrad.packet
            
            # Create RADIUS client
            client = Client(
                server=Config.RADIUS_SERVER,
                authport=Config.RADIUS_PORT,
                secret=Config.RADIUS_SECRET.encode()
            )
            
            # Set timeout
            client.timeout = Config.RADIUS_TIMEOUT
            
            # Create authentication request
            request = client.CreateAuthPacket(
                code=pyrad.packet.AccessRequest,
                User_Name=username
            )
            request["User-Password"] = request.PwCrypt(password)
            
            # Send request and get response
            response = client.SendPacket(request)
            
            # Check if authentication was successful
            if response.code == pyrad.packet.AccessAccept:
                return True, None
            else:
                return False, "RADIUS authentication rejected"
        
        except ImportError:
            logger.error("pyrad library not available")
            return False, "RADIUS library not available"
        except Exception as e:
            logger.error(f"RADIUS authentication error: {e}")
            return False, str(e)
    
    def create_local_account(self, username: str, password: str, role: str = "user") -> Tuple[bool, Optional[str]]:
        """
        Create a new local account
        Returns (success, error_message)
        """
        try:
            # Validate input
            if not username or not password:
                return False, "Username and password are required"
            
            # Validate username format
            if not isinstance(username, str):
                return False, "Username must be a string"
            if len(username) < 3 or len(username) > 50:
                return False, "Username must be between 3 and 50 characters"
            # Allow alphanumeric, underscore, hyphen
            if not all(c.isalnum() or c in ['_', '-'] for c in username):
                return False, "Username can only contain letters, numbers, underscore, and hyphen"
            
            # Validate password length
            if not isinstance(password, str):
                return False, "Password must be a string"
            if len(password) < 8 or len(password) > 128:
                return False, "Password must be between 8 and 128 characters"
            
            if not self.local_accounts_file.parent.exists():
                self.local_accounts_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Hash the password before storing
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            # Add account to dictionary
            self.local_accounts[username] = {
                'password': hashed_password,
                'role': role
            }
            
            # Save to file
            with open(self.local_accounts_file, 'w') as f:
                json.dump(self.local_accounts, f, indent=2)
            
            logger.info(f"Created local account: {username}")
            return True, None
        
        except Exception as e:
            logger.error(f"Error creating local account: {e}")
            return False, str(e)
    
    def list_accounts(self) -> list:
        """List all local accounts (without passwords)"""
        accounts = []
        for username, details in self.local_accounts.items():
            accounts.append({
                'username': username,
                'role': details.get('role', 'user')
            })
        return accounts

