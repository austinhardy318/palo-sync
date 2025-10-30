"""
Configuration management for Palo-Sync
Supports both username/password and API key authentication
"""

import os
import re
import ipaddress
from dotenv import load_dotenv
from typing import Optional, Dict, Any, Tuple

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration with dual authentication support"""
    
    # Production Panorama Configuration
    PROD_HOST: str = os.getenv('PROD_PANORAMA_HOST', '')
    PROD_USERNAME: Optional[str] = os.getenv('PROD_PANORAMA_USERNAME')
    PROD_PASSWORD: Optional[str] = os.getenv('PROD_PANORAMA_PASSWORD')
    PROD_API_KEY: Optional[str] = os.getenv('PROD_PANORAMA_API_KEY')
    
    # Lab Panorama Configuration
    LAB_HOST: str = os.getenv('LAB_PANORAMA_HOST', '')
    LAB_HOSTNAME: Optional[str] = os.getenv('LAB_PANORAMA_HOSTNAME')  # Hostname to preserve
    LAB_USERNAME: Optional[str] = os.getenv('LAB_PANORAMA_USERNAME')
    LAB_PASSWORD: Optional[str] = os.getenv('LAB_PANORAMA_PASSWORD')
    LAB_API_KEY: Optional[str] = os.getenv('LAB_PANORAMA_API_KEY')
    
    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """
        Validate hostname format (DNS name or IP address)
        Returns True if valid, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False
        
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid DNS hostname
        # Allowed characters: alphanumeric, hyphen, dot
        # Must not start or end with hyphen or dot
        # Each label must be 1-63 characters
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', hostname):
            # Check each label length
            labels = hostname.split('.')
            if all(1 <= len(label) <= 63 for label in labels):
                return True
        
        return False
    
    @staticmethod
    def validate_hostname(hostname: str, field_name: str) -> Tuple[bool, Optional[str]]:
        """
        Validate hostname and return (is_valid, error_message)
        """
        if not hostname:
            return False, f"{field_name} is required"
        
        if not Config.is_valid_hostname(hostname):
            return False, f"{field_name} must be a valid hostname or IP address"
        
        return True, None
    
    # Authentication method preference
    AUTH_METHOD: str = os.getenv('AUTH_METHOD', 'password')
    
    # Flask Configuration
    FLASK_ENV: str = os.getenv('FLASK_ENV', 'production')
    
    # Backup directory
    BACKUP_DIR: str = os.getenv('BACKUP_DIR', '/backups')
    
    # Log directory
    LOG_DIR: str = os.getenv('LOG_DIR', '/app/logs')
    
    # GUI Authentication (optional)
    GUI_USERNAME: Optional[str] = os.getenv('GUI_USERNAME')
    GUI_PASSWORD: Optional[str] = os.getenv('GUI_PASSWORD')
    
    # RADIUS Authentication (optional)
    RADIUS_ENABLED: bool = os.getenv('RADIUS_ENABLED', 'false').lower() == 'true'
    RADIUS_SERVER: Optional[str] = os.getenv('RADIUS_SERVER')
    RADIUS_PORT: int = int(os.getenv('RADIUS_PORT', '1812'))
    RADIUS_SECRET: Optional[str] = os.getenv('RADIUS_SECRET')
    RADIUS_TIMEOUT: int = int(os.getenv('RADIUS_TIMEOUT', '5'))
    
    # SSL Configuration
    SSL_VERIFY: bool = os.getenv('SSL_VERIFY', 'true').lower() == 'true'
    SSL_CERT_PATH: Optional[str] = os.getenv('SSL_CERT_PATH')
    
    @classmethod
    def get_prod_auth(cls) -> Dict[str, Any]:
        """
        Returns production Panorama authentication parameters
        Prioritizes API key if available, otherwise uses username/password
        """
        if cls.PROD_API_KEY:
            return {'api_key': cls.PROD_API_KEY}
        elif cls.PROD_USERNAME and cls.PROD_PASSWORD:
            return {'username': cls.PROD_USERNAME, 'password': cls.PROD_PASSWORD}
        else:
            raise ValueError("Production Panorama: No valid authentication credentials found")
    
    @classmethod
    def get_lab_auth(cls) -> Dict[str, Any]:
        """
        Returns lab Panorama authentication parameters
        Prioritizes API key if available, otherwise uses username/password
        """
        if cls.LAB_API_KEY:
            return {'api_key': cls.LAB_API_KEY}
        elif cls.LAB_USERNAME and cls.LAB_PASSWORD:
            return {'username': cls.LAB_USERNAME, 'password': cls.LAB_PASSWORD}
        else:
            raise ValueError("Lab Panorama: No valid authentication credentials found")
    
    @classmethod
    def validate(cls) -> tuple[bool, list[str]]:
        """
        Validate that all required configuration is present
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        # Check production Panorama hostname
        is_valid, error_msg = cls.validate_hostname(cls.PROD_HOST, "PROD_PANORAMA_HOST")
        if not is_valid:
            errors.append(error_msg or "PROD_PANORAMA_HOST is required")
        
        try:
            cls.get_prod_auth()
        except ValueError as e:
            errors.append(str(e))
        
        # Check lab Panorama hostname
        is_valid, error_msg = cls.validate_hostname(cls.LAB_HOST, "LAB_PANORAMA_HOST")
        if not is_valid:
            errors.append(error_msg or "LAB_PANORAMA_HOST is required")
        
        try:
            cls.get_lab_auth()
        except ValueError as e:
            errors.append(str(e))
        
        return len(errors) == 0, errors
    
    @classmethod
    def get_summary(cls) -> Dict[str, Any]:
        """Get configuration summary (without passwords)"""
        return {
            'production': {
                'host': cls.PROD_HOST,
                'username': cls.PROD_USERNAME,
                'has_password': bool(cls.PROD_PASSWORD),
                'has_api_key': bool(cls.PROD_API_KEY),
                'auth_method': 'API Key' if cls.PROD_API_KEY else 'Username/Password'
            },
            'lab': {
                'host': cls.LAB_HOST,
                'username': cls.LAB_USERNAME,
                'has_password': bool(cls.LAB_PASSWORD),
                'has_api_key': bool(cls.LAB_API_KEY),
                'auth_method': 'API Key' if cls.LAB_API_KEY else 'Username/Password'
            },
            'gui_auth_enabled': bool(cls.GUI_USERNAME and cls.GUI_PASSWORD)
        }

