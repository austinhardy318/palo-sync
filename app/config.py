"""
Configuration management for Palo-Sync
Supports both username/password and API key authentication
"""

import os
from dotenv import load_dotenv
from typing import Optional, Dict, Any

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
        
        # Check production Panorama
        if not cls.PROD_HOST:
            errors.append("PROD_PANORAMA_HOST is required")
        
        try:
            cls.get_prod_auth()
        except ValueError as e:
            errors.append(str(e))
        
        # Check lab Panorama
        if not cls.LAB_HOST:
            errors.append("LAB_PANORAMA_HOST is required")
        
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

