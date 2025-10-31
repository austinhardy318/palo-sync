"""
Settings Manager with caching and file change detection
Provides thread-safe, cached access to user settings
"""

import json
import logging
import os
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional

# Use structured logging if available, fallback to standard logging
try:
    from .logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)


class SettingsManager:
    """Thread-safe settings manager with file-based caching and change detection"""
    
    # Default settings fallback
    DEFAULT_SETTINGS = {
        'createBackup': True,
        'commitConfig': False,
        'preserveHostname': True,
        'autoRefreshLogs': True,
        'logRefreshInterval': 10,
        'requestTimeout': 30,
        'timezone': 'UTC',
        'diffIgnorePaths': [],
        'diffIgnoreRegexPaths': [],
        'diffSignificantDigits': None
    }
    
    def __init__(self, settings_path: str = '/app/settings/user_settings.json', cache_ttl_seconds: int = 30):
        """
        Initialize settings manager
        
        Args:
            settings_path: Path to settings JSON file
            cache_ttl_seconds: Cache TTL in seconds (default: 30)
        """
        self.settings_path = Path(settings_path)
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._lock = threading.Lock()
        self._cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._file_mtime: Optional[float] = None
    
    def _load_settings_from_file(self) -> Dict[str, Any]:
        """Load settings from file, returning defaults if file doesn't exist"""
        if not self.settings_path.exists():
            logger.debug("Settings file does not exist, using defaults")
            return self.DEFAULT_SETTINGS.copy()
        
        try:
            with open(self.settings_path, 'r') as f:
                settings = json.load(f)
            
            # Merge with defaults to ensure all keys exist
            merged = self.DEFAULT_SETTINGS.copy()
            merged.update(settings)
            return merged
        except (OSError, IOError) as e:
            logger.error(f"Error reading settings file: {e}")
            return self.DEFAULT_SETTINGS.copy()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing settings JSON: {e}")
            return self.DEFAULT_SETTINGS.copy()
    
    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid based on TTL and file modification time"""
        if self._cache is None or self._cache_timestamp is None:
            return False
        
        # Check TTL
        if datetime.now() - self._cache_timestamp > self.cache_ttl:
            logger.debug("Cache expired due to TTL")
            return False
        
        # Check file modification time
        if not self.settings_path.exists():
            # File was deleted, cache is invalid
            if self._file_mtime is not None:
                logger.debug("Settings file was deleted, cache invalid")
                return False
            # File never existed, cache is still valid
            return True
        
        try:
            current_mtime = self.settings_path.stat().st_mtime
            if self._file_mtime is None or current_mtime != self._file_mtime:
                logger.debug("Settings file was modified, cache invalid")
                return False
        except OSError as e:
            logger.warning(f"Error checking file mtime: {e}")
            # If we can't check mtime, assume cache is still valid (fail-safe)
            return True
        
        return True
    
    def get_settings(self, force_reload: bool = False) -> Dict[str, Any]:
        """
        Get settings (cached)
        
        Args:
            force_reload: If True, bypass cache and reload from file
        
        Returns:
            Dictionary of settings
        """
        with self._lock:
            if force_reload or not self._is_cache_valid():
                logger.debug("Reloading settings from file")
                self._cache = self._load_settings_from_file()
                self._cache_timestamp = datetime.now()
                
                # Update file mtime tracking
                if self.settings_path.exists():
                    try:
                        self._file_mtime = self.settings_path.stat().st_mtime
                    except OSError:
                        self._file_mtime = None
                else:
                    self._file_mtime = None
            
            return self._cache.copy()  # Return a copy to prevent external modification
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a single setting value
        
        Args:
            key: Setting key
            default: Default value if key not found
        
        Returns:
            Setting value or default
        """
        settings = self.get_settings()
        return settings.get(key, default)
    
    def invalidate_cache(self) -> None:
        """Invalidate the cache, forcing reload on next access"""
        with self._lock:
            logger.debug("Invalidating settings cache")
            self._cache = None
            self._cache_timestamp = None
            self._file_mtime = None
    
    def save_settings(self, settings: Dict[str, Any]) -> None:
        """
        Save settings to file and invalidate cache
        
        Args:
            settings: Settings dictionary to save
        """
        # Ensure settings directory exists
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.settings_path, 'w') as f:
                json.dump(settings, f, indent=2)
            
            # Invalidate cache after saving
            self.invalidate_cache()
            logger.info("Settings saved successfully")
        except (OSError, IOError) as e:
            logger.error(f"Error writing settings file: {e}")
            raise


# Global settings manager instance
_settings_manager: Optional[SettingsManager] = None
_settings_manager_lock = threading.Lock()


def get_settings_manager() -> SettingsManager:
    """Get or create the global settings manager instance"""
    global _settings_manager
    if _settings_manager is None:
        with _settings_manager_lock:
            if _settings_manager is None:
                cache_ttl = int(os.getenv('SETTINGS_CACHE_TTL_SECONDS', '30'))
                _settings_manager = SettingsManager(cache_ttl_seconds=cache_ttl)
    return _settings_manager

