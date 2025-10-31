"""
Core synchronization service
Handles diff checking, backup creation, and sync operations
"""

import os
import logging
import io
import re
import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
import xml.etree.ElementTree as ET
from threading import Lock

from panos import panorama
from panos.device import SystemSettings
from deepdiff import DeepDiff
import requests
import urllib3

from .config import Config
from .http_client import HttpClient, get_ssl_verify
from .diff_service import DiffService
from .config_service import ConfigService
from .exceptions import PanoramaConnectionError, PanoramaAPIError, BackupError, NotFoundError

# Conditionally disable SSL warnings based on configuration
if not Config.SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sanitize_error_message(error_msg: str) -> str:
    """Sanitize error messages to not expose passwords or sensitive data"""
    if not error_msg:
        return error_msg
    # Replace password in URLs
    error_msg = re.sub(r'password=[^&\s]+', 'password=***', error_msg)
    return error_msg

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SyncService:
    """Handle synchronization operations"""
    _api_key_cache: Dict[str, Dict[str, Any]] = {}
    _cache_lock = Lock()
    _cache_ttl_hours = int(os.getenv('API_KEY_CACHE_TTL_HOURS', '1'))
    _cache_max_size = int(os.getenv('API_KEY_CACHE_MAX_SIZE', '100'))  # Maximum number of cached keys

    def __init__(self):
        self.prod_auth = Config.get_prod_auth()
        self.lab_auth = Config.get_lab_auth()
        self.backup_dir = Path(Config.BACKUP_DIR)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(Config.LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.http = HttpClient(default_timeout_seconds=30)
        self.config = ConfigService(self.http)

    def get_panorama_connection(self, host: str, auth: Dict[str, Any]) -> panorama.Panorama:
        if 'api_key' in auth:
            conn = panorama.Panorama(hostname=host, api_key=auth['api_key'])
        else:
            conn = panorama.Panorama(hostname=host, api_username=auth['username'], api_password=auth['password'])
        conn.refresh_system_info()
        return conn

    def test_connection(self) -> Dict[str, Any]:
        results = {
            'production': {'connected': False, 'error': None},
            'lab': {'connected': False, 'error': None}
        }
        try:
            conn = self.get_panorama_connection(Config.PROD_HOST, self.prod_auth)
            results['production']['connected'] = True
            results['production']['version'] = conn.refresh_system_info()
            logger.info(
                f"Successfully connected to production NMS (host: {Config.PROD_HOST}, version: {results['production']['version']})"
            )
        except PanoramaConnectionError as e:
            # Don't re-raise - we want to test both connections and return error
            error_msg = str(e)
            results['production']['error'] = error_msg
            logger.error(
                f"Failed to connect to production NMS: {error_msg} (host: {Config.PROD_HOST}, type: {type(e).__name__})"
            )
        except Exception as e:
            error_msg = str(e)
            results['production']['error'] = error_msg
            logger.error(
                f"Failed to connect to production NMS: {error_msg} (host: {Config.PROD_HOST}, type: {type(e).__name__})"
            )
            # Don't raise here - we want to test both connections
        try:
            conn = self.get_panorama_connection(Config.LAB_HOST, self.lab_auth)
            results['lab']['connected'] = True
            results['lab']['version'] = conn.refresh_system_info()
            logger.info(
                f"Successfully connected to lab NMS (host: {Config.LAB_HOST}, version: {results['lab']['version']})"
            )
        except PanoramaConnectionError as e:
            # Don't re-raise - we want to test both connections and return error
            error_msg = str(e)
            results['lab']['error'] = error_msg
            logger.error(
                f"Failed to connect to lab NMS: {error_msg} (host: {Config.LAB_HOST}, type: {type(e).__name__})"
            )
        except Exception as e:
            error_msg = str(e)
            results['lab']['error'] = error_msg
            logger.error(
                f"Failed to connect to lab NMS: {error_msg} (host: {Config.LAB_HOST}, type: {type(e).__name__})"
            )
            # Don't raise here - we want to test both connections
        return results

    def _get_api_key(self, host: str, auth: Dict[str, Any]) -> str:
        if 'api_key' in auth:
            return auth['api_key']
        with self._cache_lock:
            cache_key = f"{host}:{auth.get('username', 'unknown')}"
            if cache_key in self._api_key_cache:
                cached = self._api_key_cache[cache_key]
                if cached.get('expires', datetime.min) > datetime.now():
                    logger.debug(f"Using cached API key for {host}")
                    return cached['key']
                else:
                    logger.debug(f"Cached API key expired for {host}, fetching new one")
                    del self._api_key_cache[cache_key]
        api_key_url = f"https://{host}/api/?type=keygen&user={auth['username']}&password={auth['password']}"
        try:
            response = self.http.get(api_key_url)
            response.raise_for_status()
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                raise PanoramaAPIError(f"Invalid XML response when getting API key: {str(e)}", api_response=response.text[:500])
            if root.attrib.get('status') == 'success':
                key_elem = root.find('.//key')
                if key_elem is not None and key_elem.text:
                    api_key = key_elem.text
                    with self._cache_lock:
                        expires = datetime.now() + timedelta(hours=self._cache_ttl_hours)
                        # Check cache size and evict oldest entries if needed
                        if len(self._api_key_cache) >= self._cache_max_size:
                            # Remove expired entries first
                            now = datetime.now()
                            expired_keys = [
                                k for k, v in self._api_key_cache.items()
                                if v.get('expires', datetime.min) <= now
                            ]
                            for k in expired_keys:
                                del self._api_key_cache[k]
                            
                            # If still at max size, remove oldest entry (FIFO)
                            if len(self._api_key_cache) >= self._cache_max_size:
                                oldest_key = next(iter(self._api_key_cache))
                                del self._api_key_cache[oldest_key]
                                logger.debug(f"Evicted oldest API key cache entry: {oldest_key}")
                        
                        self._api_key_cache[cache_key] = {'key': api_key, 'expires': expires}
                        logger.debug(f"Cached API key for {host}, expires at {expires} (cache size: {len(self._api_key_cache)}/{self._cache_max_size})")
                    return api_key
                else:
                    raise PanoramaAPIError("API key not found in response", api_response=response.text[:500])
            else:
                error_msg_elem = root.find('.//msg')
                error_text = error_msg_elem.text if error_msg_elem is not None else 'Unknown error'
                raise PanoramaAPIError(f"Failed to obtain API key: {error_text}", api_response=response.text[:500])
        except PanoramaAPIError:
            # Re-raise custom exceptions
            raise
        except requests.RequestException as e:
            error_msg = sanitize_error_message(str(e))
            logger.error(f"Request error getting API key: {error_msg}")
            raise PanoramaConnectionError(host, message=f"Failed to connect to Panorama: {error_msg}")
        except (ET.ParseError, IOError, OSError) as e:
            error_msg = sanitize_error_message(str(e))
            logger.error(f"Error getting API key: {error_msg}")
            raise PanoramaConnectionError(host, message=f"Failed to get API key: {error_msg}")

    @classmethod
    def clear_api_key_cache(cls, host: Optional[str] = None) -> None:
        with cls._cache_lock:
            if host:
                keys_to_remove = [k for k in cls._api_key_cache.keys() if k.startswith(f"{host}:")]
                for key in keys_to_remove:
                    del cls._api_key_cache[key]
                logger.info(f"Cleared API key cache for {host}")
            else:
                cls._api_key_cache.clear()
                logger.info("Cleared all API key caches")

    def __del__(self):
        self.clear_api_key_cache()

    def export_config(self, host: str, auth: Dict[str, Any], label: str = "config") -> str:
        api_key = self._get_api_key(host, auth)
        return self.config.export_config(host, api_key, label)

    def import_config(self, host: str, auth: Dict[str, Any], config_xml: str, commit: bool = False) -> str:
        api_key = self._get_api_key(host, auth)
        try:
            result = self.config.import_config(host, api_key, config_xml, commit=commit)
            if host == Config.LAB_HOST:
                current_hostname = self.get_current_hostname(host, auth)
                if current_hostname:
                    logger.info(f"Current lab hostname: {current_hostname}")
                    logger.info(f"Preserving lab hostname: {current_hostname}")
                    hostname_set = self.set_hostname(host, auth, current_hostname)
                    if not hostname_set:
                        logger.warning("Failed to set lab hostname - this may affect device identification")
                    else:
                        logger.info("Lab hostname successfully preserved in candidate configuration")
                else:
                    logger.warning("Could not retrieve current lab hostname - skipping hostname preservation")
            return result
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            raise

    def get_current_hostname(self, host: str, auth: Dict[str, Any]) -> Optional[str]:
        try:
            api_key = self._get_api_key(host, auth)
            api_url = f"https://{host}/api/"
            params = {'type': 'op', 'cmd': '<show><system><info></info></system></show>', 'key': api_key}
            response = self.http.post(api_url, data=params)
            response.raise_for_status()
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                logger.warning(f"Invalid XML response when getting hostname: {e}")
                return None
            if root.attrib.get('status') == 'success':
                hostname_elem = root.find('.//hostname')
                if hostname_elem is not None and hostname_elem.text:
                    return hostname_elem.text
            return None
        except requests.RequestException as e:
            logger.warning(f"Request error getting hostname: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to get current hostname: {e}")
            return None

    def set_hostname(self, host: str, auth: Dict[str, Any], hostname: str) -> bool:
        try:
            if 'api_key' in auth:
                pano = panorama.Panorama(hostname=host, api_key=auth['api_key'])
            else:
                pano = panorama.Panorama(hostname=host, api_username=auth['username'], api_password=auth['password'])
            sys_settings = SystemSettings(hostname=hostname)
            pano.add(sys_settings)
            sys_settings.apply()
            logger.info(f"Hostname successfully set to: {hostname} using pan-os-python SDK")
            return True
        except Exception as e:
            logger.error(f"Failed to set hostname: {e}")
            return False

    def xml_to_dict(self, xml_string: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(xml_string)
            return self._element_to_dict(root)
        except Exception as e:
            logger.error(f"Error converting XML to dict: {e}")
            return {}

    def _element_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        result = {}
        if element.attrib:
            result['_attributes'] = element.attrib
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()
        if len(element) > 0:
            for child in element:
                tag = child.tag
                child_dict = self._element_to_dict(child)
                if tag in result:
                    if not isinstance(result[tag], list):
                        result[tag] = [result[tag]]
                    result[tag].append(child_dict)
                else:
                    result[tag] = child_dict
        return result

    def create_backup(self, env: str) -> str:
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{env}_backup_{timestamp}.xml"
            backup_path = self.backup_dir / backup_filename
            if env == "lab":
                host = Config.LAB_HOST
                auth = self.lab_auth
            else:
                host = Config.PROD_HOST
                auth = self.prod_auth
            api_key = self._get_api_key(host, auth)
            # Stream export directly to file to avoid large in-memory strings
            self.config.stream_export_to_file(host, api_key, backup_path)
            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)
        except (PanoramaConnectionError, PanoramaAPIError):
            # Re-raise connection/API errors
            raise
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise BackupError(f"Failed to create backup: {str(e)}", operation='create', details={'env': env})

    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backup files in backup directory."""
        backups: List[Dict[str, Any]] = []
        try:
            for backup_file in self.backup_dir.glob("*.xml"):
                stat = backup_file.stat()
                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            backups.sort(key=lambda x: x['modified'], reverse=True)
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
        return backups

    def generate_diff(self) -> Dict[str, Any]:
        return DiffService(self).generate_diff()

    def sync_configuration(self, create_backup: bool = True, commit: bool = False) -> Dict[str, Any]:
        sync_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Starting sync operation: {sync_id}")
        result = {
            'sync_id': sync_id,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'backup_created': False,
            'backup_path': None,
            'error': None
        }
        try:
            if create_backup:
                logger.info("Creating pre-sync backup...")
                backup_path = self.create_backup("lab")
                result['backup_created'] = backup_path is not None
                result['backup_path'] = backup_path
            logger.info("Fetching production configuration...")
            prod_config_xml = self.export_config(Config.PROD_HOST, self.prod_auth, "production")
            logger.info("Importing configuration to lab...")
            job = self.import_config(Config.LAB_HOST, self.lab_auth, prod_config_xml, commit=commit)
            result['success'] = True
            result['commit_job_id'] = job
            
            # Invalidate diff cache since lab config has changed
            try:
                from .diff_service import DiffService
                DiffService.clear_cache()
                logger.debug("Cleared diff cache after sync")
            except Exception as e:
                logger.warning(f"Failed to clear diff cache: {e}")
            
            logger.info(f"Sync completed successfully: {sync_id}")
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Sync failed: {e}")
        return result

    def restore_backup(self, backup_path: str, commit: bool = False) -> Dict[str, Any]:
        logger.info(f"Restoring backup: {backup_path}")
        result = {
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
        try:
            # Check if backup file exists
            backup_file = Path(backup_path)
            if not backup_file.exists():
                raise NotFoundError('backup', identifier=backup_path)
            
            with open(backup_path, 'r') as f:
                backup_config = f.read()
            job = self.import_config(Config.LAB_HOST, self.lab_auth, backup_config, commit=commit)
            result['success'] = True
            result['commit_job_id'] = job
            logger.info(f"Backup restored successfully: {backup_path}")
        except (NotFoundError, PanoramaConnectionError, PanoramaAPIError):
            # Re-raise custom exceptions
            raise
        except (OSError, IOError) as e:
            logger.error(f"IO error restoring backup: {e}")
            raise BackupError(f"Failed to read backup file: {str(e)}", operation='restore')
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            raise BackupError(f"Failed to restore backup: {str(e)}", operation='restore')
        return result

    def delete_backup(self, backup_path: str) -> Dict[str, Any]:
        """Delete a backup file on disk after validating path is under backup_dir."""
        try:
            backup_file = Path(backup_path)
            # Ensure path is within configured backup directory
            if not str(backup_file.resolve()).startswith(str(self.backup_dir.resolve())):
                return {'success': False, 'error': 'Invalid backup path'}
            if not backup_file.exists():
                return {'success': False, 'error': 'Backup file not found'}
            backup_file.unlink()
            logger.info(f"Deleted backup: {backup_file}")
            return {'success': True, 'message': f'Backup {backup_file.name} deleted successfully'}
        except Exception as e:
            logger.error(f"Error deleting backup: {e}")
            return {'success': False, 'error': str(e)}


