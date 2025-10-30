"""
Core Panorama synchronization module
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

# Conditionally disable SSL warnings based on configuration
if not Config.SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_ssl_verify() -> Union[bool, str]:
    """Get SSL verification setting based on configuration"""
    if not Config.SSL_VERIFY:
        return False
    # Use custom cert if provided, otherwise use default
    return Config.SSL_CERT_PATH if Config.SSL_CERT_PATH else True

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


class PanoramaSync:
    """Handle Panorama synchronization operations"""
    
    # API key cache with TTL (default: 1 hour)
    # Structure: {host: {'key': api_key, 'expires': datetime}}
    _api_key_cache: Dict[str, Dict[str, Any]] = {}
    _cache_lock = Lock()
    _cache_ttl_hours = int(os.getenv('API_KEY_CACHE_TTL_HOURS', '1'))
    
    def __init__(self):
        self.prod_auth = Config.get_prod_auth()
        self.lab_auth = Config.get_lab_auth()
        self.backup_dir = Path(Config.BACKUP_DIR)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(Config.LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def get_panorama_connection(self, host: str, auth: Dict[str, Any]) -> panorama.Panorama:
        """Create and return a Panorama connection"""
        if 'api_key' in auth:
            conn = panorama.Panorama(
                hostname=host,
                api_key=auth['api_key']
            )
        else:
            conn = panorama.Panorama(
                hostname=host,
                api_username=auth['username'],
                api_password=auth['password']
            )
        
        # Test connection
        conn.refresh_system_info()
        return conn
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Test connections to both Panorama instances
        Returns status dictionary
        """
        results = {
            'production': {'connected': False, 'error': None},
            'lab': {'connected': False, 'error': None}
        }
        
        # Test production
        try:
            conn = self.get_panorama_connection(Config.PROD_HOST, self.prod_auth)
            results['production']['connected'] = True
            results['production']['version'] = conn.refresh_system_info()
            logger.info(f"Successfully connected to production Panorama: {Config.PROD_HOST}")
        except Exception as e:
            results['production']['error'] = str(e)
            logger.error(f"Failed to connect to production Panorama: {e}")
        
        # Test lab
        try:
            conn = self.get_panorama_connection(Config.LAB_HOST, self.lab_auth)
            results['lab']['connected'] = True
            results['lab']['version'] = conn.refresh_system_info()
            logger.info(f"Successfully connected to lab Panorama: {Config.LAB_HOST}")
        except Exception as e:
            results['lab']['error'] = str(e)
            logger.error(f"Failed to connect to lab Panorama: {e}")
        
        return results
    
    def _get_api_key(self, host: str, auth: Dict[str, Any]) -> str:
        """
        Get API key from host and auth credentials
        Uses cached API key if available and not expired
        API keys are cached with TTL to prevent unnecessary regeneration
        """
        # Check if API key is provided directly in auth
        if 'api_key' in auth:
            return auth['api_key']
        
        # Check cache first (thread-safe)
        with self._cache_lock:
            cache_key = f"{host}:{auth.get('username', 'unknown')}"
            if cache_key in self._api_key_cache:
                cached = self._api_key_cache[cache_key]
                # Check if cache entry is still valid
                if cached.get('expires', datetime.min) > datetime.now():
                    logger.debug(f"Using cached API key for {host}")
                    return cached['key']
                else:
                    # Expired, remove from cache
                    logger.debug(f"Cached API key expired for {host}, fetching new one")
                    del self._api_key_cache[cache_key]
        
        # Get API key from credentials
        api_key_url = f"https://{host}/api/?type=keygen&user={auth['username']}&password={auth['password']}"
        try:
            response = requests.get(api_key_url, verify=get_ssl_verify(), timeout=30)
            response.raise_for_status()
            
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                raise Exception(f"Invalid XML response when getting API key: {e}")
            
            if root.attrib.get('status') == 'success':
                key_elem = root.find('.//key')
                if key_elem is not None and key_elem.text:
                    api_key = key_elem.text
                    
                    # Cache the API key with expiration (thread-safe)
                    with self._cache_lock:
                        expires = datetime.now() + timedelta(hours=self._cache_ttl_hours)
                        self._api_key_cache[cache_key] = {
                            'key': api_key,
                            'expires': expires
                        }
                        logger.debug(f"Cached API key for {host}, expires at {expires}")
                    
                    return api_key
                else:
                    raise Exception("API key not found in response")
            else:
                error_msg_elem = root.find('.//msg')
                error_text = error_msg_elem.text if error_msg_elem is not None else 'Unknown error'
                raise Exception(f"Failed to obtain API key: {error_text}")
        except requests.RequestException as e:
            # Sanitize error message to not expose passwords
            error_msg = sanitize_error_message(str(e))
            logger.error(f"Request error getting API key: {error_msg}")
            raise Exception(f"Failed to get API key: {error_msg}")
        except Exception as e:
            # Sanitize error message to not expose passwords
            error_msg = sanitize_error_message(str(e))
            logger.error(f"Error getting API key: {error_msg}")
            raise
    
    @classmethod
    def clear_api_key_cache(cls, host: Optional[str] = None) -> None:
        """
        Clear API key cache
        If host is provided, only clears cache for that host
        Otherwise clears all cached API keys
        """
        with cls._cache_lock:
            if host:
                # Remove entries for specific host
                keys_to_remove = [k for k in cls._api_key_cache.keys() if k.startswith(f"{host}:")]
                for key in keys_to_remove:
                    del cls._api_key_cache[key]
                logger.info(f"Cleared API key cache for {host}")
            else:
                # Clear all cache
                cls._api_key_cache.clear()
                logger.info("Cleared all API key caches")
    
    def __del__(self):
        """Cleanup: Clear API keys from memory when object is destroyed"""
        # Note: This won't always be called due to Python's garbage collection,
        # but it's good practice to have it
        self.clear_api_key_cache()
    
    def export_config(self, host: str, auth: Dict[str, Any], label: str = "config") -> str:
        """
        Export Panorama configuration to XML string using direct API call
        """
        logger.info(f"Exporting {label} configuration...")
        
        api_key = self._get_api_key(host, auth)
        
        # Export configuration
        export_url = f"https://{host}/api/?type=export&category=configuration&key={api_key}"
        
        try:
            response = requests.get(export_url, verify=get_ssl_verify(), timeout=60)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Request error exporting configuration: {e}")
            raise Exception(f"Failed to export configuration: {e}")
        except Exception as e:
            logger.error(f"Error exporting configuration: {e}")
            raise
    
    def import_config(self, host: str, auth: Dict[str, Any], config_xml: str, commit: bool = False) -> str:
        """
        Import configuration to Panorama using direct API call
        Optionally commits the configuration to running config
        Returns commit job ID if committed, otherwise 'candidate-only'
        """
        logger.info(f"Importing configuration (commit={commit})...")
        
        api_key = self._get_api_key(host, auth)
        api_url = f"https://{host}/api/"
        
        try:
            # Write the config to candidate
            # Create a temporary file-like object
            config_file = io.BytesIO(config_xml.encode('utf-8'))
            
            # Import the configuration
            files = {
                'file': ('config.xml', config_file, 'application/xml')
            }
            
            params = {
                'type': 'import',
                'category': 'configuration',
                'format': 'xml',
                'key': api_key
            }
            
            logger.info("Uploading configuration to Panorama...")
            response = requests.post(api_url, params=params, files=files, verify=get_ssl_verify(), timeout=120)
            response.raise_for_status()
            
            # Check if import was successful
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                raise Exception(f"Invalid XML response during import: {e}")
            
            logger.info(f"Import response: {response.text}")
            if root.attrib.get('status') != 'success':
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                raise Exception(f"Import failed: {error_text}")
            
            # Try to get the config name from the response, or use default 'config'
            config_name = root.find('.//result').text if root.find('.//result') is not None else 'config.xml'
            logger.info(f"Using config name: {config_name}")
            
            # Load the imported config file into candidate using the operation:load-config
            logger.info("Loading configuration to candidate...")
            # Use operation:load-config (no merge element per PAN-OS API documentation)
            # Use POST method per API documentation (11-xml-operational-commands.md)
            load_params = {
                'type': 'op',
                'cmd': f'<load><config><from>{config_name}</from></config></load>',
                'key': api_key
            }
            
            load_response = requests.post(api_url, data=load_params, verify=get_ssl_verify(), timeout=120)
            load_response.raise_for_status()
            
            try:
                load_root = ET.fromstring(load_response.text)
            except ET.ParseError as e:
                raise Exception(f"Invalid XML response during load: {e}")
            
            logger.info(f"Load response status: {load_root.attrib.get('status')}, response: {load_response.text}")
            if load_root.attrib.get('status') != 'success':
                error_msg = load_root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                raise Exception(f"Load to candidate failed: {error_text}")
            
            # Preserve lab hostname automatically
            # Only for lab Panorama to prevent overwriting with prod hostname
            if host == Config.LAB_HOST:
                # Auto-detect current hostname from running lab Panorama
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
            
            # Only commit if requested
            if commit:
                logger.info("Committing configuration...")
                commit_params = {
                    'type': 'commit',
                    'cmd': '<commit><description>Synchronized from production via Palo-Sync</description></commit>',
                    'key': api_key
                }
                
                # Use POST method per API documentation (09-xml-commit.md)
                commit_response = requests.post(api_url, data=commit_params, verify=get_ssl_verify(), timeout=120)
                commit_response.raise_for_status()
                
                try:
                    commit_root = ET.fromstring(commit_response.text)
                except ET.ParseError as e:
                    raise Exception(f"Invalid XML response during commit: {e}")
                
                if commit_root.attrib.get('status') == 'success':
                    job_elem = commit_root.find('.//job')
                    job_id = job_elem.text if job_elem is not None and job_elem.text else 'unknown'
                    logger.info(f"Commit initiated with job ID: {job_id}")
                    return job_id
                else:
                    error_msg = commit_root.find('.//msg')
                    error_text = error_msg.text if error_msg is not None else 'Unknown error'
                    raise Exception(f"Commit failed: {error_text}")
            else:
                logger.info("Configuration loaded to candidate only (not committed)")
                return 'candidate-only'
                
        except Exception as e:
            logger.error(f"Error importing configuration: {e}")
            raise
    
    def get_current_hostname(self, host: str, auth: Dict[str, Any]) -> Optional[str]:
        """
        Get the current hostname of a Panorama device
        Returns the hostname or None if unable to retrieve
        """
        try:
            api_key = self._get_api_key(host, auth)
            api_url = f"https://{host}/api/"
            
            # Get system info
            params = {
                'type': 'op',
                'cmd': '<show><system><info></info></system></show>',
                'key': api_key
            }
            
            response = requests.post(api_url, data=params, verify=get_ssl_verify(), timeout=30)
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
        """
        Set the hostname on a Panorama device using pan-os-python SDK
        Returns True if successful, False otherwise
        """
        try:
            # Connect to Panorama using SDK
            if 'api_key' in auth:
                pano = panorama.Panorama(hostname=host, api_key=auth['api_key'])
            else:
                pano = panorama.Panorama(
                    hostname=host, 
                    api_username=auth['username'], 
                    api_password=auth['password']
                )
            
            # Create SystemSettings object with new hostname
            sys_settings = SystemSettings(hostname=hostname)
            
            # Add and apply the settings
            pano.add(sys_settings)
            sys_settings.apply()
            
            logger.info(f"Hostname successfully set to: {hostname} using pan-os-python SDK")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set hostname: {e}")
            return False
    
    def xml_to_dict(self, xml_string: str) -> Dict[str, Any]:
        """Convert XML configuration to dictionary for easier comparison"""
        try:
            root = ET.fromstring(xml_string)
            return self._element_to_dict(root)
        except Exception as e:
            logger.error(f"Error converting XML to dict: {e}")
            return {}
    
    def _element_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Recursively convert XML element to dictionary"""
        result = {}
        
        # Add element's own attributes
        if element.attrib:
            result['_attributes'] = element.attrib
        
        # Add element's text content if present
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()
        
        # Process children
        if len(element) > 0:
            for child in element:
                tag = child.tag
                child_dict = self._element_to_dict(child)
                
                # Handle multiple children with same tag
                if tag in result:
                    if not isinstance(result[tag], list):
                        result[tag] = [result[tag]]
                    result[tag].append(child_dict)
                else:
                    result[tag] = child_dict
        
        return result
    
    def create_backup(self, env: str) -> Optional[str]:
        """
        Create a timestamped backup of the configuration
        Returns path to backup file or None
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{env}_backup_{timestamp}.xml"
            backup_path = self.backup_dir / backup_filename
            
            # Determine host and auth based on environment
            if env == "lab":
                host = Config.LAB_HOST
                auth = self.lab_auth
            else:
                host = Config.PROD_HOST
                auth = self.prod_auth
            
            config_xml = self.export_config(host, auth, f"{env} backup")
            
            with open(backup_path, 'w') as f:
                f.write(config_xml)
            
            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)
        
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return None
    
    def generate_diff(self) -> Dict[str, Any]:
        """
        Generate a diff between production and lab configurations
        Returns diff results with summary
        """
        try:
            logger.info("Generating configuration diff...")
            
            # Get production configuration
            prod_config_xml = self.export_config(Config.PROD_HOST, self.prod_auth, "production")
            prod_config_dict = self.xml_to_dict(prod_config_xml)
            
            # Get lab configuration
            lab_config_xml = self.export_config(Config.LAB_HOST, self.lab_auth, "lab")
            lab_config_dict = self.xml_to_dict(lab_config_xml)
            
            # Generate diff using DeepDiff
            diff = DeepDiff(prod_config_dict, lab_config_dict, verbose_level=2, ignore_order=True)
            
            # Format results
            result = {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'differences': {
                    'items_added': len(diff.get('dictionary_item_added', [])),
                    'items_removed': len(diff.get('dictionary_item_removed', [])),
                    'values_changed': len(diff.get('values_changed', [])),
                    'items_moved': len(diff.get('dictionary_item_moved', []))
                },
                'raw_diff': str(diff)
            }
            
            # Add try/except for JSON serialization
            try:
                # Get JSON and parse it to pretty-print with indentation
                diff_json_str = diff.to_json()
                diff_parsed = json.loads(diff_json_str)
                result['diff_json'] = json.dumps(diff_parsed, indent=2)
            except Exception as e:
                logger.debug(f"Could not format diff_json: {e}")
                result['diff_json'] = str(diff)
            
            logger.info(f"Diff completed: {result['differences']}")
            return result
        
        except Exception as e:
            logger.error(f"Error generating diff: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backup files"""
        backups = []
        
        try:
            for backup_file in self.backup_dir.glob("*.xml"):
                stat = backup_file.stat()
                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            
            # Sort by modified time, newest first
            backups.sort(key=lambda x: x['modified'], reverse=True)
        
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
        
        return backups
    
    def delete_backup(self, backup_path: str) -> Dict[str, Any]:
        """Delete a backup file"""
        try:
            backup_file = Path(backup_path)
            
            # Security check: ensure the file is within the backup directory
            if not str(backup_file.resolve()).startswith(str(self.backup_dir.resolve())):
                return {
                    'success': False,
                    'error': 'Invalid backup path'
                }
            
            # Check if file exists
            if not backup_file.exists():
                return {
                    'success': False,
                    'error': 'Backup file not found'
                }
            
            # Delete the file
            backup_file.unlink()
            logger.info(f"Deleted backup: {backup_file}")
            
            return {
                'success': True,
                'message': f'Backup {backup_file.name} deleted successfully'
            }
        
        except Exception as e:
            logger.error(f"Error deleting backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def sync_configuration(self, create_backup: bool = True, commit: bool = False) -> Dict[str, Any]:
        """
        Perform one-way sync from production to lab
        Args:
            create_backup: Whether to create a backup before sync
            commit: Whether to commit the configuration (default: False for safety)
        Returns sync operation results
        """
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
            # Create backup before sync
            if create_backup:
                logger.info("Creating pre-sync backup...")
                backup_path = self.create_backup("lab")
                result['backup_created'] = backup_path is not None
                result['backup_path'] = backup_path
            
            # Get production configuration
            logger.info("Fetching production configuration...")
            prod_config_xml = self.export_config(Config.PROD_HOST, self.prod_auth, "production")
            
            # Import to lab Panorama
            logger.info("Importing configuration to lab...")
            job = self.import_config(Config.LAB_HOST, self.lab_auth, prod_config_xml, commit=commit)
            
            result['success'] = True
            result['commit_job_id'] = job
            logger.info(f"Sync completed successfully: {sync_id}")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Sync failed: {e}")
        
        return result
    
    def restore_backup(self, backup_path: str, commit: bool = False) -> Dict[str, Any]:
        """
        Restore a backup to lab Panorama
        Args:
            backup_path: Path to the backup file
            commit: Whether to commit the configuration (default: False)
        Returns restore operation results
        """
        logger.info(f"Restoring backup: {backup_path}")
        
        result = {
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
        
        try:
            # Read backup file
            with open(backup_path, 'r') as f:
                backup_config = f.read()
            
            # Import to lab Panorama
            job = self.import_config(Config.LAB_HOST, self.lab_auth, backup_config, commit=commit)
            
            result['success'] = True
            result['commit_job_id'] = job
            logger.info(f"Backup restored successfully: {backup_path}")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Restore failed: {e}")
        
        return result

