"""
Centralized input validation module
Provides reusable validation functions for request validation
"""

import re
import logging
from pathlib import Path
from typing import Tuple, Optional, List, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


def validate_backup_path(backup_path: str, backup_dir: Path, max_filename_length: int = 255) -> Tuple[bool, Optional[str]]:
    """
    Validate backup path to prevent directory traversal attacks
    Also validates filename format and length
    Returns (is_valid, error_message)
    """
    if not backup_path or not isinstance(backup_path, str):
        return False, 'backup_path is required and must be a string'
    
    # Check path length (prevent extremely long paths)
    if len(backup_path) > 4096:  # Maximum path length on most systems
        return False, 'backup_path exceeds maximum length'
    
    # Check for path traversal attempts
    if '..' in backup_path or backup_path.startswith('.'):
        return False, 'Invalid backup path: path traversal not allowed'
    
    # Validate filename format
    filename = Path(backup_path).name
    if not filename:
        return False, 'Invalid backup path: filename required'
    
    # Check filename length
    if len(filename) > max_filename_length:
        return False, f'Invalid backup path: filename exceeds maximum length of {max_filename_length} characters'
    
    # Validate filename contains only safe characters
    # Allow alphanumeric, hyphens, underscores, dots, and XML extension
    if not re.match(r'^[a-zA-Z0-9_\-\.]+\.xml$', filename):
        return False, 'Invalid backup path: filename must contain only alphanumeric characters, hyphens, underscores, dots, and end with .xml'
    
    # Ensure path is within backup directory
    try:
        backup_file = Path(backup_path)
        backups_dir = Path(backup_dir)
        # Normalize the path and check it's within the backup directory
        resolved_path = backup_file.resolve()
        backups_dir_resolved = backups_dir.resolve()
        if not str(resolved_path).startswith(str(backups_dir_resolved)):
            return False, 'Invalid backup path: must be within backup directory'
        
        # Additional check: ensure the resolved path is actually a file within the directory
        # Prevent accessing parent directories even if path seems valid
        if resolved_path.parent != backups_dir_resolved:
            return False, 'Invalid backup path: must be directly in backup directory'
        
        return True, None
    except (ValueError, OSError) as e:
        return False, f'Invalid backup path: {str(e)}'


def validate_filename(filename: str, allowed_extensions: Optional[List[str]] = None, max_length: int = 255) -> Tuple[bool, Optional[str]]:
    """
    Validate filename to prevent path traversal and malicious filenames
    Returns (is_valid, error_message)
    """
    if not filename or not isinstance(filename, str):
        return False, 'filename is required and must be a string'
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return False, 'Invalid filename: path traversal not allowed'
    
    # Check filename length
    if len(filename) > max_length:
        return False, f'Filename exceeds maximum length ({max_length} characters)'
    
    # Validate filename contains only safe characters
    # Allow alphanumeric, hyphens, underscores, dots
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return False, 'Filename must contain only alphanumeric characters, hyphens, underscores, and dots'
    
    # Check extension if specified
    if allowed_extensions:
        if not any(filename.lower().endswith(ext.lower()) for ext in allowed_extensions):
            return False, f'Filename must have one of the following extensions: {", ".join(allowed_extensions)}'
    
    return True, None


def validate_boolean(value: Any, field_name: str = "field") -> Tuple[bool, Optional[str]]:
    """
    Validate that a value is a boolean
    Returns (is_valid, error_message)
    """
    if not isinstance(value, bool):
        return False, f'{field_name} must be a boolean'
    return True, None


def validate_integer(value: Any, min_value: Optional[int] = None, max_value: Optional[int] = None, field_name: str = "field") -> Tuple[bool, Optional[str]]:
    """
    Validate that a value is an integer within optional bounds
    Returns (is_valid, error_message)
    """
    if not isinstance(value, int) and not (isinstance(value, str) and value.isdigit()):
        return False, f'{field_name} must be an integer'
    
    try:
        int_value = int(value)
    except (ValueError, TypeError):
        return False, f'{field_name} must be a valid integer'
    
    if min_value is not None and int_value < min_value:
        return False, f'{field_name} must be at least {min_value}'
    
    if max_value is not None and int_value > max_value:
        return False, f'{field_name} must be at most {max_value}'
    
    return True, None


def validate_string(value: Any, min_length: Optional[int] = None, max_length: Optional[int] = None, field_name: str = "field") -> Tuple[bool, Optional[str]]:
    """
    Validate that a value is a string within optional length bounds
    Returns (is_valid, error_message)
    """
    if not isinstance(value, str):
        return False, f'{field_name} must be a string'
    
    if min_length is not None and len(value) < min_length:
        return False, f'{field_name} must be at least {min_length} characters'
    
    if max_length is not None and len(value) > max_length:
        return False, f'{field_name} must be at most {max_length} characters'
    
    return True, None


def validate_timezone(timezone: str) -> Tuple[bool, Optional[str]]:
    """
    Validate IANA timezone identifier
    Returns (is_valid, error_message)
    """
    if not isinstance(timezone, str):
        return False, 'timezone must be a string'
    
    timezone = timezone.strip()
    if not timezone:
        return False, 'timezone cannot be empty'
    
    if len(timezone) > 100:
        return False, 'timezone exceeds maximum length (100 characters)'
    
    # Basic validation - should be IANA timezone format
    # Allow common formats but reject obviously malicious strings
    if not re.match(r'^[a-zA-Z0-9/_+\-]+$', timezone):
        return False, 'timezone contains invalid characters'
    
    # Try to validate by importing zoneinfo (if available)
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(timezone)
        return True, None
    except ImportError:
        # zoneinfo not available (Python < 3.9), skip validation
        logger.debug("zoneinfo not available, skipping timezone validation")
        return True, None
    except Exception:
        return False, 'timezone must be a valid IANA time zone (e.g., UTC, America/New_York)'


def validate_regex_pattern(pattern: str, max_length: int = 500) -> Tuple[bool, Optional[str]]:
    """
    Validate regex pattern to prevent ReDoS attacks
    Returns (is_valid, error_message)
    """
    if not isinstance(pattern, str):
        return False, 'regex pattern must be a string'
    
    pattern = pattern.strip()
    if not pattern:
        return False, 'regex pattern cannot be empty'
    
    if len(pattern) > max_length:
        return False, f'regex pattern exceeds maximum length ({max_length} characters)'
    
    # Try to compile the regex to validate it
    try:
        re.compile(pattern)
        return True, None
    except re.error as e:
        return False, f'Invalid regex pattern: {str(e)}'


def validate_file_size(file_size: int, max_size: int) -> Tuple[bool, Optional[str]]:
    """
    Validate file size is within limits
    Returns (is_valid, error_message)
    """
    if not isinstance(file_size, int):
        return False, 'file_size must be an integer'
    
    if file_size < 0:
        return False, 'file_size cannot be negative'
    
    if file_size > max_size:
        max_size_mb = max_size // (1024 * 1024)
        return False, f'File size exceeds maximum limit ({max_size_mb}MB)'
    
    return True, None


def validate_list_of_strings(value: Any, field_name: str = "field", max_items: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Validate that a value is a list of strings
    Returns (is_valid, error_message)
    """
    if not isinstance(value, list):
        return False, f'{field_name} must be an array'
    
    if not all(isinstance(item, str) for item in value):
        return False, f'{field_name} must be an array of strings'
    
    if max_items is not None and len(value) > max_items:
        return False, f'{field_name} must contain at most {max_items} items'
    
    return True, None


def validate_required(value: Any, field_name: str = "field") -> Tuple[bool, Optional[str]]:
    """
    Validate that a required field is present and not None
    Returns (is_valid, error_message)
    """
    if value is None:
        return False, f'{field_name} is required'
    return True, None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing dangerous characters
    Returns sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '')
    # Remove null bytes
    filename = filename.replace('\x00', '')
    # Remove control characters
    filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename)
    return filename

