"""
Custom exception classes for NMS-Sync
Provides consistent error handling across the application
"""

from typing import Optional, Dict, Any


class NMSException(Exception):
    """Base exception for all NMS-Sync errors"""
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize exception
        
        Args:
            message: Human-readable error message
            code: Machine-readable error code (e.g., 'VALIDATION_FAILED')
            status_code: HTTP status code (default: 500)
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON response"""
        result = {
            'success': False,
            'error': {
                'message': self.message
            }
        }
        
        if self.code:
            result['error']['code'] = self.code
        
        if self.details:
            result['error']['details'] = self.details
        
        return result


class ValidationError(NMSException):
    """Raised when input validation fails"""
    
    def __init__(self, message: str, field: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='VALIDATION_FAILED',
            status_code=400,
            details=details or {}
        )
        if field:
            self.details['field'] = field


class AuthenticationError(NMSException):
    """Raised when authentication fails"""
    
    def __init__(self, message: str = "Authentication required", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='UNAUTHORIZED',
            status_code=401,
            details=details or {}
        )


class AuthorizationError(NMSException):
    """Raised when authorization fails"""
    
    def __init__(self, message: str = "Forbidden", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='FORBIDDEN',
            status_code=403,
            details=details or {}
        )


class NotFoundError(NMSException):
    """Raised when a resource is not found"""
    
    def __init__(self, resource: str, identifier: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        message = f"{resource} not found"
        if identifier:
            message = f"{resource} '{identifier}' not found"
        
        super().__init__(
            message=message,
            code='NOT_FOUND',
            status_code=404,
            details=details or {}
        )
        self.details['resource'] = resource
        if identifier:
            self.details['identifier'] = identifier


class SyncError(NMSException):
    """Raised when sync operations fail"""
    
    def __init__(self, message: str, operation: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='SYNC_FAILED',
            status_code=500,
            details=details or {}
        )
        if operation:
            self.details['operation'] = operation


class ConfigError(NMSException):
    """Raised when configuration operations fail"""
    
    def __init__(self, message: str, config_key: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='CONFIG_ERROR',
            status_code=500,
            details=details or {}
        )
        if config_key:
            self.details['config_key'] = config_key


class BackupError(NMSException):
    """Raised when backup operations fail"""
    
    def __init__(self, message: str, operation: Optional[str] = None, details: Optional[Dict[str, Any]] = None, status_code: int = 500):
        super().__init__(
            message=message,
            code='BACKUP_ERROR',
            status_code=status_code,
            details=details or {}
        )
        if operation:
            self.details['operation'] = operation


class PanoramaConnectionError(NMSException):
    """Raised when connection to Panorama fails"""
    
    def __init__(self, host: str, message: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        error_message = message or f"Failed to connect to Panorama at {host}"
        super().__init__(
            message=error_message,
            code='PANORAMA_CONNECTION_ERROR',
            status_code=503,  # Service Unavailable
            details=details or {}
        )
        self.details['host'] = host


class PanoramaAPIError(NMSException):
    """Raised when Panorama API returns an error"""
    
    def __init__(self, message: str, api_response: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='PANORAMA_API_ERROR',
            status_code=502,  # Bad Gateway
            details=details or {}
        )
        if api_response:
            self.details['api_response'] = api_response

