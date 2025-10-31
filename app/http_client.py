import logging
from typing import Union, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .settings_manager import get_settings_manager


logger = logging.getLogger(__name__)


def get_ssl_verify() -> Union[bool, str]:
    """Resolve SSL verification setting from Config.
    
    Note: Import Config inside function to ensure we always get the latest
    Config class, even if app.config was reloaded.
    """
    from .config import Config  # Import inside function to handle module reloads
    
    if not Config.SSL_VERIFY:
        return False
    return Config.SSL_CERT_PATH if Config.SSL_CERT_PATH else True


class HttpClient:
    """Thin HTTP client with centralized timeout and SSL handling."""

    def __init__(self, default_timeout_seconds: int = 30) -> None:
        self._default_timeout: int = default_timeout_seconds
        # Create a pooled session with retries for idempotent requests
        self._session: requests.Session = requests.Session()
        retries = Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=("GET", "POST"),
        )
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=retries)
        self._session.mount('http://', adapter)
        self._session.mount('https://', adapter)

    def _get_timeout(self) -> int:
        """Read timeout from cached settings."""
        try:
            settings_manager = get_settings_manager()
            rt = settings_manager.get_setting('requestTimeout', self._default_timeout)
            rt = int(rt)
            if 5 <= rt <= 300:
                return rt
        except (ValueError, TypeError):
            # Invalid value, use default
            pass
        return self._default_timeout

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        timeout = kwargs.pop('timeout', self._get_timeout())
        verify = kwargs.pop('verify', get_ssl_verify())
        return self._session.get(url, timeout=timeout, verify=verify, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        timeout = kwargs.pop('timeout', self._get_timeout())
        verify = kwargs.pop('verify', get_ssl_verify())
        return self._session.post(url, timeout=timeout, verify=verify, **kwargs)
