import json
import logging
import xml.etree.ElementTree as ET
import os
import threading
from datetime import datetime
from typing import Dict, Any, Optional, TYPE_CHECKING

from deepdiff import DeepDiff
import hashlib
import re

if TYPE_CHECKING:
    from .sync_service import SyncService

from .config import Config
from .settings_manager import get_settings_manager


logger = logging.getLogger(__name__)


class DiffService:
    """Generates diffs between production and lab configurations."""
    
    # Class-level cache for diff results
    _diff_cache: Dict[str, Dict[str, Any]] = {}
    _cache_lock = threading.Lock()
    _cache_ttl_seconds = int(os.getenv('DIFF_CACHE_TTL_SECONDS', '300'))  # 5 minutes default
    _cache_max_size = int(os.getenv('DIFF_CACHE_MAX_SIZE', '50'))  # Maximum cached diffs

    def __init__(self, sync_service: "SyncService") -> None:  # type: ignore
        # Lazy import type to avoid circular imports at runtime
        self.sync: "SyncService" = sync_service  # type: ignore
    
    @classmethod
    def _get_cache_key(cls, prod_hash: str, lab_hash: str) -> str:
        """Generate cache key from config hashes"""
        return f"{prod_hash}:{lab_hash}"
    
    @classmethod
    def _get_cached_diff(cls, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached diff if valid"""
        with cls._cache_lock:
            if cache_key in cls._diff_cache:
                cached = cls._diff_cache[cache_key]
                # Check if cache entry is still valid
                cached_time = cached.get('cached_at')
                if cached_time:
                    age = datetime.now() - datetime.fromisoformat(cached_time)
                    if age.total_seconds() < cls._cache_ttl_seconds:
                        logger.debug(f"Using cached diff result (age: {age.total_seconds():.1f}s)")
                        # Return copy without cache metadata
                        result = cached.get('result', {})
                        if not isinstance(result, dict):
                            logger.warning(f"Invalid cached result type: {type(result)}")
                            del cls._diff_cache[cache_key]
                            return None
                        # Validate cached result has required fields
                        if 'differences' not in result:
                            logger.warning("Cached result missing 'differences' key, invalidating cache entry")
                            del cls._diff_cache[cache_key]
                            return None
                        result = result.copy()
                        result['cached'] = True
                        return result
                    else:
                        # Cache expired, remove it
                        logger.debug(f"Cache expired for diff (age: {age.total_seconds():.1f}s)")
                        del cls._diff_cache[cache_key]
        return None
    
    @classmethod
    def _cache_diff(cls, cache_key: str, result: Dict[str, Any]) -> None:
        """Cache diff result"""
        with cls._cache_lock:
            # Clean up expired entries first
            now = datetime.now()
            expired_keys = []
            for k, v in cls._diff_cache.items():
                cached_time = v.get('cached_at')
                if cached_time:
                    age = now - datetime.fromisoformat(cached_time)
                    if age.total_seconds() >= cls._cache_ttl_seconds:
                        expired_keys.append(k)
            
            for k in expired_keys:
                del cls._diff_cache[k]
            
            # If cache is still at max size, remove oldest entry
            if len(cls._diff_cache) >= cls._cache_max_size:
                oldest_key = next(iter(cls._diff_cache))
                del cls._diff_cache[oldest_key]
                logger.debug(f"Evicted oldest diff cache entry: {oldest_key}")
            
            # Store result with metadata
            cls._diff_cache[cache_key] = {
                'result': result.copy(),
                'cached_at': datetime.now().isoformat()
            }
            logger.debug(f"Cached diff result (cache size: {len(cls._diff_cache)}/{cls._cache_max_size})")
    
    @classmethod
    def clear_cache(cls) -> None:
        """Clear all cached diff results"""
        with cls._cache_lock:
            cls._diff_cache.clear()
            logger.info("Cleared diff cache")

    def generate_diff(self) -> Dict[str, Any]:
        try:
            logger.info("Generating configuration diff...")
            prod_config_xml = self.sync.export_config(Config.PROD_HOST, self.sync.prod_auth, "production")
            lab_config_xml = self.sync.export_config(Config.LAB_HOST, self.sync.lab_auth, "lab")

            # Normalize XML for hashing
            def _normalize_xml(xml_str: str) -> str:
                # remove insignificant whitespace between tags and strip
                return re.sub(r">\s+<", "><", xml_str).strip()

            prod_norm = _normalize_xml(prod_config_xml)
            lab_norm = _normalize_xml(lab_config_xml)
            
            # Generate hashes for cache key
            prod_hash = hashlib.sha256(prod_norm.encode()).hexdigest()
            lab_hash = hashlib.sha256(lab_norm.encode()).hexdigest()
            cache_key = self._get_cache_key(prod_hash, lab_hash)
            
            # Check cache first
            cached_result = self._get_cached_diff(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Fast path: if normalized XML payloads are identical, skip parsing/diff
            if prod_hash == lab_hash:
                result = {
                    'success': True,
                    'timestamp': datetime.now().isoformat(),
                    'differences': {
                        'items_added': 0,
                        'items_removed': 0,
                        'values_changed': 0,
                        'items_moved': 0
                    },
                    'raw_diff': '{}',
                    'diff_json': '{}'
                }
                logger.info("Diff completed: no changes (fast path)")
                return result

            # Fallback to structural diff
            prod_config_dict = self.sync.xml_to_dict(prod_config_xml)
            lab_config_dict = self.sync.xml_to_dict(lab_config_xml)

            # Load diff ignore settings from cached settings
            exclude_paths = set()
            exclude_regex_compiled = []
            exclude_regex_strings = []
            significant_digits = None
            try:
                settings_manager = get_settings_manager()
                settings = settings_manager.get_settings()
                
                for p in settings.get('diffIgnorePaths', []) or []:
                    if isinstance(p, str) and p.strip():
                        exclude_paths.add(p.strip())
                for rp in settings.get('diffIgnoreRegexPaths', []) or []:
                    try:
                        exclude_regex_compiled.append(re.compile(rp))
                        exclude_regex_strings.append(rp)
                    except re.error:
                        continue
                sd = settings.get('diffSignificantDigits')
                if isinstance(sd, int):
                    significant_digits = sd
            except Exception as e:
                logger.debug(f"Failed to load diff ignore settings: {e}")

            # Pre-prune dictionaries based on ignore rules to support older DeepDiff versions
            def prune(obj: Any, path: str) -> Any:
                # Remove nodes whose path matches ignores
                for regex in exclude_regex_compiled:
                    if regex.search(path):
                        return None
                if path in exclude_paths:
                    return None
                if isinstance(obj, dict):
                    pruned: Dict[str, Any] = {}
                    for k, v in obj.items():
                        child_path = f"{path}['{k}']"
                        child = prune(v, child_path)
                        if child is not None:
                            pruned[k] = child
                    return pruned
                if isinstance(obj, list):
                    pruned_list = []
                    for idx, v in enumerate(obj):
                        child_path = f"{path}[{idx}]"
                        child = prune(v, child_path)
                        if child is not None:
                            pruned_list.append(child)
                    return pruned_list
                return obj

            if exclude_paths or exclude_regex_compiled:
                prod_config_dict = prune(prod_config_dict, 'root')
                lab_config_dict = prune(lab_config_dict, 'root')

            diff = DeepDiff(
                prod_config_dict,
                lab_config_dict,
                verbose_level=1,            # lower verbosity for speed
                ignore_order=True,
                report_repetition=True,     # helps compress repeated items
                exclude_paths=exclude_paths if exclude_paths else None,
                exclude_regex_paths=exclude_regex_strings if exclude_regex_strings else None,
                significant_digits=significant_digits
            )

            # Filter counts by ignore rules in case upstream excludes did not fully apply
            def _matches_ignored(path_str: str) -> bool:
                # Normalize quotes for comparison (DeepDiff uses double quotes, user input may use single)
                # Convert both to single quotes for comparison
                normalized_path = path_str.replace('"', "'")
                # Check exact match (normalized or original)
                if normalized_path in exclude_paths or path_str in exclude_paths:
                    return True
                # Treat exact excluded paths as prefixes to catch child fields
                # Normalize both path and exclude paths for comparison
                for p in exclude_paths:
                    normalized_exclude = p.replace('"', "'")
                    # Check if path starts with exclude (both original and normalized)
                    if (path_str.startswith(p) or path_str.startswith(normalized_exclude) or
                        normalized_path.startswith(p) or normalized_path.startswith(normalized_exclude)):
                        return True
                # Check regex patterns
                for rgx in exclude_regex_compiled:
                    if rgx.search(path_str):
                        return True
                return False

            def _count_filtered(bucket: Any) -> int:
                if bucket is None:
                    return 0
                try:
                    # dict of path -> details
                    return sum(1 for k in bucket.keys() if not _matches_ignored(str(k)))
                except AttributeError:
                    try:
                        # set or list of paths
                        return sum(1 for k in bucket if not _matches_ignored(str(k)))
                    except TypeError:
                        return 0

            result = {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'differences': {
                    'items_added': _count_filtered(diff.get('dictionary_item_added', None)),
                    'items_removed': _count_filtered(diff.get('dictionary_item_removed', None)),
                    'values_changed': _count_filtered(diff.get('values_changed', None)),
                    'items_moved': _count_filtered(diff.get('dictionary_item_moved', None))
                },
                'raw_diff': str(diff)
            }

            try:
                diff_json_str = diff.to_json()
                diff_parsed = json.loads(diff_json_str)
                result['diff_json'] = json.dumps(diff_parsed, indent=2)
            except (json.JSONDecodeError, AttributeError, TypeError) as e:
                logger.debug(f"Could not format diff_json: {e}")
                result['diff_json'] = str(diff)

            logger.info(f"Diff completed: {result['differences']}")
            
            # Cache the result
            self._cache_diff(cache_key, result)
            
            return result
        except (ET.ParseError, OSError, IOError) as e:
            logger.error(f"Error generating diff: {e}")
            return {'success': False, 'error': str(e), 'timestamp': datetime.now().isoformat()}


