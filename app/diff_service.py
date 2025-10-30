import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any

from deepdiff import DeepDiff
import hashlib
import re
from pathlib import Path

from .config import Config


logger = logging.getLogger(__name__)


class DiffService:
    """Generates diffs between production and lab configurations."""

    def __init__(self, sync_service: "SyncService") -> None:
        # Lazy import type to avoid circular imports at runtime
        self.sync: "SyncService" = sync_service

    def generate_diff(self) -> Dict[str, Any]:
        try:
            logger.info("Generating configuration diff...")
            prod_config_xml = self.sync.export_config(Config.PROD_HOST, self.sync.prod_auth, "production")
            lab_config_xml = self.sync.export_config(Config.LAB_HOST, self.sync.lab_auth, "lab")

            # Fast path: if normalized XML payloads are identical, skip parsing/diff
            def _normalize_xml(xml_str: str) -> str:
                # remove insignificant whitespace between tags and strip
                return re.sub(r">\s+<", "><", xml_str).strip()

            prod_norm = _normalize_xml(prod_config_xml)
            lab_norm = _normalize_xml(lab_config_xml)
            if hashlib.sha256(prod_norm.encode()).hexdigest() == hashlib.sha256(lab_norm.encode()).hexdigest():
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

            # Load diff ignore settings
            exclude_paths = set()
            exclude_regex_compiled = []
            exclude_regex_strings = []
            significant_digits = None
            try:
                settings_path = Path('/app/settings/user_settings.json')
                if settings_path.exists():
                    with open(settings_path, 'r') as f:
                        settings = json.load(f)
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
            except (OSError, IOError, json.JSONDecodeError, KeyError) as e:
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
                if path_str in exclude_paths:
                    return True
                # Treat exact excluded paths as prefixes to catch child fields
                for p in exclude_paths:
                    if path_str.startswith(p):
                        return True
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
            return result
        except (ET.ParseError, OSError, IOError) as e:
            logger.error(f"Error generating diff: {e}")
            return {'success': False, 'error': str(e), 'timestamp': datetime.now().isoformat()}


