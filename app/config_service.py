import io
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from .http_client import HttpClient


logger = logging.getLogger(__name__)


class ConfigService:
    """Low-level config operations: export/import/commit via HTTP client."""

    def __init__(self, http: HttpClient) -> None:
        self.http: HttpClient = http

    def export_config(self, host: str, api_key: str, label: str = "config") -> str:
        logger.info(f"Exporting {label} configuration...")
        export_url = f"https://{host}/api/?type=export&category=configuration&key={api_key}"
        try:
            response = self.http.get(export_url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Request error exporting configuration: {e}")
            raise Exception(f"Failed to export configuration: {e}")
        except (IOError, OSError) as e:
            logger.error(f"IO error exporting configuration: {e}")
            raise

    def import_config(self, host: str, api_key: str, config_xml: str, commit: bool = False) -> str:
        logger.info(f"Importing configuration (commit={commit})...")
        api_url = f"https://{host}/api/"
        try:
            config_file = io.BytesIO(config_xml.encode('utf-8'))
            files = {'file': ('config.xml', config_file, 'application/xml')}
            params = {'type': 'import', 'category': 'configuration', 'format': 'xml', 'key': api_key}
            logger.info("Uploading configuration to NMS...")
            response = self.http.post(api_url, params=params, files=files)
            response.raise_for_status()
            try:
                root = ET.fromstring(response.text)
            except ET.ParseError as e:
                raise Exception(f"Invalid XML response during import: {e}")
            if root.attrib.get('status') != 'success':
                error_msg = root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                raise Exception(f"Import failed: {error_text}")
            config_name = root.find('.//result').text if root.find('.//result') is not None else 'config.xml'
            logger.info(f"Using config name: {config_name}")
            # Load to candidate
            load_params = {'type': 'op', 'cmd': f'<load><config><from>{config_name}</from></config></load>', 'key': api_key}
            load_response = self.http.post(api_url, data=load_params)
            load_response.raise_for_status()
            try:
                load_root = ET.fromstring(load_response.text)
            except ET.ParseError as e:
                raise Exception(f"Invalid XML response during load: {e}")
            if load_root.attrib.get('status') != 'success':
                error_msg = load_root.find('.//msg')
                error_text = error_msg.text if error_msg is not None else 'Unknown error'
                raise Exception(f"Load to candidate failed: {error_text}")
            if commit:
                commit_params = {'type': 'commit', 'cmd': '<commit><description>Synchronized from production via NMS-Sync</description></commit>', 'key': api_key}
                commit_response = self.http.post(api_url, data=commit_params)
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
            return 'candidate-only'
        except requests.RequestException as e:
            logger.error(f"Request error importing configuration: {e}")
            raise Exception(f"Failed to import configuration: {e}")
        except (ET.ParseError, IOError, OSError) as e:
            logger.error(f"Error importing configuration: {e}")
            raise

    def stream_export_to_file(
        self,
        host: str,
        api_key: str,
        dest_path: Path,
        chunk_size: int = 65536,
        max_bytes: int = 100 * 1024 * 1024,
    ) -> str:
        """Stream export to a file on disk with size guard and atomic rename."""
        export_url = f"https://{host}/api/?type=export&category=configuration&key={api_key}"
        tmp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")
        bytes_written = 0
        try:
            with self.http.get(export_url, stream=True) as resp:
                resp.raise_for_status()
                with open(tmp_path, 'wb') as f:
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        if not chunk:
                            continue
                        bytes_written += len(chunk)
                        if bytes_written > max_bytes:
                            raise Exception("Export exceeds maximum size limit")
                        f.write(chunk)
            # Atomic replace
            tmp_path.replace(dest_path)
            logger.info(f"Export streamed to {dest_path} ({bytes_written} bytes)")
            return str(dest_path)
        except requests.RequestException as e:
            logger.error(f"Request error streaming export: {e}")
            raise Exception(f"Failed to stream export: {e}")
        except (IOError, OSError) as e:
            logger.error(f"IO error streaming export: {e}")
            raise
        except Exception as e:
            # Catch any other exceptions and ensure cleanup
            logger.error(f"Error streaming export: {e}")
            raise
        finally:
            # Always try to cleanup tmp file if it still exists (operation failed)
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass  # Ignore cleanup errors


