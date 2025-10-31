import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .exceptions import BackupError, NotFoundError

# Use structured logging if available, fallback to standard logging
try:
    from .logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)


class BackupService:
    """Handles backup listing, creation, and deletion."""

    def __init__(self, backup_dir: str) -> None:
        self.backup_dir: Path = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def list_backups(self) -> List[Dict[str, Any]]:
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
        except (OSError, IOError) as e:
            logger.error(f"Error listing backups: {e}")
        return backups

    def create_backup_filename(self, env: str) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{env}_backup_{timestamp}.xml"
        return self.backup_dir / backup_filename

    def create_lab_backup(self, config_xml: str) -> Optional[str]:
        try:
            backup_path = self.create_backup_filename("lab")
            with open(backup_path, 'w') as f:
                f.write(config_xml)
            logger.info(f"Created backup: {backup_path}")
            return str(backup_path)
        except (OSError, IOError) as e:
            logger.error(f"Failed to create backup: {e}")
            return None

    def delete_backup(self, backup_path: str) -> Dict[str, Any]:
        try:
            backup_file = Path(backup_path)
            if not str(backup_file.resolve()).startswith(str(self.backup_dir.resolve())):
                raise BackupError('Invalid backup path', operation='delete')
            if not backup_file.exists():
                raise NotFoundError('backup', identifier=backup_path)
            backup_file.unlink()
            logger.info(f"Deleted backup: {backup_file}")
            return {'success': True, 'message': f'Backup {backup_file.name} deleted successfully'}
        except (NotFoundError, BackupError):
            # Re-raise custom exceptions
            raise
        except (OSError, IOError) as e:
            logger.error(f"Error deleting backup: {e}")
            raise BackupError(f'Failed to delete backup: {str(e)}', operation='delete')


