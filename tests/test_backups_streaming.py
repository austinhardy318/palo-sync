import os
from pathlib import Path


def test_download_rejects_large_file(authenticated_client, temp_backup_dir, monkeypatch):
    """Test that download rejects files exceeding size limit"""
    # Create a small file in temp backup directory
    fname = 'test_large.xml'
    fpath = temp_backup_dir / fname
    fpath.write_text('<xml/>')

    # Monkeypatch sync_manager to use temp backup directory
    from app.main import sync_manager
    original_backup_dir = sync_manager.backup_dir
    sync_manager.backup_dir = temp_backup_dir

    # Mock Path.stat to return large file size
    class FakeStat:
        st_size = 101 * 1024 * 1024  # 101MB
    
    original_stat = Path.stat
    
    def fake_stat(self):
        if self == fpath:
            return FakeStat()
        return original_stat(self)

    monkeypatch.setattr(Path, 'stat', fake_stat)

    try:
        # Perform download - should reject large file
        resp = authenticated_client.get(f'/api/backups/download/{fname}')
        # Should return 413 (Request Entity Too Large) for file size errors
        assert resp.status_code == 413, f"Expected 413, got {resp.status_code}: {resp.get_json()}"
    finally:
        # Restore original backup directory
        sync_manager.backup_dir = original_backup_dir
        monkeypatch.undo()  # Restore Path.stat


def test_stream_export_cleanup_tmp(monkeypatch, tmp_path):
    # Import service and prepare paths
    from app.config_service import ConfigService
    from app.http_client import HttpClient

    http = HttpClient(default_timeout_seconds=1)
    svc = ConfigService(http)
    dest = tmp_path / 'streamed.xml'

    # Fake streaming response that raises mid-stream
    class FakeResp:
        def __init__(self):
            self._iter = iter([b'part1', Exception('stream error')])

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size=65536):
            for item in self._iter:
                if isinstance(item, Exception):
                    raise item
                yield item

    class FakeSession:
        def get(self, url, **kwargs):
            return FakeResp()

    # Patch http.get to return our fake streaming response
    monkeypatch.setattr(http, 'get', FakeSession().get)

    # Run and assert tmp cleanup
    try:
        svc.stream_export_to_file('host', 'key', dest)
        assert False, 'expected exception'
    except Exception:
        pass
    # Ensure .tmp file removed
    tmp_file = dest.with_suffix(dest.suffix + '.tmp')
    assert not tmp_file.exists()

