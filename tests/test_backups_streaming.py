import os
from pathlib import Path


def test_download_rejects_large_file(client, monkeypatch):
    # Authenticate
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'tester'

    # Create a small file in /backups
    backups_dir = Path('/backups')
    backups_dir.mkdir(parents=True, exist_ok=True)
    fname = 'test_large.xml'
    fpath = backups_dir / fname
    fpath.write_text('<xml/>')

    class FakeStat:
        st_size = 101 * 1024 * 1024  # 101MB

    # Monkeypatch Path.stat for this file to simulate large size
    orig_stat = Path.stat

    def fake_stat(self):
        if str(self) == str(fpath):
            return FakeStat()
        return orig_stat(self)

    monkeypatch.setattr(Path, 'stat', fake_stat)

    # Perform download
    resp = client.get(f'/api/backups/download/{fname}')
    assert resp.status_code == 413


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

