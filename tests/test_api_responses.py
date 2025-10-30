def test_unauthorized_on_restore_requires_auth(client, monkeypatch):
    # Force GUI auth requirement
    from app.main import Config
    monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin', raising=False)
    monkeypatch.setattr(Config, 'GUI_PASSWORD', 'secret', raising=False)
    # no session -> should get 401 for API
    resp = client.post('/api/backups/restore', json={'backup_path': '/backups/missing.xml'})
    assert resp.status_code == 401
    data = resp.get_json()
    # supports both legacy and new envelope
    assert (data.get('error') == 'Authentication required') or (
        data.get('success') is False and data.get('error', {}).get('message')
    )


def test_download_missing_file_returns_404(client):
    # simulate authenticated session to hit endpoint logic
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'tester'
    resp = client.get('/api/backups/download/does-not-exist.xml')
    assert resp.status_code == 404 or resp.status_code == 400


def test_sync_validation_error(client):
    # simulate authenticated session
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'tester'
    # invalid type for create_backup
    resp = client.post('/api/sync', json={'create_backup': 'yes', 'commit': False})
    assert resp.status_code == 400
    data = resp.get_json()
    assert isinstance(data, dict)

