def test_unauthorized_diff_and_sync_when_auth_required(client, monkeypatch):
    from app.main import Config
    # Force GUI auth
    monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin', raising=False)
    monkeypatch.setattr(Config, 'GUI_PASSWORD', 'secret', raising=False)

    # diff requires auth
    resp_diff = client.post('/api/diff')
    assert resp_diff.status_code == 401

    # sync requires auth
    resp_sync = client.post('/api/sync', json={'create_backup': True, 'commit': False})
    assert resp_sync.status_code == 401


def test_unauthorized_create_backup_when_auth_required(client, monkeypatch):
    from app.main import Config
    monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin', raising=False)
    monkeypatch.setattr(Config, 'GUI_PASSWORD', 'secret', raising=False)
    resp = client.post('/api/backups/create')
    assert resp.status_code == 401

