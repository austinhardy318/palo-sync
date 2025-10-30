def test_health_ok(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and data.get('status') == 'ok'


def test_config_json(client):
    resp = client.get('/api/config')
    assert resp.status_code == 200
    assert resp.is_json


def test_csrf_token_endpoint(client):
    resp = client.get('/api/csrf-token')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and 'csrf_token' in data


def test_logs_always_json(client):
    resp = client.get('/api/logs?limit=5')
    assert resp.status_code in (200, 500, 400)
    # Regardless of error, it must be JSON with logs key present when 200
    assert resp.is_json
    data = resp.get_json()
    assert isinstance(data, dict)
    # On success it includes 'logs' list
    if resp.status_code == 200:
        assert 'logs' in data and isinstance(data['logs'], list)


