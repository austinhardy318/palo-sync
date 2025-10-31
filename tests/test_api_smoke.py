def test_health_ok(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and data.get('status') == 'ok'


def test_config_json(authenticated_client):
    """Test config endpoint requires authentication"""
    resp = authenticated_client.get('/api/config')
    assert resp.status_code == 200
    assert resp.is_json


def test_csrf_token_endpoint(client):
    resp = client.get('/api/csrf-token')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data and 'csrf_token' in data


def test_logs_always_json(client):
    """Test that logs endpoint always returns JSON, even on errors"""
    resp = client.get('/api/logs?limit=5')
    # Endpoint should always return valid JSON response
    assert resp.is_json, "Logs endpoint must return JSON"
    data = resp.get_json()
    assert isinstance(data, dict), "Response must be a dictionary"
    
    # On success (200), it includes 'logs' list
    if resp.status_code == 200:
        assert 'logs' in data, "Success response must include 'logs' key"
        assert isinstance(data['logs'], list), "'logs' must be a list"
    # On error, should have error structure
    else:
        # Error responses should have either legacy format or new envelope format
        assert 'error' in data or 'success' in data, "Error response must indicate error"


