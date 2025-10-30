import types


def test_request_timeout_roundtrip_and_usage(client, monkeypatch):
    # 1) Save settings with requestTimeout = 15
    resp = client.post('/api/settings', json={
        'settings': {
            'createBackup': True,
            'commitConfig': False,
            'preserveHostname': True,
            'autoRefreshLogs': True,
            'logRefreshInterval': 10,
            'requestTimeout': 15,
        }
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True

    # 2) Get settings and verify round-trip
    resp2 = client.get('/api/settings')
    assert resp2.status_code == 200
    settings = resp2.get_json().get('settings', {})
    assert settings.get('requestTimeout') == 15

    # 3) Verify PanoramaSync uses timeout by monkeypatching requests.Session.get
    from app.main import sync_manager
    captured = {}

    class FakeResponse:
        status_code = 200
        text = '<response status="success"><result><key>ABC123</key></result></response>'
        def raise_for_status(self):
            return None

    def fake_get(self, url, **kwargs):
        captured['timeout'] = kwargs.get('timeout')
        return FakeResponse()

    monkeypatch.setattr('requests.Session.get', fake_get)

    # Call an operation that performs requests.get with timeout
    api_key = sync_manager._get_api_key('example.local', {'username': 'u', 'password': 'p'})
    assert api_key == 'ABC123'
    assert captured.get('timeout') == 15


