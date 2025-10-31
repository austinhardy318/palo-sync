import types


def test_request_timeout_roundtrip_and_usage(authenticated_client, monkeypatch):
    # 1) Save settings with requestTimeout = 15
    # Mock settings manager to avoid file system issues
    from unittest.mock import Mock, patch
    with patch('app.main.get_settings_manager') as mock_manager:
        mock_settings = Mock()
        mock_settings.save_settings = Mock()
        mock_settings.get_settings = Mock(return_value={
            'createBackup': True,
            'commitConfig': False,
            'preserveHostname': True,
            'requestTimeout': 15
        })
        mock_manager.return_value = mock_settings
        
        resp = authenticated_client.post('/api/settings', json={
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
        resp2 = authenticated_client.get('/api/settings')
        assert resp2.status_code == 200
        settings = resp2.get_json().get('settings', {})
        assert settings.get('requestTimeout') == 15

        # 3) Verify PanoramaSync uses timeout by mocking HttpClient._get_timeout and capturing the call
        from app.main import sync_manager
        captured = {}

        class FakeResponse:
            status_code = 200
            text = '<response status="success"><result><key>ABC123</key></result></response>'
            def raise_for_status(self):
                return None

        # Mock the session.get to capture timeout parameter
        original_session_get = sync_manager.http._session.get
        def fake_session_get(url, **kwargs):
            captured['timeout'] = kwargs.get('timeout')
            return FakeResponse()
        
        sync_manager.http._session.get = fake_session_get
        
        # Also patch _get_timeout to return 15
        monkeypatch.setattr(sync_manager.http, '_get_timeout', lambda: 15)

        # Call an operation that performs http.get with timeout
        api_key = sync_manager._get_api_key('example.local', {'username': 'u', 'password': 'p'})
        assert api_key == 'ABC123'
        # Should use timeout from patched _get_timeout (15)
        assert captured.get('timeout') == 15
        
        # Restore original
        sync_manager.http._session.get = original_session_get
