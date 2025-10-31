def test_diff_ignore_paths_roundtrip_and_effect(authenticated_client):
    # Save settings with ignore for a simple XML value path
    # Mock settings manager to avoid file system issues
    from unittest.mock import Mock, patch
    
    # Clear diff cache first to avoid stale cached results from previous tests
    # This is critical because the cache is class-level and persists across tests
    from app.diff_service import DiffService
    DiffService.clear_cache()
    
    # Also ensure sync_manager is using the real implementation, not a mock
    # If it's mocked (e.g., by a fixture), we need to restore it
    from app.main import sync_manager
    # Check if generate_diff is mocked and restore if needed
    if isinstance(sync_manager.generate_diff, Mock):
        # Restore the original method
        from app.sync_service import SyncService
        sync_manager.generate_diff = SyncService.generate_diff.__get__(sync_manager, SyncService)
    
    # Create mock settings manager
    mock_settings = Mock()
    mock_settings.save_settings = Mock()
    mock_settings.get_settings = Mock(return_value={
        'createBackup': True,
        'commitConfig': False,
        'preserveHostname': True,
        'autoRefreshLogs': True,
        'logRefreshInterval': 10,
        'requestTimeout': 30,
        'timezone': 'UTC',
        'diffIgnorePaths': ["root['x']['_text']"],
        'diffIgnoreRegexPaths': []
    })
    
    # Patch both locations where get_settings_manager is used
    with patch('app.diff_service.get_settings_manager', return_value=mock_settings), \
         patch('app.main.get_settings_manager', return_value=mock_settings):
        
        payload = {
            'settings': {
                'createBackup': True,
                'commitConfig': False,
                'preserveHostname': True,
                'autoRefreshLogs': True,
                'logRefreshInterval': 10,
                'requestTimeout': 30,
                'timezone': 'UTC',
                'diffIgnorePaths': ["root['x']['_text']"],
                'diffIgnoreRegexPaths': []
            }
        }
        resp = authenticated_client.post('/api/settings', json=payload)
        assert resp.status_code == 200
        assert resp.get_json().get('success') is True

        # Monkeypatch export_config to return different XMLs differing only in ignored path
        from app.main import sync_manager

        # Use same XML for both to test ignore paths (ignore should prevent difference detection)
        # XML structure: <x>123</x> becomes {'x': {'_text': '123'}}
        # Ignore path "root['x']['_text']" should match this
        prod_xml = "<config><x>123</x><y>same</y></config>"
        lab_xml = "<config><x>999</x><y>same</y></config>"
        seq = [prod_xml, lab_xml]

        def export_stub(host, auth, label):
            return seq.pop(0)

        # Patch on the instance used by the app
        import types
        sync_manager.export_config = types.MethodType(lambda self, host, auth, label: export_stub(host, auth, label), sync_manager)

        # Clear diff cache to ensure fresh calculation
        from app.diff_service import DiffService
        DiffService.clear_cache()

        # Call diff and expect no differences due to ignore
        # The ignore path "root['x']['_text']" should prevent detection of difference in x values
        resp = authenticated_client.post('/api/diff')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data.get('success') is True, f"Diff failed with error: {data.get('error', 'Unknown error')}"
        # Ensure differences key exists (validation in diff_service should prevent invalid cached results)
        assert 'differences' in data, f"Response missing 'differences' key: {data}"
        diffs = data['differences']
        # With ignore path matching root['x']['_text'], the x difference should be ignored
        # But y values are same, so total should be 0
        assert sum(diffs.values()) == 0, f"Expected 0 differences but got {diffs}"


