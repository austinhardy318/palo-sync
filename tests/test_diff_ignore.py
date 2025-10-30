def test_diff_ignore_paths_roundtrip_and_effect(client):
    # Authenticate
    with client.session_transaction() as sess:
        sess['authenticated'] = True
        sess['username'] = 'tester'

    # Save settings with ignore for a simple XML value path
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
    resp = client.post('/api/settings', json=payload)
    assert resp.status_code == 200
    assert resp.get_json().get('success') is True

    # Monkeypatch export_config to return different XMLs differing only in ignored path
    from app.main import sync_manager

    prod_xml = "<config><x>123</x><y>same</y></config>"
    lab_xml = "<config><x>999</x><y>same</y></config>"
    seq = [prod_xml, lab_xml]

    def export_stub(host, auth, label):
        return seq.pop(0)

    # Patch on the instance used by the app
    import types
    sync_manager.export_config = types.MethodType(lambda self, host, auth, label: export_stub(host, auth, label), sync_manager)

    # Call diff and expect no differences due to ignore
    resp = client.post('/api/diff')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get('success') is True
    diffs = data['differences']
    assert sum(diffs.values()) == 0


