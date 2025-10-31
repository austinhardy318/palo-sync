def test_validation_error_envelope_on_restore_requires_body(authenticated_client):
    """Test validation error envelope format on restore"""
    # Missing body should yield validation error
    resp = authenticated_client.post('/api/backups/restore', data='{}', content_type='application/json')
    assert resp.status_code == 400
    data = resp.get_json()
    assert data['success'] is False
    assert 'error' in data and 'message' in data['error']
    assert data['error']['message']


