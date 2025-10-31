def test_unauthorized_on_restore_requires_auth(client, monkeypatch, temp_backup_dir):
    # Force GUI auth requirement
    from app.main import Config
    monkeypatch.setattr(Config, 'GUI_USERNAME', 'admin', raising=False)
    monkeypatch.setattr(Config, 'GUI_PASSWORD', 'secret', raising=False)
    # no session -> should get 401 for API
    backup_path = str(temp_backup_dir / "missing.xml")
    resp = client.post('/api/backups/restore', json={'backup_path': backup_path})
    assert resp.status_code == 401
    data = resp.get_json()
    # supports both legacy and new envelope
    assert (data.get('error') == 'Authentication required') or (
        data.get('success') is False and data.get('error', {}).get('message')
    )


def test_download_missing_file_returns_404(authenticated_client, temp_backup_dir, monkeypatch):
    """Test download of missing file returns 404 with proper error"""
    # Patch sync_manager to use temp backup directory
    from app.main import sync_manager
    original_backup_dir = sync_manager.backup_dir
    sync_manager.backup_dir = temp_backup_dir
    
    try:
        resp = authenticated_client.get('/api/backups/download/does-not-exist.xml')
        # Should return 404 for missing file, or 400 if validation fails first
        assert resp.status_code in (404, 400), f"Expected 404 or 400, got {resp.status_code}"
        assert resp.is_json, "Error response must be JSON"
        data = resp.get_json()
        # Verify error structure exists
        assert 'error' in data or (data.get('success') is False), "Response must indicate error"
    finally:
        sync_manager.backup_dir = original_backup_dir


def test_sync_validation_error(authenticated_client):
    """Test sync endpoint validates input types and returns proper error"""
    # invalid type for create_backup (should be bool, not string)
    resp = authenticated_client.post('/api/sync', json={'create_backup': 'yes', 'commit': False})
    assert resp.status_code == 400, "Invalid input should return 400"
    assert resp.is_json, "Error response must be JSON"
    data = resp.get_json()
    assert isinstance(data, dict), "Response must be a dictionary"
    # Verify error structure - should indicate validation failure
    assert data.get('success') is False, "Error response must have success=False"
    # Error should indicate validation issue
    error_info = data.get('error', {})
    if isinstance(error_info, dict):
        assert 'message' in error_info or 'Validation' in str(error_info), "Error should describe validation issue"
    else:
        assert 'validation' in str(error_info).lower() or 'invalid' in str(error_info).lower(), "Error should mention validation/invalid"

