// Palo-Sync Web GUI JavaScript

let confirmCallback = null;

// Settings management - Load settings from server into sync checkboxes for home page
async function loadSettings() {
    try {
        const response = await fetch('/api/settings');
        const data = await response.json();
        const settings = data.settings;
        
        // Apply defaults to sync section checkboxes (home page only)
        const createBackupEl = document.getElementById('create-backup');
        const commitConfigEl = document.getElementById('commit-config');
        
        if (createBackupEl) {
            createBackupEl.checked = settings.createBackup ?? true;
        }
        if (commitConfigEl) {
            commitConfigEl.checked = settings.commitConfig ?? false;
        }
    } catch (e) {
        console.error('Error loading settings:', e);
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load settings first
    loadSettings();
    
    checkStatus();
    loadBackups();
    loadLogs();
    
    // Setup event listeners
    document.getElementById('refresh-status').addEventListener('click', checkStatus);
    document.getElementById('run-diff').addEventListener('click', runDiff);
    document.getElementById('run-sync').addEventListener('click', confirmSync);
    document.getElementById('refresh-backups').addEventListener('click', loadBackups);
    document.getElementById('refresh-logs').addEventListener('click', loadLogs);
    
    // Modal handlers
    document.getElementById('confirm-yes').addEventListener('click', () => {
        if (confirmCallback) {
            confirmCallback();
        }
        hideModal();
    });
    
    document.getElementById('confirm-no').addEventListener('click', hideModal);
    
    // Auto-refresh logs every 5 seconds
    setInterval(loadLogs, 5000);
});

// Status check
async function checkStatus() {
    const prodStatus = document.getElementById('prod-status');
    const labStatus = document.getElementById('lab-status');
    const prodDetails = document.getElementById('prod-details');
    const labDetails = document.getElementById('lab-details');
    
    prodStatus.className = 'status-badge checking';
    prodStatus.textContent = 'Checking...';
    labStatus.className = 'status-badge checking';
    labStatus.textContent = 'Checking...';
    
    try {
        const response = await fetch('/api/status');
        const status = await response.json();
        
        // Production status
        if (status.production.connected) {
            prodStatus.className = 'status-badge connected';
            prodStatus.textContent = 'Connected';
            prodDetails.textContent = status.production.error || 'Connection successful';
        } else {
            prodStatus.className = 'status-badge disconnected';
            prodStatus.textContent = 'Disconnected';
            prodDetails.textContent = status.production.error || 'Connection failed';
        }
        
        // Lab status
        if (status.lab.connected) {
            labStatus.className = 'status-badge connected';
            labStatus.textContent = 'Connected';
            labDetails.textContent = status.lab.error || 'Connection successful';
        } else {
            labStatus.className = 'status-badge disconnected';
            labStatus.textContent = 'Disconnected';
            labDetails.textContent = status.lab.error || 'Connection failed';
        }
    } catch (error) {
        prodStatus.className = 'status-badge disconnected';
        prodStatus.textContent = 'Error';
        prodDetails.textContent = error.message;
        
        labStatus.className = 'status-badge disconnected';
        labStatus.textContent = 'Error';
        labDetails.textContent = error.message;
    }
}

// Run diff check
async function runDiff() {
    const btn = document.getElementById('run-diff');
    const results = document.getElementById('diff-results');
    
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Running diff...';
    results.classList.remove('show');
    
    try {
        const response = await fetch('/api/diff', { method: 'POST' });
        const data = await response.json();
        
        if (data.success) {
            results.innerHTML = `
                <h3>Diff Summary</h3>
                <div class="diff-summary">
                    <div class="diff-item">
                        <div class="label">Items to Add</div>
                        <div class="value">${data.differences.items_added}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Items to Remove</div>
                        <div class="value">${data.differences.items_removed}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Values Changed</div>
                        <div class="value">${data.differences.values_changed}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Items Moved</div>
                        <div class="value">${data.differences.items_moved}</div>
                    </div>
                </div>
                <details>
                    <summary>View Raw Diff</summary>
                    <pre class="diff-raw">${formatDiff(data.diff_json || data.raw_diff || 'No differences found')}</pre>
                </details>
            `;
        } else {
            results.innerHTML = `<p style="color: red;">Error: ${data.error || 'Unknown error'}</p>`;
        }
        
        results.classList.add('show');
    } catch (error) {
        results.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
        results.classList.add('show');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Run Diff Check';
    }
}

// Confirm and execute sync
function confirmSync() {
    const createBackup = document.getElementById('create-backup').checked;
    const commit = document.getElementById('commit-config').checked;
    
    let message = `Are you sure you want to synchronize the lab configuration with production?`;
    if (createBackup) {
        message += ' A backup will be created before the sync.';
    }
    if (commit) {
        message += ' The configuration will be committed to the running config immediately.';
    } else {
        message += ' The configuration will be loaded to candidate only (not committed).';
    }
    
    showModal(
        'Confirm Synchronization',
        message,
        () => executeSync()
    );
}

// Execute sync
async function executeSync() {
    const btn = document.getElementById('run-sync');
    const results = document.getElementById('sync-results');
    const createBackup = document.getElementById('create-backup').checked;
    const commit = document.getElementById('commit-config').checked;
    
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Syncing...';
    
    results.className = 'sync-results';
    results.innerHTML = '';
    results.classList.remove('show');
    
    try {
        const response = await fetch('/api/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ create_backup: createBackup, commit: commit })
        });
        
        const data = await response.json();
        
        results.classList.add('show');
        results.classList.add(data.success ? 'success' : 'error');
        
        if (data.success) {
            results.innerHTML = `
                <h3>✓ Sync Completed Successfully</h3>
                <p>Sync ID: ${data.sync_id}</p>
                ${data.backup_created ? `<p>Backup created: ${data.backup_path}</p>` : ''}
                <p>Commit Job ID: ${data.commit_job_id || 'N/A'}</p>
            `;
            loadBackups(); // Refresh backups list
        } else {
            results.innerHTML = `
                <h3>✗ Sync Failed</h3>
                <p>Error: ${data.error || 'Unknown error'}</p>
            `;
        }
    } catch (error) {
        results.classList.add('show');
        results.classList.add('error');
        results.innerHTML = `<h3>✗ Sync Failed</h3><p>Error: ${error.message}</p>`;
    } finally {
        btn.disabled = false;
        btn.textContent = 'Execute Sync';
    }
}

// Load backups
async function loadBackups() {
    const tbody = document.querySelector('#backups-table tbody');
    
    tbody.innerHTML = '<tr><td colspan="4" class="loading">Loading backups...</td></tr>';
    
    try {
        const response = await fetch('/api/backups');
        const data = await response.json();
        
        if (data.backups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No backups found</td></tr>';
            return;
        }
        
        tbody.innerHTML = data.backups.map(backup => `
            <tr>
                <td>${escapeHtml(backup.filename)}</td>
                <td>${formatBytes(backup.size)}</td>
                <td>${formatTimestamp(backup.modified)}</td>
                <td>
                    <button class="btn btn-primary" onclick="downloadBackup('${escapeHtml(backup.path)}')" style="margin-right: 5px;">
                        Download
                    </button>
                    <button class="btn btn-secondary" onclick="restoreBackup('${escapeHtml(backup.path)}')" style="margin-right: 5px;">
                        Restore
                    </button>
                    <button class="btn btn-danger" onclick="deleteBackup('${escapeHtml(backup.path)}')">
                        Delete
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        tbody.innerHTML = `<tr><td colspan="4" style="color: red;">Error: ${error.message}</td></tr>`;
    }
}

// Download backup
function downloadBackup(backupPath) {
    // Extract just the filename from the path for the download URL
    const filename = backupPath.split('/').pop();
    window.location.href = `/api/backups/download/${encodeURIComponent(filename)}`;
}

// Restore backup
async function restoreBackup(backupPath) {
    if (!confirm('Are you sure you want to restore this backup? This will overwrite the current lab configuration.')) {
        return;
    }
    
    try {
        const response = await fetch('/api/backups/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backup_path: backupPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Backup restored successfully!');
        } else {
            alert(`Restore failed: ${data.error}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// Delete backup
async function deleteBackup(backupPath) {
    if (!confirm('Are you sure you want to delete this backup? This action cannot be undone.')) {
        return;
    }
    
    try {
        const response = await fetch('/api/backups/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ backup_path: backupPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(data.message || 'Backup deleted successfully!');
            // Reload the backups list to update the display
            loadBackups();
        } else {
            alert(`Delete failed: ${data.error}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// Load logs
async function loadLogs() {
    const logsDiv = document.getElementById('logs');
    
    try {
        const response = await fetch('/api/logs?limit=50');
        const data = await response.json();
        
        if (data.logs.length === 0) {
            logsDiv.innerHTML = '<p class="loading">No logs available</p>';
            return;
        }
        
        logsDiv.innerHTML = data.logs.reverse().map(log => `
            <div class="log-entry">
                <span class="log-timestamp">[${formatTimestamp(log.timestamp)}]</span>
                <span class="log-user">${escapeHtml(log.user || 'system')}</span>
                <span class="log-operation">${escapeHtml(log.operation)}</span>
            </div>
        `).join('');
    } catch (error) {
        logsDiv.innerHTML = `<p style="color: red;">Error loading logs: ${error.message}</p>`;
    }
}

// Modal functions
function showModal(title, message, callback) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;
    confirmCallback = callback;
    document.getElementById('confirm-modal').classList.add('show');
}

function hideModal() {
    document.getElementById('confirm-modal').classList.remove('show');
    confirmCallback = null;
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatDiff(rawDiff) {
    // The backend now sends pre-formatted JSON with indentation
    // Just escape it for HTML display
    if (typeof rawDiff === 'string') {
        return escapeHtml(rawDiff);
    }
    return escapeHtml(String(rawDiff));
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

