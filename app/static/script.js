// NMS-Sync Web GUI JavaScript

let confirmCallback = null;
let logsAutoRefreshInterval = null; // Store interval ID for auto-refresh
let currentTimezone = 'UTC';

// Get CSRF token - try multiple methods
async function getCsrfToken() {
    // Method 1: Get from meta tag (most reliable - embedded in HTML at page load)
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        const token = metaToken.getAttribute('content');
        if (token && token.trim().length > 0) {
            return token.trim();
        }
    }
    
    // Method 2: Try to get from cookies (less common with Flask-WTF)
    const cookieNames = ['csrf_token', 'csrf'];
    for (const name of cookieNames) {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [key, value] = cookie.trim().split('=');
            if (key === name && value) {
                const decoded = decodeURIComponent(value).trim();
                if (decoded && decoded.length > 0) {
                    return decoded;
                }
            }
        }
    }
    
    // Method 3: Fetch from API endpoint (fallback - generates new token)
    try {
        const response = await fetch('/api/csrf-token', {
            credentials: 'same-origin'
        });
        if (response.ok) {
            const data = await response.json();
            if (data.csrf_token && data.csrf_token.trim()) {
                return data.csrf_token.trim();
            }
        }
    } catch (error) {
        console.error('Failed to fetch CSRF token from API:', error);
    }
    
    console.warn('CSRF token not found from any source');
    return null;
}

// Helper function to add CSRF token to fetch options
async function fetchWithCsrf(url, options = {}) {
    const token = await getCsrfToken();
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    if (token) {
        // Flask-WTF expects the token in X-CSRFToken header (or X-CSRF-Token depending on version)
        // Try both formats to be compatible
        headers['X-CSRFToken'] = token;
        headers['X-CSRF-Token'] = token;  // Some Flask-WTF versions use this format
        console.debug('CSRF token found, adding to request headers:', token.substring(0, 20) + '...');
    } else {
        console.warn('CSRF token not found - request may fail');
        console.debug('Available cookies:', document.cookie);
        console.debug('Meta tag:', document.querySelector('meta[name="csrf-token"]'));
    }
    return fetch(url, {
        ...options,
        headers: headers,
        credentials: 'same-origin'  // Include cookies for session
    });
}

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
        
        // Apply log auto-refresh settings
        const autoRefreshLogsEl = document.getElementById('auto-refresh-logs');
        const refreshInterval = settings.logRefreshInterval ?? 10;
        
        if (autoRefreshLogsEl) {
            // Load default auto-refresh state from settings
            const defaultAutoRefresh = settings.autoRefreshLogs ?? true;
            autoRefreshLogsEl.checked = defaultAutoRefresh;
            
            // Set up auto-refresh based on checkbox state
            setupLogsAutoRefresh(defaultAutoRefresh, refreshInterval);
        }

        // Apply timezone
        if (typeof settings.timezone === 'string' && settings.timezone.trim()) {
            currentTimezone = settings.timezone.trim();
        } else {
            currentTimezone = 'UTC';
        }
    } catch (e) {
        console.error('Error loading settings:', e);
    }
}

// Setup or stop logs auto-refresh
function setupLogsAutoRefresh(enabled, intervalSeconds = 10) {
    // Clear existing interval if any
    if (logsAutoRefreshInterval !== null) {
        clearInterval(logsAutoRefreshInterval);
        logsAutoRefreshInterval = null;
    }
    
    // Start new interval if enabled
    if (enabled) {
        const intervalMs = Math.max(5000, Math.min(300000, intervalSeconds * 1000)); // Clamp between 5s and 300s
        logsAutoRefreshInterval = setInterval(loadLogs, intervalMs);
        console.log(`Logs auto-refresh enabled: every ${intervalSeconds} seconds`);
    } else {
        console.log('Logs auto-refresh disabled');
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Verify CSRF token is available
    const token = getCsrfToken();
    if (!token) {
        console.warn('CSRF token not available at page load - some features may not work');
    } else {
        console.debug('CSRF token available at page load');
    }
    
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
    const createBackupBtn = document.getElementById('create-lab-backup');
    if (createBackupBtn) {
        createBackupBtn.addEventListener('click', createLabBackup);
    }
    
    // Refresh logs button - ensure it works properly
    const refreshLogsBtn = document.getElementById('refresh-logs');
    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener('click', function(e) {
            e.preventDefault();
            loadLogs();
        });
    }
    
    // Auto-refresh logs checkbox
    const autoRefreshLogsEl = document.getElementById('auto-refresh-logs');
    if (autoRefreshLogsEl) {
        autoRefreshLogsEl.addEventListener('change', function(e) {
            const enabled = e.target.checked;
            // Get current interval from settings (or use default 10)
            fetch('/api/settings')
                .then(response => response.json())
                .then(data => {
                    const intervalSeconds = data.settings?.logRefreshInterval ?? 10;
                    setupLogsAutoRefresh(enabled, intervalSeconds);
                })
                .catch(() => {
                    // Fallback to default 10 seconds if settings fetch fails
                    setupLogsAutoRefresh(enabled, 10);
                });
        });
    }
    
    // Modal handlers
    document.getElementById('confirm-yes').addEventListener('click', () => {
        if (confirmCallback) {
            confirmCallback();
        }
        hideModal();
    });
    
    document.getElementById('confirm-no').addEventListener('click', hideModal);
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
        const response = await fetchWithCsrf('/api/diff', { method: 'POST' });
        
        // Check if response is JSON before parsing
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Server returned non-JSON response (${response.status}): ${text.substring(0, 200)}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Sanitize HTML before insertion
            const diffHtml = `
                <h3>Diff Summary</h3>
                <div class="diff-summary">
                    <div class="diff-item">
                        <div class="label">Items to Add</div>
                        <div class="value">${escapeHtml(String(data.differences.items_added || 0))}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Items to Remove</div>
                        <div class="value">${escapeHtml(String(data.differences.items_removed || 0))}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Values Changed</div>
                        <div class="value">${escapeHtml(String(data.differences.values_changed || 0))}</div>
                    </div>
                    <div class="diff-item">
                        <div class="label">Items Moved</div>
                        <div class="value">${escapeHtml(String(data.differences.items_moved || 0))}</div>
                    </div>
                </div>
                <details>
                    <summary>View Raw Diff</summary>
                    <pre class="diff-raw">${formatDiff(data.diff_json || data.raw_diff || 'No differences found')}</pre>
                </details>
            `;
            results.innerHTML = sanitizeHtml(diffHtml);
        } else {
            // Use safe DOM manipulation
            results.innerHTML = '';
            const errorP = createSafeElement('p', {style: {color: 'red'}}, `Error: ${data.error || 'Unknown error'}`);
            results.appendChild(errorP);
        }
        
        results.classList.add('show');
    } catch (error) {
        // Use safe DOM manipulation
        results.innerHTML = '';
        const errorP = createSafeElement('p', {style: {color: 'red'}}, `Error: ${error.message}`);
        results.appendChild(errorP);
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
        const response = await fetchWithCsrf('/api/sync', {
            method: 'POST',
            body: JSON.stringify({ create_backup: createBackup, commit: commit })
        });
        
        // Check if response is JSON before parsing
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            throw new Error(`Server returned non-JSON response (${response.status}): ${text.substring(0, 200)}`);
        }
        
        const data = await response.json();
        
        results.classList.add('show');
        results.classList.add(data.success ? 'success' : 'error');
        
        if (data.success) {
            // Use safe DOM manipulation
            results.innerHTML = '';
            const h3 = createSafeElement('h3', {}, '✓ Sync Completed Successfully');
            results.appendChild(h3);
            const p1 = createSafeElement('p', {}, `Sync ID: ${data.sync_id}`);
            results.appendChild(p1);
            if (data.backup_created) {
                const p2 = createSafeElement('p', {}, `Backup created: ${data.backup_path}`);
                results.appendChild(p2);
            }
            const p3 = createSafeElement('p', {}, `Commit Job ID: ${data.commit_job_id || 'N/A'}`);
            results.appendChild(p3);
            loadBackups(); // Refresh backups list
        } else {
            // Use safe DOM manipulation
            results.innerHTML = '';
            const h3 = createSafeElement('h3', {}, '✗ Sync Failed');
            results.appendChild(h3);
            const p = createSafeElement('p', {}, `Error: ${data.error || 'Unknown error'}`);
            results.appendChild(p);
        }
    } catch (error) {
        results.classList.add('show');
        results.classList.add('error');
        // Use safe DOM manipulation
        results.innerHTML = '';
        const h3 = createSafeElement('h3', {}, '✗ Sync Failed');
        results.appendChild(h3);
        const p = createSafeElement('p', {}, `Error: ${error.message}`);
        results.appendChild(p);
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
        
        // Gracefully handle missing or non-array backups
        if (!data || !Array.isArray(data.backups)) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No backups found</td></tr>';
            return;
        }

        if (data.backups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No backups found</td></tr>';
            return;
        }
        
        // Use safe DOM creation instead of innerHTML with template strings
        tbody.innerHTML = '';
        data.backups.forEach(backup => {
            const tr = document.createElement('tr');
            
            const td1 = document.createElement('td');
            td1.textContent = backup.filename;
            tr.appendChild(td1);
            
            const td2 = document.createElement('td');
            td2.textContent = formatBytes(backup.size);
            tr.appendChild(td2);
            
            const td3 = document.createElement('td');
            td3.textContent = formatTimestamp(backup.modified);
            tr.appendChild(td3);
            
            const td4 = document.createElement('td');
            
            // Download button
            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'btn btn-primary';
            downloadBtn.style.marginRight = '5px';
            downloadBtn.textContent = 'Download';
            downloadBtn.onclick = () => downloadBackup(backup.path);
            td4.appendChild(downloadBtn);
            
            // Restore button
            const restoreBtn = document.createElement('button');
            restoreBtn.className = 'btn btn-secondary';
            restoreBtn.style.marginRight = '5px';
            restoreBtn.textContent = 'Restore';
            restoreBtn.onclick = () => restoreBackup(backup.path);
            td4.appendChild(restoreBtn);
            
            // Delete button
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger';
            deleteBtn.textContent = 'Delete';
            deleteBtn.onclick = () => deleteBackup(backup.path);
            td4.appendChild(deleteBtn);
            
            tr.appendChild(td4);
            tbody.appendChild(tr);
        });
    } catch (error) {
        // Use safe DOM manipulation
        tbody.innerHTML = '';
        const tr = createSafeElement('tr');
        const td = createSafeElement('td', {colspan: '4', style: {color: 'red'}}, `Error: ${error.message}`);
        tr.appendChild(td);
        tbody.appendChild(tr);
    }
}

// Download backup
function downloadBackup(backupPath) {
    // Extract just the filename from the path for the download URL
    const filename = backupPath.split('/').pop();
    window.location.href = `/api/backups/download/${encodeURIComponent(filename)}`;
}

// Restore backup
function restoreBackup(backupPath) {
    showModal(
        'Confirm Restore Backup',
        'Are you sure you want to restore this backup? This will overwrite the current lab configuration.',
        () => executeRestore(backupPath)
    );
}

async function executeRestore(backupPath) {
    hideModal();
    
    try {
        const response = await fetchWithCsrf('/api/backups/restore', {
            method: 'POST',
            body: JSON.stringify({ backup_path: backupPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showCloseModal(
                'Success',
                'Backup restored successfully!',
                () => {
                    loadBackups(); // Refresh backups list
                }
            );
        } else {
            showCloseModal(
                'Restore Failed',
                `Restore failed: ${data.error}`
            );
        }
    } catch (error) {
        showCloseModal(
            'Error',
            `Error: ${error.message}`
        );
    }
}

// Delete backup
function deleteBackup(backupPath) {
    showModal(
        'Confirm Delete Backup',
        'Are you sure you want to delete this backup? This action cannot be undone.',
        () => executeDelete(backupPath)
    );
}

// Create Lab backup
async function createLabBackup() {
    const btn = document.getElementById('create-lab-backup');
    if (btn) {
        btn.disabled = true;
        const originalText = btn.textContent;
        btn.innerHTML = '<span class="spinner"></span>Creating...';
        try {
            const response = await fetchWithCsrf('/api/backups/create', { method: 'POST' });
            const data = await response.json();
            if (data.success) {
                showCloseModal('Success', `Backup created: ${data.filename || data.backup_path}` , () => {
                    loadBackups();
                });
            } else {
                showCloseModal('Create Backup Failed', `Error: ${data.error || 'Unknown error'}`);
            }
        } catch (error) {
            showCloseModal('Error', `Error creating backup: ${error.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = originalText || 'Create Lab Backup';
        }
    }
}

async function executeDelete(backupPath) {
    hideModal();
    
    try {
        const response = await fetchWithCsrf('/api/backups/delete', {
            method: 'POST',
            body: JSON.stringify({ backup_path: backupPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showCloseModal(
                'Success',
                data.message || 'Backup deleted successfully!',
                () => {
                    loadBackups(); // Reload the backups list to update the display
                }
            );
        } else {
            showModal(
                'Delete Failed',
                `Delete failed: ${data.error}`,
                () => hideModal()
            );
        }
    } catch (error) {
        showModal(
            'Error',
            `Error: ${error.message}`,
            () => hideModal()
        );
    }
}

// Load logs
async function loadLogs() {
    const logsDiv = document.getElementById('logs');
    
    if (!logsDiv) {
        console.error('Logs div not found');
        return;
    }
    
    try {
        const response = await fetch('/api/logs?limit=20');
        
        // Check if response is JSON before parsing
        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            // Only show error if we don't have existing logs
            if (logsDiv.children.length === 0) {
                logsDiv.innerHTML = '<p class="loading" style="color: red;">Error loading logs: Server returned non-JSON response</p>';
            }
            console.error('Non-JSON response:', response.status, text.substring(0, 200));
            return; // Don't clear existing logs on error
        }
        
        // Check for errors in response
        if (!response.ok) {
            const errorText = await response.text();
            // Only show error if we don't have existing logs
            if (logsDiv.children.length === 0) {
                try {
                    const errorData = JSON.parse(errorText);
                    logsDiv.innerHTML = `<p class="loading" style="color: red;">Error: ${errorData.error || 'Server error'}</p>`;
                } catch {
                    logsDiv.innerHTML = `<p class="loading" style="color: red;">Server error (${response.status})</p>`;
                }
            }
            console.error('Error response:', response.status, errorText);
            return; // Don't clear existing logs on error
        }
        
        const data = await response.json();
        
        // Handle case where logs might be undefined or null
        if (!data.logs || !Array.isArray(data.logs)) {
            // Only show message if there are no existing logs displayed
            // Remove any "No logs available" message if logs exist
            const noLogsMsg = logsDiv.querySelector('p.loading');
            if (noLogsMsg && logsDiv.children.length === 1) {
                // Only remove if this is the only child (the "No logs available" message)
                noLogsMsg.remove();
            }
            if (logsDiv.children.length === 0) {
                logsDiv.innerHTML = '<p class="loading">No logs available</p>';
            }
            return; // Keep existing logs visible
        }
        
        if (data.logs.length === 0) {
            // Only show "No logs available" if there are no existing logs displayed
            // Remove any existing "No logs available" message first
            const noLogsMsg = logsDiv.querySelector('p.loading');
            if (noLogsMsg && logsDiv.children.length > 1) {
                // Remove "No logs available" if there are actual log entries
                noLogsMsg.remove();
            }
            if (logsDiv.children.length === 0) {
                logsDiv.innerHTML = '<p class="loading">No logs available</p>';
            }
            return; // Keep existing logs visible
        }
        
        // Remove any "No logs available" message if we have logs to display
        const noLogsMsg = logsDiv.querySelector('p.loading');
        if (noLogsMsg) {
            noLogsMsg.remove();
        }
        
        // Rolling window: add new logs incrementally, keep newest 20, remove oldest if needed
        // Get currently displayed log timestamps to avoid duplicates
        const existingTimestamps = new Set();
        Array.from(logsDiv.children).forEach(child => {
            // Use data attribute to store ISO timestamp for reliable matching
            const isoTimestamp = child.getAttribute('data-timestamp');
            if (isoTimestamp) {
                existingTimestamps.add(isoTimestamp);
            }
        });
        
        // Sort logs by timestamp (newest first) for processing
        const sortedLogs = [...data.logs].sort((a, b) => {
            return new Date(b.timestamp) - new Date(a.timestamp);
        });
        
        // If no logs displayed yet, populate with latest 20 (oldest first for display)
        if (logsDiv.children.length === 0 && sortedLogs.length > 0) {
            const displayLogs = sortedLogs.slice(0, 20).reverse(); // Reverse to show oldest first
            
            displayLogs.forEach(log => {
                const logDiv = document.createElement('div');
                logDiv.className = 'log-entry';
                logDiv.setAttribute('data-timestamp', log.timestamp); // Store ISO timestamp for matching
                
                const timestamp = document.createElement('span');
                timestamp.className = 'log-timestamp';
                timestamp.textContent = `[${formatTimestamp(log.timestamp)}]`;
                logDiv.appendChild(timestamp);
                
                const user = document.createElement('span');
                user.className = 'log-user';
                user.textContent = log.user || 'system';
                logDiv.appendChild(user);
                
                const operation = document.createElement('span');
                operation.className = 'log-operation';
                operation.textContent = log.operation;
                logDiv.appendChild(operation);
                
                logsDiv.appendChild(logDiv);
                existingTimestamps.add(log.timestamp);
            });
        } else {
            // Add only new logs (not already displayed) - append to end
            sortedLogs.forEach(log => {
                if (!existingTimestamps.has(log.timestamp)) {
                    // This is a new log, append it to the end
                    const logDiv = document.createElement('div');
                    logDiv.className = 'log-entry';
                    logDiv.setAttribute('data-timestamp', log.timestamp); // Store ISO timestamp for matching
                    
                    const timestamp = document.createElement('span');
                    timestamp.className = 'log-timestamp';
                    timestamp.textContent = `[${formatTimestamp(log.timestamp)}]`;
                    logDiv.appendChild(timestamp);
                    
                    const user = document.createElement('span');
                    user.className = 'log-user';
                    user.textContent = log.user || 'system';
                    logDiv.appendChild(user);
                    
                    const operation = document.createElement('span');
                    operation.className = 'log-operation';
                    operation.textContent = log.operation;
                    logDiv.appendChild(operation);
                    
                    logsDiv.appendChild(logDiv);
                    existingTimestamps.add(log.timestamp);
                }
            });
            
            // Keep only the newest 20 logs - remove oldest if we exceed 20
            while (logsDiv.children.length > 20) {
                logsDiv.removeChild(logsDiv.firstChild);
            }
        }
    } catch (error) {
        // Only show error if we don't have existing logs displayed
        if (logsDiv.children.length === 0) {
            const p = createSafeElement('p', {style: {color: 'red'}}, `Error loading logs: ${error.message}`);
            logsDiv.appendChild(p);
        } else {
            // Log error to console but keep existing logs visible
            console.error('Error loading logs:', error);
        }
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

// Show an informational modal with a single Close button (no cancel)
function showCloseModal(title, message, onClose) {
    const modal = document.getElementById('confirm-modal');
    const confirmBtn = document.getElementById('confirm-yes');
    const cancelBtn = document.getElementById('confirm-no');
    const originalText = confirmBtn.textContent;
    const originalCancelDisplay = cancelBtn.style.display;

    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-message').textContent = message;

    confirmBtn.textContent = 'Close';
    cancelBtn.style.display = 'none';
    confirmCallback = () => {
        try { if (typeof onClose === 'function') onClose(); } finally {
            hideModal();
            // Restore defaults for future confirmations
            confirmBtn.textContent = originalText || 'Confirm';
            cancelBtn.style.display = originalCancelDisplay || '';
        }
    };
    modal.classList.add('show');
}

// Utility functions
function escapeHtml(text) {
    if (text === null || text === undefined) {
        return '';
    }
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function sanitizeHtml(html) {
    // Use DOMPurify if available, otherwise fall back to escapeHtml
    if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(html);
    }
    // Fallback: escape HTML
    return escapeHtml(html);
}

function setTextContent(element, text) {
    // Safely set text content without HTML parsing
    if (element) {
        element.textContent = text;
    }
}

function createSafeElement(tag, attributes = {}, textContent = '') {
    // Create DOM elements safely instead of using innerHTML
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(attributes)) {
        if (key === 'class') {
            element.className = value;
        } else if (key === 'style' && typeof value === 'object') {
            Object.assign(element.style, value);
        } else {
            element.setAttribute(key, value);
        }
    }
    if (textContent) {
        element.textContent = textContent;
    }
    return element;
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
    try {
        // Treat server timestamps without timezone as UTC
        const hasTz = typeof timestamp === 'string' && /[zZ]|[\+\-]\d{2}:?\d{2}$/.test(timestamp);
        const src = (!hasTz && typeof timestamp === 'string') ? (timestamp + 'Z') : timestamp;
        const date = new Date(src);
        return date.toLocaleString(undefined, { timeZone: currentTimezone });
    } catch (e) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }
}

