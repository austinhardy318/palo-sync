// Settings Page JavaScript

// Settings management - Using server-side file storage
async function saveSettings() {
    const settings = {
        createBackup: document.getElementById('settings-backup').checked,
        commitConfig: document.getElementById('settings-commit').checked,
        preserveHostname: document.getElementById('settings-preserve-hostname').checked
    };
    
    try {
        // Save to server via API
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ settings: settings })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Show saved indicator
            const savedIndicator = document.getElementById('settings-saved');
            savedIndicator.style.display = 'inline';
            setTimeout(() => {
                savedIndicator.style.display = 'none';
            }, 3000);
        } else {
            alert(`Failed to save settings: ${data.error}`);
        }
    } catch (error) {
        alert(`Error saving settings: ${error.message}`);
    }
}

async function loadSettings() {
    try {
        const response = await fetch('/api/settings');
        const data = await response.json();
        
        const settings = data.settings;
        document.getElementById('settings-backup').checked = settings.createBackup ?? true;
        document.getElementById('settings-commit').checked = settings.commitConfig ?? false;
        document.getElementById('settings-preserve-hostname').checked = settings.preserveHostname ?? true;
    } catch (e) {
        console.error('Error loading settings:', e);
    }
}

// Load configuration
async function loadConfiguration() {
    const configDisplay = document.getElementById('config-display');
    configDisplay.innerHTML = '<p class="loading">Loading configuration...</p>';
    
    try {
        const response = await fetch('/api/config');
        const config = await response.json();
        
        configDisplay.innerHTML = `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div class="config-block">
                    <h3>Production Panorama</h3>
                    <p><strong>Host:</strong> ${escapeHtml(config.production.host)}</p>
                    <p><strong>Username:</strong> ${escapeHtml(config.production.username || 'N/A')}</p>
                    <p><strong>Auth Method:</strong> ${escapeHtml(config.production.auth_method)}</p>
                </div>
                <div class="config-block">
                    <h3>Lab Panorama</h3>
                    <p><strong>Host:</strong> ${escapeHtml(config.lab.host)}</p>
                    <p><strong>Username:</strong> ${escapeHtml(config.lab.username || 'N/A')}</p>
                    <p><strong>Auth Method:</strong> ${escapeHtml(config.lab.auth_method)}</p>
                </div>
            </div>
            <p style="margin-top: 15px; color: #666; font-size: 0.9em;">
                ${config.gui_auth_enabled ? '✓ GUI authentication is enabled' : '⚠ GUI authentication is disabled'}
            </p>
        `;
    } catch (error) {
        configDisplay.innerHTML = `<p style="color: red;">Error loading configuration: ${error.message}</p>`;
    }
}

// Cleanup backups
async function cleanupBackups() {
    // Confirm action
    if (!confirm('Are you sure you want to delete ALL backup files? This action cannot be undone.')) {
        return;
    }
    
    // Double confirmation
    if (!confirm('This will permanently delete all backup files. Are you absolutely sure?')) {
        return;
    }
    
    const cleanupResult = document.getElementById('cleanup-result');
    cleanupResult.innerHTML = '<p class="loading">Deleting backup files...</p>';
    
    try {
        const response = await fetch('/api/backups/cleanup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (data.success) {
            cleanupResult.innerHTML = `<p style="color: green;">✓ ${data.message}</p>`;
        } else {
            cleanupResult.innerHTML = `<p style="color: red;">✗ Error: ${data.error}</p>`;
        }
    } catch (error) {
        cleanupResult.innerHTML = `<p style="color: red;">✗ Error: ${error.message}</p>`;
    }
}

// Utility function
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load saved settings
    loadSettings();
    
    // Setup event listeners
    document.getElementById('save-settings').addEventListener('click', saveSettings);
    document.getElementById('load-config').addEventListener('click', loadConfiguration);
    document.getElementById('cleanup-backups').addEventListener('click', cleanupBackups);
});
