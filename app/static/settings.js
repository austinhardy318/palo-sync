// Settings Page JavaScript

let confirmCallback = null;

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

// Get CSRF token from cookie (Flask-WTF sets it in a cookie)
function getCsrfToken() {
    // Try to get from cookie first
    const name = 'csrf_token';
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [key, value] = cookie.trim().split('=');
        if (key === name) {
            return decodeURIComponent(value);
        }
    }
    
    // If not in cookie, try to get from meta tag (if present)
    const metaToken = document.querySelector('meta[name="csrf-token"]');
    if (metaToken) {
        return metaToken.getAttribute('content');
    }
    
    return null;
}

// Helper function to add CSRF token to fetch options
function fetchWithCsrf(url, options = {}) {
    const token = getCsrfToken();
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    if (token) {
        headers['X-CSRFToken'] = token;
    }
    return fetch(url, {
        ...options,
        headers: headers,
        credentials: 'same-origin'
    });
}

// Settings management - Using server-side file storage
async function saveSettings() {
    const logRefreshInterval = parseInt(document.getElementById('settings-log-refresh-interval').value) || 10;
    const validatedInterval = Math.max(5, Math.min(300, logRefreshInterval)); // Clamp between 5 and 300
    
    const settings = {
        createBackup: document.getElementById('settings-backup').checked,
        commitConfig: document.getElementById('settings-commit').checked,
        preserveHostname: document.getElementById('settings-preserve-hostname').checked,
        autoRefreshLogs: document.getElementById('settings-auto-refresh-logs').checked,
        logRefreshInterval: validatedInterval
    };
    
    try {
        // Save to server via API
        const response = await fetchWithCsrf('/api/settings', {
            method: 'POST',
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
            showModal(
                'Error Saving Settings',
                `Failed to save settings: ${data.error}`,
                () => hideModal()
            );
        }
    } catch (error) {
        showModal(
            'Error',
            `Error saving settings: ${error.message}`,
            () => hideModal()
        );
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
        
        // Load log auto-refresh settings
        const autoRefreshEl = document.getElementById('settings-auto-refresh-logs');
        const intervalEl = document.getElementById('settings-log-refresh-interval');
        if (autoRefreshEl) {
            autoRefreshEl.checked = settings.autoRefreshLogs ?? true;
        }
        if (intervalEl) {
            intervalEl.value = settings.logRefreshInterval ?? 10;
        }
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
        
        // Use safe DOM creation
        configDisplay.innerHTML = '';
        const container = document.createElement('div');
        container.style.display = 'grid';
        container.style.gridTemplateColumns = '1fr 1fr';
        container.style.gap = '20px';
        
        // Production block
        const prodBlock = document.createElement('div');
        prodBlock.className = 'config-block';
        const prodH3 = createSafeElement('h3', {}, 'Production Panorama');
        prodBlock.appendChild(prodH3);
        prodBlock.appendChild(createSafeElement('p', {}, `Host: ${config.production.host}`));
        prodBlock.appendChild(createSafeElement('p', {}, `Username: ${config.production.username || 'N/A'}`));
        prodBlock.appendChild(createSafeElement('p', {}, `Auth Method: ${config.production.auth_method}`));
        container.appendChild(prodBlock);
        
        // Lab block
        const labBlock = document.createElement('div');
        labBlock.className = 'config-block';
        const labH3 = createSafeElement('h3', {}, 'Lab Panorama');
        labBlock.appendChild(labH3);
        labBlock.appendChild(createSafeElement('p', {}, `Host: ${config.lab.host}`));
        labBlock.appendChild(createSafeElement('p', {}, `Username: ${config.lab.username || 'N/A'}`));
        labBlock.appendChild(createSafeElement('p', {}, `Auth Method: ${config.lab.auth_method}`));
        container.appendChild(labBlock);
        
        configDisplay.appendChild(container);
        
        const statusP = createSafeElement('p', {
            style: {marginTop: '15px', color: '#666', fontSize: '0.9em'}
        }, config.gui_auth_enabled ? '✓ GUI authentication is enabled' : '⚠ GUI authentication is disabled');
        configDisplay.appendChild(statusP);
    } catch (error) {
        // Use safe DOM manipulation
        configDisplay.innerHTML = '';
        const p = createSafeElement('p', {style: {color: 'red'}}, `Error loading configuration: ${error.message}`);
        configDisplay.appendChild(p);
    }
}

// Cleanup backups - first confirmation
function confirmCleanup() {
    showModal(
        'Confirm Delete All Backups',
        'Are you sure you want to delete ALL backup files? This action cannot be undone.',
        () => confirmCleanupFinal()
    );
}

// Cleanup backups - second confirmation
function confirmCleanupFinal() {
    hideModal();
    showModal(
        'Final Confirmation',
        'This will permanently delete all backup files. Are you absolutely sure?',
        () => executeCleanup()
    );
}

// Execute cleanup after confirmations
async function executeCleanup() {
    hideModal();
    
    const cleanupResult = document.getElementById('cleanup-result');
    cleanupResult.innerHTML = '<p class="loading">Deleting backup files...</p>';
    
    try {
        const response = await fetchWithCsrf('/api/backups/cleanup', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Use safe DOM manipulation
            cleanupResult.innerHTML = '';
            const p = createSafeElement('p', {style: {color: 'green'}}, `✓ ${data.message}`);
            cleanupResult.appendChild(p);
        } else {
            // Use safe DOM manipulation
            cleanupResult.innerHTML = '';
            const p = createSafeElement('p', {style: {color: 'red'}}, `✗ Error: ${data.error}`);
            cleanupResult.appendChild(p);
        }
    } catch (error) {
        // Use safe DOM manipulation
        cleanupResult.innerHTML = '';
        const p = createSafeElement('p', {style: {color: 'red'}}, `✗ Error: ${error.message}`);
        cleanupResult.appendChild(p);
    }
}

// Utility function
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

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load saved settings
    loadSettings();
    
    // Setup event listeners
    document.getElementById('save-settings').addEventListener('click', saveSettings);
    document.getElementById('load-config').addEventListener('click', loadConfiguration);
    document.getElementById('cleanup-backups').addEventListener('click', confirmCleanup);
    
    // Modal handlers
    document.getElementById('confirm-yes').addEventListener('click', () => {
        if (confirmCallback) {
            confirmCallback();
        }
    });
    
    document.getElementById('confirm-no').addEventListener('click', hideModal);
});
