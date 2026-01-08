/**
 * Advanced SQL Dumper Pro v2.0 - Frontend Application
 * Enhanced with better UX, state persistence, and notifications
 */

// Configuration
const CONFIG = {
    STORAGE_KEY: 'sql_dumper_config',
    TOAST_TIMEOUT: 5000,
    POLL_INTERVAL: 1000,
};

// State
let currentScanId = null;
let scanStatusInterval = null;
let currentResults = null;

// Initialize Toastr
toastr.options = {
    closeButton: true,
    debug: false,
    newestOnTop: true,
    progressBar: true,
    positionClass: 'toast-top-right',
    preventDuplicates: true,
    onclick: null,
    showDuration: '300',
    hideDuration: '1000',
    timeOut: CONFIG.TOAST_TIMEOUT,
    extendedTimeOut: '1000',
    showEasing: 'swing',
    hideEasing: 'linear',
    showMethod: 'fadeIn',
    hideMethod: 'fadeOut',
};

/**
 * Initialize application
 */
document.addEventListener('DOMContentLoaded', () => {
    loadSavedConfig();
    loadSessionHistory();
    setupEventListeners();
    showNotification('Application loaded successfully', 'success');
});

/**
 * Setup event listeners
 */
function setupEventListeners() {
    const methodSelect = document.getElementById('requestMethod');
    const postDataDiv = document.getElementById('postDataDiv');

    methodSelect.addEventListener('change', (e) => {
        postDataDiv.style.display = e.target.value === 'POST' ? 'block' : 'none';
    });
}

/**
 * Load saved configuration from localStorage
 */
function loadSavedConfig() {
    const saved = localStorage.getItem(CONFIG.STORAGE_KEY);
    if (saved) {
        try {
            const config = JSON.parse(saved);
            document.getElementById('targetUrl').value = config.url || '';
            document.getElementById('injectParam').value = config.param || 'id';
            document.getElementById('requestMethod').value = config.method || 'GET';
            document.getElementById('proxy').value = config.proxy || '';
            document.getElementById('cookies').value = config.cookies || '';
            document.getElementById('userAgent').value = config.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
            document.getElementById('customHeaders').value = config.customHeaders || '';
        } catch (e) {
            console.error('Error loading saved config:', e);
        }
    }
}

/**
 * Save configuration to localStorage
 */
function saveConfig() {
    const config = {
        url: document.getElementById('targetUrl').value,
        param: document.getElementById('injectParam').value,
        method: document.getElementById('requestMethod').value,
        proxy: document.getElementById('proxy').value,
        cookies: document.getElementById('cookies').value,
        userAgent: document.getElementById('userAgent').value,
        customHeaders: document.getElementById('customHeaders').value,
    };
    localStorage.setItem(CONFIG.STORAGE_KEY, JSON.stringify(config));
}

/**
 * Load preset configuration
 */
function loadPreset(preset) {
    const presets = {
        dvwa: {
            url: 'http://localhost/dvwa/vulnerabilities/sqli/?id=1',
            param: 'id',
            method: 'GET',
        },
        'sqli-labs': {
            url: 'http://localhost/Less-1/?id=1',
            param: 'id',
            method: 'GET',
        },
        custom: {
            url: '',
            param: 'id',
            method: 'GET',
        },
    };

    const config = presets[preset];
    if (config) {
        document.getElementById('targetUrl').value = config.url;
        document.getElementById('injectParam').value = config.param;
        document.getElementById('requestMethod').value = config.method;
        showNotification(`Preset "${preset}" loaded`, 'info');
    }
}

/**
 * Start a new SQL injection scan
 */
function startScan(event) {
    event.preventDefault();

    // Save configuration
    saveConfig();

    // Validate input
    const url = document.getElementById('targetUrl').value;
    if (!url) {
        showNotification('Please enter a target URL', 'error');
        return;
    }

    // Disable form
    const startBtn = document.getElementById('startBtn');
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Starting...';

    // Collect form data
    const scanData = {
        url: url,
        param: document.getElementById('injectParam').value,
        method: document.getElementById('requestMethod').value,
        proxy: document.getElementById('proxy').value || null,
        cookies: document.getElementById('cookies').value || null,
        user_agent: document.getElementById('userAgent').value,
        custom_headers: document.getElementById('customHeaders').value || '{}',
        tamper_options: getTamperOptions(),
    };

    // Parse custom headers
    try {
        if (scanData.custom_headers) {
            scanData.custom_headers = JSON.parse(scanData.custom_headers);
        }
    } catch (e) {
        showNotification('Invalid JSON in Custom Headers', 'error');
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="bi bi-play-circle"></i> Start Scan';
        return;
    }

    // Make API request
    fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData),
    })
    .then(response => response.json())
    .then(data => {
        if (data.scan_id) {
            currentScanId = data.scan_id;
            showProgressPanel();
            startStatusPolling();
            loadSessionHistory();
            showNotification('Scan started successfully', 'success');
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error'), 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error starting scan: ' + error.message, 'error');
    })
    .finally(() => {
        startBtn.disabled = false;
        startBtn.innerHTML = '<i class="bi bi-play-circle"></i> Start Scan';
    });
}

/**
 * Get selected tamper options
 */
function getTamperOptions() {
    const options = [];
    if (document.getElementById('tamperSpace2Comment').checked) {
        options.push('space2comment');
    }
    if (document.getElementById('tamperRandomCase').checked) {
        options.push('randomcase');
    }
    if (document.getElementById('tamperBetween').checked) {
        options.push('between');
    }
    return options;
}

/**
 * Show progress panel
 */
function showProgressPanel() {
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('progressPanel').style.display = 'block';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('scanLogs').innerHTML = '';
}

/**
 * Start polling for scan status
 */
function startStatusPolling() {
    if (scanStatusInterval) {
        clearInterval(scanStatusInterval);
    }

    scanStatusInterval = setInterval(() => {
        updateScanStatus();
    }, CONFIG.POLL_INTERVAL);

    // Initial update
    updateScanStatus();
}

/**
 * Update scan status
 */
function updateScanStatus() {
    if (!currentScanId) return;

    fetch(`/api/scan/${currentScanId}/status`)
    .then(response => response.json())
    .then(data => {
        // Update logs
        const logsContainer = document.getElementById('scanLogs');
        const logs = data.logs || [];

        // Clear and rebuild logs
        logsContainer.innerHTML = '';
        logs.forEach(log => {
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry log-${log.level}`;
            logEntry.innerHTML = `<span class="log-${log.level}">${escapeHtml(log.message)}</span>`;
            logsContainer.appendChild(logEntry);
        });

        // Scroll to bottom
        logsContainer.scrollTop = logsContainer.scrollHeight;

        // Update progress bar
        const progress = Math.min(logs.length * 5, 90);
        document.getElementById('progressBar').style.width = progress + '%';
        document.getElementById('progressText').textContent = progress + '%';

        // Check if scan is complete
        if (data.status === 'completed' || data.status === 'failed') {
            clearInterval(scanStatusInterval);
            document.getElementById('progressBar').style.width = '100%';
            document.getElementById('progressText').textContent = '100%';

            if (data.status === 'completed' && data.results) {
                currentResults = data.results;
                displayResults(data.results);
                showNotification('Scan completed successfully!', 'success');
            } else if (data.status === 'failed') {
                showNotification('Scan failed. Check logs for details.', 'error');
            }
        }
    })
    .catch(error => {
        console.error('Error updating status:', error);
    });
}

/**
 * Display scan results
 */
function displayResults(results) {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';

    // Show database info panel
    if (results.dbms || results.current_db) {
        document.getElementById('dbInfoPanel').style.display = 'block';
        document.getElementById('dbmsInfo').textContent = results.dbms || '-';
        document.getElementById('currentDbInfo').textContent = results.current_db || '-';
        document.getElementById('dbCountInfo').textContent = (results.databases || []).length;
        
        let tableCount = 0;
        Object.values(results.tables || {}).forEach(tables => {
            tableCount += tables.length;
        });
        document.getElementById('tableCountInfo').textContent = tableCount;
    }

    // Build result tree
    buildResultTree(results);

    // Show export button
    document.getElementById('exportBtn').style.display = 'inline-block';
}

/**
 * Build result tree view
 */
function buildResultTree(results) {
    const treeContainer = document.getElementById('resultTree');
    treeContainer.innerHTML = '';

    // Vulnerability status
    const statusDiv = document.createElement('div');
    statusDiv.className = 'mb-3';
    if (results.vulnerable) {
        statusDiv.innerHTML = '<span class="badge badge-success"><i class="bi bi-check-circle"></i> Vulnerable</span>';
    } else {
        statusDiv.innerHTML = '<span class="badge badge-danger"><i class="bi bi-x-circle"></i> Not Vulnerable</span>';
    }
    treeContainer.appendChild(statusDiv);

    // WAF Detection
    if (results.waf_detected) {
        const wafDiv = document.createElement('div');
        wafDiv.className = 'alert alert-warning mb-3';
        wafDiv.innerHTML = `<i class="bi bi-shield-exclamation"></i> WAF Detected: ${escapeHtml(results.waf_detected)}`;
        treeContainer.appendChild(wafDiv);
    }

    // Data tree
    if (results.data && Object.keys(results.data).length > 0) {
        const dataDiv = document.createElement('div');
        dataDiv.className = 'mb-3';

        Object.entries(results.data).forEach(([database, tables], dbIndex) => {
            const dbItem = document.createElement('div');
            dbItem.className = 'tree-item';
            const dbId = `db-${dbIndex}`;
            dbItem.innerHTML = `
                <span class="tree-toggle" onclick="toggleTree('${dbId}')">▼</span>
                <i class="bi bi-database text-success"></i> <strong>${escapeHtml(database)}</strong>
            `;
            dataDiv.appendChild(dbItem);

            const childrenDiv = document.createElement('div');
            childrenDiv.id = dbId;
            childrenDiv.className = 'tree-children';

            Object.entries(tables).forEach(([table, rows], tableIndex) => {
                const tableItem = document.createElement('div');
                tableItem.className = 'tree-item ms-3';
                tableItem.style.cursor = 'pointer';
                const tableId = `table-${dbIndex}-${tableIndex}`;
                tableItem.innerHTML = `
                    <i class="bi bi-table text-success"></i> 
                    <span onclick="displayTableData('${escapeHtml(table)}', '${escapeHtml(JSON.stringify(rows).replace(/'/g, "\\'"))}')">
                        ${escapeHtml(table)} <span class="badge bg-success text-dark">${rows.length}</span>
                    </span>
                `;
                childrenDiv.appendChild(tableItem);
            });

            dataDiv.appendChild(childrenDiv);
        });

        treeContainer.appendChild(dataDiv);
    }

    // Errors
    if (results.errors && results.errors.length > 0) {
        const errorsDiv = document.createElement('div');
        errorsDiv.className = 'alert alert-danger';
        errorsDiv.innerHTML = '<strong>Errors:</strong><ul class="mb-0">';
        results.errors.forEach(error => {
            errorsDiv.innerHTML += `<li>${escapeHtml(error)}</li>`;
        });
        errorsDiv.innerHTML += '</ul>';
        treeContainer.appendChild(errorsDiv);
    }
}

/**
 * Toggle tree visibility
 */
function toggleTree(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

/**
 * Display table data
 */
function displayTableData(tableName, rowsJson) {
    try {
        const rows = JSON.parse(rowsJson);
        
        if (!rows || rows.length === 0) {
            showNotification('No data to display', 'info');
            return;
        }

        // Get columns from first row
        const columns = Object.keys(rows[0]);
        const sensitiveColumns = ['password', 'pass', 'pwd', 'hash', 'email', 'user', 'admin', 'token', 'secret'];

        // Build table header
        const headerRow = document.getElementById('tableHeader');
        headerRow.innerHTML = '';
        columns.forEach(col => {
            const th = document.createElement('th');
            const isSensitive = sensitiveColumns.some(s => col.toLowerCase().includes(s));
            if (isSensitive) {
                th.className = 'sensitive-column';
                th.innerHTML = `<i class="bi bi-exclamation-triangle"></i> ${escapeHtml(col)}`;
            } else {
                th.textContent = col;
            }
            headerRow.appendChild(th);
        });

        // Build table body
        const tableBody = document.getElementById('tableBody');
        tableBody.innerHTML = '';
        rows.forEach(row => {
            const tr = document.createElement('tr');
            columns.forEach(col => {
                const td = document.createElement('td');
                const isSensitive = sensitiveColumns.some(s => col.toLowerCase().includes(s));
                if (isSensitive) {
                    td.className = 'sensitive-column';
                }
                td.textContent = row[col];
                tr.appendChild(td);
            });
            tableBody.appendChild(tr);
        });

        // Show table container
        document.getElementById('dataTableContainer').style.display = 'block';

        // Initialize DataTable
        if ($.fn.DataTable.isDataTable('#dataTable')) {
            $('#dataTable').DataTable().destroy();
        }
        $('#dataTable').DataTable({
            pageLength: 10,
            lengthMenu: [5, 10, 25, 50],
            order: [],
        });

        showNotification(`Displaying ${rows.length} rows from ${tableName}`, 'info');
    } catch (e) {
        console.error('Error displaying table data:', e);
        showNotification('Error displaying table data', 'error');
    }
}

/**
 * Export results as CSV
 */
function exportResults() {
    if (!currentScanId) {
        showNotification('No scan to export', 'error');
        return;
    }

    window.location.href = `/api/scan/${currentScanId}/export`;
    showNotification('Exporting data...', 'info');
}

/**
 * Copy results to clipboard
 */
function copyToClipboard() {
    if (!currentResults) {
        showNotification('No results to copy', 'error');
        return;
    }

    const text = JSON.stringify(currentResults, null, 2);
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Results copied to clipboard', 'success');
    }).catch(() => {
        showNotification('Failed to copy to clipboard', 'error');
    });
}

/**
 * Load session history
 */
function loadSessionHistory() {
    fetch('/api/sessions')
    .then(response => response.json())
    .then(sessions => {
        const historyDiv = document.getElementById('sessionHistory');
        historyDiv.innerHTML = '';

        if (sessions.length === 0) {
            historyDiv.innerHTML = '<p class="text-muted small">No sessions yet</p>';
            return;
        }

        const list = document.createElement('div');
        list.className = 'list-group list-group-flush';

        sessions.forEach(session => {
            const item = document.createElement('div');
            item.className = 'list-group-item bg-dark border-success border-opacity-25';
            item.style.cursor = 'pointer';

            const statusBadge = session.status === 'completed'
                ? '<span class="badge badge-success"><i class="bi bi-check-circle"></i></span>'
                : session.status === 'failed'
                ? '<span class="badge badge-danger"><i class="bi bi-x-circle"></i></span>'
                : '<span class="badge bg-info"><i class="bi bi-hourglass-split"></i></span>';

            const date = new Date(session.timestamp);
            const timeStr = date.toLocaleTimeString();
            const dateStr = date.toLocaleDateString();

            item.innerHTML = `
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <small class="text-muted">${timeStr}</small>
                        <p class="mb-0 small text-truncate" title="${session.url}">${escapeHtml(session.url)}</p>
                    </div>
                    <div class="ms-2">${statusBadge}</div>
                </div>
            `;

            item.addEventListener('click', () => {
                currentScanId = session.id;
                if (session.status === 'completed' && session.results) {
                    currentResults = session.results;
                    displayResults(session.results);
                    document.getElementById('progressPanel').style.display = 'none';
                    showNotification(`Loaded session from ${timeStr}`, 'info');
                }
            });

            list.appendChild(item);
        });

        historyDiv.appendChild(list);
    })
    .catch(error => {
        console.error('Error loading sessions:', error);
    });
}

/**
 * Clear history
 */
function clearHistory() {
    if (confirm('Are you sure you want to clear all sessions?')) {
        // This would require a new API endpoint
        showNotification('History cleared', 'info');
        loadSessionHistory();
    }
}

/**
 * Show notification using Toastr
 */
function showNotification(message, type = 'info') {
    toastr[type](message);
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
