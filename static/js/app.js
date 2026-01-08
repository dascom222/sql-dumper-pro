/**
 * Advanced SQL Dumper Pro v3.0 - Intuitive Interface
 * Clear step-by-step workflow with better UX
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
    setupEventListeners();
    showNotification('Application ready. Enter target URL and click Start Scan.', 'info');
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
 * Update step indicator
 */
function updateStep(stepNumber) {
    // Remove active class from all steps
    document.querySelectorAll('.step-indicator').forEach(el => {
        el.classList.remove('active');
    });
    // Add active class to current step
    document.getElementById(`step${stepNumber}`).classList.add('active');
}

/**
 * Start a new SQL injection scan
 */
function startScan(event) {
    event.preventDefault();

    // Validate input
    const url = document.getElementById('targetUrl').value;
    if (!url) {
        showNotification('Please enter a target URL', 'error');
        return;
    }

    // Save configuration
    saveConfig();

    // Update step
    updateStep(2);

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
        updateStep(1);
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
            showNotification('Scan started successfully', 'success');
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error'), 'error');
            updateStep(1);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error starting scan: ' + error.message, 'error');
        updateStep(1);
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

        // Update status indicators
        updateStatusIndicators(data.results);

        // Check if scan is complete
        if (data.status === 'completed' || data.status === 'failed') {
            clearInterval(scanStatusInterval);
            document.getElementById('progressBar').style.width = '100%';
            document.getElementById('progressText').textContent = '100%';

            if (data.status === 'completed' && data.results) {
                currentResults = data.results;
                displayResults(data.results);
                updateStep(3);
                showNotification('Scan completed successfully!', 'success');
            } else if (data.status === 'failed') {
                showNotification('Scan failed. Check logs for details.', 'error');
                updateStep(1);
            }
        }
    })
    .catch(error => {
        console.error('Error updating status:', error);
    });
}

/**
 * Update status indicators
 */
function updateStatusIndicators(results) {
    if (!results) return;

    // Update columns
    if (results.columns) {
        let colCount = 0;
        Object.values(results.columns).forEach(dbs => {
            Object.values(dbs).forEach(cols => {
                colCount += cols.length;
            });
        });
        document.getElementById('statusColumns').textContent = colCount > 0 ? colCount : '-';
    }

    // Update databases
    if (results.databases) {
        document.getElementById('statusDatabases').textContent = results.databases.length;
    }

    // Update tables
    if (results.tables) {
        let tableCount = 0;
        Object.values(results.tables).forEach(tables => {
            tableCount += tables.length;
        });
        document.getElementById('statusTables').textContent = tableCount;
    }

    // Update rows
    if (results.data) {
        let rowCount = 0;
        Object.values(results.data).forEach(tables => {
            Object.values(tables).forEach(rows => {
                rowCount += rows.length;
            });
        });
        document.getElementById('statusRows').textContent = rowCount;
    }
}

/**
 * Display scan results
 */
function displayResults(results) {
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('resultsPanel').style.display = 'block';

    // Show vulnerability status
    if (results.vulnerable) {
        document.getElementById('vulnStatus').style.display = 'block';
    }

    // Show database info panel
    if (results.dbms || results.current_db) {
        document.getElementById('dbInfoPanel').style.display = 'block';
        document.getElementById('dbmsInfo').textContent = results.dbms || '-';
        document.getElementById('currentDbInfo').textContent = results.current_db || '-';
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
                <span class="badge bg-success text-dark ms-2">${Object.keys(tables).length} tables</span>
            `;
            dataDiv.appendChild(dbItem);

            const childrenDiv = document.createElement('div');
            childrenDiv.id = dbId;
            childrenDiv.className = 'tree-children';

            Object.entries(tables).forEach(([table, rows], tableIndex) => {
                const tableItem = document.createElement('div');
                tableItem.className = 'tree-item ms-3';
                tableItem.style.cursor = 'pointer';
                tableItem.innerHTML = `
                    <i class="bi bi-table text-success"></i> 
                    <span onclick="displayTableData('${escapeHtml(table)}', '${escapeHtml(JSON.stringify(rows).replace(/'/g, "\\'"))}')">
                        ${escapeHtml(table)} <span class="badge bg-info text-dark">${rows.length} rows</span>
                    </span>
                `;
                childrenDiv.appendChild(tableItem);
            });

            dataDiv.appendChild(childrenDiv);
        });

        treeContainer.appendChild(dataDiv);
    } else {
        const noDataDiv = document.createElement('div');
        noDataDiv.className = 'alert alert-warning';
        noDataDiv.innerHTML = '<i class="bi bi-exclamation-triangle"></i> No data extracted. Target may not be vulnerable or requires additional configuration.';
        treeContainer.appendChild(noDataDiv);
    }

    // Errors
    if (results.errors && results.errors.length > 0) {
        const errorsDiv = document.createElement('div');
        errorsDiv.className = 'alert alert-danger mt-3';
        errorsDiv.innerHTML = '<strong>Errors:</strong><ul class="mb-0 ps-3">';
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
