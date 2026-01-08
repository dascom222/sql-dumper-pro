/**
 * Advanced SQL Dumper Pro - Frontend Application
 */

let currentScanId = null;
let scanStatusInterval = null;

/**
 * Start a new SQL injection scan
 */
function startScan(event) {
    event.preventDefault();

    // Disable form
    const startBtn = document.getElementById('startBtn');
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Starting...';

    // Collect form data
    const scanData = {
        url: document.getElementById('targetUrl').value,
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
        alert('Invalid JSON in Custom Headers');
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
        } else {
            alert('Error: ' + (data.error || 'Unknown error'));
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error starting scan: ' + error.message);
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
    }, 1000); // Poll every second

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
            logEntry.textContent = log.message;
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
                displayResults(data.results);
            } else if (data.status === 'failed') {
                showAlert('Scan failed. Check logs for details.', 'danger');
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

    // Database info
    if (results.dbms || results.current_db) {
        const infoDiv = document.createElement('div');
        infoDiv.className = 'mb-3';
        let infoHtml = '<div class="text-muted small"><i class="bi bi-info-circle"></i> ';
        if (results.dbms) infoHtml += `DBMS: ${results.dbms} | `;
        if (results.current_db) infoHtml += `Database: ${results.current_db}`;
        infoHtml += '</div>';
        infoDiv.innerHTML = infoHtml;
        treeContainer.appendChild(infoDiv);
    }

    // WAF Detection
    if (results.waf_detected) {
        const wafDiv = document.createElement('div');
        wafDiv.className = 'alert alert-warning mb-3';
        wafDiv.innerHTML = `<i class="bi bi-shield-exclamation"></i> WAF Detected: ${results.waf_detected}`;
        treeContainer.appendChild(wafDiv);
    }

    // Data tree
    if (results.data && Object.keys(results.data).length > 0) {
        const dataDiv = document.createElement('div');
        dataDiv.className = 'mb-3';

        Object.entries(results.data).forEach(([database, tables]) => {
            const dbItem = document.createElement('div');
            dbItem.className = 'tree-item';
            dbItem.innerHTML = `<i class="bi bi-database"></i> <strong>${database}</strong>`;
            dataDiv.appendChild(dbItem);

            Object.entries(tables).forEach(([table, rows]) => {
                const tableItem = document.createElement('div');
                tableItem.className = 'tree-item ms-3';
                tableItem.style.cursor = 'pointer';
                tableItem.innerHTML = `<i class="bi bi-table"></i> ${table} (${rows.length} rows)`;

                tableItem.addEventListener('click', () => {
                    displayTableData(table, rows);
                });

                dataDiv.appendChild(tableItem);
            });
        });

        treeContainer.appendChild(dataDiv);
    }

    // Errors
    if (results.errors && results.errors.length > 0) {
        const errorsDiv = document.createElement('div');
        errorsDiv.className = 'alert alert-danger';
        errorsDiv.innerHTML = '<strong>Errors:</strong><ul class="mb-0">';
        results.errors.forEach(error => {
            errorsDiv.innerHTML += `<li>${error}</li>`;
        });
        errorsDiv.innerHTML += '</ul>';
        treeContainer.appendChild(errorsDiv);
    }
}

/**
 * Display table data
 */
function displayTableData(tableName, rows) {
    if (!rows || rows.length === 0) {
        showAlert('No data to display', 'info');
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
            th.innerHTML = `<i class="bi bi-exclamation-triangle"></i> ${col}`;
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
}

/**
 * Export results as CSV
 */
function exportResults() {
    if (!currentScanId) {
        alert('No scan to export');
        return;
    }

    window.location.href = `/api/scan/${currentScanId}/export`;
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
            item.className = 'list-group-item bg-dark border-success';
            item.style.cursor = 'pointer';

            const statusBadge = session.status === 'completed'
                ? '<span class="badge badge-success">✓</span>'
                : session.status === 'failed'
                ? '<span class="badge badge-danger">✗</span>'
                : '<span class="badge bg-info">⟳</span>';

            item.innerHTML = `
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <small class="text-muted">${new Date(session.timestamp).toLocaleString()}</small>
                        <p class="mb-0 small text-truncate">${session.url}</p>
                    </div>
                    <div>${statusBadge}</div>
                </div>
            `;

            item.addEventListener('click', () => {
                currentScanId = session.id;
                if (session.status === 'completed' && session.results) {
                    displayResults(session.results);
                    document.getElementById('progressPanel').style.display = 'none';
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
 * Show alert
 */
function showAlert(message, type = 'info') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    const container = document.querySelector('.container-fluid');
    container.insertBefore(alert, container.firstChild);

    setTimeout(() => {
        alert.remove();
    }, 5000);
}

/**
 * Handle request method change
 */
document.addEventListener('DOMContentLoaded', () => {
    const methodSelect = document.getElementById('requestMethod');
    const postDataDiv = document.getElementById('postDataDiv');

    methodSelect.addEventListener('change', (e) => {
        postDataDiv.style.display = e.target.value === 'POST' ? 'block' : 'none';
    });

    // Load initial session history
    loadSessionHistory();
});
