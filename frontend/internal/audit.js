// NPL DocSeal: Audit Dashboard (Tab 3)
// Handles sub-tab switching, 3s polling while the Audit tab is visible,
// and all Chart.js rendering for the 4 audit sub-panels.

window._auditCharts = window._auditCharts || {};
let auditPollInterval = null;

if (typeof Chart !== 'undefined') {
    Chart.defaults.font.family = "'Inter', -apple-system, sans-serif";
    Chart.defaults.color = '#6B6862';
    Chart.defaults.borderColor = '#E8E3D8';
}

// Single navy accent (as tints for multi-series charts), plus the two
// reserved status hues (success/danger) for pass-fail / intact-tampered
// signals only. No other colours appear in any chart.
const AUDIT_PALETTE = {
    navy: '#1E3A5F',
    navyLight: '#3A5A80',
    navyLighter: '#6B84A0',
    navyLightest: '#9FB0C2',
    success: '#3D6B4F',
    danger: '#A34438',
    textSecondary: '#6B6862',
    textMuted: '#8A8680',
    gridLine: '#E8E3D8',
};

// ── Sub-tab switching ─────────────────────────────────────────────

function switchAuditPanel(panelName) {
    document.querySelectorAll('.audit-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.panel === panelName);
    });
    document.querySelectorAll('.audit-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    const target = document.getElementById(`audit-panel-${panelName}`);
    if (target) target.classList.add('active');

    renderActiveAuditPanel();
}

function renderActiveAuditPanel() {
    const activePanel = document.querySelector('.audit-panel.active');
    if (!activePanel) return;
    const panelName = activePanel.id.replace('audit-panel-', '');

    if (panelName === 'performance') renderPerformancePanel();
    else if (panelName === 'validation') renderValidationPanel();
    else if (panelName === 'coverage') renderCoveragePanel();
    else if (panelName === 'blockchain') renderBlockchainPanel();
}

// ── Polling ────────────────────────────────────────────────────────

function startAuditPolling() {
    fetchAndRenderAllPanels();
    if (auditPollInterval) clearInterval(auditPollInterval);
    auditPollInterval = setInterval(fetchAndRenderAllPanels, 3000);
}

function stopAuditPolling() {
    if (auditPollInterval) {
        clearInterval(auditPollInterval);
        auditPollInterval = null;
    }
}

function fetchAndRenderAllPanels() {
    // Only re-render whichever sub-panel is currently visible.
    renderActiveAuditPanel();
}

// ── Fetch + chart helpers ────────────────────────────────────────────

async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Request failed (${res.status}): ${url}`);
    return res.json();
}

function renderChart(canvasId, config) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    if (window._auditCharts[canvasId]) {
        window._auditCharts[canvasId].destroy();
    }
    window._auditCharts[canvasId] = new Chart(canvas, config);
}

function formatTimestamp(iso) {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleString();
    } catch (e) {
        return iso;
    }
}

function fmtMs(v) {
    return (v === null || v === undefined) ? '—' : `${Number(v).toFixed(1)} ms`;
}

function fmtPct(v) {
    return (v === null || v === undefined) ? '—' : `${Number(v).toFixed(1)}%`;
}

// Shared toggle: clicking either Avg Seal Time or Avg Verify Time flips
// both between milliseconds and seconds, since they're rendered by the
// same function off the same state.
let _showDurationInSeconds = false;
let _lastPerfSummary = null;

function fmtDuration(v) {
    if (v === null || v === undefined) return '—';
    const num = Number(v);
    return _showDurationInSeconds ? `${(num / 1000).toFixed(2)} s` : `${num.toFixed(1)} ms`;
}

function toggleDurationUnit() {
    _showDurationInSeconds = !_showDurationInSeconds;
    if (_lastPerfSummary) renderPerfSummaryCards(_lastPerfSummary);
}

// ── Panel 1: Performance Metrics ─────────────────────────────────────

async function renderPerformancePanel() {
    try {
        const summary = await fetchJSON('/api/audit/summary');
        renderPerfSummaryCards(summary);
        renderSignVsVerifyChart(summary);
    } catch (e) {
        console.error('[audit] summary fetch failed', e);
    }

    try {
        const series = await fetchJSON('/api/audit/duration-series?type=seal&limit=50');
        renderDurationBreakdownChart(series);
    } catch (e) {
        console.error('[audit] duration series fetch failed', e);
    }

    try {
        const ops = await fetchJSON('/api/audit/operations?limit=200');
        renderFilesizeVsTimeChart(ops);
    } catch (e) {
        console.error('[audit] operations fetch failed', e);
    }
}

function renderPerfSummaryCards(summary) {
    const container = document.getElementById('perf-summary-cards');
    if (!container) return;
    _lastPerfSummary = summary;
    const unitHint = _showDurationInSeconds ? 'Click to show ms' : 'Click to show seconds';
    container.innerHTML = `
        <div class="metric-card">
            <span class="metric-label">Total Operations</span>
            <span class="metric-value">${summary.total_operations ?? 0}</span>
        </div>
        <div class="metric-card">
            <span class="metric-label">Avg Seal Time</span>
            <span class="metric-value metric-value-toggle" onclick="toggleDurationUnit()" title="${unitHint}">${fmtDuration(summary.avg_seal_duration_ms)}</span>
        </div>
        <div class="metric-card">
            <span class="metric-label">Avg Verify Time</span>
            <span class="metric-value metric-value-toggle" onclick="toggleDurationUnit()" title="${unitHint}">${fmtDuration(summary.avg_verify_duration_ms)}</span>
        </div>
        <div class="metric-card">
            <span class="metric-label">Pass Rate</span>
            <span class="metric-value">${fmtPct(summary.pass_rate_percent)}</span>
        </div>
    `;
}

function renderDurationBreakdownChart(series) {
    const labels = series.map((op, i) => op.filename || `#${i + 1}`);
    const seg = (key) => series.map(op => op[key] || 0);

    renderChart('chart-duration-breakdown', {
        type: 'bar',
        data: {
            labels,
            datasets: [
                { label: 'Parse', data: seg('parse_duration_ms'), backgroundColor: AUDIT_PALETTE.navy },
                { label: 'Merkle', data: seg('merkle_duration_ms'), backgroundColor: AUDIT_PALETTE.navyLight },
                { label: 'Sign', data: seg('sign_duration_ms'), backgroundColor: AUDIT_PALETTE.navyLighter },
                { label: 'Encrypt', data: seg('encrypt_duration_ms'), backgroundColor: AUDIT_PALETTE.navyLightest },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: true, ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
                y: { stacked: true, ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
            },
            plugins: { legend: { labels: { color: AUDIT_PALETTE.textSecondary } } },
        },
    });
}

function renderFilesizeVsTimeChart(ops) {
    const points = ops
        .filter(op => op.file_size_bytes != null && op.total_duration_ms != null)
        .map(op => ({ x: op.file_size_bytes, y: op.total_duration_ms }));

    renderChart('chart-filesize-vs-time', {
        type: 'scatter',
        data: {
            datasets: [{ label: 'Operations', data: points, backgroundColor: AUDIT_PALETTE.navy }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { title: { display: true, text: 'File size (bytes)', color: AUDIT_PALETTE.textMuted }, ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
                y: { title: { display: true, text: 'Total duration (ms)', color: AUDIT_PALETTE.textMuted }, ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
            },
            plugins: { legend: { labels: { color: AUDIT_PALETTE.textSecondary } } },
        },
    });
}

function renderSignVsVerifyChart(summary) {
    renderChart('chart-sign-vs-verify', {
        type: 'bar',
        data: {
            labels: ['Avg Seal Time', 'Avg Verify Time'],
            datasets: [{
                label: 'Avg duration (ms)',
                data: [summary.avg_seal_duration_ms || 0, summary.avg_verify_duration_ms || 0],
                backgroundColor: [AUDIT_PALETTE.navy, AUDIT_PALETTE.navyLight],
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { display: false } },
                y: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
            },
            plugins: { legend: { display: false } },
        },
    });
}

// ── Panel 2: Validation & Tamper Stats ───────────────────────────────

async function renderValidationPanel() {
    try {
        const summary = await fetchJSON('/api/audit/summary');
        renderFieldStatusDonut(summary);
    } catch (e) {
        console.error('[audit] summary fetch failed', e);
    }

    try {
        const tampers = await fetchJSON('/api/audit/field-tampers');
        renderTamperFrequencyChart(tampers);
    } catch (e) {
        console.error('[audit] field-tampers fetch failed', e);
    }

    try {
        const ops = await fetchJSON('/api/audit/operations?limit=200');
        renderValidationLogTable(ops);
    } catch (e) {
        console.error('[audit] operations fetch failed', e);
    }
}

function renderFieldStatusDonut(summary) {
    const intact = summary.total_intact || 0;
    const tampered = summary.total_tampered || 0;

    renderChart('chart-field-status-donut', {
        type: 'doughnut',
        data: {
            labels: ['Intact', 'Tampered'],
            datasets: [{ data: [intact, tampered], backgroundColor: [AUDIT_PALETTE.success, AUDIT_PALETTE.danger] }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: AUDIT_PALETTE.textSecondary } } },
        },
    });
}

function renderTamperFrequencyChart(tampers) {
    const entries = Object.entries(tampers || {}).sort((a, b) => b[1] - a[1]);

    renderChart('chart-tamper-frequency', {
        type: 'bar',
        data: {
            labels: entries.map(e => e[0]),
            datasets: [{ label: 'Tamper count', data: entries.map(e => e[1]), backgroundColor: AUDIT_PALETTE.danger }],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
                y: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
            },
            plugins: { legend: { display: false } },
        },
    });
}

function renderValidationLogTable(ops) {
    const table = document.getElementById('validation-log-table');
    if (!table) return;

    const rows = ops.map(op => `
        <tr>
            <td class="text-monospace">${formatTimestamp(op.timestamp)}</td>
            <td>${op.filename || '—'}</td>
            <td>${op.test_scenario || '—'}</td>
            <td>${op.field_count ?? '—'}</td>
            <td>${op.intact_count ?? '—'} / ${op.tampered_count ?? '—'}</td>
            <td><span class="badge badge-${op.overall_status === 'PASS' ? 'success' : 'danger'}">${op.overall_status}</span></td>
        </tr>
    `).join('');

    table.innerHTML = `
        <thead>
            <tr><th>Timestamp</th><th>Filename</th><th>Scenario</th><th>Fields</th><th>Intact/Tampered</th><th>Status</th></tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="6" class="text-muted" style="text-align:center;">No records yet.</td></tr>'}</tbody>
    `;
}

// ── Panel 3: Test Coverage Matrix ────────────────────────────────────

async function renderCoveragePanel() {
    try {
        const matrix = await fetchJSON('/api/audit/coverage-matrix');
        renderCoverageMatrixGrid(matrix);
    } catch (e) {
        console.error('[audit] coverage matrix fetch failed', e);
    }
}

function renderCoverageMatrixGrid(matrix) {
    const container = document.getElementById('coverage-matrix-grid');
    if (!container) return;
    container.innerHTML = '';

    if (!matrix || matrix.length === 0) {
        container.innerHTML = '<p class="text-muted">No test data logged yet.</p>';
        return;
    }

    const fileFormats = [...new Set(matrix.map(r => r.file_format))].sort();
    const scenarios = [...new Set(matrix.map(r => r.test_scenario))].sort();
    const lookup = {};
    matrix.forEach(r => { lookup[`${r.file_format}::${r.test_scenario}`] = r; });

    const gridCols = `160px repeat(${scenarios.length}, minmax(140px, 1fr))`;

    const headerRow = document.createElement('div');
    headerRow.className = 'matrix-row';
    headerRow.style.gridTemplateColumns = gridCols;
    headerRow.innerHTML = `<div class="coverage-matrix-header" style="text-align:left;">File Format</div>` +
        scenarios.map(s => `<div class="coverage-matrix-header">${s}</div>`).join('');
    container.appendChild(headerRow);

    fileFormats.forEach(fmt => {
        const row = document.createElement('div');
        row.className = 'matrix-row';
        row.style.gridTemplateColumns = gridCols;

        let cellsHtml = `<div class="coverage-matrix-rowlabel">${fmt}</div>`;
        scenarios.forEach(scenario => {
            const cell = lookup[`${fmt}::${scenario}`];
            if (!cell || (cell.pass_count === 0 && cell.fail_count === 0)) {
                cellsHtml += `<div class="coverage-matrix-cell coverage-cell-empty">not tested</div>`;
            } else if (cell.fail_count > 0 && cell.pass_count > 0) {
                cellsHtml += `<div class="coverage-matrix-cell coverage-cell-mixed"><span class="count-pass">${cell.pass_count} pass</span> / <span class="count-fail">${cell.fail_count} fail</span></div>`;
            } else {
                const cls = cell.fail_count > 0 ? 'coverage-cell-fail' : 'coverage-cell-pass';
                cellsHtml += `<div class="coverage-matrix-cell ${cls}">${cell.pass_count} pass / ${cell.fail_count} fail</div>`;
            }
        });
        row.innerHTML = cellsHtml;
        container.appendChild(row);
    });
}

// ── Panel 4: Blockchain Anchor Log ───────────────────────────────────

async function renderBlockchainPanel() {
    try {
        const ops = await fetchJSON('/api/audit/operations?limit=200');
        const anchored = ops.filter(op => op.tx_hash);
        renderConfirmationTimesChart(anchored);
        renderBlockchainLogTable(anchored);
    } catch (e) {
        console.error('[audit] operations fetch failed', e);
    }
}

function renderConfirmationTimesChart(anchored) {
    const chronological = [...anchored].reverse(); // API returns newest-first

    renderChart('chart-confirmation-times', {
        type: 'line',
        data: {
            labels: chronological.map((op, i) => `#${i + 1}`),
            datasets: [{
                label: 'Confirmation time (ms)',
                data: chronological.map(op => op.confirmation_time_ms),
                borderColor: AUDIT_PALETTE.navy,
                backgroundColor: 'transparent',
                tension: 0.3,
                spanGaps: true,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
                y: { ticks: { color: AUDIT_PALETTE.textMuted }, grid: { color: AUDIT_PALETTE.gridLine } },
            },
            plugins: { legend: { labels: { color: AUDIT_PALETTE.textSecondary } } },
        },
    });
}

function renderBlockchainLogTable(anchored) {
    const table = document.getElementById('blockchain-log-table');
    if (!table) return;

    const rows = anchored.map(op => {
        const shortTx = op.tx_hash ? `${op.tx_hash.slice(0, 10)}...${op.tx_hash.slice(-6)}` : '—';
        const txCell = op.etherscan_url
            ? `<a href="${op.etherscan_url}" target="_blank" rel="noopener" class="text-cyan">${shortTx}</a>`
            : shortTx;
        return `
        <tr>
            <td class="text-monospace">${formatTimestamp(op.timestamp)}</td>
            <td>${op.filename || '—'}</td>
            <td class="text-monospace">${txCell}</td>
            <td>${op.block_number ?? 'pending'}</td>
            <td>${op.confirmation_time_ms ? Number(op.confirmation_time_ms).toFixed(0) + ' ms' : '—'}</td>
        </tr>`;
    }).join('');

    table.innerHTML = `
        <thead>
            <tr><th>Timestamp</th><th>Filename</th><th>TX Hash</th><th>Block</th><th>Confirmation Time</th></tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="5" class="text-muted" style="text-align:center;">No blockchain-anchored operations yet.</td></tr>'}</tbody>
    `;
}

// ── Clear audit log (overrides the legacy localStorage-only handler) ─

function clearAudit() {
    if (!confirm('Are you sure you want to clear all audit log data? This cannot be undone.')) return;

    fetch('/api/audit/clear?confirm=true', { method: 'POST', headers: dashboardAuthHeaders() })
        .then(res => {
            if (!res.ok) throw new Error('Server rejected clear request');
            return res.json();
        })
        .then(() => {
            localStorage.removeItem('npl_audit_logs');
            if (typeof loadAuditLogs === 'function') loadAuditLogs();
            renderActiveAuditPanel();
        })
        .catch(err => alert('Failed to clear audit log: ' + err.message));
}
