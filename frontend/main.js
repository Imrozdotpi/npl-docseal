// ═══════════════════════════════════════════════════════════════
// NPL DocSeal – Integrated Frontend: Pipeline Animation + Backend
// ═══════════════════════════════════════════════════════════════

// ─── State ───
let currentTab = 'seal';
let sealFile = null;
let verifyZipFile = null;

let sealedZipFilename = '';
let sealedZipData = '';       // Base64

let recoveredFilename = '';
let recoveredData = '';       // Base64

let sealRunning = false;
let verifyRunning = false;

let sealAnchorMode = 'immediate'; // 'immediate' | 'batch'
let batchPollInterval = null;

// ─── SVG icons (inline strings) ───
const SVG_CLOCK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
const SVG_LOADER = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>';
const SVG_CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
const SVG_X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>';
const SVG_INFO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
const SVG_CHECK_SM = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
const SVG_ALERT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
const SVG_CHEVRON_DOWN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><polyline points="6 9 12 15 18 9"/></svg>';
const SVG_SKIP = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>';

// ─── Step configurations (used ONLY for initial UI rendering) ───
const SEAL_STEPS = [
    { title: 'File received', avg: 'avg ~0.4s', hasTooltip: false },
    { title: 'Reading XML fields', avg: 'avg ~0.5s', hasTooltip: false },
    { title: 'Computing field hashes', avg: 'avg ~0.3s', hasTooltip: false },
    { title: 'Building Merkle tree', avg: 'avg ~0.1s', hasTooltip: false },
    { title: 'RSA-4096 digital signature', avg: 'avg ~0.6s', hasTooltip: false },
    { title: 'AES-256-GCM encryption', avg: 'avg ~0.3s', hasTooltip: false },
    { title: 'Anchoring to blockchain', avg: 'avg ~12s', hasTooltip: true },
    { title: 'Packaging output ZIP', avg: 'avg ~0.4s', hasTooltip: false },
    { title: 'Sealed — ready to download', avg: 'avg ~0.1s', hasTooltip: false },
];

const VERIFY_STEPS = [
    { title: 'ZIP received', avg: 'avg ~0.3s', hasTooltip: false },
    { title: 'Loading certificate files', avg: 'avg ~0.2s', hasTooltip: false },
    { title: 'Decrypting XML', avg: 'avg ~0.3s', hasTooltip: false },
    { title: 'Parsing certificate fields', avg: 'avg ~0.2s', hasTooltip: false },
    { title: 'Recomputing field hashes', avg: 'avg ~0.2s', hasTooltip: false },
    { title: 'Rebuilding Merkle tree', avg: 'avg ~0.1s', hasTooltip: false },
    { title: 'Verifying RSA signature', avg: 'avg ~0.5s', hasTooltip: false },
    { title: 'Blockchain confirmation', avg: 'avg ~7s', hasTooltip: true },
    { title: 'Field integrity check', avg: 'avg ~0.4s', hasTooltip: false },
    { title: 'Verification complete', avg: 'avg ~0.1s', hasTooltip: false },
];

// ═══════════════════ INITIALIZATION ═══════════════════

document.addEventListener('DOMContentLoaded', () => {
    setupDragAndDrop();
    loadAuditLogs();
    buildPipelineUI('seal-pipeline', SEAL_STEPS);
    buildPipelineUI('verify-pipeline', VERIFY_STEPS);
});

// ═══════════════════ TAB SWITCHING ═══════════════════

function switchTab(tabId) {
    currentTab = tabId;
    document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`nav-btn-${tabId}`).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    const titleEl = document.getElementById('current-page-title');
    const descEl = document.getElementById('current-page-desc');

    if (tabId === 'seal') {
        titleEl.textContent = 'Seal Document';
        descEl.textContent = 'Encrypt, digitally sign, and timestamp XML documents.';
    } else if (tabId === 'verify') {
        titleEl.textContent = 'Verify & Recover';
        descEl.textContent = 'Verify cryptographic authenticity and recover original documents.';
    } else if (tabId === 'audit') {
        titleEl.textContent = 'Audit Log';
        descEl.textContent = 'Inspect historical sealing and verification logs.';
        loadAuditLogs();
    }

    if (tabId === 'audit') {
        if (typeof startAuditPolling === 'function') startAuditPolling();
    } else {
        if (typeof stopAuditPolling === 'function') stopAuditPolling();
    }
}

// ═══════════════════ PIPELINE UI BUILDER ═══════════════════

function buildPipelineUI(containerId, steps) {
    const container = document.getElementById(containerId);
    container.innerHTML = '';

    steps.forEach((step, i) => {
        const isLast = i === steps.length - 1;

        const tooltipHtml = step.hasTooltip
            ? `<span class="info-trigger">${SVG_INFO}<span class="tooltip-text">Waiting for a new Ethereum block to include the transaction. This is the only step that requires internet and a blockchain node.</span></span>`
            : '';

        const html = `
            <div class="pipeline-step step-waiting" id="${containerId}-step-${i}">
                ${!isLast ? '<div class="connector"><div class="connector-fill"></div></div>' : ''}
                <div class="icon-circle">${SVG_CLOCK}</div>
                <div class="step-content">
                    <div class="step-row">
                        <span class="step-title">${step.title} ${tooltipHtml}</span>
                        <span class="avg-badge">${step.avg}</span>
                    </div>
                    <div class="step-sub">Waiting…</div>
                </div>
                <button class="step-chevron" onclick="toggleStepDetails('${containerId}', ${i})">
                    ${SVG_CHEVRON_DOWN}
                </button>
            </div>
            <div class="step-details-panel" id="${containerId}-details-${i}"></div>
        `;
        container.insertAdjacentHTML('beforeend', html);
    });
}

// ═══════════════════ STEP DETAIL EXPAND/COLLAPSE ═══════════════════

function toggleStepDetails(containerId, index) {
    const panel = document.getElementById(`${containerId}-details-${index}`);
    const chevron = document.querySelector(`#${containerId}-step-${index} .step-chevron`);
    if (!panel || !chevron || !chevron.classList.contains('enabled')) return;

    if (panel.classList.contains('expanded')) {
        panel.style.maxHeight = '0px';
        panel.classList.remove('expanded');
        chevron.classList.remove('expanded');
    } else {
        panel.style.maxHeight = (panel.scrollHeight + 60) + 'px';
        panel.classList.add('expanded');
        chevron.classList.add('expanded');
    }
}

// Package A: Monospace Cryptographic Copy Chips
function formatCryptoChip(text, label) {
    if (!text || text === 'N/A') return text;
    const str = String(text);
    const escapedText = str.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '&quot;');
    return `
        <div class="crypto-chip" title="Click copy to copy ${label || 'value'} to clipboard">
            <span class="crypto-chip-text">${str}</span>
            <button type="button" class="crypto-copy-btn" onclick="copyCryptoText(event, '${escapedText}')">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
                <span class="copy-label">Copy</span>
            </button>
        </div>
    `;
}

function copyCryptoText(event, text) {
    if (event) event.stopPropagation();
    const btn = event?.currentTarget;
    const cleanText = String(text).replace(/\.\.\.$/, '');
    navigator.clipboard.writeText(cleanText).then(() => {
        if (btn) {
            const labelEl = btn.querySelector('.copy-label');
            const orig = labelEl ? labelEl.textContent : 'Copy';
            btn.classList.add('copied');
            if (labelEl) labelEl.textContent = 'Copied!';
            setTimeout(() => {
                btn.classList.remove('copied');
                if (labelEl) labelEl.textContent = orig;
            }, 1800);
        }
    }).catch(err => {
        console.error('Failed to copy: ', err);
    });
}

function renderStepDetails(containerId, index, stepData) {
    const panel = document.getElementById(`${containerId}-details-${index}`);
    if (!panel) return;

    let html = '<div class="detail-panel-inner">';

    // Section: What happened
    html += '<div class="detail-section-title">What happened</div>';
    html += `<div class="detail-summary-text">${stepData.summary || 'No summary available.'}</div>`;

    // Section: Failure reason (only if failed)
    if (stepData.error) {
        html += '<div class="detail-error-box">';
        html += '<div class="error-label">Failure Reason</div>';
        html += `<div class="error-message">${stepData.error.message}</div>`;
        if (stepData.error.suggestion) {
            html += `<div class="error-suggestion">${stepData.error.suggestion}</div>`;
        }
        html += '</div>';
    }

    // Section: Technical Details
    if (stepData.details && Object.keys(stepData.details).length > 0) {
        html += '<div class="detail-section-title">Technical Details</div>';
        html += '<div class="detail-grid">';
        for (const [key, value] of Object.entries(stepData.details)) {
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            let displayVal = value;
            if (Array.isArray(value)) displayVal = value.join(', ');
            if (typeof value === 'boolean') displayVal = value ? '✓ Yes' : '✗ No';
            if (typeof value === 'object' && value !== null && !Array.isArray(value)) displayVal = JSON.stringify(value);

            if (typeof displayVal === 'string' && (
                key.includes('hash') || key.includes('root') || key.includes('fingerprint') ||
                key.includes('certificate_id') || key.includes('tx_') || key.includes('signature') ||
                (/^[0-9a-fA-F\.]{16,}$/.test(displayVal))
            )) {
                displayVal = formatCryptoChip(displayVal, label);
            }

            html += `<div class="detail-key">${label}</div>`;
            html += `<div class="detail-val">${displayVal}</div>`;
        }
        html += '</div>';
    }

    // Section: Execution Time
    if (stepData.duration_ms !== undefined && stepData.duration_ms !== null) {
        html += '<div class="detail-section-title">Execution Time</div>';
        const timeDisplay = stepData.duration_ms >= 1000
            ? `${(stepData.duration_ms / 1000).toFixed(2)} s`
            : `${stepData.duration_ms} ms`;
        html += `<span class="detail-exec-time">${timeDisplay}</span>`;
    }

    // Section: Status
    html += '<div class="detail-section-title">Status</div>';
    if (stepData.status === 'completed') {
        html += '<span class="detail-status-badge status-completed">Completed Successfully</span>';
    } else if (stepData.status === 'failed') {
        html += '<span class="detail-status-badge status-failed">Failed</span>';
    }

    html += '</div>'; // close detail-panel-inner
    panel.innerHTML = html;
}

// ═══════════════════ PIPELINE ANIMATION ENGINE ═══════════════════

function setStepState(containerId, index, state, duration, doneSub) {
    const stepEl = document.getElementById(`${containerId}-step-${index}`);
    if (!stepEl) return;

    // Remove all state classes
    stepEl.classList.remove('step-waiting', 'step-active', 'step-done', 'step-error', 'step-skipped', 'step-queued');
    stepEl.classList.add(`step-${state}`);

    const iconCircle = stepEl.querySelector('.icon-circle');
    const subEl = stepEl.querySelector('.step-sub');
    const badgeEl = stepEl.querySelector('.avg-badge');

    switch (state) {
        case 'waiting':
            iconCircle.innerHTML = SVG_CLOCK;
            subEl.textContent = 'Waiting…';
            if (badgeEl) { badgeEl.className = 'avg-badge'; }
            break;
        case 'active':
            iconCircle.innerHTML = SVG_LOADER;
            subEl.textContent = 'In progress 0.0s';
            if (badgeEl) { badgeEl.textContent = 'Running…'; badgeEl.className = 'avg-badge badge-running'; }
            break;
        case 'done':
            iconCircle.innerHTML = SVG_CHECK;
            subEl.textContent = doneSub || `Completed in ${duration.toFixed(1)}s`;
            const connector = stepEl.querySelector('.connector');
            if (connector) connector.classList.add('filled');
            if (badgeEl && duration !== undefined && duration !== null) {
                const ms = Math.round(duration * 1000);
                badgeEl.textContent = ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`;
                badgeEl.className = 'avg-badge badge-actual';
            }
            break;
        case 'error':
            iconCircle.innerHTML = SVG_X;
            subEl.textContent = doneSub || 'Failed — see details below';
            if (badgeEl) { badgeEl.textContent = 'Failed'; badgeEl.className = 'avg-badge badge-error'; }
            break;
        case 'skipped':
            iconCircle.innerHTML = SVG_SKIP;
            subEl.textContent = doneSub || 'Skipped — previous step failed';
            if (badgeEl) { badgeEl.textContent = 'Skipped'; badgeEl.className = 'avg-badge badge-skipped'; }
            break;
        case 'queued':
            iconCircle.innerHTML = SVG_CLOCK;
            subEl.textContent = doneSub || 'Queued for batch anchoring…';
            if (badgeEl) { badgeEl.textContent = 'Queued'; badgeEl.className = 'avg-badge badge-queued'; }
            break;
    }
}

// Elapsed ticker for active step
let elapsedInterval = null;

function startElapsedTicker(containerId, index) {
    stopElapsedTicker();
    const start = Date.now();
    elapsedInterval = setInterval(() => {
        const stepEl = document.getElementById(`${containerId}-step-${index}`);
        if (!stepEl) return;
        const subEl = stepEl.querySelector('.step-sub');
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);
        subEl.textContent = `In progress ${elapsed}s`;
    }, 100);
    return start;
}

function stopElapsedTicker() {
    if (elapsedInterval) {
        clearInterval(elapsedInterval);
        elapsedInterval = null;
    }
}

async function animatePipelineFromBackend(containerId, backendSteps) {
    for (let i = 0; i < backendSteps.length; i++) {
        const step = backendSteps[i];
        const stepEl = document.getElementById(`${containerId}-step-${i}`);

        if (step.status === 'skipped') {
            setStepState(containerId, i, 'skipped');
            continue;
        }

        setStepState(containerId, i, 'active');

        const durationMs = step.duration_ms || 100;
        const animDelay = 200 + Math.min(1200, Math.log1p(durationMs) * 100);

        startElapsedTicker(containerId, i);

        await new Promise(resolve => setTimeout(resolve, animDelay));

        stopElapsedTicker();

        if (step.status === 'completed') {
            setStepState(containerId, i, 'done', durationMs / 1000, step.summary);
        } else if (step.status === 'failed') {
            setStepState(containerId, i, 'error', null, step.summary || 'Failed — see details below');
        } else if (step.status === 'queued') {
            setStepState(containerId, i, 'queued', durationMs / 1000, 'Queued for batch anchoring…');
        }

        renderStepDetails(containerId, i, step);
        const chevron = stepEl?.querySelector('.step-chevron');
        if (chevron) {
            chevron.classList.add('enabled');
            if (step.status === 'failed') {
                toggleStepDetails(containerId, i);
            }
        }

        if (step.status === 'failed') {
            // Continue loop — remaining steps will be handled by the skipped branch
        }
    }
}

// ═══════════════════ FAILURE BANNER ═══════════════════

function showFailureBanner(elementId, failedStep) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const errorMsg = failedStep.error ? failedStep.error.message : 'An unknown error occurred.';
    const suggestion = failedStep.error && failedStep.error.suggestion ? failedStep.error.suggestion : '';

    let bodyHtml = `
        <div class="fb-row"><span class="fb-label">Failed Step</span><span class="fb-value">${failedStep.title}</span></div>
        <div class="fb-row"><span class="fb-label">Reason</span><span class="fb-value">${errorMsg}</span></div>
    `;

    if (suggestion) {
        bodyHtml += `<div class="fb-row"><span class="fb-label">Suggestion</span><span class="fb-value">${suggestion}</span></div>`;
    }

    el.innerHTML = `
        <div class="failure-header">${SVG_ALERT} ⚠ Process Failed</div>
        <div class="failure-body">${bodyHtml}</div>
        <div class="failure-footer">No further cryptographic operations were performed.</div>
    `;
    el.classList.add('visible');
}

function showRevokedBanner(elementId, details) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const reason = (details && details.reason) || 'No reason given.';
    const revokedAt = details && details.revoked_at ? new Date(details.revoked_at).toLocaleString() : 'Unknown';
    const revokedBy = (details && details.revoked_by) || 'Unknown';

    el.innerHTML = `
        <div class="failure-header">${SVG_ALERT} ⚠ Certificate Revoked</div>
        <div class="failure-body">
            <div class="fb-row"><span class="fb-label">Reason</span><span class="fb-value">${reason}</span></div>
            <div class="fb-row"><span class="fb-label">Revoked At</span><span class="fb-value">${revokedAt}</span></div>
            <div class="fb-row"><span class="fb-label">Revoked By</span><span class="fb-value">${revokedBy}</span></div>
        </div>
        <div class="failure-footer">This certificate is cryptographically valid but has since been invalidated by a business decision — not a tampering signal.</div>
    `;
    el.classList.add('revoked');
    el.classList.add('visible');
}

// ═══════════════════ DRAG & DROP & SMART VALIDATION ═══════════════════

function showDropzoneWarning(dropzone, message) {
    if (!dropzone) return;
    dropzone.classList.add('drag-invalid');
    let toast = dropzone.querySelector('.drag-warning-toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'drag-warning-toast';
        dropzone.appendChild(toast);
    }
    toast.textContent = message;
    setTimeout(() => {
        dropzone.classList.remove('drag-invalid');
        if (toast && toast.parentNode === dropzone) {
            dropzone.removeChild(toast);
        }
    }, 3500);
}

function checkDragItemValidity(e, expectedExtension) {
    if (!expectedExtension || !e.dataTransfer || !e.dataTransfer.items) return true;
    for (let i = 0; i < e.dataTransfer.items.length; i++) {
        const item = e.dataTransfer.items[i];
        if (item.kind === 'file' && item.type) {
            if (expectedExtension === '.xml') {
                if (!item.type.includes('xml') && !item.type.includes('text') && item.type !== '') {
                    return false;
                }
            } else if (expectedExtension === '.zip') {
                if (item.type.includes('image/') || item.type.includes('video/') || item.type.includes('text/') || item.type.includes('pdf')) {
                    return false;
                }
            }
        }
    }
    return true;
}

function setupDragAndDrop() {
    const sealDropzone = document.getElementById('seal-dropzone');
    const pdfUpload = document.getElementById('pdf-upload');

    const isAllowedSealFile = (file) => {
        return file.type === 'text/xml' || file.type === 'application/xml' || file.name.endsWith('.xml');
    };

    setupDropzoneListeners(sealDropzone, pdfUpload, (file) => {
        if (isAllowedSealFile(file)) {
            sealFile = file;
            displaySealFileInfo(file);
        } else {
            showDropzoneWarning(sealDropzone, '⚠ Invalid format: Only .XML DCC calibration documents supported.');
        }
    }, '.xml');

    pdfUpload.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (isAllowedSealFile(file)) {
                sealFile = file;
                displaySealFileInfo(file);
            } else {
                showDropzoneWarning(sealDropzone, '⚠ Invalid format: Only .XML DCC calibration documents supported.');
            }
        }
    });

    setupFieldDropzone('zip-dropzone', 'zip-upload', '.zip', (file) => {
        verifyZipFile = file;
        document.getElementById('zip-file-label').textContent = file.name;
    });
}

function setupDropzoneListeners(dropzone, input, onFileSelect, expectedExtension) {
    if (!dropzone) return;
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!checkDragItemValidity(e, expectedExtension)) {
                dropzone.classList.add('drag-invalid');
                dropzone.classList.remove('dragover');
            } else {
                dropzone.classList.add('dragover');
                dropzone.classList.remove('drag-invalid');
            }
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover', 'drag-invalid');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            const file = files[0];
            if (expectedExtension && !file.name.endsWith(expectedExtension) && !(expectedExtension === '.xml' && (file.type === 'text/xml' || file.type === 'application/xml'))) {
                showDropzoneWarning(dropzone, `⚠ Invalid file format. Expected an ${expectedExtension.toUpperCase()} document.`);
            } else {
                onFileSelect(file);
            }
        }
    });
}

function setupFieldDropzone(dropzoneId, inputId, extension, onSelect) {
    const dropzone = document.getElementById(dropzoneId);
    const input = document.getElementById(inputId);
    if (!dropzone || !input) return;

    setupDropzoneListeners(dropzone, input, (file) => {
        if (file.name.endsWith(extension)) {
            onSelect(file);
        } else {
            showDropzoneWarning(dropzone, `⚠ Invalid format: Expected a file with extension ${extension}`);
        }
    }, extension);

    input.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (file.name.endsWith(extension)) {
                onSelect(file);
            } else {
                showDropzoneWarning(dropzone, `⚠ Invalid format: Expected a file with extension ${extension}`);
            }
        }
    });
}

function displaySealFileInfo(file) {
    document.getElementById('seal-dropzone').style.display = 'none';
    const infoBox = document.getElementById('seal-file-info');
    infoBox.style.display = 'flex';
    infoBox.querySelector('.file-name-text').textContent = file.name;
    document.getElementById('seal-file-size').textContent = (file.size / 1024).toFixed(1) + ' KB';
    document.getElementById('btn-preview-seal').style.display = 'inline-flex';
}

function removeSealFile() {
    sealFile = null;
    document.getElementById('pdf-upload').value = '';
    document.getElementById('seal-file-info').style.display = 'none';
    document.getElementById('seal-dropzone').style.display = 'flex';
    document.getElementById('btn-preview-seal').style.display = 'none';
    closeModal('seal-preview-card', 'seal-preview-iframe');
    resetSealPipeline();
}

function resetSealPipeline() {
    buildPipelineUI('seal-pipeline', SEAL_STEPS);
    document.getElementById('seal-summary').classList.remove('visible');
    document.getElementById('seal-summary').innerHTML = '';
    document.getElementById('seal-error-card').classList.remove('visible');
    document.getElementById('seal-error-card').innerHTML = '';
    document.getElementById('seal-failure-banner').classList.remove('visible');
    document.getElementById('seal-failure-banner').innerHTML = '';
    document.getElementById('seal-download-wrap').classList.remove('visible');
    document.getElementById('seal-api-error').classList.remove('visible');
    stopBatchStatusPolling();
    document.getElementById('seal-batch-status').classList.remove('visible', 'anchored');
    document.getElementById('seal-revoke-trigger-row').style.display = 'none';
    document.getElementById('revoke-reason').value = '';
    document.getElementById('revoke-keypass').value = '';
    closeModal('revoke-modal');
    window._lastSealRoot = null;
    window._lastSealCertNumber = null;
    const btn = document.getElementById('btn-seal');
    btn.disabled = false;
    document.getElementById('btn-seal-text').textContent = 'Seal Document';
    btn.classList.remove('btn-reset');
    btn.classList.add('btn-primary');
    btn.onclick = sealDocument;
    sealRunning = false;
}

function resetVerifyPipeline() {
    buildPipelineUI('verify-pipeline', VERIFY_STEPS);
    document.getElementById('verify-summary').classList.remove('visible');
    document.getElementById('verify-summary').innerHTML = '';
    document.getElementById('verify-error-card').classList.remove('visible');
    document.getElementById('verify-error-card').innerHTML = '';
    document.getElementById('verify-failure-banner').classList.remove('visible');
    document.getElementById('verify-failure-banner').classList.remove('revoked');
    document.getElementById('verify-failure-banner').innerHTML = '';
    document.getElementById('verify-download-wrap').classList.remove('visible');
    document.getElementById('verify-api-error').classList.remove('visible');
    document.getElementById('btn-field-report').style.display = 'none';
    closeModal('field-report-modal');
    document.getElementById('btn-preview-verify').style.display = 'none';
    closeModal('verify-preview-card', 'verify-preview-iframe');
    const btn = document.getElementById('btn-verify');
    btn.disabled = false;
    document.getElementById('btn-verify-text').textContent = 'Verify & Recover';
    btn.classList.remove('btn-reset');
    btn.classList.add('btn-primary');
    btn.onclick = verifyDocument;
    verifyRunning = false;
}

// ═══════════════════ SEAL DOCUMENT ═══════════════════

async function sealDocument() {
    if (sealRunning) return;

    if (!sealFile) { alert('Please upload an XML document first.'); return; }
    const password = document.getElementById('encryption-password').value;
    const keypass = document.getElementById('key-passphrase').value;

    if (!password) { showApiError('seal-api-error', 'Please enter an encryption password.'); return; }
    if (!keypass) { showApiError('seal-api-error', 'Please enter the key passphrase.'); return; }

    sealRunning = true;
    hideApiError('seal-api-error');

    // Set button to processing
    const btn = document.getElementById('btn-seal');
    btn.disabled = true;
    document.getElementById('btn-seal-text').textContent = 'Processing…';

    // Reset pipeline UI
    buildPipelineUI('seal-pipeline', SEAL_STEPS);
    document.getElementById('seal-summary').classList.remove('visible');
    document.getElementById('seal-error-card').classList.remove('visible');
    document.getElementById('seal-failure-banner').classList.remove('visible');
    document.getElementById('seal-download-wrap').classList.remove('visible');
    stopBatchStatusPolling();
    document.getElementById('seal-batch-status').classList.remove('visible', 'anchored');

    // Immediately start step 0 active ticker while waiting for server response
    setStepState('seal-pipeline', 0, 'active');
    startElapsedTicker('seal-pipeline', 0);

    // Fire API call
    const formData = new FormData();
    formData.append('document', sealFile);
    formData.append('password', password);
    formData.append('keypass', keypass);

    try {
        const sealUrl = sealAnchorMode === 'batch' ? '/api/seal?batch=true' : '/api/seal';
        const res = await fetch(sealUrl, { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }
        const apiResult = await res.json();
        stopElapsedTicker();

        // Animate pipeline from backend steps
        if (apiResult.steps && apiResult.steps.length > 0) {
            await animatePipelineFromBackend('seal-pipeline', apiResult.steps);
        }

        if (apiResult.overall === 'PASS') {
            // Store download data
            sealedZipFilename = apiResult.zip_filename;
            sealedZipData = apiResult.zip_data;

            // Calculate total time from steps
            const totalTime = (apiResult.steps || []).reduce((sum, s) => sum + (s.duration_ms || 0), 0) / 1000;
            const fieldCount = apiResult.field_count || 31;

            // Show summary
            showSealSummary(fieldCount, totalTime, apiResult);

            if (apiResult.batch_status === 'queued' && apiResult.batch_id) {
                startBatchStatusPolling(apiResult.batch_id);
            }

            // Show download button
            const dlWrap = document.getElementById('seal-download-wrap');
            dlWrap.classList.add('visible');
            document.getElementById('seal-download-sub').textContent = sealedZipFilename;
            const dlBtn = document.getElementById('btn-download-zip');
            dlBtn.classList.add('glow');
            setTimeout(() => dlBtn.classList.remove('glow'), 3200);

            // Add to audit log
            addAuditRecord(sealFile.name, apiResult.hash || 'unknown', 'SEALED', 'success');

            // Store the Merkle root client-side so "Revoke this certificate"
            // can reference it without re-uploading or re-parsing anything.
            if (apiResult.hash) {
                window._lastSealRoot = apiResult.hash;
                const xmlStep = (apiResult.steps || []).find(s => s.step === 'xml_parsing');
                window._lastSealCertNumber = (xmlStep && xmlStep.details && xmlStep.details.certificate_id) || 'N/A';
                document.getElementById('revoke-modal-root').textContent = apiResult.hash.slice(0, 16) + '…';
                document.getElementById('seal-revoke-trigger-row').style.display = 'flex';
            }

            // Change button to Reset
            btn.disabled = false;
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-reset');
            document.getElementById('btn-seal-text').textContent = '↺ Reset';
            btn.onclick = () => {
                resetSealPipeline();
                removeSealFile();
            };

        } else {
            // FAIL — find the failed step
            const failedStep = (apiResult.steps || []).find(s => s.status === 'failed');
            if (failedStep) {
                showFailureBanner('seal-failure-banner', failedStep);
            } else {
                showErrorCard('seal-error-card', '⚠ Sealing Failed', 'Process failed');
            }

            addAuditRecord(sealFile.name, 'N/A', 'SEAL_FAILED', 'danger');

            btn.disabled = false;
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-reset');
            document.getElementById('btn-seal-text').textContent = '↺ Try Again';
            btn.onclick = () => {
                resetSealPipeline();
            };
        }

    } catch (err) {
        stopElapsedTicker();
        showApiError('seal-api-error', err.message);
        showErrorCard('seal-error-card', 'Sealing Failed', err.message);

        // Mark first active/waiting step as error
        for (let i = 0; i < SEAL_STEPS.length; i++) {
            const el = document.getElementById(`seal-pipeline-step-${i}`);
            if (el && (el.classList.contains('step-active') || el.classList.contains('step-waiting'))) {
                if (el.classList.contains('step-active')) {
                    setStepState('seal-pipeline', i, 'error');
                }
                break;
            }
        }

        // Reset button
        btn.disabled = false;
        document.getElementById('btn-seal-text').textContent = 'Seal Document';
    } finally {
        sealRunning = false;
    }
}

function showSealSummary(fieldCount, totalTime, apiResult) {
    const el = document.getElementById('seal-summary');
    const hashRow = apiResult && apiResult.hash
        ? `<div class="stat-row"><span class="stat-label">Document Root</span><span class="stat-value">${formatCryptoChip(apiResult.hash, 'Merkle Root')}</span></div>`
        : '';
    const blockchainValue = apiResult && apiResult.batch_status === 'queued'
        ? 'Ethereum Sepolia (batch — pending)'
        : 'Ethereum Sepolia';
    el.innerHTML = `
        <div class="summary-header">${SVG_CHECK_SM} Sealing Complete</div>
        <div class="summary-body">
            <div class="stat-row"><span class="stat-label">Fields processed</span><span class="stat-value">${fieldCount}</span></div>
            <div class="stat-row"><span class="stat-label">Hashes computed</span><span class="stat-value">${fieldCount} (SHA-256)</span></div>
            <div class="stat-row"><span class="stat-label">Signature</span><span class="stat-value">RSA-4096</span></div>
            <div class="stat-row"><span class="stat-label">Encryption</span><span class="stat-value">AES-256-GCM</span></div>
            <div class="stat-row"><span class="stat-label">Blockchain</span><span class="stat-value" id="seal-summary-blockchain-value">${blockchainValue}</span></div>
            ${hashRow}
            <div class="stat-row"><span class="stat-label">Total time</span><span class="stat-value green">${totalTime.toFixed(1)}s</span></div>
        </div>
    `;
    el.classList.add('visible');
}

// ═══════════════════ BATCH ANCHORING (Seal tab toggle) ═══════════════════

function setAnchorMode(mode) {
    sealAnchorMode = mode;
    document.getElementById('anchor-mode-immediate').classList.toggle('active', mode === 'immediate');
    document.getElementById('anchor-mode-batch').classList.toggle('active', mode === 'batch');
}

function startBatchStatusPolling(batchId) {
    stopBatchStatusPolling();
    const note = document.getElementById('seal-batch-status');
    note.textContent = 'Waiting for batch anchor… (checking every 3s)';
    note.classList.add('visible');
    note.classList.remove('anchored');

    batchPollInterval = setInterval(async () => {
        try {
            const res = await fetch(`/api/batch/status/${batchId}`);
            if (!res.ok) return;
            const status = await res.json();
            if (status.status === 'anchored') {
                stopBatchStatusPolling();
                note.textContent = `Anchored — tx ${status.tx_hash.slice(0, 16)}…`;
                note.classList.add('anchored');

                // The blockchain_anchor step is a fixed position in SEAL_STEPS
                // (index 6) — reflect the now-confirmed anchor there too.
                setStepState('seal-pipeline', 6, 'done', null, `Anchored in batch — tx ${status.tx_hash.slice(0, 16)}…`);

                const blockchainValueEl = document.getElementById('seal-summary-blockchain-value');
                if (blockchainValueEl) blockchainValueEl.textContent = 'Ethereum Sepolia (batch confirmed)';
            }
        } catch (err) {
            // Network hiccup — silently retry on the next tick.
        }
    }, 3000);
}

function stopBatchStatusPolling() {
    if (batchPollInterval) {
        clearInterval(batchPollInterval);
        batchPollInterval = null;
    }
}

// ═══════════════════ REVOCATION ═══════════════════

async function confirmRevocation() {
    const reason = document.getElementById('revoke-reason').value.trim();
    const keypass = document.getElementById('revoke-keypass').value;
    hideApiError('revoke-api-error');

    if (!window._lastSealRoot) { showApiError('revoke-api-error', 'No sealed certificate to revoke.'); return; }
    if (!reason) { showApiError('revoke-api-error', 'Please enter a reason for revocation.'); return; }
    if (!keypass) { showApiError('revoke-api-error', "Please enter the Director's key passphrase."); return; }

    const btn = document.getElementById('btn-confirm-revoke');
    btn.disabled = true;
    btn.textContent = 'Revoking…';

    try {
        const res = await fetch('/api/revoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                merkle_root: window._lastSealRoot,
                certificate_number: window._lastSealCertNumber || 'N/A',
                reason,
                keypass
            })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }
        const entry = await res.json();

        closeModal('revoke-modal');
        const triggerRow = document.getElementById('seal-revoke-trigger-row');
        triggerRow.innerHTML = `<div class="api-error-banner visible" style="border-left-color: var(--accent-amber); color: var(--accent-amber);">
            Certificate revoked ${new Date(entry.revoked_at).toLocaleString()} — "${entry.reason}"
        </div>`;
    } catch (err) {
        showApiError('revoke-api-error', err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Revoke Certificate';
    }
}

// ═══════════════════ VERIFY DOCUMENT ═══════════════════

async function verifyDocument() {
    if (verifyRunning) return;

    if (!verifyZipFile) { alert('Please upload the sealed ZIP package.'); return; }
    const password = document.getElementById('verify-password').value;
    if (!password) { showApiError('verify-api-error', 'Please enter the decryption password.'); return; }

    verifyRunning = true;
    hideApiError('verify-api-error');

    const btn = document.getElementById('btn-verify');
    btn.disabled = true;
    document.getElementById('btn-verify-text').textContent = 'Processing…';

    buildPipelineUI('verify-pipeline', VERIFY_STEPS);
    document.getElementById('verify-summary').classList.remove('visible');
    document.getElementById('verify-error-card').classList.remove('visible');
    document.getElementById('verify-failure-banner').classList.remove('visible');
    document.getElementById('verify-failure-banner').classList.remove('revoked');
    document.getElementById('verify-download-wrap').classList.remove('visible');
    document.getElementById('btn-field-report').style.display = 'none';
    closeModal('field-report-modal');

    // Immediately start step 0 active ticker while waiting for server response
    setStepState('verify-pipeline', 0, 'active');
    startElapsedTicker('verify-pipeline', 0);

    const formData = new FormData();
    formData.append('document_zip', verifyZipFile);
    formData.append('password', password);

    try {
        const res = await fetch('/api/verify', { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }
        const apiResult = await res.json();
        stopElapsedTicker();

        // Animate pipeline from backend steps
        if (apiResult.steps && apiResult.steps.length > 0) {
            await animatePipelineFromBackend('verify-pipeline', apiResult.steps);
        }

        if (apiResult.overall === 'FAIL') {
            // Find the failed step
            const failedStep = (apiResult.steps || []).find(s => s.status === 'failed');

            if (apiResult.revoked) {
                // Revocation is a business-level invalidation, not a
                // cryptographic failure — the pipeline itself completed
                // cleanly, so there's no failedStep to point at.
                showRevokedBanner('verify-failure-banner', apiResult.revocation_details);
            } else if (failedStep) {
                showFailureBanner('verify-failure-banner', failedStep);
            }

            // Show field report if available
            renderFieldReport(apiResult.fields);

            addAuditRecord(verifyZipFile.name, apiResult.root_matches ? 'Root verified' : 'Root mismatch', 'TAMPERED', 'danger');

            btn.disabled = false;
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-reset');
            document.getElementById('btn-verify-text').textContent = '↺ Try Again';
            btn.onclick = resetVerifyPipeline;
            return;
        }

        // Success
        recoveredFilename = apiResult.original_filename || 'recovered_document.xml';
        recoveredData = apiResult.decrypted_data || '';

        const fields = apiResult.fields || {};
        const intactCount = Object.values(fields).filter(f => f.status === 'INTACT').length;
        const tamperedCount = Object.values(fields).filter(f => f.status !== 'INTACT').length;
        const totalFields = intactCount + tamperedCount;

        // Calculate total time from steps
        const totalTime = (apiResult.steps || []).reduce((sum, s) => sum + (s.duration_ms || 0), 0) / 1000;

        showVerifySummary(apiResult, intactCount, totalFields, tamperedCount, totalTime);
        renderFieldReport(apiResult.fields);

        // Show preview button now that decrypted certificate data is available
        if (recoveredData) {
            document.getElementById('btn-preview-verify').style.display = 'inline-flex';
        }

        // Show download
        if (recoveredData) {
            const dlWrap = document.getElementById('verify-download-wrap');
            dlWrap.classList.add('visible');
            const spanText = recoveredFilename.endsWith('.xml') ? 'Download Decrypted XML' : 'Download Original Document';
            document.getElementById('verify-download-text').textContent = spanText;
            document.getElementById('verify-download-sub').textContent = recoveredFilename;
            const dlBtn = document.getElementById('btn-download-recovered');
            dlBtn.classList.add('glow');
            setTimeout(() => dlBtn.classList.remove('glow'), 3200);
        }

        addAuditRecord(verifyZipFile.name, apiResult.root_matches ? 'Root verified' : 'Root mismatch', 'VERIFIED', 'success');

        btn.disabled = false;
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-reset');
        document.getElementById('btn-verify-text').textContent = '↺ Reset';
        btn.onclick = resetVerifyPipeline;

    } catch (err) {
        stopElapsedTicker();
        showApiError('verify-api-error', err.message);
        showErrorCard('verify-error-card', 'Verification Failed', err.message);

        for (let i = 0; i < VERIFY_STEPS.length; i++) {
            const el = document.getElementById(`verify-pipeline-step-${i}`);
            if (el && el.classList.contains('step-active')) {
                setStepState('verify-pipeline', i, 'error');
                break;
            }
        }

        btn.disabled = false;
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-reset');
        document.getElementById('btn-verify-text').textContent = '↺ Try Again';
        btn.onclick = resetVerifyPipeline;
    }
}

function showVerifySummary(result, intactCount, totalFields, tamperedCount, totalTime) {
    const el = document.getElementById('verify-summary');
    const hashRow = result && (result.hash || result.merkle_root)
        ? `<div class="stat-row"><span class="stat-label">Verified Root</span><span class="stat-value">${formatCryptoChip(result.hash || result.merkle_root, 'Verified Root')}</span></div>`
        : '';
    el.innerHTML = `
        <div class="summary-header">${SVG_CHECK_SM} Verification Passed</div>
        <div class="summary-body">
            <div class="stat-row"><span class="stat-label">Fields checked</span><span class="stat-value green">${intactCount} / ${totalFields}  ✓</span></div>
            <div class="stat-row"><span class="stat-label">Signature</span><span class="stat-value green">${result.signature_valid ? 'Valid  ✓' : 'Invalid  ✗'}</span></div>
            <div class="stat-row"><span class="stat-label">Blockchain</span><span class="stat-value green">${result.root_matches ? 'Confirmed  ✓' : 'Mismatch  ✗'}</span></div>
            <div class="stat-row"><span class="stat-label">Tampered fields</span><span class="stat-value">${tamperedCount}</span></div>
            <div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value green">AUTHENTIC</span></div>
            ${hashRow}
            <div class="stat-row"><span class="stat-label">Total time</span><span class="stat-value green">${totalTime.toFixed(1)}s</span></div>
        </div>
    `;
    el.classList.add('visible');
}

function renderFieldReport(fields) {
    if (!fields || Object.keys(fields).length === 0) return;

    const container = document.getElementById('field-report-rows');
    container.innerHTML = '';
    let intactCount = 0, tamperedCount = 0;

    Object.keys(fields).forEach(fieldName => {
        const fieldData = fields[fieldName];
        const status = fieldData.status;
        const value = fieldData.value || '';
        const displayVal = value.length > 40 ? value.substring(0, 40) + '...' : value;

        const row = document.createElement('div');
        row.className = `field-row ${status === 'INTACT' ? 'field-intact-row' : 'field-tampered-row'}`;

        let statusBadge = '';
        if (status === 'INTACT') {
            intactCount++;
            statusBadge = '<span class="field-intact">✓ INTACT</span>';
        } else {
            tamperedCount++;
            statusBadge = `<span class="field-tampered">✗ ${status}</span>`;
        }

        row.innerHTML = `
            <span class="field-name">${fieldName}</span>
            <span class="field-value" title="${value}">${displayVal}</span>
            ${statusBadge}
        `;
        container.appendChild(row);
    });

    document.getElementById('field-summary').textContent = `${intactCount} fields intact, ${tamperedCount} fields tampered`;
    document.getElementById('btn-field-report').style.display = 'inline-flex';
}

// ═══════════════════ DOWNLOAD HANDLERS ═══════════════════

function downloadSealedZip() {
    if (!sealedZipData || !sealedZipFilename) return;
    downloadBase64File(sealedZipData, sealedZipFilename, 'application/zip');
    flashDownloadButton('seal-download-text', 'Download started', 'Download Sealed ZIP');
}

function downloadRecoveredDocument() {
    if (!recoveredData || !recoveredFilename) return;
    const mime = recoveredFilename.endsWith('.xml') ? 'text/xml' : 'application/octet-stream';
    downloadBase64File(recoveredData, recoveredFilename, mime);
    const label = recoveredFilename.endsWith('.xml') ? 'Download Decrypted XML' : 'Download Original Document';
    flashDownloadButton('verify-download-text', 'Download started', label);
}

function downloadBase64File(base64Data, filename, mimeType) {
    const binaryString = window.atob(base64Data);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    const blob = new Blob([bytes], { type: mimeType });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
}

function flashDownloadButton(textElId, flashText, originalText) {
    const el = document.getElementById(textElId);
    el.textContent = flashText;
    setTimeout(() => { el.textContent = originalText; }, 1500);
}

// ═══════════════════ MODAL HELPERS (certificate preview + field report) ═══════════════════

function openModal(overlayId) {
    document.getElementById(overlayId).classList.add('visible');
}

function closeModal(overlayId, iframeId) {
    document.getElementById(overlayId).classList.remove('visible');
    if (iframeId) {
        const iframe = document.getElementById(iframeId);
        if (iframe && iframe.src) {
            URL.revokeObjectURL(iframe.src);
            iframe.src = '';
        }
    }
}

// ═══════════════════ CERTIFICATE PDF PREVIEW ═══════════════════

async function renderCertificatePreview(xmlText, filename, cardId, iframeId, btnId, errorBannerId) {
    const btn = document.getElementById(btnId);
    const originalLabel = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Rendering…';
    hideApiError(errorBannerId);

    try {
        const formData = new FormData();
        formData.append('xml_file', new Blob([xmlText], { type: 'application/xml' }), filename || 'certificate.xml');

        const res = await fetch('/api/preview-pdf', { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }
        const result = await res.json();

        const binaryString = window.atob(result.pdf_data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
        const blob = new Blob([bytes], { type: 'application/pdf' });
        const objectUrl = URL.createObjectURL(blob);

        document.getElementById(iframeId).src = objectUrl;
        openModal(cardId);
    } catch (err) {
        showApiError(errorBannerId, `Preview failed: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.textContent = originalLabel;
    }
}

async function previewSealCertificate() {
    if (!sealFile) return;
    const xmlText = await sealFile.text();
    renderCertificatePreview(xmlText, sealFile.name, 'seal-preview-card', 'seal-preview-iframe', 'btn-preview-seal', 'seal-api-error');
}

async function previewVerifyCertificate() {
    if (!recoveredData) return;
    const xmlText = window.atob(recoveredData);
    renderCertificatePreview(xmlText, recoveredFilename, 'verify-preview-card', 'verify-preview-iframe', 'btn-preview-verify', 'verify-api-error');
}

// ═══════════════════ HELPERS ═══════════════════

function showApiError(elementId, message) {
    const el = document.getElementById(elementId);
    el.innerHTML = `<strong>Error:</strong> ${message}`;
    el.classList.add('visible');
}

function hideApiError(elementId) {
    const el = document.getElementById(elementId);
    el.classList.remove('visible');
    el.innerHTML = '';
}

function showErrorCard(elementId, title, message) {
    const el = document.getElementById(elementId);
    el.innerHTML = `
        <div class="error-header">${SVG_ALERT} ${title}</div>
        <div class="error-body">${message}</div>
    `;
    el.classList.add('visible');
}

// ═══════════════════ AUDIT LOG ═══════════════════

function loadAuditLogs() {
    const tbody = document.getElementById('audit-table-body');
    if (!tbody) return; // legacy table replaced by the Audit Log dashboard panels

    const logsJson = localStorage.getItem('npl_audit_logs');
    const logs = logsJson ? JSON.parse(logsJson) : [];
    tbody.innerHTML = '';

    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #94a3b8; padding: 40px;">No transaction records found.</td></tr>';
        return;
    }

    logs.slice().reverse().forEach(log => {
        const row = document.createElement('tr');
        const fullHash = log.hash;
        const displayHash = fullHash && fullHash !== 'unknown'
            ? `${fullHash.substring(0, 12)}...${fullHash.substring(fullHash.length - 12)}`
            : 'N/A';

        row.innerHTML = `
            <td>${log.filename}</td>
            <td class="text-monospace">${log.timestamp}</td>
            <td class="text-monospace" title="${fullHash}">${displayHash}</td>
            <td><span class="badge badge-${log.badgeClass}">${log.action}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function addAuditRecord(filename, hash, action, badgeClass) {
    const logsJson = localStorage.getItem('npl_audit_logs');
    const logs = logsJson ? JSON.parse(logsJson) : [];
    logs.push({
        filename,
        timestamp: new Date().toLocaleString(),
        hash,
        action,
        badgeClass
    });
    localStorage.setItem('npl_audit_logs', JSON.stringify(logs));
}

function clearAudit() {
    if (confirm('Clear all transaction logs?')) {
        localStorage.removeItem('npl_audit_logs');
        loadAuditLogs();
    }
}
