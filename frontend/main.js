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

// ─── SVG icons (inline strings) ───
const SVG_CLOCK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
const SVG_LOADER = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>';
const SVG_CHECK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
const SVG_X = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>';
const SVG_INFO = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
const SVG_CHECK_SM = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
const SVG_ALERT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';

// ─── Step configurations ───
const SEAL_STEPS = [
    { title: 'File received', doneSub: 'XML parsed, fields ready for processing', range: [300,600], avg: 'avg ~0.4s' },
    { title: 'Reading XML fields', doneSub: '31 certificate fields extracted and validated', range: [400,800], avg: 'avg ~0.5s' },
    { title: 'Computing field hashes', doneSub: '31 SHA-256 hashes computed (one per field)', range: [200,500], avg: 'avg ~0.3s' },
    { title: 'Building Merkle tree', doneSub: '32-byte Merkle root derived from all field hashes', range: [100,300], avg: 'avg ~0.1s' },
    { title: 'RSA-4096 digital signature', doneSub: "Merkle root signed with Director's private key", range: [500,900], avg: 'avg ~0.6s' },
    { title: 'AES-256-GCM encryption', doneSub: 'XML encrypted; only authorised parties can read it', range: [200,500], avg: 'avg ~0.3s' },
    { title: 'Anchoring to blockchain', doneSub: 'Merkle root recorded on Ethereum Sepolia; tx confirmed', range: [8000,14000], avg: 'avg ~12s', hasTooltip: true },
    { title: 'Packaging output ZIP', doneSub: 'Signature, Merkle proof, public key and encrypted XML bundled', range: [300,600], avg: 'avg ~0.4s' },
    { title: 'Sealed — ready to download', doneSub: 'Your certificate is cryptographically sealed and tamper-evident', range: [100,200], avg: 'avg ~0.1s' },
];

const VERIFY_STEPS = [
    { title: 'ZIP received', doneSub: 'Archive extracted; all expected files found', range: [300,500], avg: 'avg ~0.3s' },
    { title: 'Loading certificate files', doneSub: 'Encrypted XML, signature, Merkle proof and public key loaded', range: [200,400], avg: 'avg ~0.2s' },
    { title: 'Decrypting XML', doneSub: 'AES-256-GCM decryption complete; plaintext XML recovered', range: [200,500], avg: 'avg ~0.3s' },
    { title: 'Parsing certificate fields', doneSub: '31 fields extracted from decrypted XML', range: [200,400], avg: 'avg ~0.2s' },
    { title: 'Recomputing field hashes', doneSub: '31 SHA-256 hashes recalculated from live data', range: [200,400], avg: 'avg ~0.2s' },
    { title: 'Rebuilding Merkle tree', doneSub: 'New Merkle root computed from recomputed hashes', range: [100,200], avg: 'avg ~0.1s' },
    { title: 'Verifying RSA signature', doneSub: 'Merkle root matches signed value — signature valid', range: [400,700], avg: 'avg ~0.5s' },
    { title: 'Blockchain confirmation', doneSub: 'Merkle root found on Ethereum Sepolia — timestamp verified', range: [5000,10000], avg: 'avg ~7s' },
    { title: 'Field integrity check', doneSub: 'All 31 fields intact — no tampering detected', range: [300,600], avg: 'avg ~0.4s' },
    { title: 'Verification complete', doneSub: 'Certificate is authentic and unmodified', range: [100,200], avg: 'avg ~0.1s' },
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
            </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
    });
}

// ═══════════════════ PIPELINE ANIMATION ENGINE ═══════════════════

function simulateDelay(min, max) {
    const ms = min + Math.random() * (max - min);
    return new Promise(resolve => setTimeout(resolve, ms));
}

function setStepState(containerId, index, state, duration, doneSub) {
    const stepEl = document.getElementById(`${containerId}-step-${index}`);
    if (!stepEl) return;

    // Remove all state classes
    stepEl.classList.remove('step-waiting', 'step-active', 'step-done', 'step-error');
    stepEl.classList.add(`step-${state}`);

    const iconCircle = stepEl.querySelector('.icon-circle');
    const subEl = stepEl.querySelector('.step-sub');

    switch (state) {
        case 'waiting':
            iconCircle.innerHTML = SVG_CLOCK;
            subEl.textContent = 'Waiting…';
            break;
        case 'active':
            iconCircle.innerHTML = SVG_LOADER;
            subEl.textContent = 'In progress 0.0s';
            break;
        case 'done':
            iconCircle.innerHTML = SVG_CHECK;
            subEl.textContent = doneSub || `Completed in ${duration.toFixed(1)}s`;
            // Fill connector
            const connector = stepEl.querySelector('.connector');
            if (connector) connector.classList.add('filled');
            break;
        case 'error':
            iconCircle.innerHTML = SVG_X;
            subEl.textContent = 'Failed — see details below';
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

async function runPipelineAnimation(containerId, steps) {
    const durations = [];
    let totalTime = 0;

    for (let i = 0; i < steps.length; i++) {
        setStepState(containerId, i, 'active');
        const start = startElapsedTicker(containerId, i);

        const [min, max] = steps[i].range;
        await simulateDelay(min, max);

        stopElapsedTicker();
        const elapsed = (Date.now() - start) / 1000;
        durations.push(elapsed);
        totalTime += elapsed;

        setStepState(containerId, i, 'done', elapsed, steps[i].doneSub);
    }

    return { durations, totalTime };
}

// ═══════════════════ DRAG & DROP ═══════════════════

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
            alert('Only XML files are supported.');
        }
    });

    pdfUpload.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (isAllowedSealFile(file)) {
                sealFile = file;
                displaySealFileInfo(file);
            } else {
                alert('Only XML files are supported.');
            }
        }
    });

    setupFieldDropzone('zip-dropzone', 'zip-upload', '.zip', (file) => {
        verifyZipFile = file;
        document.getElementById('zip-file-label').textContent = file.name;
    });
}

function setupDropzoneListeners(dropzone, input, onFileSelect) {
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) onFileSelect(files[0]);
    });
}

function setupFieldDropzone(dropzoneId, inputId, extension, onSelect) {
    const dropzone = document.getElementById(dropzoneId);
    const input = document.getElementById(inputId);

    setupDropzoneListeners(dropzone, input, (file) => {
        if (file.name.endsWith(extension)) {
            onSelect(file);
        } else {
            alert(`Expected a file with extension: ${extension}`);
        }
    });

    input.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (file.name.endsWith(extension)) {
                onSelect(file);
            } else {
                alert(`Expected a file with extension: ${extension}`);
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
}

function removeSealFile() {
    sealFile = null;
    document.getElementById('pdf-upload').value = '';
    document.getElementById('seal-file-info').style.display = 'none';
    document.getElementById('seal-dropzone').style.display = 'flex';
    resetSealPipeline();
}

function resetSealPipeline() {
    buildPipelineUI('seal-pipeline', SEAL_STEPS);
    document.getElementById('seal-summary').classList.remove('visible');
    document.getElementById('seal-summary').innerHTML = '';
    document.getElementById('seal-error-card').classList.remove('visible');
    document.getElementById('seal-error-card').innerHTML = '';
    document.getElementById('seal-download-wrap').classList.remove('visible');
    document.getElementById('seal-api-error').classList.remove('visible');
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
    document.getElementById('verify-download-wrap').classList.remove('visible');
    document.getElementById('verify-api-error').classList.remove('visible');
    document.getElementById('field-report-container').style.display = 'none';
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
    document.getElementById('btn-seal-text').innerHTML = '<span class="btn-spinner"></span> Processing…';

    // Reset pipeline UI
    buildPipelineUI('seal-pipeline', SEAL_STEPS);
    document.getElementById('seal-summary').classList.remove('visible');
    document.getElementById('seal-error-card').classList.remove('visible');
    document.getElementById('seal-download-wrap').classList.remove('visible');

    // Fire API call
    const formData = new FormData();
    formData.append('document', sealFile);
    formData.append('password', password);
    formData.append('keypass', keypass);

    const apiPromise = fetch('/api/seal', { method: 'POST', body: formData })
        .then(async (res) => {
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || `Server error ${res.status}`);
            }
            return res.json();
        });

    // Run animation + API in parallel
    const animPromise = runPipelineAnimation('seal-pipeline', SEAL_STEPS);

    try {
        const [apiResult, animResult] = await Promise.all([apiPromise, animPromise]);

        // Store download data
        sealedZipFilename = apiResult.zip_filename;
        sealedZipData = apiResult.zip_data;

        // Show summary
        const fieldCount = apiResult.field_count || 31;
        showSealSummary(fieldCount, animResult.totalTime);

        // Show download button
        const dlWrap = document.getElementById('seal-download-wrap');
        dlWrap.classList.add('visible');
        document.getElementById('seal-download-sub').textContent = sealedZipFilename;
        const dlBtn = document.getElementById('btn-download-zip');
        dlBtn.classList.add('glow');
        setTimeout(() => dlBtn.classList.remove('glow'), 3200);

        // Add to audit log
        addAuditRecord(sealFile.name, apiResult.hash, 'SEALED', 'success');

        // Change button to Reset
        btn.disabled = false;
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-reset');
        document.getElementById('btn-seal-text').textContent = '↺ Reset';
        btn.onclick = () => {
            resetSealPipeline();
            removeSealFile();
        };

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
        btn.classList.remove('btn-primary');
        btn.classList.add('btn-reset');
        document.getElementById('btn-seal-text').textContent = '↺ Try Again';
        btn.onclick = () => {
            resetSealPipeline();
        };
    }
}

function showSealSummary(fieldCount, totalTime) {
    const el = document.getElementById('seal-summary');
    el.innerHTML = `
        <div class="summary-header">${SVG_CHECK_SM} ✓ Sealing Complete</div>
        <div class="summary-body">
            <div class="stat-row"><span class="stat-label">Fields processed</span><span class="stat-value">${fieldCount}</span></div>
            <div class="stat-row"><span class="stat-label">Hashes computed</span><span class="stat-value">${fieldCount} (SHA-256)</span></div>
            <div class="stat-row"><span class="stat-label">Signature</span><span class="stat-value">RSA-4096</span></div>
            <div class="stat-row"><span class="stat-label">Encryption</span><span class="stat-value">AES-256-GCM</span></div>
            <div class="stat-row"><span class="stat-label">Blockchain</span><span class="stat-value">Ethereum Sepolia</span></div>
            <div class="stat-row"><span class="stat-label">Total time</span><span class="stat-value green">${totalTime.toFixed(1)}s</span></div>
        </div>
    `;
    el.classList.add('visible');
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
    document.getElementById('btn-verify-text').innerHTML = '<span class="btn-spinner"></span> Processing…';

    buildPipelineUI('verify-pipeline', VERIFY_STEPS);
    document.getElementById('verify-summary').classList.remove('visible');
    document.getElementById('verify-error-card').classList.remove('visible');
    document.getElementById('verify-download-wrap').classList.remove('visible');
    document.getElementById('field-report-container').style.display = 'none';

    const formData = new FormData();
    formData.append('document_zip', verifyZipFile);
    formData.append('password', password);

    const apiPromise = fetch('/api/verify', { method: 'POST', body: formData })
        .then(async (res) => {
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || `Server error ${res.status}`);
            }
            return res.json();
        });

    const animPromise = runPipelineAnimation('verify-pipeline', VERIFY_STEPS);

    try {
        const [apiResult, animResult] = await Promise.all([apiPromise, animPromise]);

        if (apiResult.overall === 'FAIL') {
            // Mark field integrity step as error
            setStepState('verify-pipeline', 8, 'error');
            // Keep step 9 as waiting
            setStepState('verify-pipeline', 9, 'waiting');

            // Show error card
            let errorMsg = 'One or more cryptographic checks failed.';
            if (apiResult.fields) {
                const tampered = Object.entries(apiResult.fields).filter(([,v]) => v.status !== 'INTACT');
                if (tampered.length > 0) {
                    errorMsg = `Field mismatch found in: <strong>${tampered.map(([k]) => k).join(', ')}</strong> — expected value does not match signed value.`;
                }
            }
            if (!apiResult.signature_valid) errorMsg = 'RSA signature verification failed — the document may have been re-signed with an untrusted key.';

            showErrorCard('verify-error-card', '⚠ Verification Failed', errorMsg);

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

        showVerifySummary(apiResult, intactCount, totalFields, tamperedCount, animResult.totalTime);
        renderFieldReport(apiResult.fields);

        // Show download
        if (recoveredData) {
            const dlWrap = document.getElementById('verify-download-wrap');
            dlWrap.classList.add('visible');
            const spanText = recoveredFilename.endsWith('.xml') ? '⬇ Download Decrypted XML' : '⬇ Download Original Document';
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
    el.innerHTML = `
        <div class="summary-header">${SVG_CHECK_SM} ✓ Verification Passed</div>
        <div class="summary-body">
            <div class="stat-row"><span class="stat-label">Fields checked</span><span class="stat-value green">${intactCount} / ${totalFields}  ✓</span></div>
            <div class="stat-row"><span class="stat-label">Signature</span><span class="stat-value green">${result.signature_valid ? 'Valid  ✓' : 'Invalid  ✗'}</span></div>
            <div class="stat-row"><span class="stat-label">Blockchain</span><span class="stat-value green">${result.root_matches ? 'Confirmed  ✓' : 'Mismatch  ✗'}</span></div>
            <div class="stat-row"><span class="stat-label">Tampered fields</span><span class="stat-value">${tamperedCount}</span></div>
            <div class="stat-row"><span class="stat-label">Verdict</span><span class="stat-value green">AUTHENTIC</span></div>
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
    document.getElementById('field-report-container').style.display = 'block';
}

// ═══════════════════ DOWNLOAD HANDLERS ═══════════════════

function downloadSealedZip() {
    if (!sealedZipData || !sealedZipFilename) return;
    downloadBase64File(sealedZipData, sealedZipFilename, 'application/zip');
    flashDownloadButton('seal-download-text', '✓ Download started', '⬇ Download Sealed ZIP');
}

function downloadRecoveredDocument() {
    if (!recoveredData || !recoveredFilename) return;
    const mime = recoveredFilename.endsWith('.xml') ? 'text/xml' : 'application/octet-stream';
    downloadBase64File(recoveredData, recoveredFilename, mime);
    const label = recoveredFilename.endsWith('.xml') ? '⬇ Download Decrypted XML' : '⬇ Download Original Document';
    flashDownloadButton('verify-download-text', '✓ Download started', label);
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
    const logsJson = localStorage.getItem('npl_audit_logs');
    const logs = logsJson ? JSON.parse(logsJson) : [];
    const tbody = document.getElementById('audit-table-body');
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
