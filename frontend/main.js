// State Variables
let currentTab = 'seal';
let sealFile = null;
let verifyZipFile = null;

// Sealed details
let sealedZipFilename = '';
let sealedZipData = ''; // Base64

// Decrypted details
let recoveredPdfFilename = '';
let recoveredPdfData = ''; // Base64

// Initialize Page
document.addEventListener('DOMContentLoaded', () => {
    setupDragAndDrop();
    loadAuditLogs();
});

// Tab Switching
function switchTab(tabId) {
    currentTab = tabId;
    
    // Toggle active nav menu item
    document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`nav-btn-${tabId}`).classList.add('active');
    
    // Toggle active tab content
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');
    
    // Update top header description
    const titleEl = document.getElementById('current-page-title');
    const descEl = document.getElementById('current-page-desc');
    
    if (tabId === 'seal') {
        titleEl.textContent = 'Seal Document';
        descEl.textContent = 'Encrypt, digitally sign, and timestamp PDF documents.';
    } else if (tabId === 'verify') {
        titleEl.textContent = 'Verify & Recover';
        descEl.textContent = 'Verify cryptographic authenticity, verify timestamps, and recover original documents.';
    } else if (tabId === 'audit') {
        titleEl.textContent = 'Audit Log';
        descEl.textContent = 'Inspect historical sealing and verification logs persisted in this session.';
        loadAuditLogs();
    }
}

// Drag and Drop Utilities
function setupDragAndDrop() {
    // 1. Seal Document File Dropzone
    const sealDropzone = document.getElementById('seal-dropzone');
    const pdfUpload = document.getElementById('pdf-upload');
    
    setupDropzoneListeners(sealDropzone, pdfUpload, (file) => {
        if (file.type === 'application/pdf') {
            sealFile = file;
            displaySealFileInfo(file.name);
        } else {
            alert('Only PDF files are supported.');
        }
    });
    
    pdfUpload.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            const file = e.target.files[0];
            if (file.type === 'application/pdf') {
                sealFile = file;
                displaySealFileInfo(file.name);
            } else {
                alert('Only PDF files are supported.');
            }
        }
    });

    // 2. Verify Tab File Fields (Single ZIP)
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
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            onFileSelect(files[0]);
        }
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

// Seal File UI updates
function displaySealFileInfo(filename) {
    document.getElementById('seal-dropzone').style.display = 'none';
    const infoBox = document.getElementById('seal-file-info');
    infoBox.style.display = 'flex';
    infoBox.querySelector('.file-name-text').textContent = filename;
}

function removeSealFile() {
    sealFile = null;
    document.getElementById('pdf-upload').value = '';
    document.getElementById('seal-file-info').style.display = 'none';
    document.getElementById('seal-dropzone').style.display = 'flex';
    document.getElementById('seal-console').innerHTML = '<div class="console-line text-muted">&gt; System idle. Awaiting document upload...</div>';
    document.getElementById('seal-actions').style.display = 'none';
}

// Console helper
function logToConsole(text, type = 'info') {
    const consoleEl = document.getElementById('seal-console');
    const line = document.createElement('div');
    line.className = `console-line text-${type}`;
    
    const time = new Date().toLocaleTimeString();
    line.innerHTML = `<span class="text-muted">[${time}]</span> ${text}`;
    
    consoleEl.appendChild(line);
    // Auto scroll to bottom
    const box = consoleEl.parentElement;
    box.scrollTop = box.scrollHeight;
}

// Action: Seal Document
async function sealDocument() {
    if (!sealFile) {
        alert('Please upload a PDF document first.');
        return;
    }
    const password = document.getElementById('encryption-password').value;
    const keypass = document.getElementById('key-passphrase').value;
    
    if (!password) {
        alert('Please enter an encryption password.');
        return;
    }
    if (!keypass) {
        alert('Please enter the private key passphrase.');
        return;
    }

    // Reset UI
    document.getElementById('seal-console').innerHTML = '';
    document.getElementById('seal-actions').style.display = 'none';
    
    logToConsole('Initializing security pipeline...', 'info');
    logToConsole(`File targeted: ${sealFile.name} (${(sealFile.size / 1024).toFixed(2)} KB)`, 'info');
    logToConsole('Packaging payload and preparing keys...', 'info');

    // Create Form data
    const formData = new FormData();
    formData.append('document', sealFile);
    formData.append('password', password);
    formData.append('keypass', keypass);

    try {
        logToConsole('Transmitting document to secure backend...', 'info');
        
        const response = await fetch('/api/seal', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Internal Cryptographic Server Error');
        }

        const result = await response.json();
        
        // Log steps with green checks
        logToConsole(`[SUCCESS] HASH: SHA-256 Generated successfully.`, 'success');
        logToConsole(`Hash Value: ${result.hash}`, 'info');
        logToConsole(`[SUCCESS] SIGNATURE: RSA-PSS Signature Created (using keys/private_key.pem).`, 'success');
        logToConsole(`[SUCCESS] TIMESTAMP: OpenTimestamp Proof Created (.ots timestamp broadcast via WSL).`, 'success');
        logToConsole(`[SUCCESS] ENCRYPTION: AES-256-GCM Encryption Complete (.enc document output).`, 'success');
        logToConsole(`[SUCCESS] Final payload packaged into secure ZIP. Ready for download.`, 'success');

        // Store ZIP details
        sealedZipFilename = result.zip_filename;
        sealedZipData = result.zip_data;

        // Show download buttons
        document.getElementById('seal-actions').style.display = 'block';

        // Add to Audit Log
        addAuditRecord(sealFile.name, result.hash, 'SEALED', 'success');

    } catch (error) {
        logToConsole(`[ERROR] Operations halted. Execution failed: ${error.message}`, 'error');
    }
}

// Action: Download Sealed ZIP
function downloadSealedZip() {
    if (!sealedZipData || !sealedZipFilename) return;
    
    const binaryString = window.atob(sealedZipData);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    const blob = new Blob([bytes], {type: 'application/zip'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sealedZipFilename;
    link.click();
}

// Action: Verify Document
async function verifyDocument() {
    if (!verifyZipFile) {
        alert('Please upload the sealed ZIP package (.zip) to proceed.');
        return;
    }
    const password = document.getElementById('verify-password').value;
    if (!password) {
        alert('Please enter the decryption password.');
        return;
    }

    // Toggle states
    document.getElementById('verify-idle-state').style.display = 'none';
    const resultPanel = document.getElementById('verify-result-panel');
    const resultsState = document.getElementById('verify-results-state');
    resultsState.style.display = 'none';

    // Show processing banner
    logToConsole('Initiating verifying operations...', 'info');

    const formData = new FormData();
    formData.append('document_zip', verifyZipFile);
    formData.append('password', password);

    try {
        const response = await fetch('/api/verify', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Internal Verifier Error');
        }

        const result = await response.json();
        const report = result.report;

        // Render Report Card
        resultsState.style.display = 'flex';
        
        // 1. Overall banner styling
        const banner = document.getElementById('banner-authenticity');
        banner.className = 'authenticity-banner'; // Clear previous
        
        if (report.authenticity_status === 'authentic') {
            banner.classList.add('banner-authentic');
            banner.querySelector('.banner-title').textContent = 'AUTHENTICITY VERIFIED';
            banner.querySelector('.banner-desc').textContent = 'Document integrity, RSA signature, and blockchain timestamp have been successfully verified.';
        } else {
            banner.classList.add('banner-compromised');
            banner.querySelector('.banner-title').textContent = 'SECURITY ALERT: TAMPERED / COMPROMISED';
            banner.querySelector('.banner-desc').textContent = 'One or more cryptographic controls failed. Integrity is compromised.';
        }

        // 2. Status Box breakdowns
        updateStatusBox('box-encryption', report.encryption_status === 'decrypted' ? 'DECRYPTED' : 'FAILED', report.encryption_status === 'decrypted' ? 'success' : 'danger');
        
        let sigText = 'INVALID';
        let sigClass = 'danger';
        if (report.signature_status === 'valid') {
            sigText = 'VALID';
            sigClass = 'success';
        } else if (report.signature_status === 'unverified') {
            sigText = 'UNVERIFIED';
            sigClass = 'warning';
        }
        updateStatusBox('box-signature', sigText, sigClass);

        let otsText = 'FAILED';
        let otsClass = 'danger';
        if (report.timestamp_status === 'confirmed') {
            otsText = 'VERIFIED';
            otsClass = 'success';
        } else if (report.timestamp_status === 'pending') {
            otsText = 'PENDING';
            otsClass = 'warning';
        } else if (report.timestamp_status === 'unverified') {
            otsText = 'UNVERIFIED';
            otsClass = 'warning';
        }
        updateStatusBox('box-timestamp', otsText, otsClass);

        // 3. Technical report detail logs
        document.getElementById('result-hash').textContent = report.sha256;
        document.getElementById('result-blockchain').textContent = report.blockchain || 'Bitcoin';
        document.getElementById('result-timestamp-status').textContent = (report.timestamp_status === 'confirmed' ? 'VERIFIED' : report.timestamp_status.toUpperCase());
        document.getElementById('result-block-height').textContent = report.block_height ? report.block_height : 'Not yet anchored';
        document.getElementById('result-timestamp-time').textContent = formatDateTime(report.timestamp_datetime);
        document.getElementById('result-details').textContent = report.details;

        // 4. Decrypted download action
        const downloadBtn = document.getElementById('btn-download-recovered');
        if (result.decrypted_data) {
            recoveredPdfFilename = result.original_filename;
            recoveredPdfData = result.decrypted_data;
            downloadBtn.style.display = 'inline-flex';
        } else {
            downloadBtn.style.display = 'none';
        }

        // Add to Audit Log
        const logStatusText = report.authenticity_status === 'authentic' ? 'VERIFIED' : 'TAMPERED';
        const logStatusClass = report.authenticity_status === 'authentic' ? 'success' : 'danger';
        addAuditRecord(verifyZipFile.name, report.sha256, logStatusText, logStatusClass);

    } catch (error) {
        alert('Server verification request failed: ' + error.message);
        document.getElementById('verify-idle-state').style.display = 'flex';
    }
}

function updateStatusBox(boxId, value, statusClass) {
    const box = document.getElementById(boxId);
    const valEl = box.querySelector('.status-value');
    valEl.textContent = value;
    valEl.className = 'status-value'; // Reset
    valEl.classList.add(`status-${statusClass}`);
}

// Download recovered document helper
function downloadRecoveredDocument() {
    if (!recoveredPdfData || !recoveredPdfFilename) return;
    
    const binaryString = window.atob(recoveredPdfData);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    
    const blob = new Blob([bytes], {type: 'application/pdf'});
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = recoveredPdfFilename;
    link.click();
}

// Audit Logs Manager
function loadAuditLogs() {
    const logsJson = localStorage.getItem('npl_audit_logs');
    const logs = logsJson ? JSON.parse(logsJson) : [];
    
    const tbody = document.getElementById('audit-table-body');
    tbody.innerHTML = '';
    
    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-muted" style="text-align: center;">No transaction records found.</td></tr>';
        return;
    }
    
    logs.reverse().forEach(log => {
        const row = document.createElement('tr');
        
        // Truncate hash
        const fullHash = log.hash;
        const displayHash = fullHash && fullHash !== 'unknown' ? `${fullHash.substring(0, 12)}...${fullHash.substring(fullHash.length - 12)}` : 'N/A';
        
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
    
    const dateStr = new Date().toLocaleString();
    
    logs.push({
        filename: filename,
        timestamp: dateStr,
        hash: hash,
        action: action,
        badgeClass: badgeClass
    });
    
    localStorage.setItem('npl_audit_logs', JSON.stringify(logs));
}

function clearAudit() {
    if (confirm('Are you sure you want to clear all transaction logs?')) {
        localStorage.removeItem('npl_audit_logs');
        loadAuditLogs();
    }
}

function formatDateTime(isoStr) {
    if (!isoStr) return 'Awaiting blockchain anchoring';
    try {
        const d = new Date(isoStr);
        return d.toUTCString();
    } catch (e) {
        return isoStr;
    }
}
