// NPL DocSeal: standalone public verification page.
// Deliberately self-contained (no shared JS module with the internal
// dashboard) since this page has nothing else in common with it: no
// pipeline animation, no tabs, no audit log, just one upload and one
// result render.

let publicCertFile = null;

const SVG_CHECK_SM = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>';
const SVG_ALERT = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('cert-dropzone');
    const input = document.getElementById('cert-upload');
    const label = document.getElementById('cert-file-label');

    input.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            publicCertFile = e.target.files[0];
            label.textContent = publicCertFile.name;
        }
    });

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-active');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-active'));
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-active');
        if (e.dataTransfer.files.length > 0) {
            publicCertFile = e.dataTransfer.files[0];
            label.textContent = publicCertFile.name;
        }
    });
});

function showApiError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = `Error: ${message}`;
    el.classList.add('visible');
}

function hideApiError(elementId) {
    const el = document.getElementById(elementId);
    el.classList.remove('visible');
    el.textContent = '';
}

async function verifyPublicCertificate() {
    hideApiError('public-verify-api-error');

    if (!publicCertFile) {
        showApiError('public-verify-api-error', 'Please upload a certificate XML file first.');
        return;
    }

    const btn = document.getElementById('btn-public-verify');
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    document.getElementById('public-verify-result').innerHTML = '';

    const formData = new FormData();
    formData.append('document', publicCertFile);

    try {
        const res = await fetch('/api/public/verify', { method: 'POST', body: formData });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Server error ${res.status}`);
        }
        const result = await res.json();
        renderPublicResult(result);
    } catch (err) {
        showApiError('public-verify-api-error', err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Verify Certificate';
    }
}

function renderPublicResult(result) {
    const container = document.getElementById('public-verify-result');

    if (!result.found) {
        container.innerHTML = `
            <div class="card result-unknown">
                <div class="summary-header">No Record Found</div>
                <p class="page-desc">${result.message || 'No NPL record exists for this certificate number.'}</p>
            </div>
        `;
        return;
    }

    if (result.revoked) {
        const details = result.revocation_details || {};
        container.innerHTML = `
            <div class="failure-banner revoked visible">
                <div class="failure-header">${SVG_ALERT} Certificate Revoked</div>
                <div class="failure-body">
                    <div class="fb-row"><span class="fb-label">Certificate</span><span class="fb-value">${result.certificate_number}</span></div>
                    <div class="fb-row"><span class="fb-label">Reason</span><span class="fb-value">${details.revoked_reason || 'N/A'}</span></div>
                    <div class="fb-row"><span class="fb-label">Revoked At</span><span class="fb-value">${details.revoked_at ? new Date(details.revoked_at).toLocaleString() : 'N/A'}</span></div>
                </div>
                <div class="failure-footer">This certificate is cryptographically valid but has since been invalidated by NPL, not a tampering signal.</div>
            </div>
            ${renderFieldTable(result.fields)}
        `;
        return;
    }

    if (result.overall === 'PASS') {
        container.innerHTML = `
            <div class="pipeline-summary visible">
                <div class="summary-header">${SVG_CHECK_SM} Certificate Verified</div>
                <div class="summary-body">
                    <div class="stat-row"><span class="stat-label">Certificate</span><span class="stat-value">${result.certificate_number}</span></div>
                    <div class="stat-row"><span class="stat-label">Signature</span><span class="stat-value green">Valid</span></div>
                    <div class="stat-row"><span class="stat-label">Merkle Root</span><span class="stat-value green">Matches</span></div>
                    <div class="stat-row"><span class="stat-label">Sealed At</span><span class="stat-value">${new Date(result.sealed_at).toLocaleString()}</span></div>
                </div>
            </div>
            ${renderFieldTable(result.fields)}
        `;
        return;
    }

    container.innerHTML = `
        <div class="failure-banner visible">
            <div class="failure-header">${SVG_ALERT} Verification Failed</div>
            <div class="failure-body">
                <div class="fb-row"><span class="fb-label">Certificate</span><span class="fb-value">${result.certificate_number}</span></div>
                <div class="fb-row"><span class="fb-label">Signature Valid</span><span class="fb-value">${result.signature_valid ? 'Yes' : 'No'}</span></div>
                <div class="fb-row"><span class="fb-label">Merkle Root Matches</span><span class="fb-value">${result.root_matches ? 'Yes' : 'No'}</span></div>
            </div>
            <div class="failure-footer">One or more fields do not match what NPL originally sealed.</div>
        </div>
        ${renderFieldTable(result.fields)}
    `;
}

function renderFieldTable(fields) {
    if (!fields || Object.keys(fields).length === 0) return '';

    const rows = Object.entries(fields).map(([name, info]) => {
        return `<tr>
            <td>${name}</td>
            <td>${info.value}</td>
            <td class="field-status-${info.status}">${info.status}</td>
        </tr>`;
    }).join('');

    return `
        <div class="card audit-card">
            <h3>Field-Level Detail</h3>
            <div class="table-container">
                <table class="audit-table">
                    <thead><tr><th>Field</th><th>Value</th><th>Status</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        </div>
    `;
}
