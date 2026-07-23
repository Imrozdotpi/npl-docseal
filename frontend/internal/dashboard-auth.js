// NPL DocSeal: dashboard access gate.
// Not real auth: just enough to stop casual public misuse of a live
// demo's real signing key and real (test) Ethereum wallet. The actual
// enforcement is server-side (core/auth.py, POST /api/seal and
// POST /api/audit/clear both require the correct key). This gate's job
// is to check that same key against the server BEFORE ever showing the
// dashboard, so a wrong or missing key never gets in, not to just take
// whatever was typed on faith.

document.addEventListener('DOMContentLoaded', () => {
    const gate = document.getElementById('dashboard-gate');
    const form = document.getElementById('dashboard-gate-form');
    const input = document.getElementById('dashboard-gate-key');
    const submitBtn = document.getElementById('dashboard-gate-submit');
    const errorEl = document.getElementById('dashboard-gate-api-error');

    async function keyIsValid(key) {
        try {
            const res = await fetch('/api/internal/check-access', {
                method: 'POST',
                headers: { 'X-Dashboard-Key': key || '' }
            });
            return res.ok;
        } catch (err) {
            return false;
        }
    }

    function showGateError(message) {
        errorEl.innerHTML = `<strong>Error:</strong> ${message}`;
        errorEl.classList.add('visible');
    }

    function hideGateError() {
        errorEl.classList.remove('visible');
        errorEl.innerHTML = '';
    }

    async function tryStoredKey() {
        const stored = sessionStorage.getItem('dashboard_key');
        // Also covers the case where no access key is configured
        // server-side at all: checking with an empty key succeeds, so
        // the gate never bothers the user in that case.
        const valid = await keyIsValid(stored || '');
        if (valid) {
            sessionStorage.setItem('dashboard_key', stored || '');
            gate.classList.remove('visible');
        } else {
            sessionStorage.removeItem('dashboard_key');
        }
    }

    tryStoredKey();

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideGateError();
        submitBtn.disabled = true;
        submitBtn.textContent = 'Checking...';

        const key = input.value;
        const valid = await keyIsValid(key);

        submitBtn.disabled = false;
        submitBtn.textContent = 'Unlock';

        if (valid) {
            sessionStorage.setItem('dashboard_key', key);
            gate.classList.remove('visible');
        } else {
            showGateError('Incorrect access key.');
            input.value = '';
            input.focus();
        }
    });
});

function dashboardAuthHeaders() {
    return { 'X-Dashboard-Key': sessionStorage.getItem('dashboard_key') || '' };
}
