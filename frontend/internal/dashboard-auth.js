// NPL DocSeal: lightweight dashboard access gate.
// Not real auth: just enough to stop casual public misuse of a live
// demo's real signing key and real (test) Ethereum wallet. The actual
// enforcement happens server-side (core/auth.py); this only decides
// when to show the overlay and attaches the key to protected requests.

document.addEventListener('DOMContentLoaded', () => {
    const gate = document.getElementById('dashboard-gate');
    const form = document.getElementById('dashboard-gate-form');
    const input = document.getElementById('dashboard-gate-key');

    if (sessionStorage.getItem('dashboard_key') !== null) {
        gate.classList.remove('visible');
    }

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        sessionStorage.setItem('dashboard_key', input.value);
        gate.classList.remove('visible');
    });
});

function dashboardAuthHeaders() {
    return { 'X-Dashboard-Key': sessionStorage.getItem('dashboard_key') || '' };
}
