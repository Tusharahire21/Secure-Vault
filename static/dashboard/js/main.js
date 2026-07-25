/**
 * SecureVault Dashboard – main.js
 * Handles ingest button loading state, auto-dismiss alerts
 */

document.addEventListener('DOMContentLoaded', function () {

    // ---- Ingest button: show spinner while submitting ----
    const ingestBtn = document.getElementById('btn-ingest');
    if (ingestBtn) {
        const ingestForm = ingestBtn.closest('form');
        if (ingestForm) {
            ingestForm.addEventListener('submit', function () {
                ingestBtn.disabled = true;
                ingestBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Ingesting…';
            });
        }
    }

    // ---- Auto-dismiss success/info alerts after 5 seconds ----
    const alerts = document.querySelectorAll('.sv-alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = new bootstrap.Alert(alert);
            if (document.contains(alert)) {
                bsAlert.close();
            }
        }, 5000);
    });

    // ---- Highlight active severity filter badge ----
    const severitySelect = document.getElementById('filter-severity');
    if (severitySelect && severitySelect.value) {
        severitySelect.style.borderColor = '#4f86f7';
    }

    // ---- Animate progress bars on load ----
    const bars = document.querySelectorAll('.sv-progress-bar');
    bars.forEach(function (bar) {
        const target = bar.style.width;
        bar.style.width = '0%';
        setTimeout(function () {
            bar.style.width = target;
        }, 100);
    });

    // ---- Table row click → detail page ----
    const rows = document.querySelectorAll('.sv-table-row');
    rows.forEach(function (row) {
        const detailBtn = row.querySelector('.sv-btn-detail');
        if (detailBtn) {
            row.style.cursor = 'pointer';
            row.addEventListener('click', function (e) {
                if (!e.target.closest('.sv-btn-detail')) {
                    detailBtn.click();
                }
            });
        }
    });
});
