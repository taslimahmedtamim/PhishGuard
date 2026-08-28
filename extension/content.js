// Privacy Monitoring: Detect sensitive fields without extracting data
function detectSensitiveFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const emailFields = document.querySelectorAll('input[type="email"]');
    const paymentFields = document.querySelectorAll('input[name*="card"], input[name*="cc-number"], input[name*="cvv"]');

    const result = {
        hasPassword: passwordFields.length > 0,
        hasEmail: emailFields.length > 0,
        hasPayment: paymentFields.length > 0
    };

    chrome.runtime.sendMessage({ type: "SENSITIVE_FIELDS_DETECTED", data: result });
}

// Run on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', detectSensitiveFields);
} else {
    detectSensitiveFields();
}
