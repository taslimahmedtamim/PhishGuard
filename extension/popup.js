let currentUrl = '';
let currentTabId = null;

document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs[0];
        if (tab && tab.url) {
            currentUrl = tab.url;
            currentTabId = tab.id;
            
            try {
                const domain = new URL(tab.url).hostname;
                document.getElementById('domain-name').textContent = domain;
            } catch (e) {
                document.getElementById('domain-name').textContent = tab.url;
            }

            // Check if we already have a result from background script
            chrome.storage.local.get([currentTabId.toString()], (result) => {
                if (result[currentTabId]) {
                    updateUI(result[currentTabId]);
                } else {
                    updateUIError("Analyzing URL...");
                }
            });
        }
    });
});

function updateUI(data) {
    const statusCard = document.getElementById('status-card');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    
    document.getElementById('risk-level-container').style.display = 'block';
    document.getElementById('model-score-container').style.display = 'block';
    
    document.getElementById('risk-level').textContent = data.risk_level || 'UNKNOWN';
    if (data.risk_score !== undefined) {
        document.getElementById('model-score').textContent = (data.risk_score * 100).toFixed(1) + '%';
    } else {
        document.getElementById('model-score').textContent = 'N/A';
    }

    statusCard.className = 'status-card';
    
    if (data.error && data.risk_level === 'UNKNOWN') {
        updateUIError(data.message || "Analysis incomplete.");
        return;
    }

    if (data.is_phishing || data.risk_level === 'HIGH') {
        statusCard.classList.add('phishing');
        statusTitle.textContent = '🔴 PHISHING';
        statusDesc.innerHTML = '⚠️ ' + (data.message || 'Potential phishing website detected.') + '<br><br><strong>Do not enter sensitive information.</strong>';
    } else {
        statusCard.classList.add('safe');
        statusTitle.textContent = '🟢 SAFE';
        statusDesc.textContent = data.message || 'Website appears legitimate based on analysis.';
    }

    // Update Security Analysis Details
    if (data.features) {
        document.getElementById('sa-url-val').textContent = data.features.url_length > 100 ? 'Suspiciously Long' : 'Normal';
        document.getElementById('sa-https-val').textContent = data.features.contains_https ? 'Enabled' : 'No';
        document.getElementById('sa-ip-val').textContent = data.features.contains_ip ? 'Yes' : 'No';
        
        if (data.features.whois_available) {
            document.getElementById('sa-whois-val').textContent = data.features.domain_age_days ? `${data.features.domain_age_days} days` : 'Available';
        } else {
            document.getElementById('sa-whois-val').textContent = 'Unavailable';
        }

        // Detailed View
        document.getElementById('det-url-len').textContent = data.features.url_length || '-';
        document.getElementById('det-path-len').textContent = data.features.path_length || '-';
        document.getElementById('det-dots').textContent = data.features.num_dots || '-';
        document.getElementById('det-entropy').textContent = data.features.entropy ? data.features.entropy.toFixed(2) : '-';
        document.getElementById('det-cert').textContent = data.features.cert_issuer || 'Unknown';
    }

    // Update Privacy Monitor Details (from Extension Data)
    if (data.sensitive_fields) {
        document.getElementById('pw-status').textContent = data.sensitive_fields.hasPassword ? 'YES' : 'No';
        document.getElementById('pw-status').className = data.sensitive_fields.hasPassword ? 'active' : 'inactive';
        
        document.getElementById('email-status').textContent = data.sensitive_fields.hasEmail ? 'YES' : 'No';
        document.getElementById('email-status').className = data.sensitive_fields.hasEmail ? 'active' : 'inactive';
    }
    
    if (data.has_third_party_cookies !== undefined) {
        document.getElementById('cookie-status').textContent = data.has_third_party_cookies ? 'Detected' : 'None detected';
        document.getElementById('cookie-status').className = data.has_third_party_cookies ? 'active' : 'inactive';
    }
}

function updateUIError(msg) {
    const statusCard = document.getElementById('status-card');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    
    document.getElementById('risk-level-container').style.display = 'none';
    document.getElementById('model-score-container').style.display = 'none';
    
    statusCard.className = 'status-card checking';
    statusTitle.textContent = 'UNKNOWN';
    statusDesc.textContent = msg;
}

// Listen for dynamic updates (e.g. if background script finishes while popup is open)
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes[currentTabId.toString()]) {
        updateUI(changes[currentTabId.toString()].newValue);
    }
});
