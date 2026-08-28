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
                    // Fallback to fetch manually if background didn't catch it
                    analyzeManual(tab.url);
                }
            });
        }
    });
});

async function analyzeManual(url) {
    if (!url.startsWith('http')) {
        updateUIError("Extension cannot analyze this page.");
        return;
    }
    try {
        const res = await fetch('http://127.0.0.1:5000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        
        if (res.ok) {
            const data = await res.json();
            updateUI(data);
            chrome.storage.local.set({ [currentTabId]: data });
        } else {
            updateUIError("Backend server is not reachable.");
        }
    } catch (e) {
        updateUIError("Failed to connect to PhishGuard backend.");
    }
}

function updateUI(data) {
    const statusCard = document.getElementById('status-card');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    const xgbValue = document.getElementById('xgb-value');
    const xgbFill = document.getElementById('xgb-fill');
    const rfValue = document.getElementById('rf-value');
    const rfFill = document.getElementById('rf-fill');

    statusCard.className = 'status-card';
    
    if (data.is_phishing) {
        statusCard.classList.add('phishing');
        statusTitle.textContent = '⚠ PHISHING';
        statusDesc.innerHTML = 'This website may be dangerous.<br><br>Avoid entering passwords, banking information, or other sensitive information.';
    } else {
        statusCard.classList.add('safe');
        statusTitle.textContent = 'SAFE';
        statusDesc.textContent = 'This website appears to be legitimate.';
    }

    const xgbPerc = (data.xgb_confidence * 100).toFixed(1);
    xgbValue.textContent = `${xgbPerc}%`;
    xgbFill.style.width = `${xgbPerc}%`;
    xgbFill.style.background = data.xgb_is_phishing ? '#dc2626' : '#10b981';
    
    const rfPerc = (data.rf_confidence * 100).toFixed(1);
    rfValue.textContent = `${rfPerc}%`;
    rfFill.style.width = `${rfPerc}%`;
    rfFill.style.background = data.rf_is_phishing ? '#dc2626' : '#10b981';
}

function updateUIError(msg) {
    const statusCard = document.getElementById('status-card');
    const statusTitle = document.getElementById('status-title');
    const statusDesc = document.getElementById('status-desc');
    
    statusCard.className = 'status-card checking';
    statusTitle.textContent = 'ERROR';
    statusDesc.textContent = msg;
}

// Listen for privacy monitor messages
chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "SENSITIVE_FIELDS_DETECTED") {
        const data = message.data;
        if (data.hasPassword) {
            document.getElementById('pw-status').className = 'active';
        }
        if (data.hasEmail) {
            document.getElementById('email-status').className = 'active';
        }
        if (data.hasPayment) {
            document.getElementById('payment-status').className = 'active';
        }
    }
});
