const API_URL = 'http://127.0.0.1:5000/predict';

// Cache to avoid analyzing the same URL multiple times in a short window
const resultCache = new Map();

// Store temporary extension data per tab
const extensionDataCache = new Map();

async function checkThirdPartyCookies(url) {
    if (!chrome.cookies) return false;
    try {
        const parsedUrl = new URL(url);
        const domain = parsedUrl.hostname;
        
        // Very basic heuristic: check if there are cookies for this URL that belong to a different domain
        return new Promise((resolve) => {
            chrome.cookies.getAll({ url: url }, (cookies) => {
                let hasThirdParty = false;
                if (cookies) {
                    for (let cookie of cookies) {
                        if (!domain.includes(cookie.domain) && !cookie.domain.includes(domain)) {
                            hasThirdParty = true;
                            break;
                        }
                    }
                }
                resolve(hasThirdParty);
            });
        });
    } catch (e) {
        return false;
    }
}

async function analyzeUrl(url, tabId) {
    if (!url || !url.startsWith('http')) {
        return;
    }

    // Initialize extension data cache for this tab if empty
    if (!extensionDataCache.has(tabId)) {
        extensionDataCache.set(tabId, {
            sensitive_fields: { hasPassword: false, hasEmail: false, hasPayment: false },
            has_third_party_cookies: false
        });
    }
    
    // Check cookies
    const hasThirdParty = await checkThirdPartyCookies(url);
    const tabData = extensionDataCache.get(tabId);
    tabData.has_third_party_cookies = hasThirdParty;
    extensionDataCache.set(tabId, tabData);

    if (resultCache.has(url)) {
        updateTabState(tabId, url, resultCache.get(url));
        return;
    }

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            console.error('API Error:', response.statusText);
            const errorData = {
                risk_level: "UNKNOWN",
                message: "Analysis service unavailable.",
                error: true
            };
            updateTabState(tabId, url, errorData);
            return;
        }

        const data = await response.json();
        resultCache.set(url, data);
        updateTabState(tabId, url, data);
        
    } catch (error) {
        console.error('Failed to analyze URL:', error);
        const errorData = {
            risk_level: "UNKNOWN",
            message: "Network timeout or backend unavailable.",
            error: true
        };
        updateTabState(tabId, url, errorData);
    }
}

function updateTabState(tabId, url, apiData) {
    // Merge API data with extension monitoring data
    const extData = extensionDataCache.get(tabId) || {
        sensitive_fields: { hasPassword: false, hasEmail: false, hasPayment: false },
        has_third_party_cookies: false
    };
    
    const finalData = { ...apiData, ...extData };
    
    chrome.storage.local.set({ [tabId]: finalData });
    
    // Change icon based on risk level
    if (finalData.risk_level === 'HIGH' || finalData.is_phishing) {
        chrome.action.setBadgeText({ text: '!', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId: tabId });
    } else if (finalData.risk_level === 'UNKNOWN') {
        chrome.action.setBadgeText({ text: '?', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#888888', tabId: tabId });
    } else {
        chrome.action.setBadgeText({ text: '✓', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#00FF00', tabId: tabId });
    }
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SENSITIVE_FIELDS_DETECTED" && sender.tab) {
        const tabId = sender.tab.id;
        
        let tabData = extensionDataCache.get(tabId);
        if (!tabData) {
            tabData = { sensitive_fields: message.data, has_third_party_cookies: false };
        } else {
            tabData.sensitive_fields = message.data;
        }
        extensionDataCache.set(tabId, tabData);
        
        // Re-sync storage
        chrome.storage.local.get([tabId.toString()], (result) => {
            if (result[tabId]) {
                const finalData = { ...result[tabId], ...tabData };
                chrome.storage.local.set({ [tabId]: finalData });
            }
        });
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        analyzeUrl(tab.url, tabId);
    }
});

chrome.tabs.onActivated.addListener(activeInfo => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab && tab.url) {
            analyzeUrl(tab.url, activeInfo.tabId);
        }
    });
});
