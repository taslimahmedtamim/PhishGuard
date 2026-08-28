const API_URL = 'http://127.0.0.1:5000/predict';

// Cache to avoid analyzing the same URL multiple times in a short window
const resultCache = new Map();

async function analyzeUrl(url, tabId) {
    if (!url || !url.startsWith('http')) {
        return;
    }

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
            return;
        }

        const data = await response.json();
        resultCache.set(url, data);
        updateTabState(tabId, url, data);
        
    } catch (error) {
        console.error('Failed to analyze URL:', error);
    }
}

function updateTabState(tabId, url, data) {
    chrome.storage.local.set({ [tabId]: data });
    
    // Optionally change icon based on state
    if (data.is_phishing) {
        chrome.action.setBadgeText({ text: '!', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId: tabId });
    } else {
        chrome.action.setBadgeText({ text: '✓', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#00FF00', tabId: tabId });
    }
}

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
