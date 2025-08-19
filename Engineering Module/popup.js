function showStatus(message, type) {
    const statusNode = document.getElementById('status');
    statusNode.className = `status ${type} show`;
    
    let icon = '';
    switch(type) {
        case 'safe':
            icon = '✅';
            break;
        case 'danger':
            icon = '⚠️';
            break;
        case 'info':
            icon = 'ℹ️';
            break;
        case 'error':
            icon = '❌';
            break;
    }
    
    statusNode.innerHTML = `<span class="status-icon">${icon}</span>${message}`;
}

function setButtonLoading(loading) {
    const button = document.getElementById('scan');
    if (loading) {
        button.classList.add('loading');
        button.innerHTML = 'Scanning...';
    } else {
        button.classList.remove('loading');
        button.innerHTML = '🔍 Scan This Page';
    }
}

function sendScan(tabId){
    chrome.tabs.sendMessage(tabId, { type: 'SCAN_PAGE' }, function(response){
        if (chrome.runtime.lastError) {
            showStatus('Injecting scanner...', 'info');
            chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['jquery-3.1.1.min.js'] }, function(){
                if (chrome.runtime.lastError) {
                    setButtonLoading(false);
                    showStatus('Cannot access this page. Open a normal website and try again.', 'error');
                    return;
                }
                chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['content.js'] }, function(){
                    if (chrome.runtime.lastError) {
                        setButtonLoading(false);
                        showStatus('Cannot access this page. Open a normal website and try again.', 'error');
                        return;
                    }
                    // Try again after injection
                    setTimeout(() => {
                        chrome.tabs.sendMessage(tabId, { type: 'SCAN_PAGE' }, function(resp2){
                            setButtonLoading(false);
                            if (!resp2) {
                                showStatus('Scanner injected. Reload page if it still fails.', 'info');
                                return;
                            }
                            if (resp2.prediction === 1) {
                                showStatus('🚨 PHISHING DETECTED! This page appears to be malicious.', 'danger');
                            } else {
                                showStatus('✅ SAFE! No phishing threats detected on this page.', 'safe');
                            }
                        });
                    }, 500);
                });
            });
            return;
        }
        if (!response) {
            setButtonLoading(false);
            showStatus('No response from content script.', 'error');
            return;
        }
        setButtonLoading(false);
        if (response.prediction === 1) {
            showStatus('🚨 PHISHING DETECTED! This page appears to be malicious.', 'danger');
        } else {
            showStatus('✅ SAFE! No phishing threats detected on this page.', 'safe');
        }
    });
}

document.getElementById('scan').addEventListener('click', function(){
    const button = this;
    if (button.classList.contains('loading')) return;
    
    setButtonLoading(true);
    showStatus('Initializing scan...', 'info');
    
    chrome.tabs.query({ active: true, currentWindow: true }, function(tabs){
        if (!tabs || !tabs.length) { 
            setButtonLoading(false);
            showStatus('No active tab found.', 'error');
            return; 
        }
        sendScan(tabs[0].id);
    });
});

