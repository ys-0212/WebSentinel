function sendScan(tabId){
	chrome.tabs.sendMessage(tabId, { type: 'SCAN_PAGE' }, function(response){
		var statusNode = document.getElementById('status');
		if (chrome.runtime.lastError) {
			statusNode.textContent = 'Injecting scanner...';
			chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['jquery-3.1.1.min.js'] }, function(){
				if (chrome.runtime.lastError) {
					statusNode.textContent = 'Cannot access this page. Open a normal website and try again.';
					return;
				}
				chrome.scripting.executeScript({ target: { tabId: tabId }, files: ['content.js'] }, function(){
					if (chrome.runtime.lastError) {
						statusNode.textContent = 'Cannot access this page. Open a normal website and try again.';
						return;
					}
					// Try again after injection
					chrome.tabs.sendMessage(tabId, { type: 'SCAN_PAGE' }, function(resp2){
						if (!resp2) {
							statusNode.textContent = 'Scanner injected, reload page if it still fails.';
							return;
						}
						statusNode.textContent = resp2.prediction === 1 ? 'Phishing detected' : 'No phishing detected';
					});
				});
			});
			return;
		}
		if (!response) {
			document.getElementById('status').textContent = 'No response from content script.';
			return;
		}
		document.getElementById('status').textContent = response.prediction === 1 ? 'Phishing detected' : 'No phishing detected';
	});
}

document.getElementById('scan').addEventListener('click', function(){
	chrome.tabs.query({ active: true, currentWindow: true }, function(tabs){
		if (!tabs || !tabs.length) { return; }
		sendScan(tabs[0].id);
	});
});

