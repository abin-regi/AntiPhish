// Create a self-executing function to avoid global scope pollution
(function() {
  // Function to create and show the warning overlay
  function createWarningOverlay(suspiciousUrl) {
    // Remove any existing overlay first
    const existingOverlay = document.getElementById('phishing-warning-overlay');
    if (existingOverlay) {
      existingOverlay.remove();
    }

    const overlay = document.createElement('div');
    overlay.id = 'phishing-warning-overlay';
    overlay.innerHTML = `
        <div class="warning-content">
            <h2>⚠️ Warning: Potential Phishing Attempt</h2>
            <p>The link you clicked may be dangerous:</p>
            <p class="suspicious-url">${suspiciousUrl}</p>
            <p>This site might be trying to steal your personal information.</p>
            <div class="warning-buttons">
                <button id="warning-back-button">Go Back</button>
                <button id="warning-continue-button">Continue Anyway</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    const backButton = document.getElementById('warning-back-button');
    const continueButton = document.getElementById('warning-continue-button');

    backButton.addEventListener('click', function() {
        // First remove the overlay
        overlay.remove();
        
        // Try window.history.back() first
        try {
            window.history.back();
        } catch (error) {
            console.error('Error using history.back():', error);
            
            // If history.back() fails, try the extension's goBack functionality
            chrome.runtime.sendMessage({ 
                action: 'goBack',
                url: window.location.href
            }, (response) => {
                if (!response || !response.success) {
                    // Final fallback: try to close the current tab
                    chrome.runtime.sendMessage({
                        action: 'closeTab'
                    });
                }
            });
        }
    });

    continueButton.addEventListener('click', function() {
        const confirmed = window.confirm('Are you absolutely sure you want to continue? This site may steal your personal information!');
        
        if (confirmed) {
            // First approve the URL to prevent infinite warning loops
            chrome.runtime.sendMessage({ 
                action: 'proceed',
                url: suspiciousUrl
            }, (response) => {
                if (response && response.success) {
                    overlay.remove();
                    // Use chrome.tabs.update for navigation if possible
                    chrome.runtime.sendMessage({
                        action: 'navigateTab',
                        url: suspiciousUrl
                    }, (navResponse) => {
                        if (!navResponse || !navResponse.success) {
                            // Fallback: direct navigation
                            window.location.href = suspiciousUrl;
                        }
                    });
                } else {
                    console.error('Failed to proceed to URL');
                    overlay.remove();
                    // Fallback: direct navigation with a slight delay
                    setTimeout(() => {
                        window.location.href = suspiciousUrl;
                    }, 100);
                }
            });
        }
    });

    return overlay;
  }

  // Listen for messages from the background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
      createWarningOverlay(message.url);
      sendResponse({ success: true });
      return true; // Keep the message channel open for async response
    }
  });
})(); 