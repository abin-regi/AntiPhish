// Create a self-executing function to avoid global scope pollution
(function() {
  // Inject required styles if not already present
  function injectStyles() {
    if (!document.getElementById('phishing-warning-styles')) {
      const styles = document.createElement('style');
      styles.id = 'phishing-warning-styles';
      styles.textContent = `
        #phishing-warning-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background-color: rgba(0, 0, 0, 0.9);
          z-index: 2147483647;
          display: flex;
          justify-content: center;
          align-items: center;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        
        .warning-content {
          background-color: white;
          padding: 2rem;
          border-radius: 8px;
          max-width: 600px;
          width: 90%;
          text-align: center;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        .warning-content h2 {
          color: #d32f2f;
          margin-top: 0;
        }
        
        .suspicious-url {
          background-color: #fff3e0;
          padding: 0.5rem;
          border-radius: 4px;
          word-break: break-all;
          font-family: monospace;
          margin: 1rem 0;
        }
        
        .warning-buttons {
          margin-top: 1.5rem;
          display: flex;
          justify-content: center;
          gap: 1rem;
        }
        
        .warning-buttons button {
          padding: 0.75rem 1.5rem;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 1rem;
          transition: background-color 0.2s;
        }
        
        #warning-back-button {
          background-color: #2196f3;
          color: white;
        }
        
        #warning-continue-button {
          background-color: #f44336;
          color: white;
        }
        
        #warning-back-button:hover {
          background-color: #1976d2;
        }
        
        #warning-continue-button:hover {
          background-color: #d32f2f;
        }
      `;
      document.head.appendChild(styles);
    }
  }

  // Function to create and show the warning overlay
  function createWarningOverlay(suspiciousUrl) {
    // Ensure styles are injected
    injectStyles();

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
            <p class="suspicious-url">${escapeHtml(suspiciousUrl)}</p>
            <p>This site might be trying to steal your personal information.</p>
            <div class="warning-buttons">
                <button id="warning-back-button">Go Back (Safe)</button>
                <button id="warning-continue-button">Continue Anyway (Unsafe)</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);

    const backButton = document.getElementById('warning-back-button');
    const continueButton = document.getElementById('warning-continue-button');

    // Enhanced back button functionality
    backButton.addEventListener('click', async function() {
        let navigationSuccessful = false;

        // 1. Try the extension's goBack with current URL
        try {
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage({ 
                    action: 'goBack',
                    url: window.location.href
                }, resolve);
            });
            
            if (response && response.success) {
                navigationSuccessful = true;
                overlay.remove();
                return;
            }
        } catch (error) {
            console.error('Extension goBack failed:', error);
        }

        // 2. Try window.history.back() if we have history
        if (!navigationSuccessful && window.history.length > 1) {
            try {
                overlay.remove();
                window.history.back();
                navigationSuccessful = true;
                return;
            } catch (error) {
                console.error('History back failed:', error);
            }
        }

        // 3. Final fallback: close tab or go to new tab
        if (!navigationSuccessful) {
            chrome.runtime.sendMessage({
                action: 'closeTab'
            }, (response) => {
                if (!response || !response.success) {
                    // If we can't close the tab, go to new tab page
                    window.location.href = 'chrome://newtab';
                }
            });
        }
    });

    continueButton.addEventListener('click', async function() {
        const confirmed = window.confirm(
            'WARNING: You are about to enter a potentially dangerous website.\n\n' +
            'This site may:\n' +
            '• Steal your personal information\n' +
            '• Install malware on your device\n' +
            '• Impersonate a legitimate website\n\n' +
            'Are you absolutely sure you want to continue?'
        );
        
        if (confirmed) {
            try {
                // First approve the URL
                const response = await new Promise((resolve) => {
                    chrome.runtime.sendMessage({ 
                        action: 'proceed',
                        url: suspiciousUrl
                    }, resolve);
                });

                if (response && response.success) {
                    overlay.remove();
                    // Try extension navigation first
                    const navResponse = await new Promise((resolve) => {
                        chrome.runtime.sendMessage({
                            action: 'navigateTab',
                            url: suspiciousUrl
                        }, resolve);
                    });

                    if (!navResponse || !navResponse.success) {
                        // Fallback: direct navigation
                        window.location.href = suspiciousUrl;
                    }
                } else {
                    console.error('Failed to proceed to URL');
                    overlay.remove();
                    // Fallback: direct navigation
                    window.location.href = suspiciousUrl;
                }
            } catch (error) {
                console.error('Error in continue navigation:', error);
                overlay.remove();
                // Final fallback
                window.location.href = suspiciousUrl;
            }
        }
    });

    return overlay;
  }

  // Helper function to escape HTML and prevent XSS
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Listen for messages from the background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'showWarning') {
      try {
        createWarningOverlay(message.url);
        sendResponse({ success: true });
      } catch (error) {
        console.error('Error showing warning overlay:', error);
        sendResponse({ success: false, error: error.message });
      }
      return true; // Keep the message channel open for async response
    }
  });
})(); 