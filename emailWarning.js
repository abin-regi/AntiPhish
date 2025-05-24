// Email warning component
class EmailWarningOverlay {
  constructor() {
    this.warningStyles = `
      .antiphish-warning {
        background-color: #fff3cd;
        border: 2px solid #ffeeba;
        border-radius: 4px;
        color: #856404;
        margin: 10px 0;
        padding: 15px;
        position: relative;
        z-index: 1000;
      }
      .antiphish-warning-icon {
        color: #dc3545;
        font-size: 18px;
        margin-right: 8px;
      }
      .antiphish-warning-header {
        font-weight: bold;
        margin-bottom: 8px;
      }
      .antiphish-warning-details {
        font-size: 14px;
        margin-top: 5px;
      }
      .antiphish-warning-reasons {
        margin-top: 10px;
        padding-left: 20px;
      }
      .antiphish-warning-buttons {
        display: flex;
        gap: 10px;
        margin-top: 15px;
      }
      .antiphish-warning-back-button {
        background-color: #4caf50;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
        font-size: 14px;
        transition: background-color 0.3s;
      }
      .antiphish-warning-back-button:hover {
        background-color: #388e3c;
      }
    `;
  }

  injectStyles() {
    if (!document.getElementById('antiphish-styles')) {
      const style = document.createElement('style');
      style.id = 'antiphish-styles';
      style.textContent = this.warningStyles;
      document.head.appendChild(style);
    }
  }

  createWarning(reasons) {
    const warningElement = document.createElement('div');
    warningElement.className = 'antiphish-warning';
    warningElement.innerHTML = `
      <div class="antiphish-warning-header">
        <span class="antiphish-warning-icon">⚠️</span>
        Potential Phishing Email Detected
      </div>
      <div class="antiphish-warning-details">
        This email contains suspicious content that may be an attempt to steal your information.
      </div>
      <ul class="antiphish-warning-reasons">
        ${reasons.map(reason => `<li>${reason}</li>`).join('')}
      </ul>
      <div class="antiphish-warning-buttons">
        <button class="antiphish-warning-back-button">Go Back</button>
      </div>
    `;

    // Add event listener for the back button
    const backButton = warningElement.querySelector('.antiphish-warning-back-button');
    backButton.addEventListener('click', () => {
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

    return warningElement;
  }

  insertWarning(emailContainer, reasons) {
    this.injectStyles();
    const existingWarning = emailContainer.querySelector('.antiphish-warning');
    if (!existingWarning) {
      const warning = this.createWarning(reasons);
      emailContainer.insertBefore(warning, emailContainer.firstChild);
    }
  }
}

// Export for use in content script
if (typeof window !== 'undefined') {
  window.EmailWarningOverlay = EmailWarningOverlay;
}

// Handle messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'createWarning') {
    const overlay = new EmailWarningOverlay();
    overlay.insertWarning(document.querySelector(message.container), message.reasons);
    sendResponse({ success: true });
    return true;
  }
}); 