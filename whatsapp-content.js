// WhatsApp Web Configuration
const WHATSAPP_CONFIG = {
  selectors: {
    messageContainer: '._2gzeB, .message-in, .message-out', // Message containers
    messageText: '._21Ahp, .selectable-text', // Message text
    linkSelector: 'a[href]', // Links in messages
    chatContainer: '.app, ._1XkO3' // Main chat container
  },
  scanInterval: 2000 // Scan every 2 seconds
};

let warningOverlay = null;
let lastScannedUrl = null;
let processedMessages = new Set();

// Initialize the warning overlay
function initializeWarningOverlay() {
  if (!warningOverlay && window.EmailWarningOverlay) {
    warningOverlay = new window.EmailWarningOverlay();
  }
}

// Analyze message content for phishing indicators
async function analyzeMessageContent(messageContainer) {
  if (!messageContainer || processedMessages.has(messageContainer)) return;
  
  const messageText = messageContainer.querySelector(WHATSAPP_CONFIG.selectors.messageText)?.textContent || '';
  const links = Array.from(messageContainer.querySelectorAll(WHATSAPP_CONFIG.selectors.linkSelector));
  
  // Store the current URL
  lastScannedUrl = window.location.href;
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'analyzeContent',
      data: {
        content: messageText,
        links: links.map(link => link.href),
        platform: 'whatsapp'
      }
    });

    if (response.isPhishing) {
      // Add click handlers to all links in the suspicious message
      links.forEach(link => {
        // Remove any existing click handlers
        link.removeEventListener('click', handleSuspiciousLinkClick);
        // Add new click handler
        link.addEventListener('click', handleSuspiciousLinkClick);
      });

      // Mark message as suspicious
      markMessageAsSuspicious(messageContainer, response.reasons);
      processedMessages.add(messageContainer);
    }
  } catch (error) {
    console.error('Error analyzing WhatsApp message:', error);
  }
}

// Handle suspicious link clicks
function handleSuspiciousLinkClick(event) {
  event.preventDefault();
  
  const url = event.currentTarget.href;
  // Show warning overlay through background script
  chrome.runtime.sendMessage({
    type: 'showPhishingWarning',
    data: {
      url: url
    }
  });
}

// Mark suspicious messages with warning styles
function markMessageAsSuspicious(messageContainer, reasons) {
  // Create warning banner
  const warningBanner = document.createElement('div');
  warningBanner.className = 'whatsapp-phishing-warning';
  warningBanner.style.cssText = `
    background-color: #fff3cd;
    border: 2px solid #ffeeba;
    border-radius: 4px;
    color: #856404;
    margin: 5px 0;
    padding: 8px;
    font-size: 12px;
    position: relative;
    z-index: 1;
  `;

  warningBanner.innerHTML = `
    <div style="display: flex; align-items: center;">
      <span style="margin-right: 5px;">⚠️</span>
      <strong>Potential Phishing Message Detected</strong>
    </div>
    <ul style="margin: 5px 0 0 20px; padding: 0;">
      ${reasons.map(reason => `<li>${reason}</li>`).join('')}
    </ul>
  `;

  // Insert warning before the message
  messageContainer.insertBefore(warningBanner, messageContainer.firstChild);

  // Add subtle background to the message
  messageContainer.style.backgroundColor = '#fff8f8';
  messageContainer.style.border = '1px solid #ffe0e0';
  messageContainer.style.borderRadius = '4px';
  messageContainer.style.padding = '8px';
}

// Set up message scanning
function setupMessageScanning() {
  // Initialize warning overlay
  initializeWarningOverlay();

  // Create mutation observer for dynamic content
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        const messages = document.querySelectorAll(WHATSAPP_CONFIG.selectors.messageContainer);
        messages.forEach(message => {
          if (!processedMessages.has(message)) {
            analyzeMessageContent(message);
          }
        });
      }
    });
  });

  // Start observing
  const chatContainer = document.querySelector(WHATSAPP_CONFIG.selectors.chatContainer);
  if (chatContainer) {
    observer.observe(chatContainer, {
      childList: true,
      subtree: true
    });
  }

  // Initial scan
  const messages = document.querySelectorAll(WHATSAPP_CONFIG.selectors.messageContainer);
  messages.forEach(message => {
    if (!processedMessages.has(message)) {
      analyzeMessageContent(message);
    }
  });

  // Set up interval scanning
  setInterval(() => {
    const messages = document.querySelectorAll(WHATSAPP_CONFIG.selectors.messageContainer);
    messages.forEach(message => {
      if (!processedMessages.has(message)) {
        analyzeMessageContent(message);
      }
    });
  }, WHATSAPP_CONFIG.scanInterval);
}

// Load the warning overlay script
function loadWarningOverlay() {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('emailWarning.js');
  script.onload = () => {
    setupMessageScanning();
  };
  (document.head || document.documentElement).appendChild(script);
}

// Initialize when the page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', loadWarningOverlay);
} else {
  loadWarningOverlay();
} 