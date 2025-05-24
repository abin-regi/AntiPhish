// Configuration
const SUPPORTED_PLATFORMS = {
  'web.whatsapp.com': {
    messageSelector: '._21Ahp',
    linkSelector: 'a',
    contextSelector: '._21Ahp'
  },
  'mail.google.com': {
    messageSelector: '.a3s, .ii, .gt',  // Enhanced selectors for Gmail
    linkSelector: 'a[href]',  // Only links with href attributes
    contextSelector: '.a3s, .ii, .gt',  // Match message selectors
    scanInterval: 2000,  // Scan every 2 seconds for new content
    scanOnLoad: true    // Scan immediately when email is opened
  },
  'www.facebook.com': {
    messageSelector: '[role="main"]',
    linkSelector: 'a[href]',
    contextSelector: '.xdj266r'
  },
  'twitter.com': {
    messageSelector: '[data-testid="tweet"]',
    linkSelector: 'a[href]',
    contextSelector: '[data-testid="tweet"]'
  },
  'www.instagram.com': {
    messageSelector: 'article',
    linkSelector: 'a[href]',
    contextSelector: '.C4VMK'
  }
};

// Email scanning configuration
const EMAIL_SCAN_CONFIG = {
  scanInterval: 1000,  // Scan every second
  selectors: {
    gmail: {
      container: '.adn.ads',
      subject: '.hP',
      body: '.a3s.aiL',
      sender: '.gD',
      links: 'a[href]'
    }
  }
};

let warningOverlay = null;
let lastScannedUrl = null;

// Initialize the warning overlay
function initializeWarningOverlay() {
  if (!warningOverlay && window.EmailWarningOverlay) {
    warningOverlay = new window.EmailWarningOverlay();
  }
}

// Analyze email content for phishing indicators
async function analyzeEmailContent(emailContainer) {
  if (!emailContainer) return;
  
  const subject = emailContainer.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.subject)?.textContent || '';
  const body = emailContainer.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.body)?.textContent || '';
  const sender = emailContainer.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.sender)?.textContent || '';
  const links = Array.from(emailContainer.querySelectorAll(EMAIL_SCAN_CONFIG.selectors.gmail.links));

  // Store the current URL before analysis
  lastScannedUrl = window.location.href;
  
  const contentToAnalyze = `${subject}\n${body}`;
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'analyzeContent',
      data: {
        content: contentToAnalyze,
        links: links.map(link => link.href),
        sender: sender
      }
    });

    if (response.isPhishing) {
      // Add click handlers to all links in the suspicious email
      links.forEach(link => {
        // Remove any existing click handlers
        link.removeEventListener('click', handleSuspiciousLinkClick);
        // Add new click handler
        link.addEventListener('click', handleSuspiciousLinkClick);
      });

      displayWarning(emailContainer, response.reasons);
    }
  } catch (error) {
    console.error('Error analyzing email content:', error);
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

// Display warning if phishing is detected
function displayWarning(emailContainer, reasons) {
  if (!warningOverlay) {
    initializeWarningOverlay();
  }
  
  if (warningOverlay) {
    warningOverlay.insertWarning(emailContainer, reasons);
  }
}

// Set up email scanning
function setupEmailScanning() {
  // Initialize warning overlay
  initializeWarningOverlay();

  // Create mutation observer for dynamic content
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        const emailContainers = document.querySelectorAll(EMAIL_SCAN_CONFIG.selectors.gmail.container);
        emailContainers.forEach(container => {
          if (!container.dataset.scanned) {
            container.dataset.scanned = 'true';
            analyzeEmailContent(container);
          }
        });
      }
    });
  });

  // Start observing
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initial scan
  const emailContainers = document.querySelectorAll(EMAIL_SCAN_CONFIG.selectors.gmail.container);
  emailContainers.forEach(container => {
    if (!container.dataset.scanned) {
      container.dataset.scanned = 'true';
      analyzeEmailContent(container);
    }
  });
}

// Load the warning overlay script
function loadWarningOverlay() {
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('emailWarning.js');
  script.onload = () => {
    setupEmailScanning();
  };
  (document.head || document.documentElement).appendChild(script);
}

// Initialize when the page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', loadWarningOverlay);
} else {
  loadWarningOverlay();
}

// Initialize platform config
const currentPlatform = SUPPORTED_PLATFORMS[window.location.hostname];

// Track processed links and messages to avoid duplicates
const processedLinks = new Set();
const processedMessages = new Set();

// Initialize MutationObserver
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.type === 'childList') {
      scanContent();
    }
  });
});

// Start observing DOM changes
if (currentPlatform) {
  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
  
  // Initial scan
  scanContent();
  
  // Set up interval scanning for platforms that need it
  if (currentPlatform.scanInterval) {
    setInterval(scanContent, currentPlatform.scanInterval);
  }
}

// Main content scanning function
async function scanContent() {
  if (!currentPlatform) return;

  // Scan for messages first
  const messages = document.querySelectorAll(currentPlatform.messageSelector);
  
  messages.forEach(async (message) => {
    // Skip if already processed
    if (processedMessages.has(message)) return;
    processedMessages.add(message);

    // Get message content
    const messageContent = message.textContent;
    const messageHtml = message.innerHTML;

    // Send message content for analysis
    const contentAnalysis = await chrome.runtime.sendMessage({
      type: 'analyzeContent',
      data: {
        content: messageContent,
        html: messageHtml
      }
    });

    if (contentAnalysis && contentAnalysis.isPhishing) {
      markMessageAsSuspicious(message, contentAnalysis);
    }
  });

  // Then scan for links
  const links = document.querySelectorAll(currentPlatform.linkSelector);
  
  links.forEach(async (link) => {
    const url = link.href;
    
    // Skip if already processed or internal link
    if (processedLinks.has(url) || isInternalLink(url)) return;
    processedLinks.add(url);

    // Get surrounding context
    const context = getSurroundingContext(link);

    // Send link and context to background script for analysis
    const result = await chrome.runtime.sendMessage({
      type: 'analyzeLink',
      data: {
        url,
        context
      }
    });

    if (result && result.isSuspicious) {
      // Add warning styles and click handler
      markLinkAsSuspicious(link, result);
    }
  });
}

// Mark suspicious messages with warning styles
function markMessageAsSuspicious(message, analysis) {
  // Add warning banner at the top of the message
  const warningBanner = document.createElement('div');
  warningBanner.className = 'phishing-warning-banner';
  warningBanner.style.cssText = `
    background-color: #ffebee;
    border: 2px solid #d32f2f;
    color: #d32f2f;
    padding: 10px;
    margin-bottom: 10px;
    border-radius: 4px;
    font-weight: bold;
  `;
  warningBanner.innerHTML = `
    ⚠️ Warning: This email appears to be a phishing attempt!
    <br>
    Reason: ${analysis.reasons.join(', ')}
  `;
  
  // Insert banner before the message content
  message.insertBefore(warningBanner, message.firstChild);
  
  // Add a subtle background to the entire message
  message.style.backgroundColor = '#fff8f8';
  message.style.border = '1px solid #ffe0e0';
  message.style.borderRadius = '4px';
  message.style.padding = '10px';
}

// Mark suspicious links with warning styles and handlers
function markLinkAsSuspicious(link, analysisResult) {
  // Add warning styles
  link.style.border = '2px solid #d32f2f';
  link.style.padding = '2px 4px';
  link.style.borderRadius = '4px';
  link.style.color = '#d32f2f';
  link.style.textDecoration = 'none';
  link.style.position = 'relative';
  
  // Add warning icon
  const warningIcon = document.createElement('span');
  warningIcon.textContent = ' ⚠️';
  warningIcon.style.marginLeft = '4px';
  link.appendChild(warningIcon);

  // Add tooltip with reason
  const tooltip = document.createElement('div');
  tooltip.style.cssText = `
    display: none;
    position: absolute;
    background: #d32f2f;
    color: white;
    padding: 8px;
    border-radius: 4px;
    font-size: 12px;
    max-width: 200px;
    top: 100%;
    left: 0;
    margin-top: 4px;
    z-index: 1000;
  `;
  tooltip.textContent = analysisResult.reasons.join('\n');
  link.appendChild(tooltip);

  // Show tooltip on hover
  link.addEventListener('mouseenter', () => tooltip.style.display = 'block');
  link.addEventListener('mouseleave', () => tooltip.style.display = 'none');

  // Store original click handler
  const originalClick = link.onclick;

  // Add warning click handler
  link.onclick = async (e) => {
    e.preventDefault();

    // Send message to background script to show warning
    await chrome.runtime.sendMessage({
      type: 'showPhishingWarning',
      data: {
        url: link.href,
        analysis: analysisResult
      }
    });

    // Restore original click handler (will only trigger if user chooses to continue)
    link.onclick = originalClick;
  };
}

// Get surrounding context for a link
function getSurroundingContext(link) {
  if (!currentPlatform) return '';

  // Find the closest context element
  const contextElement = link.closest(currentPlatform.contextSelector);
  if (!contextElement) return '';

  // Get text content of the context element
  return contextElement.textContent.trim();
}

// Check if a URL is internal
function isInternalLink(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname === window.location.hostname;
  } catch (e) {
    return false;
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'rescanLinks') {
    processedLinks.clear();
    processedMessages.clear();
    scanContent();
  }
});

// Initialize scanning for the current platform
function initializeScanning() {
  // Set up mutation observer to watch for new emails
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        scanEmailContent();
      }
    });
  });

  // Start observing email container
  const emailContainer = document.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.container);
  if (emailContainer) {
    observer.observe(emailContainer, {
      childList: true,
      subtree: true
    });
  }

  // Initial scan
  scanEmailContent();
  
  // Set up interval scanning
  setInterval(scanEmailContent, EMAIL_SCAN_CONFIG.scanInterval);
}

// Scan email content for phishing indicators
async function scanEmailContent() {
  const emails = document.querySelectorAll(EMAIL_SCAN_CONFIG.selectors.gmail.container);
  
  for (const email of emails) {
    // Skip if already processed
    if (email.dataset.scanned) continue;
    email.dataset.scanned = 'true';

    // Get email content
    const subject = email.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.subject)?.textContent || '';
    const body = email.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.body)?.textContent || '';
    const content = subject + ' ' + body;

    // Check for phishing patterns
    let isPhishing = false;
    const reasons = [];

    // 1. Check content against patterns
    EMAIL_SCAN_CONFIG.phishingPatterns.forEach(pattern => {
      if (pattern.test(content)) {
        isPhishing = true;
        reasons.push('Suspicious content pattern detected');
      }
    });

    // 2. Check links in email
    const links = email.querySelectorAll(EMAIL_SCAN_CONFIG.selectors.gmail.links);
    for (const link of links) {
      const url = link.href;
      if (!url) continue;

      try {
        // Check with background script
        const result = await chrome.runtime.sendMessage({
          type: 'analyzeLink',
          data: { url, context: content }
        });

        if (result && result.isSuspicious) {
          isPhishing = true;
          reasons.push(`Suspicious link detected: ${result.reason}`);
          
          // Style suspicious link
          link.style.border = '2px solid #d32f2f';
          link.style.padding = '2px 4px';
          link.style.borderRadius = '4px';
          link.style.color = '#d32f2f';
          link.style.textDecoration = 'none';
          
          // Add warning icon
          const warningIcon = document.createElement('span');
          warningIcon.textContent = ' ⚠️';
          warningIcon.style.marginLeft = '4px';
          link.appendChild(warningIcon);
        }
      } catch (error) {
        console.error('Error checking link:', error);
      }
    }

    // 3. Check with AI model
    try {
      const aiResult = await chrome.runtime.sendMessage({
        type: 'analyzeContent',
        data: { content }
      });

      if (aiResult && aiResult.isPhishing) {
        isPhishing = true;
        reasons.push(aiResult.reason);
      }
    } catch (error) {
      console.error('Error in AI content check:', error);
    }

    // Add warning if phishing detected
    if (isPhishing) {
      const warningBanner = document.createElement('div');
      warningBanner.className = 'phishing-warning-banner';
      warningBanner.style.cssText = `
        background-color: #ffebee;
        border: 2px solid #d32f2f;
        color: #d32f2f;
        padding: 10px;
        margin: 10px 0;
        border-radius: 4px;
        font-weight: bold;
      `;
      warningBanner.innerHTML = `
        ⚠️ Warning: This email appears to be a phishing attempt!
        <br>
        Reasons:
        <ul style="margin: 5px 0 0 20px;">
          ${reasons.map(reason => `<li>${reason}</li>`).join('')}
        </ul>
      `;

      // Insert warning at the top of the email
      const emailBody = email.querySelector(EMAIL_SCAN_CONFIG.selectors.gmail.body);
      if (emailBody) {
        emailBody.insertBefore(warningBanner, emailBody.firstChild);
      }

      // Add subtle background to the entire email
      emailBody.style.backgroundColor = '#fff8f8';
      emailBody.style.border = '1px solid #ffe0e0';
      emailBody.style.borderRadius = '4px';
      emailBody.style.padding = '10px';
    }
  }
}

// Initialize scanning when the page loads
document.addEventListener('DOMContentLoaded', initializeScanning);

// Re-scan when new content is loaded (e.g., when opening a new email)
document.addEventListener('load', initializeScanning); 