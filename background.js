// Configuration and API endpoints
const CONFIG = {
  SAFE_BROWSING_API_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  HUGGING_FACE_API_ENDPOINT: 'https://api-inference.huggingface.co/models/mrm8488/bert-tiny-finetuned-sms-spam-detection',
  MIN_RISK_SCORE: 0.5,
  TRUSTED_DOMAINS: [
    // Search engines
    'google.com',
    'bing.com',
    'yahoo.com',
    'duckduckgo.com',
    'baidu.com',
    // Social media
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'linkedin.com',
    'pinterest.com',
    'reddit.com',
    'youtube.com',
    // Communication
    'whatsapp.com',
    'web.whatsapp.com',
    'telegram.org',
    'zoom.us',
    'teams.microsoft.com',
    'discord.com',
    'slack.com',
    // Email
    'gmail.com',
    'outlook.com',
    'live.com',
    'yahoo.com',
    'protonmail.com',
    // Cloud & Development
    'github.com',
    'gitlab.com',
    'bitbucket.org',
    'dropbox.com',
    'drive.google.com',
    'onedrive.live.com',
    'box.com',
    // Shopping
    'amazon.com',
    'ebay.com',
    'walmart.com',
    'target.com',
    'bestbuy.com',
    // Payment
    'paypal.com',
    'stripe.com',
    'square.com',
    // Banking
    'chase.com',
    'wellsfargo.com',
    'bankofamerica.com',
    'citibank.com',
    'capitalone.com',
    // Microsoft services
    'microsoft.com',
    'office.com',
    'live.com',
    'windows.com',
    // Apple services
    'apple.com',
    'icloud.com',
    'me.com',
    // Google services
    'google.com',
    'googleapis.com',
    'gstatic.com',
    'chrome.google.com',
    // Other common services
    'netflix.com',
    'spotify.com',
    'adobe.com',
    'cloudflare.com',
    'amazonaws.com'
  ],
  PHISHING_PATTERNS: [
    /urgent.*account.*suspend/i,
    /verify.*account/i,
    /security.*alert/i,
    /unusual.*login/i,
    /account.*restrict/i,
    /suspicious.*activity/i,
    /limited.*access/i,
    /password.*expire/i,
    /unusual.*device/i,
    /confirm.*identity/i,
    /account.*verify/i,
    /verify.*identity/i,
    /account.*security/i,
    /security.*breach/i,
    /update.*account.*info/i
  ]
};

// Function to check if a domain is trusted
function isTrustedDomain(domain) {
  domain = domain.toLowerCase();
  return CONFIG.TRUSTED_DOMAINS.some(trusted => {
    // Check exact match
    if (domain === trusted) return true;
    // Check subdomain match
    if (domain.endsWith('.' + trusted)) return true;
    // Check if the trusted domain is actually a subdomain pattern
    if (trusted.includes('.') && domain === trusted.split('.').slice(-2).join('.')) return true;
    return false;
  });
}

// URL approval state management
const approvedUrls = new Set();
const APPROVAL_TIMEOUT = 300000; // 5 minutes

// Function to temporarily approve a URL
function approveUrl(url) {
  approvedUrls.add(url);
  // Auto-remove approval after timeout
  setTimeout(() => {
    approvedUrls.delete(url);
  }, APPROVAL_TIMEOUT);
}

// Function to check if URL is approved
function isUrlApproved(url) {
  return approvedUrls.has(url);
}

// Store API keys securely
let apiKeys = {
  googleSafeBrowsing: null,
  huggingFace: null
};

// Initialize API keys from storage
async function initializeApiKeys() {
  try {
    const result = await chrome.storage.local.get(['googleApiKey', 'huggingFaceToken']);
    
    // Set default API keys if not present
    if (!result.googleApiKey) {
      await chrome.storage.local.set({
        googleApiKey: 'GOOGLE_API_KEY'
      });
    }
    
    if (!result.huggingFaceToken) {
      await chrome.storage.local.set({
        huggingFaceToken: 'HUGGINGFACE_TOKEN'
      });
    }

    // Update apiKeys object with stored or default values
    apiKeys.googleSafeBrowsing = result.googleApiKey || 'GOOGLE_API_KEY';
    apiKeys.huggingFace = result.huggingFaceToken || 'HUGGINGFACE_TOKEN';

    console.log('API keys initialized:', {
      googleKeySet: !!apiKeys.googleSafeBrowsing,
      huggingFaceTokenSet: !!apiKeys.huggingFace
    });
  } catch (error) {
    console.error('Error initializing API keys:', error);
  }
}

// Initialize on install and startup
chrome.runtime.onInstalled.addListener(initializeApiKeys);
initializeApiKeys();

// Listen for API key updates
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local') {
    if (changes.googleApiKey) {
      apiKeys.googleSafeBrowsing = changes.googleApiKey.newValue;
    }
    if (changes.huggingFaceToken) {
      apiKeys.huggingFace = changes.huggingFaceToken.newValue;
    }
  }
});

// Store navigation history
const navigationHistory = new Map(); // tabId -> previous URL

// Listen for navigation events to track history and check for phishing
if (chrome.webNavigation) {
  // Track navigation history
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && !details.url.startsWith('chrome://')) {
      navigationHistory.set(details.tabId, details.url);
    }
  });

  // Monitor for phishing attempts
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId === 0) { // Only check main frame navigation
      const url = details.url;
      
      // Skip restricted URLs
      if (url.startsWith('chrome://') || 
          url.startsWith('chrome-extension://') || 
          url.startsWith('edge://') || 
          url.startsWith('about:')) {
        return;
      }

      // Check if URL is already approved
      if (isUrlApproved(url)) {
        console.log('URL approved, allowing navigation:', url);
        return;
      }

      try {
        console.log('Checking URL:', url);
        const urlObj = new URL(url);
        const checkResult = await checkIfPhishing(urlObj.href);
        
        console.log('Check result:', checkResult);
        
        if (checkResult.isPhishing) {
          console.log('Phishing detected, showing warning');
          // Store current URL before showing warning
          navigationHistory.set(details.tabId, details.url);
          
          // Cancel the navigation by redirecting to warning page
          const warningUrl = chrome.runtime.getURL('warning.html') + 
            `?url=${encodeURIComponent(url)}` +
            `&tabId=${details.tabId}` +
            `&reasons=${encodeURIComponent(JSON.stringify(checkResult.reasons))}` +
            `&sourceUrl=${encodeURIComponent(details.url)}` +
            (checkResult.suggestedDomain ? `&suggestedDomain=${encodeURIComponent(checkResult.suggestedDomain)}` : '');
          
          await chrome.tabs.update(details.tabId, { url: warningUrl });
          
          // Update stats
          await updateStats('threatBlocked', url);
        }
      } catch (error) {
        console.error('Error checking URL:', error);
        // Run fallback check on error
        const fallbackResult = fallbackUrlCheck(url);
        if (fallbackResult.isSuspicious) {
          // Store current URL before showing warning
          navigationHistory.set(details.tabId, details.url);
          
          const warningUrl = chrome.runtime.getURL('warning.html') + 
            `?url=${encodeURIComponent(url)}` +
            `&tabId=${details.tabId}` +
            `&sourceUrl=${encodeURIComponent(details.url)}` +
            `&reasons=${encodeURIComponent(JSON.stringify([fallbackResult.reason]))}`;
          
          await chrome.tabs.update(details.tabId, { url: warningUrl });
        }
      }
    }
  });
}

// Message handling for extension communication
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Ensure we have a valid message
  if (!message || typeof message !== 'object') {
    console.warn('Invalid message received:', message);
    sendResponse({ error: 'Invalid message format' });
    return false;
  }

  // Handle different message types
  if (message.type === 'analyzeContent') {
    // Use Promise.resolve to handle both async and sync responses
    Promise.resolve(analyzeContent(message.data, sender))
      .then(result => {
        try {
          sendResponse(result);
        } catch (error) {
          console.warn('Error sending response:', error);
        }
      })
      .catch(error => {
        console.error('Error analyzing content:', error);
        try {
          sendResponse({ isPhishing: false, reason: 'Analysis error' });
        } catch (sendError) {
          console.warn('Error sending error response:', sendError);
        }
      });
    return true; // Keep the message channel open
  }

  if (message.type === 'analyzeLink') {
    analyzeLinkAndContext(message.data.url, message.data.context)
      .then(result => sendResponse(result))
      .catch(error => {
        console.error('Error in analyzeLink handler:', error);
        sendResponse({ isSuspicious: false, reason: 'Analysis error' });
      });
    return true;
  }

  // Handle navigation actions from warning overlay
  if (message.action === 'goBack') {
    handleGoBack(sender.tab.id, message.url)
      .then(result => sendResponse(result))
      .catch(error => {
        console.error('Error handling go back:', error);
        sendResponse({ success: false });
      });
    return true;
  }

  // Handle tab closure request
  if (message.action === 'closeTab') {
    chrome.tabs.remove(sender.tab.id)
      .then(() => sendResponse({ success: true }))
      .catch(error => {
        console.error('Error closing tab:', error);
        sendResponse({ success: false });
      });
    return true;
  }

  if (message.action === 'proceed') {
    // Approve the URL to bypass future blocks
    approveUrl(message.url);
    
    // Navigate to the approved URL
    chrome.tabs.update(sender.tab.id, { url: message.url })
      .then(() => sendResponse({ success: true }))
      .catch(error => {
        console.error('Error updating tab:', error);
        sendResponse({ success: false });
      });
    return true;
  }

  if (message.type === 'continueToUrl') {
    approveUrl(message.data.url);
    chrome.tabs.update(message.data.tabId || sender.tab.id, { url: message.data.url });
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'showPhishingWarning') {
    showPhishingWarning(sender.tab.id, message.data.url)
      .then(() => sendResponse({ success: true }))
      .catch(error => {
        console.error('Error showing phishing warning:', error);
        sendResponse({ success: false });
      });
    return true;
  }

  if (message.type === 'apiKeysUpdated') {
    console.log('API keys updated from popup');
    sendResponse({ success: true });
    return true;
  }

  if (message.type === 'settingsUpdated') {
    console.log('Settings updated:', message.settings);
    sendResponse({ success: true });
    return true;
  }
});

// Handle going back from warning
async function handleGoBack(tabId, sourceUrl = null) {
  try {
    // Get the current tab
    const tab = await chrome.tabs.get(tabId);
    
    // Try different methods in order of preference:
    
    // 1. Use provided source URL if available
    if (sourceUrl && sourceUrl !== 'undefined' && !sourceUrl.includes('warning.html')) {
      await chrome.tabs.update(tabId, { url: sourceUrl });
      return { success: true };
    }
    
    // 2. Use stored navigation history
    const previousUrl = navigationHistory.get(tabId);
    if (previousUrl && !previousUrl.includes('warning.html')) {
      navigationHistory.delete(tabId); // Clear after use
      await chrome.tabs.update(tabId, { url: previousUrl });
      return { success: true };
    }
    
    // 3. Check if there are other tabs
    const tabs = await chrome.tabs.query({ currentWindow: true });
    if (tabs.length > 1) {
      // If current tab isn't first, activate previous tab
      if (tab.index > 0) {
        await chrome.tabs.update(tabs[tab.index - 1].id, { active: true });
      } else {
        // If it's the first tab, activate the next one
        await chrome.tabs.update(tabs[1].id, { active: true });
      }
      await chrome.tabs.remove(tabId);
      return { success: true };
    }
    
    // 4. Final fallback: go to new tab page
    await chrome.tabs.update(tabId, { url: 'chrome://newtab' });
    return { success: true };
    
  } catch (error) {
    console.error('Error in handleGoBack:', error);
    // Emergency fallback
    try {
      await chrome.tabs.update(tabId, { url: 'chrome://newtab' });
      return { success: true };
    } catch (fallbackError) {
      console.error('Fallback navigation failed:', fallbackError);
      return { success: false };
    }
  }
}

// Analyze link and its context
async function analyzeLinkAndContext(url, context) {
  try {
    await updateStats('linkScanned');

    // Get feature settings
    const { urlCheck, aiCheck, domainCheck } = await chrome.storage.local.get([
      'urlCheck',
      'aiCheck',
      'domainCheck'
    ]);

    let results = [];

    // Domain similarity check
    if (domainCheck !== false) {
      const domainResult = checkDomainSimilarity(url);
      if (domainResult.isSuspicious) {
        results.push(domainResult);
      }
    }

    // Google Safe Browsing check
    if (urlCheck !== false) {
      const googleResult = await checkGoogleSafeBrowsing(url);
      if (googleResult.isSuspicious) {
        results.push(googleResult);
      }
    }

    // Content analysis with Hugging Face
    if (aiCheck !== false && context) {
      const aiResult = await checkContentWithHuggingFace(context);
      if (aiResult.isSuspicious) {
        results.push(aiResult);
      }
    }

    // Combine results
    const isSuspicious = results.length > 0;
    if (isSuspicious) {
      await updateStats('threatBlocked', url);
    }

    return {
      isSuspicious,
      reasons: results.map(r => r.reason).filter(Boolean),
      suggestedDomain: results.find(r => r.suggestedDomain)?.suggestedDomain
    };
  } catch (error) {
    console.error('Error analyzing link:', error);
    return { isSuspicious: false, reason: 'Analysis error' };
  }
}

// Modify the checkIfPhishing function
async function checkIfPhishing(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // First check if it's a trusted domain
    if (isTrustedDomain(domain)) {
      return { 
        isPhishing: false,
        reasons: [],
        suggestedDomain: null
      };
    }

    let isPhishing = false;
    let reasons = [];
    let suggestedDomain = null;

    // 1. Check with Google Safe Browsing API
    const safeBrowsingResult = await checkGoogleSafeBrowsing(url);
    if (safeBrowsingResult.isSuspicious) {
      isPhishing = true;
      reasons.push(safeBrowsingResult.reason);
    }

    // 2. Check with fallback URL checker
    const fallbackResult = fallbackUrlCheck(url);
    if (fallbackResult.isSuspicious) {
      isPhishing = true;
      reasons.push(fallbackResult.reason);
    }

    // 3. Check domain similarity with known trusted domains
    const domainCheck = isDomainSuspicious(url);
    if (domainCheck.suspicious) {
      isPhishing = true;
      reasons.push(domainCheck.reason);
      suggestedDomain = domainCheck.suggestedDomain;
    }

    // Log the check results
    console.log('URL Check Results:', {
      url,
      domain,
      isPhishing,
      reasons,
      suggestedDomain
    });

    return { 
      isPhishing, 
      reasons: [...new Set(reasons)],
      suggestedDomain 
    };
  } catch (error) {
    console.error('Error checking phishing:', error);
    return { 
      isPhishing: false,
      reasons: [],
      suggestedDomain: null
    };
  }
}

// Query Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
  try {
    const requestBody = {
      client: {
        clientId: "antiphish-extension",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    // First check if we can make a successful API call
    try {
      const response = await fetch(`${CONFIG.SAFE_BROWSING_API_ENDPOINT}?key=${apiKeys.googleSafeBrowsing}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        console.warn(`Safe Browsing API returned status ${response.status}`);
        return fallbackUrlCheck(url);
      }

      const data = await response.json();
      return {
        isSuspicious: !!(data.matches && data.matches.length > 0),
        reason: data.matches?.[0]?.threatType || null
      };
    } catch (error) {
      console.warn('Safe Browsing API request failed:', error);
      return fallbackUrlCheck(url);
    }
  } catch (error) {
    console.warn('Error in checkGoogleSafeBrowsing:', error);
    return fallbackUrlCheck(url);
  }
}

// Fallback URL check when API is not available
function fallbackUrlCheck(url) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();
    
    // Skip check if domain is trusted
    if (isTrustedDomain(domain)) {
      return {
        isSuspicious: false,
        reason: null
      };
    }

    // Check for character substitutions in domain
    const substitutions = {
      '0': 'o',
      '1': 'i',
      '1': 'l',
      '3': 'e',
      '4': 'a',
      '5': 's',
      '7': 't',
      '@': 'a',
      '$': 's',
      'vv': 'w',
      'rn': 'm'
    };

    let normalizedDomain = domain;
    let hasSubstitutions = false;
    
    // Apply all substitutions and check if any were made
    Object.entries(substitutions).forEach(([fake, real]) => {
      if (domain.includes(fake)) {
        normalizedDomain = normalizedDomain.replace(new RegExp(fake, 'g'), real);
        hasSubstitutions = true;
      }
    });

    // List of major brands to check for impersonation
    const majorBrands = [
      'amazon', 'paypal', 'apple', 'microsoft', 'google', 'facebook', 
      'instagram', 'netflix', 'twitter', 'linkedin', 'chase', 'wellsfargo',
      'bankofamerica', 'citibank', 'amex', 'americanexpress'
    ];

    // Check for brand impersonation
    for (const brand of majorBrands) {
      if ((domain.includes(brand) || normalizedDomain.includes(brand)) && 
          !isTrustedDomain(domain)) {
        return {
          isSuspicious: true,
          reason: `Possible ${brand} impersonation detected`
        };
      }
    }

    // Enhanced suspicious patterns
    const suspiciousPatterns = [
      // Domain patterns
      /^secure[0-9-]+/i,
      /^login[0-9-]+/i,
      /^verify[0-9-]+/i,
      /^account[0-9-]+/i,
      /^banking[0-9-]+/i,
      /^confirm[0-9-]+/i,
      /^update[0-9-]+/i,
      /^security[0-9-]+/i,
      /-?secure-?/i,
      /-?verify-?/i,
      /-?account-?/i,
      /-?login-?/i,
      /-?confirm-?/i,
      /-?update-?/i,
      
      // URL path patterns
      /\/secure.*login/i,
      /\/account.*verify/i,
      /\/verify.*account/i,
      /\/confirm.*identity/i,
      /\/update.*account/i,
      /\/password.*reset/i,
      /\/billing.*update/i,
      /\/payment.*verify/i,
      /\/security.*alert/i,
      /\/login.*secure/i
    ];

    // Check domain against patterns
    for (const pattern of suspiciousPatterns.slice(0, 14)) { // Domain patterns
      if (pattern.test(domain)) {
        return {
          isSuspicious: true,
          reason: 'Suspicious domain pattern detected'
        };
      }
    }

    // Check URL path against patterns
    const urlPath = urlObj.pathname.toLowerCase();
    for (const pattern of suspiciousPatterns.slice(14)) { // Path patterns
      if (pattern.test(urlPath)) {
        return {
          isSuspicious: true,
          reason: 'Suspicious URL path pattern detected'
        };
      }
    }

    // Check for suspicious TLDs combined with security-related terms
    const suspiciousTlds = [
      'xyz', 'top', 'work', 'click', 'loan', 'win', 'review',
      'country', 'party', 'date', 'stream', 'download', 'racing',
      'online', 'science', 'icu', 'buzz', 'site', 'fun', 'live',
      'world', 'today', 'space', 'store', 'tech', 'one', 'host'
    ];

    const securityTerms = [
      'secure', 'login', 'verify', 'account', 'banking', 'confirm',
      'update', 'password', 'billing', 'payment', 'identity'
    ];

    const tld = domain.split('.').pop().toLowerCase();
    if (suspiciousTlds.includes(tld)) {
      // Check if domain contains security-related terms
      if (securityTerms.some(term => domain.includes(term))) {
        return {
          isSuspicious: true,
          reason: `Suspicious combination of TLD and security terms`
        };
      }
    }

    // Check for excessive hyphens or numbers (common in phishing domains)
    const hyphenCount = (domain.match(/-/g) || []).length;
    const numberCount = (domain.match(/\d/g) || []).length;
    
    if (hyphenCount > 2 || numberCount > 3) {
      return {
        isSuspicious: true,
        reason: 'Suspicious domain structure detected'
      };
    }

    return {
      isSuspicious: false,
      reason: null
    };
  } catch (error) {
    console.error('Error in fallback URL check:', error);
    return {
      isSuspicious: false,
      reason: null
    };
  }
}

// Add retry logic for Hugging Face API
async function checkContentWithHuggingFace(content) {
  const MAX_RETRIES = 3;
  const RETRY_DELAY = 1000; // 1 second

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      if (!apiKeys.huggingFace) {
        console.warn('Hugging Face API token not configured');
        return { isSuspicious: false, reason: 'AI analysis not configured' };
      }

      const response = await fetch(CONFIG.HUGGING_FACE_API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKeys.huggingFace}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ inputs: content })
      });

      if (!response.ok) {
        if (response.status === 500) {
          console.warn(`Hugging Face API server error (attempt ${attempt}/${MAX_RETRIES})`);
          if (attempt < MAX_RETRIES) {
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            continue;
          }
        }
        throw new Error(`Hugging Face API error: ${response.status}`);
      }

      const data = await response.json();
      
      // Handle empty or invalid response
      if (!Array.isArray(data) || !data.length || !Array.isArray(data[0])) {
        console.warn('Invalid response format from Hugging Face API');
        return { isSuspicious: false, reason: 'Invalid API response' };
      }

      const spamScore = data[0][1]?.score || 0;
      const isSuspicious = spamScore > CONFIG.MIN_RISK_SCORE;

      return {
        isSuspicious,
        reason: isSuspicious ? `AI Risk Score: ${(spamScore * 100).toFixed(1)}%` : null
      };
    } catch (error) {
      console.error(`Error checking content with Hugging Face (attempt ${attempt}/${MAX_RETRIES}):`, error);
      if (attempt < MAX_RETRIES) {
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
        continue;
      }
      return { isSuspicious: false, reason: 'AI analysis error' };
    }
  }

  return { isSuspicious: false, reason: 'AI analysis failed after retries' };
}

// Check domain similarity with known trusted domains
function isDomainSuspicious(url) {
  const trustedDomains = [
    'google.com',
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'linkedin.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'paypal.com',
    'chase.com',
    'wellsfargo.com',
    'bankofamerica.com'
  ];

  // Common phishing patterns
  const phishingPatterns = [
    /secure.*bank/i,
    /bank.*secure/i,
    /bank.*1/i,  // Catches bank1ng
    /verify.*account/i,
    /account.*verify/i,
    /\d+.*bank/i,  // Any numbers with bank
    /bank.*\d+/i,  // Bank with any numbers
    /secure.*\d+/i,  // Secure with numbers
    /\d+.*secure/i,  // Numbers with secure
    /my.*account.*verify/i,
    /verify.*my.*account/i,
    /online.*banking/i,
    /banking.*online/i
  ];

  try {
    const urlDomain = new URL(url).hostname.toLowerCase();
    
    // First check for exact trusted domain endings
    const isDomainTrusted = trustedDomains.some(trusted => 
      urlDomain === trusted || urlDomain.endsWith('.' + trusted)
    );
    
    if (isDomainTrusted) {
      return { suspicious: false };
    }

    // Check for phishing patterns
    for (const pattern of phishingPatterns) {
      if (pattern.test(urlDomain)) {
        return {
          suspicious: true,
          reason: 'Suspicious domain pattern detected',
          suggestedDomain: null
        };
      }
    }

    // Find the most similar trusted domain
    let mostSimilarDomain = null;
    let smallestDistance = Infinity;

    trustedDomains.forEach(trusted => {
      const trustedBase = trusted.split('.')[0];
      const urlBase = urlDomain.split('.')[0];
      
      // Check for number substitutions (common in phishing)
      const substitutions = {
        '0': 'o',
        '1': 'l',
        '1': 'i',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '@': 'a',
        '$': 's'
      };
      
      let normalizedTrusted = trustedBase;
      let normalizedUrl = urlBase;
      
      // Apply all substitutions
      Object.entries(substitutions).forEach(([num, letter]) => {
        normalizedTrusted = normalizedTrusted.replace(new RegExp(num, 'g'), letter);
        normalizedUrl = normalizedUrl.replace(new RegExp(num, 'g'), letter);
      });
      
      if (normalizedTrusted === normalizedUrl && trustedBase !== urlBase) {
        mostSimilarDomain = trusted;
        smallestDistance = 0;
        return;
      }
      
      // Check Levenshtein distance for close matches
      const distance = levenshteinDistance(urlBase, trustedBase);
      if (distance <= 2) {  // Flag if two or fewer characters are different
        smallestDistance = distance;
        mostSimilarDomain = trusted;
      }
    });

    return {
      suspicious: smallestDistance <= 2 && mostSimilarDomain !== null,
      suggestedDomain: mostSimilarDomain,
      reason: mostSimilarDomain ? `Similar to trusted domain: ${mostSimilarDomain}` : null
    };
  } catch (error) {
    console.error('Error checking domain similarity:', error);
    return { suspicious: false };  // Default to not suspicious on error
  }
}

// Levenshtein distance calculation for domain similarity checking
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) {
    dp[i][0] = i;
  }
  for (let j = 0; j <= n; j++) {
    dp[0][j] = j;
  }

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j - 1] + 1,
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1
        );
      }
    }
  }

  return dp[m][n];
}

// Show phishing warning popup for non-navigation contexts (like clicked links)
async function showPhishingWarning(tabId, url) {
  try {
    // Skip restricted URLs and return early
    if (url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') || 
        url.startsWith('edge://') || 
        url.startsWith('about:')) {
      console.log('Skipping warning for restricted URL:', url);
      return;
    }

    // First try to get tab info to verify if we can access it
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || tab.url.startsWith('chrome://') || 
        url.startsWith('chrome-extension://') || 
        url.startsWith('edge://') || 
        url.startsWith('about:')) {
      console.log('Cannot show warning on restricted tab:', tab.url);
      // Redirect to warning page instead
      await chrome.tabs.update(tabId, { 
        url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(url)}`
      });
      return;
    }

    // Inject the CSS and JS files first
    await chrome.scripting.insertCSS({
      target: { tabId },
      files: ['warning.css']
    });

    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['warning-overlay.js']
    });

    // Send message to show the warning
    await chrome.tabs.sendMessage(tabId, {
      action: 'showWarning',
      url: url
    });

  } catch (error) {
    console.error('Error showing warning:', error);
    
    // Only attempt redirect for non-restricted URLs
    if (!url.startsWith('chrome://') && 
        !url.startsWith('chrome-extension://') && 
        !url.startsWith('edge://') && 
        !url.startsWith('about:')) {
      try {
        await chrome.tabs.update(tabId, { 
          url: chrome.runtime.getURL('warning.html') + `?url=${encodeURIComponent(url)}`
        });
      } catch (e) {
        console.error('Failed to show warning page:', e);
      }
    }
  }
}

// Check domain similarity
function checkDomainSimilarity(url) {
  try {
    const trustedDomains = [
      'google.com',
      'facebook.com',
      'twitter.com',
      'instagram.com',
      'linkedin.com',
      'microsoft.com',
      'apple.com',
      'amazon.com',
      'paypal.com',
      'chase.com',
      'wellsfargo.com',
      'bankofamerica.com'
    ];

    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    
    // Direct match check
    if (trustedDomains.some(trusted => domain === trusted || domain.endsWith('.' + trusted))) {
      return { isSuspicious: false };
    }

    // Similarity check
    for (const trustedDomain of trustedDomains) {
      // Check for typosquatting variations
      if (domain.includes(trustedDomain.replace('.com', '')) && domain !== trustedDomain) {
        return {
          isSuspicious: true,
          reason: `Similar to ${trustedDomain}`,
          suggestedDomain: trustedDomain
        };
      }

      // Check for character substitution (e.g., 0 for o, 1 for l)
      const normalizedDomain = domain
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/\$/g, 's');

      if (normalizedDomain.includes(trustedDomain.replace('.com', '')) && domain !== trustedDomain) {
        return {
          isSuspicious: true,
          reason: `Possible typosquatting of ${trustedDomain}`,
          suggestedDomain: trustedDomain
        };
      }
    }

    // Additional phishing patterns
    const suspiciousPatterns = [
      /secure.*\-/i,
      /\-?secure/i,
      /login.*\-/i,
      /\-?login/i,
      /account.*\-/i,
      /\-?account/i,
      /bank.*\-/i,
      /\-?bank/i,
      /verify.*\-/i,
      /\-?verify/i
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(domain)) {
        return {
          isSuspicious: true,
          reason: 'Suspicious domain pattern detected'
        };
      }
    }

    return { isSuspicious: false };
  } catch (error) {
    console.error('Error checking domain similarity:', error);
    return { isSuspicious: false, reason: 'Domain check error' };
  }
}

// Statistics tracking
async function updateStats(type, url = '') {
  try {
    const result = await chrome.storage.local.get(['linksScanned', 'threatsBlocked', 'recentThreats']);
    const updates = {};
    
    if (type === 'linkScanned') {
      updates.linksScanned = (result.linksScanned || 0) + 1;
    } else if (type === 'threatBlocked') {
      updates.threatsBlocked = (result.threatsBlocked || 0) + 1;
      
      // Add to recent threats
      const recentThreats = result.recentThreats || [];
      recentThreats.unshift({
        url: url,
        timestamp: Date.now()
      });
      
      // Keep only last 10 threats
      updates.recentThreats = recentThreats.slice(0, 10);
    }
    
    await chrome.storage.local.set(updates);
    
    // Notify popup if open
    try {
      chrome.runtime.sendMessage({
        type: 'statsUpdate',
        ...updates
      });
    } catch (e) {
      // Popup might not be open, ignore error
    }
  } catch (error) {
    console.error('Error updating stats:', error);
  }
}

// Analyze content with platform-specific considerations
async function analyzeContent(data, senderInfo = null) {
  try {
    const { content, links = [], platform = 'generic' } = data;
    let reasons = [];
    let isPhishing = false;

    // 1. Check content against phishing patterns
    CONFIG.PHISHING_PATTERNS.forEach(pattern => {
      if (pattern.test(content)) {
        isPhishing = true;
        reasons.push('Suspicious content pattern detected');
      }
    });

    // 2. WhatsApp-specific patterns
    if (platform === 'whatsapp') {
      const whatsappPatterns = [
        /join.*group.*link/i,
        /free.*gift/i,
        /lottery.*win/i,
        /click.*claim/i,
        /verify.*whatsapp/i,
        /whatsapp.*gold/i,
        /whatsapp.*update/i,
        /account.*expire/i,
        /prize.*claim/i,
        /investment.*opportunity/i
      ];

      whatsappPatterns.forEach(pattern => {
        if (pattern.test(content)) {
          isPhishing = true;
          reasons.push('Suspicious WhatsApp-specific pattern detected');
        }
      });
    }

    // 3. Extract and check URLs in content
    for (const url of links) {
      try {
        const domainCheck = isDomainSuspicious(url);
        if (domainCheck.suspicious) {
          isPhishing = true;
          reasons.push(domainCheck.reason || 'Suspicious domain detected');
        }
      } catch (error) {
        console.error('Error checking URL:', error);
      }
    }

    // 4. Check content with Hugging Face AI
    try {
      const aiResult = await checkContentWithHuggingFace(content);
      if (aiResult.isSuspicious) {
        isPhishing = true;
        reasons.push(aiResult.reason);
      }
    } catch (error) {
      console.error('Error in AI content check:', error);
    }

    // Update stats if phishing detected
    if (isPhishing && senderInfo?.tab?.url) {
      await updateStats('threatBlocked', senderInfo.tab.url);
    }

    return {
      isPhishing,
      reasons: [...new Set(reasons)] // Remove duplicates
    };
  } catch (error) {
    console.error('Error analyzing content:', error);
    return { isPhishing: false, reasons: ['Analysis error'] };
  }
} 