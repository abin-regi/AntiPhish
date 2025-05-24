// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  await loadStats();
  await loadSettings();
  await checkApiStatus();
  setupEventListeners();
  loadRecentActivity();
});

// Load statistics
async function loadStats() {
  try {
    const { linksScanned, threatsBlocked } = await chrome.storage.local.get([
      'linksScanned',
      'threatsBlocked'
    ]);

    document.getElementById('linksScanned').textContent = linksScanned || 0;
    document.getElementById('threatsBlocked').textContent = threatsBlocked || 0;
  } catch (error) {
    console.error('Error loading stats:', error);
  }
}

// Load feature settings
async function loadSettings() {
  try {
    const { urlCheck, aiCheck, domainCheck } = await chrome.storage.local.get([
      'urlCheck',
      'aiCheck',
      'domainCheck'
    ]);

    document.getElementById('urlCheck').checked = urlCheck !== false;
    document.getElementById('aiCheck').checked = aiCheck !== false;
    document.getElementById('domainCheck').checked = domainCheck !== false;
  } catch (error) {
    console.error('Error loading settings:', error);
  }
}

// Check API key status
async function checkApiStatus() {
  try {
    const { googleApiKey, huggingFaceToken } = await chrome.storage.local.get([
      'googleApiKey',
      'huggingFaceToken'
    ]);

    const statusIndicator = document.getElementById('apiStatusIndicator');
    const statusText = document.getElementById('apiStatusText');
    const apiStatus = document.getElementById('apiStatus');
    const protectionStatus = document.getElementById('protectionStatus');

    if (googleApiKey) {
      statusIndicator.textContent = '✅';
      statusText.textContent = 'API keys configured';
      apiStatus.classList.add('configured');
      protectionStatus.textContent = 'Protection Active';
      protectionStatus.classList.remove('inactive');
    } else {
      statusIndicator.textContent = '⚠️';
      statusText.textContent = 'API keys required for full protection';
      apiStatus.classList.remove('configured');
      protectionStatus.textContent = 'Limited Protection (API key needed)';
      protectionStatus.classList.add('inactive');
    }

    // Pre-fill existing keys (masked)
    if (googleApiKey) {
      document.getElementById('googleApiKey').placeholder = '••••••••••••••••';
    }
    if (huggingFaceToken) {
      document.getElementById('huggingFaceToken').placeholder = '••••••••••••••••';
    }
  } catch (error) {
    console.error('Error checking API status:', error);
  }
}

// Setup event listeners
function setupEventListeners() {
  // API key save button
  document.getElementById('saveApiKeys').addEventListener('click', saveApiKeys);

  // Feature toggles
  const toggles = ['urlCheck', 'aiCheck', 'domainCheck'];
  toggles.forEach(id => {
    document.getElementById(id).addEventListener('change', async (e) => {
      try {
        await chrome.storage.local.set({ [id]: e.target.checked });
        
        // Notify background script of settings change
        chrome.runtime.sendMessage({
          type: 'settingsUpdated',
          settings: {
            [id]: e.target.checked
          }
        });
      } catch (error) {
        console.error('Error saving setting:', error);
      }
    });
  });
}

// Save API keys
async function saveApiKeys() {
  const googleApiKey = document.getElementById('googleApiKey').value.trim();
  const huggingFaceToken = document.getElementById('huggingFaceToken').value.trim();
  const saveButton = document.getElementById('saveApiKeys');

  if (!googleApiKey) {
    showMessage('error', 'Google API key is required for basic protection');
    return;
  }

  try {
    saveButton.disabled = true;
    saveButton.textContent = 'Saving...';

    // Save to storage
    const dataToSave = { googleApiKey };
    if (huggingFaceToken) {
      dataToSave.huggingFaceToken = huggingFaceToken;
    }

    await chrome.storage.local.set(dataToSave);

    // Notify background script
    chrome.runtime.sendMessage({
      type: 'apiKeysUpdated',
      keys: dataToSave
    });

    // Clear input fields
    document.getElementById('googleApiKey').value = '';
    document.getElementById('huggingFaceToken').value = '';

    showMessage('success', 'API keys saved successfully!');
    await checkApiStatus(); // Refresh status

  } catch (error) {
    console.error('Error saving API keys:', error);
    showMessage('error', 'Failed to save API keys. Please try again.');
  } finally {
    saveButton.disabled = false;
    saveButton.textContent = 'Save API Keys';
  }
}

// Load recent activity
async function loadRecentActivity() {
  try {
    const { recentThreats } = await chrome.storage.local.get(['recentThreats']);
    const activityList = document.getElementById('recentActivity');

    if (!recentThreats || recentThreats.length === 0) {
      activityList.innerHTML = '<p class="no-activity">No recent threats detected</p>';
      return;
    }

    const activityHTML = recentThreats.slice(0, 5).map(threat => `
      <div class="activity-item">
        <div class="threat-url">${threat.url}</div>
        <div class="timestamp">${new Date(threat.timestamp).toLocaleString()}</div>
      </div>
    `).join('');

    activityList.innerHTML = activityHTML;
  } catch (error) {
    console.error('Error loading recent activity:', error);
  }
}

// Show message to user
function showMessage(type, text) {
  // Remove existing messages
  const existingMessages = document.querySelectorAll('.success-message, .error-message');
  existingMessages.forEach(msg => msg.remove());

  // Create new message
  const message = document.createElement('div');
  message.className = type === 'success' ? 'success-message' : 'error-message';
  message.textContent = text;

  // Insert after API status
  const apiStatus = document.getElementById('apiStatus');
  apiStatus.parentNode.insertBefore(message, apiStatus.nextSibling);

  // Auto-remove after 3 seconds
  setTimeout(() => {
    if (message.parentNode) {
      message.remove();
    }
  }, 3000);
}

// Listen for stats updates from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'statsUpdate') {
    if (message.linksScanned !== undefined) {
      document.getElementById('linksScanned').textContent = message.linksScanned;
    }
    if (message.threatsBlocked !== undefined) {
      document.getElementById('threatsBlocked').textContent = message.threatsBlocked;
    }
  }
  
  if (message.type === 'threatDetected') {
    loadRecentActivity(); // Refresh activity list
  }
}); 