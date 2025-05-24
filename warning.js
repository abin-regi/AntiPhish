// Get the dangerous URL from query parameters
const urlParams = new URLSearchParams(window.location.search);
const dangerousUrl = urlParams.get('url');
const tabId = urlParams.get('tabId');
const suggestedDomain = urlParams.get('suggestedDomain');

document.getElementById('dangerous-url').textContent = dangerousUrl || 'Unknown URL';

// Setup suggested domain if available
if (suggestedDomain) {
    const container = document.getElementById('suggested-domain-container');
    const trustedDomainInput = document.getElementById('trusted-domain');
    const visitTrustedButton = document.getElementById('visitTrustedButton');
    
    container.style.display = 'block';
    trustedDomainInput.value = suggestedDomain;
    
    visitTrustedButton.addEventListener('click', function() {
        const trustedUrl = 'https://' + suggestedDomain;
        chrome.runtime.sendMessage({
            type: 'continueToUrl',
            data: {
                url: trustedUrl,
                tabId: tabId ? parseInt(tabId) : undefined
            }
        }, (response) => {
            if (response && response.success) {
                console.log('Navigation to trusted domain initiated');
            } else {
                console.error('Failed to navigate to trusted domain');
                window.location.href = trustedUrl;
            }
        });
    });
}

// Add event listeners when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const backButton = document.getElementById('backButton');
    const proceedButton = document.getElementById('proceedButton');

    // Simple back button functionality
    backButton.addEventListener('click', function() {
        window.history.back();
    });

    proceedButton.addEventListener('click', function() {
        const confirmed = window.confirm('Are you absolutely sure you want to continue? This site may steal your personal information!');
        
        if (confirmed && dangerousUrl) {
            // Send message to background script to approve and navigate
            chrome.runtime.sendMessage({
                type: 'continueToUrl',
                data: {
                    url: dangerousUrl,
                    tabId: tabId ? parseInt(tabId) : undefined
                }
            }, (response) => {
                if (response && response.success) {
                    console.log('Navigation approved and initiated');
                } else {
                    console.error('Failed to continue to URL');
                    // Fallback: direct navigation
                    window.location.href = dangerousUrl;
                }
            });
        }
    });
}); 