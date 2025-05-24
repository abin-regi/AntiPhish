// Get the dangerous URL from query parameters
const urlParams = new URLSearchParams(window.location.search);
const dangerousUrl = urlParams.get('url');
const tabId = urlParams.get('tabId');
const suggestedDomain = urlParams.get('suggestedDomain');
const sourceUrl = urlParams.get('sourceUrl');

// Store the referrer for better back navigation
const referrer = document.referrer || sourceUrl;

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

    // Enhanced back button functionality with multiple fallbacks
    backButton.addEventListener('click', async function() {
        let navigationSuccessful = false;

        // 1. Try using the extension's goBack with source URL
        try {
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage({ 
                    action: 'goBack',
                    url: referrer
                }, resolve);
            });
            
            if (response && response.success) {
                navigationSuccessful = true;
                return;
            }
        } catch (error) {
            console.error('Extension goBack failed:', error);
        }

        // 2. Try window.history.back() if we have history
        if (!navigationSuccessful && window.history.length > 1) {
            try {
                window.history.back();
                navigationSuccessful = true;
                return;
            } catch (error) {
                console.error('History back failed:', error);
            }
        }

        // 3. Try navigating to referrer directly
        if (!navigationSuccessful && referrer && !referrer.includes('warning.html')) {
            try {
                window.location.href = referrer;
                navigationSuccessful = true;
                return;
            } catch (error) {
                console.error('Direct referrer navigation failed:', error);
            }
        }

        // 4. Final fallback: close tab or go to new tab
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