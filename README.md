AntiPhish Browser Extension
🛡️ Protect yourself from phishing attacks with AI-powered detection

📌 Overview
AntiPhish is a browser extension that detects and blocks phishing websites, malicious links, and scam content in real-time using:

AI (BERT-tiny NLP model) for text analysis

Google Safe Browsing API for URL scanning

Heuristic checks (domain spoofing, Levenshtein distance, regex patterns)

Designed for Chrome & Firefox, it scans emails (Gmail), messages (WhatsApp Web), and general web browsing to keep you safe.

✨ Features
✔ Real-time URL blocking – Prevents access to phishing sites
✔ Email & message scanning – Flags suspicious content in Gmail & WhatsApp
✔ Smart warnings – Explains risks & suggests safe alternatives
✔ Lightweight & private – No data collection; processing happens locally

🛠️ Installation
Method 1: Load Unpacked (Chrome/Edge/Brave)
Download this repo (git clone or ZIP).

Go to chrome://extensions.

Enable Developer mode (top-right toggle).

Click Load unpacked and select the extension folder.

Method 2: Firefox
Open about:debugging#/runtime/this-firefox.

Click Load Temporary Add-on and select any file in the repo.

(A published Web Store version is coming soon!)

🔧 Configuration
Set API keys (optional for enhanced detection):

Get a Google Safe Browsing API key.

Get a Hugging Face API token.

Paste them in the extension’s Settings (click the toolbar icon).

📸 Screenshots
Warning Page	Gmail Alert
Warning Screen	Gmail Alert
🤖 How It Works
URLs are checked against:

Google’s blacklist

Domain similarity (e.g., paypa1.com → suggests paypal.com)

Emails/messages are analyzed by:

BERT-tiny NLP model (spam/phishing detection)

50+ phishing-related regex patterns

Warnings appear before risky pages load, with options to go back or proceed.


💡 Contributing
Found a bug? Want a new feature?

Open an issue (describe the problem/idea).

Fork & submit a PR (for code changes).

📜 License
MIT © [abin-regi]

(Replace placeholder images with actual screenshots later. Customize license/author as needed!)
