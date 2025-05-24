# AntiPhish Browser Extension 🛡️  
**Protect yourself from phishing attacks with AI-powered detection**

---

## 📌 Overview

**AntiPhish** is a browser extension that detects and blocks phishing websites, malicious links, and scam content in real-time using:

- 🤖 **AI (BERT-tiny NLP model)** for text analysis  
- 🛡️ **Google Safe Browsing API** for URL scanning  
- 🧠 **Heuristic checks** like domain spoofing, Levenshtein distance, and regex pattern matching

Built for **Chrome** and **Firefox**, AntiPhish monitors:

- 📧 Emails (e.g., **Gmail**)  
- 💬 Messages (e.g., **WhatsApp Web**)  
- 🌐 General web browsing

to help you stay safe from scams and phishing attacks.

---

## ✨ Features

- ✔️ **Real-time URL blocking** – Prevents access to known phishing sites  
- ✔️ **Email & message scanning** – Flags suspicious content in Gmail & WhatsApp Web  
- ✔️ **Smart warnings** – Explains risks and suggests safer alternatives  
- ✔️ **Lightweight & private** – No data collection; all processing happens locally on your device

---

## 🛠️ Installation

### Method 1: Load Unpacked (Chrome/Edge/Brave)

1. Download this repository (via `git clone` or ZIP).
2. Go to: `chrome://extensions`
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the extension folder.

### Method 2: Firefox

1. Open: `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select any file (e.g., `manifest.json`) from the repo

> ⚠️ A published Web Store version is coming soon!

---

## 🔧 Configuration

You can set **API keys** (optional but improves detection accuracy):

1. Get a **Google Safe Browsing API** key → https://developers.google.com/safe-browsing/
2. Get a **Hugging Face API token** → https://huggingface.co/settings/tokens
3. Paste them in the extension’s **Settings** (click the extension icon in your toolbar)

---

## 📸 Screenshots

> *(Replace these with actual screenshots when available)*

- 🛑 **Warning Page** – Shows when a phishing attempt is detected  
- 📧 **Gmail Alert** – Flags malicious links in your inbox  
- ⚠️ **Warning Screen** – Explains the danger and gives you the choice to go back or continue  
- 🕵️‍♂️ **Gmail Alert (detailed)** – Highlights suspicious emails with inline alerts

---

## 🤖 How It Works

### 🔍 URL Checks
- ✅ Google Safe Browsing blacklist
- 🔁 Domain similarity (e.g., `paypa1.com` is compared to `paypal.com`)
- 🔡 Heuristic rules (Levenshtein distance, URL patterns, typosquatting detection)

### 🧠 Content Scanning
- 🧬 BERT-tiny NLP model classifies messages as phishing/spam
- 🔎 Over 50 phishing-related regex patterns detect scam keywords and structures

### ⚠️ Smart Warnings
- AntiPhish displays a **warning page before a risky page loads**
- User sees:
  - Reason for the block (e.g., "Suspicious domain")
  - A suggestion or alternative (if possible)
  - Options to:
    - 🔙 **Go Back** (recommended)
    - 🚧 **Continue Anyway** (with a second confirmation)

---

## 💡 Contributing

We welcome all contributions!

- 🐞 **Found a bug?** – Open an issue with steps to reproduce
- 💡 **Have a feature idea?** – Let us know via Issues
- 🛠️ **Want to help?** – Fork this repo and open a pull request!

---

## 📜 License

MIT © [abin-regi]

> *(You can customize license terms and replace author as needed)*

---
