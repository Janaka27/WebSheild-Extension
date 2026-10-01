# Privacy Policy for WebShield

**Last Updated:** October 1, 2026

## 1. Overview
WebShield ("we", "our", or "us") is committed to protecting your privacy. WebShield is a client-side security and vulnerability scanner browser extension designed to audit web page security health. 

This Privacy Policy explains our data practices for the WebShield browser extension.

## 2. Zero Data Collection
WebShield does **NOT** collect, store, transmit, log, sell, or share any personal data, browsing history, authentication credentials, network activity, or website content to external servers or third parties.

All security audits, header analyses, vulnerability scans, and score calculations are performed **100% locally** inside your browser instance on your device.

## 3. Local Storage Usage
WebShield uses your browser's local storage (`chrome.storage.local`) strictly to:
- Save up to 20 of your most recent local security scan reports.
- Store your extension settings (e.g., notification badge preferences).

This data remains strictly on your local device and is never uploaded or transmitted off your machine.

## 4. Permissions Disclosure
WebShield requests specific browser permissions strictly to perform its single purpose—auditing page security when requested by the user:
- `activeTab`: To inspect the currently active web page when you click the extension popup.
- `scripting`: To execute the client-side analyzer script inside the target web page DOM.
- `storage`: To save your recent audit history and extension preferences locally.
- `tabs`: To read the active tab's URL and protocol (HTTP/HTTPS) for connection security analysis.
- `<all_urls>`: To enable scanning on any website or local web app you choose to audit.

## 5. Third-Party Services & Remote Code
WebShield does not use any third-party analytics, tracking scripts, or remotely hosted code. All scripts and libraries are statically bundled within the extension package.

## 6. Changes to This Privacy Policy
We may update this Privacy Policy from time to time. Any updates will be posted in this repository.

## 7. Contact Information
If you have any questions about this Privacy Policy, please open an issue on our GitHub repository:
[https://github.com/Janaka27/WebSheild-Extension](https://github.com/Janaka27/WebSheild-Extension)
