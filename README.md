# 🛡️ WebShield - Security & Vulnerability Scanner Pro

> A powerful, privacy-first Google Chrome Extension (Manifest V3) to audit website security in one click. Detect client-side DOM flaws, OWASP vulnerabilities, secret leaks, missing headers, insecure forms, and unsafe cookies.

[![Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-3B82F6?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Security Audit](https://img.shields.io/badge/Security-OWASP_Top_10-10B981?logo=shield&logoColor=white)](#-vulnerability-checks)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Google_Chrome-00F2FE?logo=googlechrome&logoColor=white)](#-installation)

---

## 🌟 Overview

**WebShield** is a modern security inspection extension for web developers, security analysts, and privacy-conscious users. With a single click, WebShield injects a client-side auditing engine into the active tab, evaluates DOM execution patterns, headers, cookies, forms, and network protocols, and presents an interactive security health score alongside actionable fix recommendations.

---

## ✨ Features

- ⚡ **Instant 1-Click Scan:** Analyze any active web page in seconds without leaving your tab.
- 📊 **Security Health Score (0-100):** Visual gauge meter color-coded by risk severity (`CRITICAL`, `HIGH`, `MODERATE`, `EXCELLENT`).
- 🔍 **OWASP & DOM Vulnerability Scanner:** Deep client-side inspection for DOM XSS, exposed API keys, mixed content, insecure HTTP forms, and non-HttpOnly cookies.
- 📑 **Exportable Vector PDF Reports:** Generate clean, multi-page vector PDF security reports (`.pdf`) offline using bundled `jsPDF`.
- 🖥️ **Full-Page Printable Dashboard:** Open an executive HTML report tab with print-ready CSS (`window.print()`).
- 🎯 **Severity Pill Filters:** Easily filter findings by severity level (`Critical`, `High`, `Medium`, `Low`, `Info`).
- 🔒 **100% Privacy-First:** Performs all scanning client-side inside your browser. No external API calls, tracking, or remote data exfiltration.

---

## 🔬 Vulnerability Audits Covered

| Category | Finding ID | Vulnerability Check | Risk Severity |
| :--- | :--- | :--- | :---: |
| **Connection** | `SEC-CONN-01` | Unencrypted HTTP Connection (missing TLS) | `CRITICAL` |
| **Connection** | `SEC-CONN-02` | Active & Passive Mixed Content Resources | `HIGH` / `MEDIUM` |
| **Sensitive Data** | `SEC-DATA-01` | Hardcoded API Keys / Secrets (AWS, OpenAI, Stripe, JWT, Private Keys) | `CRITICAL` / `HIGH` |
| **Sensitive Data** | `SEC-DATA-02` | Sensitive Keywords in HTML Comments (`TODO`, `password`, `admin`, `api_key`) | `LOW` |
| **Storage & Cookies** | `SEC-STOR-01` | Sensitive Tokens in `localStorage` or `sessionStorage` | `MEDIUM` |
| **Storage & Cookies** | `SEC-STOR-02` | Session Cookies readable via JS (`document.cookie` missing `HttpOnly`) | `MEDIUM` |
| **DOM / XSS** | `SEC-DOM-01` | Dangerous Execution Functions (`eval()`, `document.write()`, unsafe `innerHTML`) | `HIGH` |
| **DOM / XSS** | `SEC-DOM-02` | Obsolete `javascript:` Scheme URIs | `LOW` |
| **Headers & Meta** | `SEC-META-01` | Missing Content Security Policy (CSP) Meta Tag | `HIGH` |
| **Headers & Meta** | `SEC-META-02` | Weak CSP Directives (`unsafe-inline`, `unsafe-eval`, `*`) | `MEDIUM` |
| **Headers & Meta** | `SEC-META-03` | Missing Clickjacking Defense (`X-Frame-Options` / `frame-ancestors`) | `LOW` |
| **Headers & Meta** | `SEC-META-04` | Permissive / Unspecified Referrer Policy | `INFO` / `LOW` |
| **Third-Party** | `SEC-RES-01` | External CDN Scripts Missing Subresource Integrity (`integrity` / SRI) | `MEDIUM` |
| **Third-Party** | `SEC-RES-02` | Reverse Tabnabbing (`target="_blank"` missing `rel="noopener"`) | `LOW` |
| **Third-Party** | `SEC-LIB-01` | Outdated Vulnerable Libraries (jQuery < 3.5.0, AngularJS 1.x, Bootstrap < 4.3.1) | `HIGH` |
| **Form Security** | `SEC-FORM-01` | Forms Submitting to Unencrypted HTTP Targets | `HIGH` |
| **Form Security** | `SEC-FORM-02` | Password Submissions via HTTP `GET` Method | `CRITICAL` |
| **Form Security** | `SEC-FORM-03` | Forms Lacking Anti-CSRF Tokens | `MEDIUM` |

---

## 🚀 Installation Guide

### Load Unpacked Extension in Google Chrome

1. Clone or download this repository:
   ```bash
   git clone https://github.com/Janaka27/WebSheild-Extension.git
   ```
2. Open Google Chrome and navigate to:
   ```text
   chrome://extensions/
   ```
3. Enable **Developer mode** using the toggle switch in the top right corner.
4. Click the **Load unpacked** button in the top left toolbar.
5. Select the project directory (`WebSheild-Extension`).
6. Pin **WebShield** to your extension bar and start scanning!

---

## 🛠️ Tech Stack & Architecture

- **Manifest Version:** Chrome Extensions Manifest V3 (`manifest_version: 3`)
- **Frontend Logic:** Vanilla JavaScript (ES6+), Modern HTML5, Custom CSS3 Dark-Mode System
- **Background Layer:** Service Worker (`background/service-worker.js`)
- **DOM Engine:** Content Script (`scripts/analyzer.js`)
- **PDF Export Engine:** `jsPDF` (`lib/jspdf.umd.min.js` & `scripts/pdf-exporter.js`)
- **Report Dashboard:** Dedicated printable HTML viewer (`report/report.html`)

---

## 📂 Project Structure

```text
WebSheild-Extension/
├── manifest.json            # Manifest V3 extension configuration
├── background/
│   └── service-worker.js    # Ephemeral service worker for storage & badges
├── scripts/
│   ├── analyzer.js          # DOM & Client-side vulnerability scanning engine
│   └── pdf-exporter.js      # Vector PDF document builder module
├── popup/
│   ├── popup.html           # Extension popup interface
│   ├── popup.css            # Dark mode glassmorphic styling & layout
│   └── popup.js             # Popup controller & UI interactions
├── report/
│   ├── report.html          # Full-screen printable HTML report viewer
│   ├── report.css           # Print & dashboard stylesheet
│   └── report.js            # Report viewer controller
├── icons/                   # Extension icons (16px, 48px, 128px)
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
├── lib/
│   └── jspdf.umd.min.js     # Offline bundled jsPDF library
├── CHROMEWEBSTORE.md        # Web Store listing metadata & permissions guide
└── README.md                # Repository documentation
```

---

## 🔒 Privacy & Security

WebShield is designed with strict security and privacy principles:
- **Zero External Requests:** All scanning scripts and PDF engines are bundled locally. No telemetry or analytics.
- **Local Storage Only:** Scan history and scores are cached in `chrome.storage.local` on your machine.
- **No Remote Code Execution:** Strictly adheres to Chrome Web Store Manifest V3 Security Policies.

---

## 📄 License

This project is licensed under the **MIT License**. Feel free to use, customize, and build upon it.
