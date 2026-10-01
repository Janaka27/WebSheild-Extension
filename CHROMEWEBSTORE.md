# Chrome Web Store Metadata & Publishing Guide

## Store Metadata

- **Extension Name:** WebShield - Security & Vulnerability Scanner
- **Short Description (max 132 chars):** Analyze website security in one click. Detect client-side vulnerabilities, OWASP flaws, secret leaks, and insecure forms.
- **Category:** Developer Tools / Productivity
- **Primary Language:** English

## Full Description

WebShield is a powerful client-side website vulnerability analyzer that helps web developers, security researchers, and privacy-conscious users inspect and audit the security health of any web page in real-time.

With a single click, WebShield scans the active web page and delivers a comprehensive security report with actionable remediation guidance.

### Key Features:
- **Instant Security Auditing:** Scan any web page with a single click of the extension popup button.
- **Security Score Gauge:** Get an overall 0-100 security rating based on real-time findings.
- **Technology Stack Detection:** Instantly identify frameworks, JS libraries, CSS toolkits, CMS engines, analytics trackers, and server signatures.
- **Cross-Site Scripting (XSS) & DOM Analysis:** Detect dangerous inline script executions, eval() usage, and unsanitized innerHTML DOM manipulations.
- **Secret & Credential Leak Detection:** Scan inline scripts and page source for hardcoded API keys (AWS, Stripe, OpenAI), JWT tokens, and private keys.
- **Connection & Protocol Health:** Identify unencrypted HTTP connections, active mixed content, and insecure resource loading.
- **Header & Meta Security Checks:** Audit Content Security Policy (CSP), anti-clickjacking frame options, and referrer leak policies.
- **Form & Input Inspection:** Flag cleartext password submissions, missing anti-CSRF tokens, and insecure HTTP form targets.
- **Resource Integrity & Link Safety:** Detect third-party CDN scripts missing Subresource Integrity (SRI) hashes and reverse tabnabbing links.
- **Exportable PDF & HTML Reports:** Generate vector PDF reports and printable executive security dashboards.

---

## Permissions Justification

| Permission / Host | Justification |
| :--- | :--- |
| `activeTab` | Required to gain temporary permission to analyze the security structure of the currently open tab when the user clicks the extension action. |
| `scripting` | Required to execute the client-side vulnerability analyzer script inside the active tab DOM to detect DOM flaws, form security issues, and inline script risks. |
| `storage` | Required to save recent scan history and security scores locally on the user's browser so results persist across popups. |
| `tabs` | Required to retrieve the URL, protocol, and hostname of the current tab for domain security score calculation. |
| `<all_urls>` (host permission) | Required to allow the security scanner to analyze any website or web application that the user chooses to audit. |

---

## Privacy & Data Use Disclosure

- **Data Collection:** WebShield does NOT collect, store, transmit, or share any personal data, browsing history, or user credentials to external servers. All vulnerability analysis is performed entirely client-side inside your local browser instance.
- **Remote Code:** WebShield does NOT execute any remotely hosted code. All analysis scripts are bundled within the extension package.

---

## Version History

### Version 1.0.0 (Initial Release)
- Initial launch of WebShield Security & Vulnerability Scanner.
- Real-time client-side vulnerability auditing engine.
- Interactive score gauge, severity filter tabs, and Markdown report export.
