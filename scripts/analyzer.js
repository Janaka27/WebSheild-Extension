/**
 * WebShield Security Analyzer - Client-Side Vulnerability Engine
 * Performs comprehensive DOM, client-side, form, meta, script, and storage auditing.
 */
(() => {
  const vulnerabilities = [];

  // Helper to push vulnerability finding
  function addFinding({ id, severity, category, title, description, impact, recommendation, elementSnippet = null }) {
    vulnerabilities.push({
      id,
      severity, // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
      category, // 'Connection' | 'Sensitive Data' | 'DOM/XSS' | 'Headers & Meta' | 'Form Security' | 'Third-Party'
      title,
      description,
      impact,
      recommendation,
      elementSnippet: elementSnippet ? String(elementSnippet).trim().substring(0, 200) : null
    });
  }

  const pageUrl = window.location.href;
  const isHttps = window.location.protocol === 'https:';

  // -------------------------------------------------------------
  // 1. Connection & Protocol Audits
  // -------------------------------------------------------------
  if (!isHttps && !window.location.hostname.includes('localhost') && window.location.hostname !== '127.0.0.1') {
    addFinding({
      id: 'SEC-CONN-01',
      severity: 'CRITICAL',
      category: 'Connection',
      title: 'Unencrypted Connection (HTTP)',
      description: 'This website is loaded using plain HTTP instead of encrypted HTTPS.',
      impact: 'All traffic, passwords, and session data transmitted between browser and server can be intercepted or modified by Man-in-the-Middle (MitM) attackers.',
      recommendation: 'Enforce HTTPS across the entire domain and implement HTTP Strict Transport Security (HSTS).'
    });
  }

  // Mixed Content Check (Only relevant on HTTPS sites)
  if (isHttps) {
    const mixedElements = [];
    const elementsToCheck = [
      { selector: 'script[src^="http:"]', type: 'Script' },
      { selector: 'link[rel="stylesheet"][href^="http:"]', type: 'Stylesheet' },
      { selector: 'img[src^="http:"]', type: 'Image' },
      { selector: 'iframe[src^="http:"]', type: 'IFrame' },
      { selector: 'audio[src^="http:"], video[src^="http:"]', type: 'Media' }
    ];

    elementsToCheck.forEach(({ selector, type }) => {
      document.querySelectorAll(selector).forEach(el => {
        const url = el.src || el.href;
        mixedElements.push({ type, url, outerHTML: el.outerHTML });
      });
    });

    if (mixedElements.length > 0) {
      const activeMixed = mixedElements.filter(m => m.type === 'Script' || m.type === 'Stylesheet' || m.type === 'IFrame');
      const severity = activeMixed.length > 0 ? 'HIGH' : 'MEDIUM';

      addFinding({
        id: 'SEC-CONN-02',
        severity,
        category: 'Connection',
        title: `Mixed Content Detected (${mixedElements.length} resources)`,
        description: `This HTTPS page loads ${mixedElements.length} subresources over insecure HTTP.`,
        impact: activeMixed.length > 0
          ? 'Active mixed content (scripts/iframes) allows attackers to tamper with execution context and inject malicious scripts.'
          : 'Passive mixed content (images/media) allows eavesdroppers to spy on user activity or alter graphics.',
        recommendation: 'Update all subresource URLs to use relative paths or explicit https:// protocols.',
        elementSnippet: mixedElements.slice(0, 3).map(m => `[${m.type}] ${m.url}`).join('\n')
      });
    }
  }

  // -------------------------------------------------------------
  // 2. Sensitive Data & Secret Leak Audit
  // -------------------------------------------------------------
  const secretPatterns = [
    { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL' },
    { name: 'OpenAI / AI Secret Key', regex: /sk-[a-zA-Z0-9]{32,}/g, severity: 'CRITICAL' },
    { name: 'Stripe Live API Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'CRITICAL' },
    { name: 'RSA / PEM Private Key', regex: /-----BEGIN (RSA|EC|PGP|OPENSSH)? PRIVATE KEY-----/g, severity: 'CRITICAL' },
    { name: 'Generic JWT / Bearer Token', regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g, severity: 'HIGH' },
    { name: 'Hardcoded Password Field', regex: /(["']?password["']?\s*[:=]\s*["'][^"']{4,}["'])/gi, severity: 'HIGH' }
  ];

  // Scan inline scripts & DOM content for exposed secrets
  const scripts = Array.from(document.querySelectorAll('script:not([src])'));
  const htmlContent = document.documentElement.outerHTML;

  secretPatterns.forEach(({ name, regex, severity }) => {
    let matches = htmlContent.match(regex);
    if (matches && matches.length > 0) {
      // Filter out common false positives for JWT/Tokens if needed
      const sample = matches[0].substring(0, 40) + '...';
      addFinding({
        id: 'SEC-DATA-01',
        severity,
        category: 'Sensitive Data',
        title: `Exposed ${name}`,
        description: `Found potential hardcoded ${name} in the page source or inline scripts.`,
        impact: 'Exposed secret keys can grant unauthorized API access, lead to account takeover, or allow data exfiltration.',
        recommendation: 'Remove hardcoded credentials from client-side files. Use backend proxy services to handle API requests securely.',
        elementSnippet: `Match: ${sample}`
      });
    }
  });

  // Scan HTML Comments for sensitive developer leaks
  const commentNodeIterator = document.createNodeIterator(
    document.documentElement,
    NodeFilter.SHOW_COMMENT,
    null
  );

  let currentComment;
  const sensitiveComments = [];
  const sensitiveKeywords = ['todo', 'fixme', 'password', 'secret', 'admin', 'api_key', 'apikey', 'credentials', 'config'];

  while ((currentComment = commentNodeIterator.nextNode())) {
    const text = currentComment.nodeValue.toLowerCase();
    const matchedKW = sensitiveKeywords.find(kw => text.includes(kw));
    if (matchedKW) {
      sensitiveComments.push({ keyword: matchedKW, text: currentComment.nodeValue.trim() });
    }
  }

  if (sensitiveComments.length > 0) {
    addFinding({
      id: 'SEC-DATA-02',
      severity: 'LOW',
      category: 'Sensitive Data',
      title: `Sensitive Information in HTML Comments (${sensitiveComments.length})`,
      description: 'Found HTML comments containing keywords like TODO, FIXME, admin, or API key references.',
      impact: 'Exposes internal architecture, unfinished features, or internal credentials to public inspection.',
      recommendation: 'Strip HTML comments in production build pipelines.',
      elementSnippet: sensitiveComments.slice(0, 2).map(c => `<!-- ${c.text.substring(0, 100)} -->`).join('\n')
    });
  }

  // -------------------------------------------------------------
  // 3. Client Storage & Cookie Audit
  // -------------------------------------------------------------
  try {
    const sensitiveStorageKeys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const lowerKey = key.toLowerCase();
      if (['token', 'auth', 'password', 'secret', 'jwt', 'session', 'creds', 'user'].some(k => lowerKey.includes(k))) {
        sensitiveStorageKeys.push(`localStorage.${key}`);
      }
    }
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const lowerKey = key.toLowerCase();
      if (['token', 'auth', 'password', 'secret', 'jwt', 'session', 'creds', 'user'].some(k => lowerKey.includes(k))) {
        sensitiveStorageKeys.push(`sessionStorage.${key}`);
      }
    }

    if (sensitiveStorageKeys.length > 0) {
      addFinding({
        id: 'SEC-STOR-01',
        severity: 'MEDIUM',
        category: 'Sensitive Data',
        title: 'Sensitive Tokens in Local/Session Storage',
        description: `Found sensitive storage keys: ${sensitiveStorageKeys.join(', ')}`,
        impact: 'Data in localStorage/sessionStorage is accessible to any JavaScript running on the origin. If an XSS vulnerability exists, attackers can easily steal session tokens.',
        recommendation: 'Store session tokens in HttpOnly, SameSite, Secure cookies instead of web storage.',
        elementSnippet: sensitiveStorageKeys.join('\n')
      });
    }
  } catch (e) {
    // Storage access blocked or restricted
  }

  // Cookie Accessibility Check (Client JS accessible cookies)
  if (document.cookie) {
    const cookieNames = document.cookie.split(';').map(c => c.split('=')[0].trim());
    const sensitiveCookieNames = cookieNames.filter(name =>
      ['session', 'sess', 'token', 'auth', 'jwt', 'sid', 'user'].some(k => name.toLowerCase().includes(k))
    );

    if (sensitiveCookieNames.length > 0) {
      addFinding({
        id: 'SEC-STOR-02',
        severity: 'MEDIUM',
        category: 'Sensitive Data',
        title: `Non-HttpOnly Session Cookie Readable by JS (${sensitiveCookieNames.length})`,
        description: `The following session cookies are accessible via document.cookie: ${sensitiveCookieNames.join(', ')}`,
        impact: 'If cookies lack the HttpOnly flag, malicious scripts injected via XSS can instantly exfiltrate session credentials.',
        recommendation: 'Set the HttpOnly flag on all session cookies to block JavaScript access.'
      });
    }
  }

  // -------------------------------------------------------------
  // 4. DOM Cross-Site Scripting (XSS) & Execution Audits
  // -------------------------------------------------------------
  const inlineScriptsWithDanger = [];
  scripts.forEach(script => {
    const code = script.textContent;
    if (/eval\s*\(|document\.write\s*\(|innerHTML\s*=\s*.*(location|url|search|hash)|setTimeout\s*\(\s*["']/i.test(code)) {
      inlineScriptsWithDanger.push(script.outerHTML.substring(0, 150));
    }
  });

  if (inlineScriptsWithDanger.length > 0) {
    addFinding({
      id: 'SEC-DOM-01',
      severity: 'HIGH',
      category: 'DOM/XSS',
      title: 'Risky DOM Execution Functions Found',
      description: 'Inline scripts contain unsafe DOM manipulation functions like eval(), document.write(), or innerHTML with URL parameters.',
      impact: 'Creates opportunities for DOM-based Cross-Site Scripting (DOM XSS), allowing attackers to run arbitrary code in the user browser context.',
      recommendation: 'Avoid eval() and document.write(). Use safe DOM APIs like textContent, createElement, or DOMPurify for user input rendering.',
      elementSnippet: inlineScriptsWithDanger.slice(0, 2).join('\n')
    });
  }

  // Check for dangerous javascript: URIs in anchors or frames
  const jsUris = Array.from(document.querySelectorAll('a[href^="javascript:"], iframe[src^="javascript:"]'));
  if (jsUris.length > 0) {
    addFinding({
      id: 'SEC-DOM-02',
      severity: 'LOW',
      category: 'DOM/XSS',
      title: `javascript: Scheme URIs Found (${jsUris.length})`,
      description: 'Found links or iframes using inline javascript: scheme execution.',
      impact: 'Obsolete pattern that interferes with CSP restrictions and increases XSS risk.',
      recommendation: 'Replace javascript: pseudo-protocol URIs with standard event listeners in external scripts.',
      elementSnippet: jsUris[0].outerHTML
    });
  }

  // -------------------------------------------------------------
  // 5. Headers & Meta Security Policy Audits
  // -------------------------------------------------------------
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!cspMeta) {
    addFinding({
      id: 'SEC-META-01',
      severity: 'HIGH',
      category: 'Headers & Meta',
      title: 'Missing Content Security Policy (CSP) Meta Tag',
      description: 'No client-side Content-Security-Policy (CSP) meta tag was detected.',
      impact: 'Without CSP, the browser has no defense-in-depth rules to restrict script sources, object loading, or unauthorized network requests if XSS occurs.',
      recommendation: 'Implement a strict Content-Security-Policy via HTTP headers or <meta http-equiv="Content-Security-Policy"> tag.'
    });
  } else {
    const cspContent = cspMeta.getAttribute('content') || '';
    if (cspContent.includes("'unsafe-inline'") || cspContent.includes("'unsafe-eval'") || cspContent.includes('*')) {
      addFinding({
        id: 'SEC-META-02',
        severity: 'MEDIUM',
        category: 'Headers & Meta',
        title: 'Weak Content Security Policy Directives',
        description: 'CSP meta tag contains weak keywords such as unsafe-inline, unsafe-eval, or wildcard (*).',
        impact: 'Allows inline script execution or unvalidated external script origins, undermining the primary security benefits of CSP.',
        recommendation: 'Remove unsafe-inline/unsafe-eval directives. Use nonces or hashes for legitimate inline scripts.'
      });
    }
  }

  // Anti-Clickjacking / Frame Protection Check
  const frameOptionsMeta = document.querySelector('meta[http-equiv="X-Frame-Options"]');
  if (!frameOptionsMeta && (!cspMeta || !cspMeta.getAttribute('content')?.includes('frame-ancestors'))) {
    addFinding({
      id: 'SEC-META-03',
      severity: 'LOW',
      category: 'Headers & Meta',
      title: 'Missing Clickjacking Defense Meta Tag',
      description: 'No X-Frame-Options or CSP frame-ancestors directive found in HTML meta tags.',
      impact: 'The page might be embeddable inside an iframe on malicious websites, subjecting users to clickjacking attacks.',
      recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN in HTTP headers or CSP frame-ancestors directive.'
    });
  }

  // Referrer Policy Check
  const referrerMeta = document.querySelector('meta[name="referrer"]');
  if (!referrerMeta) {
    addFinding({
      id: 'SEC-META-04',
      severity: 'INFO',
      category: 'Headers & Meta',
      title: 'Unspecified Referrer Policy',
      description: 'No explicit Referrer-Policy meta tag defined.',
      impact: 'Full page URLs containing sensitive tokens or parameter keys in the query string may leak to external domains upon navigation.',
      recommendation: 'Add <meta name="referrer" content="strict-origin-when-cross-origin"> to preserve privacy.'
    });
  } else {
    const refVal = referrerMeta.getAttribute('content') || '';
    if (['unsafe-url', 'no-referrer-when-downgrade'].includes(refVal.toLowerCase())) {
      addFinding({
        id: 'SEC-META-05',
        severity: 'LOW',
        category: 'Headers & Meta',
        title: 'Permissive Referrer Policy',
        description: `Referrer Policy is set to permissive value: "${refVal}".`,
        impact: 'May leak confidential query parameters and URLs to third parties.',
        recommendation: 'Change referrer policy to strict-origin-when-cross-origin or no-referrer.'
      });
    }
  }

  // -------------------------------------------------------------
  // 6. Resource Integrity & Link Security
  // -------------------------------------------------------------
  // Subresource Integrity (SRI) for external scripts
  const externalScripts = Array.from(document.querySelectorAll('script[src^="http"]'));
  const scriptsLackingSRI = externalScripts.filter(s => {
    const src = s.getAttribute('src') || '';
    return !src.includes(window.location.hostname) && !s.hasAttribute('integrity');
  });

  if (scriptsLackingSRI.length > 0) {
    addFinding({
      id: 'SEC-RES-01',
      severity: 'MEDIUM',
      category: 'Third-Party',
      title: `Third-Party Scripts Missing Subresource Integrity (SRI) (${scriptsLackingSRI.length})`,
      description: `${scriptsLackingSRI.length} external CDN script(s) are loaded without integrity hashes.`,
      impact: 'If the external CDN server is compromised or hijacked, attackers can serve malicious code to all visitors without detection.',
      recommendation: 'Add integrity cryptographic hash attribute (e.g. integrity="sha384-...") and crossorigin="anonymous" to all external scripts.',
      elementSnippet: scriptsLackingSRI.slice(0, 2).map(s => s.outerHTML).join('\n')
    });
  }

  // Reverse Tabnabbing (target="_blank" without rel="noopener")
  const blankLinks = Array.from(document.querySelectorAll('a[target="_blank"]'));
  const tabnabbingLinks = blankLinks.filter(a => {
    const rel = (a.getAttribute('rel') || '').toLowerCase();
    return !rel.includes('noopener') && !rel.includes('noreferrer');
  });

  if (tabnabbingLinks.length > 0) {
    addFinding({
      id: 'SEC-RES-02',
      severity: 'LOW',
      category: 'Third-Party',
      title: `Reverse Tabnabbing Vulnerability (${tabnabbingLinks.length} links)`,
      description: `Found ${tabnabbingLinks.length} target="_blank" link(s) missing rel="noopener" or rel="noreferrer".`,
      impact: 'Opened target page can access window.opener property and redirect the original tab to a fraudulent phishing website.',
      recommendation: 'Add rel="noopener noreferrer" to all external links opening in a new tab.',
      elementSnippet: tabnabbingLinks.slice(0, 2).map(a => a.outerHTML).join('\n')
    });
  }

  // -------------------------------------------------------------
  // 7. Form Security Audits
  // -------------------------------------------------------------
  const forms = Array.from(document.querySelectorAll('form'));
  let insecureFormSubmissions = 0;
  let getMethodPasswordForms = 0;
  let formsLackingCsrf = 0;

  forms.forEach(form => {
    const action = form.getAttribute('action') || '';
    const method = (form.getAttribute('method') || 'GET').toUpperCase();
    const hasPasswordInput = form.querySelector('input[type="password"]');

    if (isHttps && action.startsWith('http:')) {
      insecureFormSubmissions++;
    }

    if (method === 'GET' && hasPasswordInput) {
      getMethodPasswordForms++;
    }

    if (method === 'POST') {
      const hasCsrfInput = Array.from(form.querySelectorAll('input')).some(input => {
        const name = (input.name || input.id || '').toLowerCase();
        return name.includes('csrf') || name.includes('token') || name.includes('nonce') || name.includes('_token');
      });
      if (!hasCsrfInput) formsLackingCsrf++;
    }
  });

  if (insecureFormSubmissions > 0) {
    addFinding({
      id: 'SEC-FORM-01',
      severity: 'HIGH',
      category: 'Form Security',
      title: 'Forms Submitting to Insecure HTTP Endpoints',
      description: `Found ${insecureFormSubmissions} form(s) submitting data to unencrypted HTTP URLs on an HTTPS site.`,
      impact: 'Submitted credentials and user data will be exposed in cleartext across the network.',
      recommendation: 'Ensure all form action targets use explicit HTTPS URLs.'
    });
  }

  if (getMethodPasswordForms > 0) {
    addFinding({
      id: 'SEC-FORM-02',
      severity: 'CRITICAL',
      category: 'Form Security',
      title: 'Passwords Submitted via HTTP GET Method',
      description: 'Found form(s) containing password inputs that submit via GET method.',
      impact: 'Passwords will be appended directly to the URL query string, appearing in browser history, server access logs, and referrer headers.',
      recommendation: 'Change form method to POST and handle authentication requests over TLS.'
    });
  }

  if (formsLackingCsrf > 0 && forms.length > 0) {
    addFinding({
      id: 'SEC-FORM-03',
      severity: 'MEDIUM',
      category: 'Form Security',
      title: `Forms Lacking CSRF Protection Tokens (${formsLackingCsrf})`,
      description: `Detected ${formsLackingCsrf} POST form(s) without visible hidden CSRF tokens.`,
      impact: 'Renders users vulnerable to Cross-Site Request Forgery (CSRF), allowing malicious sites to submit unauthorized actions on their behalf.',
      recommendation: 'Include unique anti-CSRF tokens in form hidden fields or send them via custom HTTP headers.'
    });
  }

  // -------------------------------------------------------------
  // 8. Outdated JavaScript Libraries Check
  // -------------------------------------------------------------
  const libraryChecks = [
    {
      name: 'jQuery',
      detect: () => window.jQuery?.fn?.jquery,
      isVulnerable: (ver) => {
        const parts = ver.split('.').map(Number);
        return parts[0] < 3 || (parts[0] === 3 && parts[1] < 5);
      },
      vulnDesc: 'jQuery versions prior to 3.5.0 contain known XSS vulnerabilities in HTML parsing (CVE-2020-11022).'
    },
    {
      name: 'AngularJS',
      detect: () => window.angular?.version?.full,
      isVulnerable: () => true, // All 1.x versions are EOL
      vulnDesc: 'AngularJS (1.x) reached End-Of-Life and suffers from sandbox escape and DOM XSS issues.'
    },
    {
      name: 'Bootstrap JS',
      detect: () => window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION,
      isVulnerable: (ver) => ver.startsWith('3.') || ver.startsWith('4.0') || ver.startsWith('4.1'),
      vulnDesc: 'Older Bootstrap versions (< 4.3.1) contain XSS vulnerabilities in tooltip and popover plugins.'
    }
  ];

  libraryChecks.forEach(lib => {
    try {
      const version = lib.detect();
      if (version) {
        const vulnerable = lib.isVulnerable(version);
        if (vulnerable) {
          addFinding({
            id: 'SEC-LIB-01',
            severity: 'HIGH',
            category: 'Third-Party',
            title: `Outdated Library: ${lib.name} v${version}`,
            description: `Detected vulnerable version of ${lib.name} (v${version}). ${lib.vulnDesc}`,
            impact: 'Known security vulnerabilities in unpatched legacy libraries can be easily exploited with existing public exploits.',
            recommendation: `Upgrade ${lib.name} to the latest stable release.`
          });
        }
      }
    } catch (e) {
      // Ignore detection errors
    }
  });

  // -------------------------------------------------------------
  // 9. Technology Stack Detection Engine
  // -------------------------------------------------------------
  const detectedTechs = [];

  function addTech(name, category, version = null, description = '') {
    if (!detectedTechs.some(t => t.name === name)) {
      detectedTechs.push({ name, category, version, description });
    }
  }

  try {
    // A. Web Frameworks & Libraries
    if (window.__NEXT_DATA__ || document.getElementById('__NEXT_DATA__') || document.querySelector('script[src*="/_next/"]')) {
      addTech('Next.js', 'Web Framework', window.__NEXT_DATA__?.buildId ? 'React SSR' : null, 'React Framework for Production');
    }

    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot], [data-reactid]') || Array.from(document.querySelectorAll('*')).some(el => Object.keys(el).some(k => k.startsWith('__reactFiber$') || k.startsWith('__reactProps$') || k.startsWith('_reactRootContainer')))) {
      const ver = window.React?.version || null;
      addTech('React', 'JavaScript Library', ver, 'UI Component Library by Meta');
    }

    if (window.__NUXT__ || document.getElementById('__NUXT__') || document.querySelector('script[src*="/_nuxt/"]')) {
      addTech('Nuxt.js', 'Web Framework', null, 'Intuitive Vue Framework');
    }

    if (window.Vue || window.__VUE__ || document.querySelector('[data-v-]') || Array.from(document.querySelectorAll('*')).some(el => Object.keys(el).some(k => k.startsWith('__vue')))) {
      const ver = window.Vue?.version || (window.__VUE__ ? 'v3' : null);
      addTech('Vue.js', 'JavaScript Framework', ver, 'Progressive JavaScript Framework');
    }

    const ngEl = document.querySelector('[ng-version]');
    if (window.ng || ngEl || document.querySelector('[ng-app], [ng-controller]')) {
      const ver = ngEl?.getAttribute('ng-version') || null;
      addTech('Angular', 'JavaScript Framework', ver, 'Web Application Platform by Google');
    }

    if (window.angular) {
      const ver = window.angular?.version?.full || '1.x';
      addTech('AngularJS', 'Legacy Framework', ver, 'Legacy JavaScript Framework');
    }

    if (window.__svelte || document.querySelector('style[id*="svelte"]') || document.querySelector('script[src*="_app/immutable"]') || Array.from(document.querySelectorAll('*')).some(el => Array.from(el.classList || []).some(c => c.startsWith('svelte-')))) {
      addTech('Svelte', 'JavaScript Framework', null, 'Cybernetically enhanced web apps');
    }

    if (window.___gatsby || document.getElementById('___gatsby')) {
      addTech('Gatsby', 'Static Site Generator', null, 'React-based static site generator');
    }

    if (window.jQuery || window.$?.fn?.jquery) {
      const ver = window.jQuery?.fn?.jquery || window.$?.fn?.jquery || null;
      addTech('jQuery', 'JavaScript Library', ver, 'DOM Manipulation Library');
    }

    if (window.Alpine || document.querySelector('[x-data], [x-init]')) {
      const ver = window.Alpine?.version || null;
      addTech('Alpine.js', 'JavaScript Framework', ver, 'Lightweight reactive framework');
    }

    if (window.htmx || document.querySelector('[hx-get], [hx-post], [hx-target], [hx-swap]')) {
      const ver = window.htmx?.version || null;
      addTech('HTMX', 'JavaScript Library', ver, 'AJAX & HTML extensions');
    }

    if (window.Ember || document.querySelector('.ember-view')) {
      addTech('Ember.js', 'JavaScript Framework', window.Ember?.VERSION || null, 'Framework for ambitious web developers');
    }

    if (window.Backbone) {
      addTech('Backbone.js', 'JavaScript Library', window.Backbone?.VERSION || null, 'RESTful JSON interface library');
    }

    // B. UI & CSS Frameworks
    const hasTailwindClass = Array.from(document.querySelectorAll('*')).some(el => {
      const cls = typeof el.className === 'string' ? el.className : '';
      return /\b(flex|grid|hidden|bg-\w+-\d+|text-\w+-\d+|p[xy]?-\d+|m[xy]?-\d+|rounded-\w+|shadow-\w+)\b/.test(cls);
    });
    const hasTailwindLink = document.querySelector('link[href*="tailwind"], script[src*="tailwind"], style[id*="tailwind"]');
    if (hasTailwindLink || hasTailwindClass) {
      addTech('Tailwind CSS', 'CSS Framework', null, 'Utility-First CSS Framework');
    }

    const bsVer = window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION || null;
    const hasBsLink = document.querySelector('link[href*="bootstrap"], script[src*="bootstrap"]');
    const hasBsClass = document.querySelector('.container, .row, .col-md-6, .btn-primary, .modal-dialog');
    if (window.bootstrap || hasBsLink || (hasBsClass && hasBsLink)) {
      addTech('Bootstrap', 'CSS Framework', bsVer, 'Popular Responsive CSS Toolkit');
    }

    if (document.querySelector('link[href*="bulma"]') || (document.querySelector('.is-flex, .has-text-centered, .hero-body') && document.querySelector('link[href*="bulma"]'))) {
      addTech('Bulma', 'CSS Framework', null, 'Modern CSS framework based on Flexbox');
    }

    if (window.Mui || document.querySelector('[class*="MuiBox-root"], [class*="MuiButton-root"], [class*="MuiTypography-root"]')) {
      addTech('Material UI (MUI)', 'UI Component Library', null, 'React UI component library');
    }

    if (document.querySelector('[class*="chakra-"]')) {
      addTech('Chakra UI', 'UI Component Library', null, 'Modular React component library');
    }

    if (document.querySelector('[class*="ant-btn"], [class*="ant-layout"], [class*="ant-menu"]')) {
      addTech('Ant Design', 'UI Component Library', null, 'Enterprise-class UI design language');
    }

    if (document.querySelector('link[href*="font-awesome"], link[href*="fontawesome"], script[src*="fontawesome"]') || document.querySelector('i[class*="fa-"], i[class*="fas "], i[class*="fab "]')) {
      addTech('Font Awesome', 'Icon Toolkit', null, 'Icon library and SVG toolkit');
    }

    // C. CMS & Site Builders
    const wpMeta = document.querySelector('meta[name="generator"][content*="WordPress"]');
    if (window.wp || wpMeta || document.querySelector('link[href*="wp-content"], script[src*="wp-includes"]')) {
      const verMatch = wpMeta?.getAttribute('content')?.match(/WordPress\s+([\d.]+)/i);
      addTech('WordPress', 'CMS', verMatch ? verMatch[1] : null, 'Popular Content Management System');
    }

    if (window.Shopify || document.querySelector('script[src*="cdn.shopify.com"]')) {
      addTech('Shopify', 'E-commerce Platform', null, 'Global E-commerce Platform');
    }

    const wfMeta = document.querySelector('meta[content*="Webflow"]');
    if (window.Webflow || wfMeta || document.querySelector('html[data-wf-page]')) {
      addTech('Webflow', 'Website Builder', null, 'Visual web design & CMS platform');
    }

    const wixMeta = document.querySelector('meta[name="generator"][content*="Wix"]');
    if (window.wixDeveloperAnalytics || wixMeta || document.querySelector('script[src*="wix.com"], link[href*="wixstatic.com"]')) {
      addTech('Wix', 'Website Builder', null, 'Cloud-based web development platform');
    }

    const sqMeta = document.querySelector('meta[name="generator"][content*="Squarespace"]');
    if (window.Static?.SQUARESPACE_CACHE_VERSION || sqMeta || document.querySelector('link[href*="squarespace.com"]')) {
      addTech('Squarespace', 'Website Builder', null, 'Website builder and hosting platform');
    }

    const drupalMeta = document.querySelector('meta[name="generator"][content*="Drupal"]');
    if (window.Drupal || drupalMeta || document.querySelector('script[src*="drupal.js"]')) {
      const verMatch = drupalMeta?.getAttribute('content')?.match(/Drupal\s+([\d.]+)/i);
      addTech('Drupal', 'CMS', verMatch ? verMatch[1] : null, 'Open-source content management software');
    }

    const joomlaMeta = document.querySelector('meta[name="generator"][content*="Joomla"]');
    if (joomlaMeta || document.querySelector('script[src*="joomla"]')) {
      addTech('Joomla', 'CMS', null, 'Flexible Content Management System');
    }

    const ghostMeta = document.querySelector('meta[name="generator"][content*="Ghost"]');
    if (ghostMeta || document.querySelector('link[href*="ghost.css"]')) {
      addTech('Ghost', 'Publishing Platform', null, 'Independent technology for modern publishing');
    }

    if (window.Mage || document.querySelector('script[src*="mage/"], link[href*="skin/frontend"]')) {
      addTech('Magento', 'E-commerce Platform', null, 'Open source e-commerce platform');
    }

    // D. Analytics & Tracking
    if (window.ga || window.gtag || window.dataLayer || document.querySelector('script[src*="google-analytics.com"], script[src*="googletagmanager.com/gtag/js"]')) {
      addTech('Google Analytics', 'Analytics', null, 'Web analytics service by Google');
    }

    if (window.google_tag_manager || document.querySelector('script[src*="googletagmanager.com/gtm.js"]')) {
      addTech('Google Tag Manager', 'Tag Management', null, 'Tag management system by Google');
    }

    if (window.fbq || document.querySelector('script[src*="connect.facebook.net"]')) {
      addTech('Meta Pixel', 'Analytics & Ads', null, 'Conversion tracking for Facebook ads');
    }

    if (window.hj || document.querySelector('script[src*="static.hotjar.com"]')) {
      addTech('Hotjar', 'Behavior Analytics', null, 'Heatmaps and behavior analytics');
    }

    if (window.clarity || document.querySelector('script[src*="clarity.ms"]')) {
      addTech('Microsoft Clarity', 'Behavior Analytics', null, 'User behavior analytics tool');
    }

    if (window.mixpanel || document.querySelector('script[src*="mixpanel.com"]')) {
      addTech('Mixpanel', 'Analytics', null, 'Product analytics software');
    }

    if (window.posthog || document.querySelector('script[src*="posthog"]')) {
      addTech('PostHog', 'Product Analytics', null, 'Open source product analytics');
    }

    if (window.analytics?.track || document.querySelector('script[src*="cdn.segment.com"]')) {
      addTech('Segment', 'Customer Data Platform', null, 'Customer data infrastructure platform');
    }

    // E. CDNs & Cloud Infrastructure
    if (document.querySelector('script[src*="challenges.cloudflare.com"], script[src*="static.cloudflareinsights.com"]') || document.cookie.includes('__cf_bm') || document.cookie.includes('cf_clearance')) {
      addTech('Cloudflare', 'CDN & Security', null, 'Content delivery network & security');
    }

    if (window.__VERCEL_ANALYTICS__ || document.querySelector('script[src*="_vercel"]')) {
      addTech('Vercel', 'Hosting & Cloud', null, 'Cloud platform for web apps and functions');
    }

    if (document.querySelector('form[data-netlify]') || document.querySelector('script[src*="netlify"]')) {
      addTech('Netlify', 'Hosting & Cloud', null, 'Web development and automation platform');
    }

    if (document.querySelector('script[src*="cloudfront.net"], link[href*="cloudfront.net"]')) {
      addTech('Amazon CloudFront', 'CDN', null, 'Global content delivery network by AWS');
    }

    // F. Backend / Server Signatures
    if (document.cookie.includes('PHPSESSID') || Array.from(document.querySelectorAll('a[href]')).some(a => (a.href || '').includes('.php'))) {
      addTech('PHP', 'Backend Language', null, 'Server-side scripting language');
    }

    if (document.querySelector('input[name="__VIEWSTATE"]') || document.cookie.includes('ASP.NET_SessionId')) {
      addTech('ASP.NET', 'Web Framework', null, 'Microsoft web framework');
    }

    if (document.cookie.includes('XSRF-TOKEN') && document.cookie.includes('laravel_session')) {
      addTech('Laravel', 'Web Framework', null, 'PHP Web Framework');
    }

    if (document.cookie.includes('csrftoken') && document.cookie.includes('sessionid')) {
      addTech('Django', 'Web Framework', null, 'Python Web Framework');
    }

    if (document.querySelector('meta[name="csrf-param"][content="authenticity_token"]') || document.cookie.includes('_session_id')) {
      addTech('Ruby on Rails', 'Web Framework', null, 'Ruby Web Framework');
    }

    // Generic Generator Meta Tag Fallback
    const genMeta = document.querySelector('meta[name="generator"]')?.getAttribute('content');
    if (genMeta && !detectedTechs.some(t => genMeta.toLowerCase().includes(t.name.toLowerCase()))) {
      addTech(genMeta.trim(), 'CMS / Generator', null, 'Detected from HTML generator meta tag');
    }

  } catch (e) {
    // Ignore tech detection errors gracefully
  }

  // -------------------------------------------------------------
  // Score Calculation & Final Synthesis
  // -------------------------------------------------------------
  let score = 100;
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

  vulnerabilities.forEach(v => {
    counts[v.severity] = (counts[v.severity] || 0) + 1;
    if (v.severity === 'CRITICAL') score -= 25;
    else if (v.severity === 'HIGH') score -= 15;
    else if (v.severity === 'MEDIUM') score -= 8;
    else if (v.severity === 'LOW') score -= 3;
    else if (v.severity === 'INFO') score -= 1;
  });

  score = Math.max(0, Math.min(100, score));

  let rating = 'EXCELLENT';
  let badgeColor = '#10B981'; // Green
  if (score < 50 || counts.CRITICAL > 0) {
    rating = 'CRITICAL RISK';
    badgeColor = '#EF4444'; // Red
  } else if (score < 70 || counts.HIGH > 0) {
    rating = 'HIGH RISK';
    badgeColor = '#F97316'; // Orange
  } else if (score < 88 || counts.MEDIUM > 0) {
    rating = 'MODERATE RISK';
    badgeColor = '#F59E0B'; // Amber
  }

  return {
    url: pageUrl,
    title: document.title,
    hostname: window.location.hostname,
    protocol: window.location.protocol,
    timestamp: new Date().toISOString(),
    score,
    rating,
    badgeColor,
    counts,
    totalIssues: vulnerabilities.length,
    vulnerabilities,
    technologies: detectedTechs
  };
})();
