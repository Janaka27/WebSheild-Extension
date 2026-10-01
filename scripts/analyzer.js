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
    vulnerabilities
  };
})();
