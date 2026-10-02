/**
 * WebShield Extension Popup Controller
 */
document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  const targetDomainEl = document.getElementById('targetDomain');
  const siteProtocolBadge = document.getElementById('siteProtocolBadge');

  const initialState = document.getElementById('initialState');
  const scanningState = document.getElementById('scanningState');
  const resultsState = document.getElementById('resultsState');

  const startScanBtn = document.getElementById('startScanBtn');
  const rescanBtn = document.getElementById('rescanBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');

  const scanningStepText = document.getElementById('scanningStepText');
  const scanProgressBar = document.getElementById('scanProgressBar');

  const scoreValue = document.getElementById('scoreValue');
  const scoreGaugeArc = document.getElementById('scoreGaugeArc');
  const scoreRatingBadge = document.getElementById('scoreRatingBadge');
  const totalIssuesText = document.getElementById('totalIssuesText');

  const cntCritical = document.getElementById('cntCritical');
  const cntHigh = document.getElementById('cntHigh');
  const cntMedium = document.getElementById('cntMedium');
  const cntLow = document.getElementById('cntLow');
  const cntInfo = document.getElementById('cntInfo');
  const cntTech = document.getElementById('cntTech');

  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
  const techStackSection = document.getElementById('techStackSection');
  const noIssuesState = document.getElementById('noIssuesState');
  const tabButtons = document.querySelectorAll('.tab-btn');

  let currentScanResult = null;
  let activeTab = null;

  // Initialize & Query Active Tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs.length > 0) {
      activeTab = tabs[0];
      const url = new URL(activeTab.url || 'http://localhost');
      targetDomainEl.textContent = url.hostname || activeTab.url;

      siteProtocolBadge.textContent = url.protocol.replace(':', '').toUpperCase();
      if (url.protocol === 'https:') {
        siteProtocolBadge.style.color = '#10B981';
        siteProtocolBadge.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      } else {
        siteProtocolBadge.style.color = '#EF4444';
        siteProtocolBadge.style.borderColor = 'rgba(239, 68, 68, 0.4)';
      }

      // Check if we have cached scan results for this URL
      const { lastScan } = await chrome.storage.local.get('lastScan');
      if (lastScan && lastScan.url === activeTab.url) {
        currentScanResult = lastScan;
        renderScanResults(lastScan);
      }
    }
  } catch (err) {
    targetDomainEl.textContent = 'Active Page';
    console.error('Error fetching tab:', err);
  }

  // Event Listeners
  startScanBtn.addEventListener('click', () => runSecurityScan());
  rescanBtn.addEventListener('click', () => runSecurityScan());
  exportReportBtn.addEventListener('click', () => exportSecurityReport());

  // Filter Tabs Event Handlers
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const filter = btn.dataset.tab;
      renderVulnerabilitiesList(filter);
    });
  });

  // Severity Pills Click Handlers
  const sevPills = document.querySelectorAll('.sev-pill');
  sevPills.forEach(pill => {
    pill.style.cursor = 'pointer';
    pill.addEventListener('click', () => {
      const sev = pill.dataset.sev;
      tabButtons.forEach(b => b.classList.remove('active'));
      renderVulnerabilitiesList(sev);
    });
  });

  /**
   * Runs the step-by-step security scanner
   */
  async function runSecurityScan() {
    if (!activeTab || !activeTab.id) {
      alert('Cannot access active tab context.');
      return;
    }

    // Prevent scanning browser internal pages (chrome://, chrome-extension://, edge://)
    if (activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('chrome-extension://') || activeTab.url.startsWith('edge://')) {
      alert('Security scans cannot be run on internal browser pages.');
      return;
    }

    // Switch UI to Scanning state
    initialState.classList.add('hidden');
    resultsState.classList.add('hidden');
    scanningState.classList.remove('hidden');

    const steps = [
      { text: 'Connecting to tab DOM...', progress: 15 },
      { text: 'Scanning inline scripts & secret leaks...', progress: 35 },
      { text: 'Auditing security headers & forms...', progress: 55 },
      { text: 'Detecting frameworks & tech stack...', progress: 75 },
      { text: 'Analyzing cookies & third-party CDNs...', progress: 90 },
      { text: 'Calculating security risk score...', progress: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
      scanningStepText.textContent = steps[i].text;
      scanProgressBar.style.width = `${steps[i].progress}%`;
      await new Promise(r => setTimeout(r, 200));
    }

    try {
      // Execute analyzer script on the page
      const results = await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        files: ['scripts/analyzer.js']
      });

      if (results && results[0] && results[0].result) {
        currentScanResult = results[0].result;

        // Save scan result & update badge
        await chrome.runtime.sendMessage({
          type: 'SAVE_SCAN',
          scanResult: currentScanResult
        });

        await chrome.runtime.sendMessage({
          type: 'UPDATE_BADGE',
          count: currentScanResult.totalIssues,
          color: currentScanResult.badgeColor
        });

        // Delay slightly for smooth transition
        setTimeout(() => {
          renderScanResults(currentScanResult);
        }, 150);
      } else {
        throw new Error('No audit data returned from script execution.');
      }
    } catch (err) {
      console.error('Scan execution error:', err);
      alert(`Failed to scan page: ${err.message}`);
      scanningState.classList.add('hidden');
      initialState.classList.remove('hidden');
    }
  }

  /**
   * Renders the complete scan results view
   */
  function renderScanResults(scan) {
    scanningState.classList.add('hidden');
    initialState.classList.add('hidden');
    resultsState.classList.remove('hidden');

    // 1. Update Gauge & Score
    scoreValue.textContent = scan.score;
    const maxDash = 263.89; // 2 * PI * 42
    const offset = maxDash - (maxDash * scan.score) / 100;
    scoreGaugeArc.style.strokeDashoffset = offset;

    // Colorize Arc based on score
    let strokeColor = '#10B981'; // Green
    let ratingClass = 'rating-good';
    if (scan.score < 50 || scan.counts.CRITICAL > 0) {
      strokeColor = '#EF4444';
      ratingClass = 'rating-critical';
    } else if (scan.score < 70 || scan.counts.HIGH > 0) {
      strokeColor = '#F97316';
      ratingClass = 'rating-high';
    } else if (scan.score < 88 || scan.counts.MEDIUM > 0) {
      strokeColor = '#F59E0B';
      ratingClass = 'rating-mod';
    }

    scoreGaugeArc.style.stroke = strokeColor;
    scoreRatingBadge.className = `rating-badge ${ratingClass}`;
    scoreRatingBadge.textContent = scan.rating;

    totalIssuesText.textContent = scan.totalIssues === 1
      ? '1 vulnerability detected'
      : `${scan.totalIssues} vulnerabilities detected`;

    // 2. Update Severity & Tech Counts
    cntCritical.textContent = scan.counts.CRITICAL || 0;
    cntHigh.textContent = scan.counts.HIGH || 0;
    cntMedium.textContent = scan.counts.MEDIUM || 0;
    cntLow.textContent = scan.counts.LOW || 0;
    cntInfo.textContent = scan.counts.INFO || 0;
    if (cntTech) cntTech.textContent = (scan.technologies || []).length;

    // 3. Render List
    renderVulnerabilitiesList('ALL');
  }

  /**
   * Renders the list of vulnerabilities or tech stack based on selected filter tab
   */
  function renderVulnerabilitiesList(filter = 'ALL') {
    if (!currentScanResult) return;

    if (filter === 'TECH_STACK') {
      vulnerabilitiesList.classList.add('hidden');
      noIssuesState.classList.add('hidden');
      techStackSection.classList.remove('hidden');
      renderTechStack(currentScanResult.technologies || []);
      return;
    }

    techStackSection.classList.add('hidden');
    vulnerabilitiesList.innerHTML = '';
    const items = currentScanResult.vulnerabilities || [];

    let filtered = items;
    if (filter === 'HIGH_RISK') {
      filtered = items.filter(i => i.severity === 'CRITICAL' || i.severity === 'HIGH');
    } else if (filter === 'MEDIUM') {
      filtered = items.filter(i => i.severity === 'MEDIUM');
    } else if (filter === 'LOW') {
      filtered = items.filter(i => i.severity === 'LOW' || i.severity === 'INFO');
    } else if (['CRITICAL', 'HIGH', 'LOW', 'INFO'].includes(filter)) {
      filtered = items.filter(i => i.severity === filter);
    }

    if (filtered.length === 0) {
      vulnerabilitiesList.classList.add('hidden');
      noIssuesState.classList.remove('hidden');
      return;
    }

    vulnerabilitiesList.classList.remove('hidden');
    noIssuesState.classList.add('hidden');

    filtered.forEach((item, index) => {
      const card = document.createElement('div');
      card.className = `vuln-item ${index === 0 ? 'open' : ''}`; // Expand first item by default

      const sevClass = item.severity.toLowerCase();

      card.innerHTML = `
        <div class="vuln-header">
          <div class="vuln-title-area">
            <span class="sev-tag ${sevClass}">${item.severity}</span>
            <span class="vuln-title">${escapeHtml(item.title)}</span>
          </div>
          <svg class="chevron-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>
        <div class="vuln-body">
          <div class="meta-row">
            <span>ID: <strong>${item.id}</strong></span>
            <span class="category-badge">${escapeHtml(item.category)}</span>
          </div>
          <div class="vuln-section">
            <div class="vuln-section-title">Exact Location / Path</div>
            <button class="vuln-location-badge action-btn" title="Click to jump & highlight location on target page">
              📍 ${escapeHtml(item.location || 'Page Source / Global Context')}
              <span class="jump-hint">Jump to Place &rarr;</span>
            </button>
          </div>
          <div class="vuln-section">
            <div class="vuln-section-title">Description</div>
            <div class="vuln-desc">${escapeHtml(item.description)}</div>
          </div>
          <div class="vuln-section">
            <div class="vuln-section-title">Security Impact</div>
            <div class="vuln-desc">${escapeHtml(item.impact)}</div>
          </div>
          <div class="vuln-section">
            <div class="vuln-section-title">Recommended Fix</div>
            <div class="vuln-rec">${escapeHtml(item.recommendation)}</div>
          </div>
          ${item.elementSnippet ? `
            <div class="vuln-section">
              <div class="vuln-section-title">Evidence Snippet</div>
              <div class="code-snippet">${escapeHtml(item.elementSnippet)}</div>
            </div>
          ` : ''}
        </div>
      `;

      // Accordion toggle
      const header = card.querySelector('.vuln-header');
      header.addEventListener('click', () => {
        card.classList.toggle('open');
      });

      // Jump to Location click handler
      const locBtn = card.querySelector('.vuln-location-badge.action-btn');
      if (locBtn) {
        locBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          highlightVulnerabilityTarget(item);
        });
      }

      vulnerabilitiesList.appendChild(card);
    });
  }

  /**
   * Highlights & jumps to target vulnerability location on active browser tab
   */
  async function highlightVulnerabilityTarget(item) {
    if (!activeTab || !activeTab.id) return;
    try {
      await chrome.tabs.update(activeTab.id, { active: true });
      await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: (vulnItem) => {
          document.querySelectorAll('.webshield-target-overlay, .webshield-target-banner').forEach(el => el.remove());

          let targetEl = null;

          if (vulnItem.targetType === 'SCRIPT' && vulnItem.targetSelector !== null) {
            const scripts = Array.from(document.querySelectorAll('script'));
            const idx = parseInt(vulnItem.targetSelector, 10);
            if (!isNaN(idx) && scripts[idx]) {
              targetEl = scripts[idx];
            }
          } else if (vulnItem.targetType === 'DOM_ELEMENT' && vulnItem.targetSelector) {
            try {
              targetEl = document.querySelector(vulnItem.targetSelector);
            } catch (e) {}
          } else if (vulnItem.targetType === 'FORM') {
            targetEl = document.querySelector('form');
          }

          if (!targetEl && vulnItem.elementSnippet) {
            const cleanSnippet = vulnItem.elementSnippet.replace(/^Match:\s*/, '').trim();
            const allElements = Array.from(document.querySelectorAll('*'));
            targetEl = allElements.find(el => el.outerHTML && el.outerHTML.includes(cleanSnippet.substring(0, 30)));
          }

          if (targetEl && targetEl.tagName && !['head', 'script', 'meta'].includes(targetEl.tagName.toLowerCase())) {
            targetEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            const origOutline = targetEl.style.outline;
            const origBoxShadow = targetEl.style.boxShadow;
            const origTransition = targetEl.style.transition;

            targetEl.style.transition = 'all 0.3s ease';
            targetEl.style.outline = '4px solid #EF4444';
            targetEl.style.boxShadow = '0 0 24px rgba(239, 68, 68, 0.9)';

            setTimeout(() => {
              targetEl.style.outline = origOutline;
              targetEl.style.boxShadow = origBoxShadow;
              targetEl.style.transition = origTransition;
            }, 6000);
          }

          const banner = document.createElement('div');
          banner.className = 'webshield-target-banner';
          banner.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 2147483647;
            background: #0F172A;
            color: #F8FAFC;
            border: 2px solid #00F2FE;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(0, 242, 254, 0.3);
            border-radius: 12px;
            padding: 16px;
            max-width: 440px;
            font-family: system-ui, -apple-system, sans-serif;
            font-size: 13px;
            line-height: 1.4;
            animation: webShieldSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
          `;

          banner.innerHTML = `
            <style>
              @keyframes webShieldSlideIn {
                from { transform: translateY(30px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
              }
            </style>
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
              <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; color: #00F2FE;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
                WebShield Target Inspector
              </div>
              <button id="webshieldCloseBannerBtn" style="background: none; border: none; color: #94A3B8; cursor: pointer; font-size: 18px; font-weight: 700; padding: 0 4px;">&times;</button>
            </div>
            <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px; color: #FFFFFF;">${vulnItem.title}</div>
            <div style="font-size: 11px; color: #38BDF8; font-family: monospace; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); padding: 4px 8px; border-radius: 4px; margin-bottom: 8px; word-break: break-all;">
              📍 Location: ${vulnItem.location}
            </div>
            ${vulnItem.elementSnippet ? `
              <div style="font-size: 11px; color: #94A3B8; margin-bottom: 2px;">Evidence Snippet:</div>
              <div style="font-family: monospace; font-size: 11px; background: #070A12; color: #F59E0B; padding: 6px; border-radius: 4px; overflow-x: auto; max-height: 80px; margin-bottom: 8px; border: 1px solid #1E293B;">
                ${vulnItem.elementSnippet}
              </div>
            ` : ''}
            <div style="font-size: 11px; color: #A7F3D0;">💡 Recommendation: ${vulnItem.recommendation}</div>
          `;

          document.body.appendChild(banner);

          document.getElementById('webshieldCloseBannerBtn')?.addEventListener('click', () => {
            banner.remove();
          });

          setTimeout(() => {
            if (document.body.contains(banner)) banner.remove();
          }, 8000);
        },
        args: [item]
      });
    } catch (err) {
      console.error('Error navigating to location:', err);
    }
  }

  /**
   * Generates vector PDF report & opens dedicated report tab
   */
  async function exportSecurityReport() {
    if (!currentScanResult) return;

    try {
      exportReportBtn.textContent = 'Generating PDF Report...';

      // 1. Generate & download structured PDF file
      if (window.WebShieldPdfExporter && window.WebShieldPdfExporter.generateSecurityPdf) {
        const { pdfDoc, filename } = await window.WebShieldPdfExporter.generateSecurityPdf(currentScanResult);
        pdfDoc.save(filename);
      }

      // 2. Open full printable report page in new tab
      await chrome.tabs.create({ url: chrome.runtime.getURL('report/report.html') });

      exportReportBtn.innerHTML = `✓ PDF Report Exported!`;
      setTimeout(() => {
        exportReportBtn.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Export Security Report
        `;
      }, 2500);
    } catch (err) {
      console.error('PDF Export error:', err);
      alert(`Export failed: ${err.message}`);
      exportReportBtn.innerHTML = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="7 10 12 15 17 10"/>
          <line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Export Security Report
      `;
    }
  }

  /**
   * Renders detected technology stack items
   */
  function renderTechStack(techs) {
    techStackSection.innerHTML = '';
    if (!techs || techs.length === 0) {
      techStackSection.innerHTML = `
        <div class="no-tech-state">
          <div style="font-weight: 600; margin-bottom: 4px; color: var(--text-primary);">No Technology Signatures Detected</div>
          <div>No standard web frameworks, libraries, or CMS signatures were identified on this page.</div>
        </div>
      `;
      return;
    }

    techs.forEach(t => {
      const card = document.createElement('div');
      card.className = 'tech-card';

      const iconLetter = (t.name || 'T').charAt(0).toUpperCase();

      card.innerHTML = `
        <div class="tech-icon-box">${iconLetter}</div>
        <div class="tech-info">
          <div class="tech-header-line">
            <span class="tech-name">${escapeHtml(t.name)}</span>
            ${t.version ? `<span class="tech-version-badge">v${escapeHtml(t.version)}</span>` : ''}
          </div>
          <span class="tech-category-pill">${escapeHtml(t.category)}</span>
          ${t.description ? `<div class="tech-desc">${escapeHtml(t.description)}</div>` : ''}
        </div>
      `;

      techStackSection.appendChild(card);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
