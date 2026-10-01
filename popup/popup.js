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
  
  const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
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
      { text: 'Connecting to tab DOM...', progress: 20 },
      { text: 'Scanning inline scripts & secret leaks...', progress: 45 },
      { text: 'Auditing security headers & forms...', progress: 70 },
      { text: 'Analyzing cookies & third-party CDNs...', progress: 90 },
      { text: 'Calculating security risk score...', progress: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
      scanningStepText.textContent = steps[i].text;
      scanProgressBar.style.width = `${steps[i].progress}%`;
      await new Promise(r => setTimeout(r, 220));
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

    // 2. Update Severity Counts
    cntCritical.textContent = scan.counts.CRITICAL || 0;
    cntHigh.textContent = scan.counts.HIGH || 0;
    cntMedium.textContent = scan.counts.MEDIUM || 0;
    cntLow.textContent = scan.counts.LOW || 0;
    cntInfo.textContent = scan.counts.INFO || 0;

    // 3. Render List
    renderVulnerabilitiesList('ALL');
  }

  /**
   * Renders the list of vulnerabilities based on selected filter tab
   */
  function renderVulnerabilitiesList(filter = 'ALL') {
    if (!currentScanResult) return;

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

      vulnerabilitiesList.appendChild(card);
    });
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
