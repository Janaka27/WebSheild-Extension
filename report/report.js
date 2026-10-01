/**
 * WebShield Security Assessment Report Viewer Controller
 */
document.addEventListener('DOMContentLoaded', async () => {
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');
  const printBtn = document.getElementById('printBtn');

  const reportUrl = document.getElementById('reportUrl');
  const reportProtocol = document.getElementById('reportProtocol');
  const reportDate = document.getElementById('reportDate');
  const reportRating = document.getElementById('reportRating');
  const reportScoreBadge = document.getElementById('reportScoreBadge');
  const scoreNum = document.getElementById('scoreNum');

  const sumTotal = document.getElementById('sumTotal');
  const sumCritical = document.getElementById('sumCritical');
  const sumHigh = document.getElementById('sumHigh');
  const sumMedium = document.getElementById('sumMedium');
  const sumLow = document.getElementById('sumLow');

  const findingsContainer = document.getElementById('findingsContainer');

  let currentScan = null;

  // Retrieve scan data from chrome.storage
  try {
    const { lastScan } = await chrome.storage.local.get('lastScan');
    if (!lastScan) {
      alert('No recent security scan data found.');
      return;
    }

    currentScan = lastScan;
    renderReport(currentScan);
  } catch (err) {
    console.error('Failed to load scan data:', err);
  }

  // Event Listeners
  printBtn.addEventListener('click', () => {
    window.print();
  });

  downloadPdfBtn.addEventListener('click', async () => {
    if (!currentScan || !window.WebShieldPdfExporter) {
      alert('PDF Exporter is not available.');
      return;
    }

    try {
      const origText = downloadPdfBtn.textContent;
      downloadPdfBtn.textContent = 'Generating PDF...';

      const { pdfDoc, filename } = await window.WebShieldPdfExporter.generateSecurityPdf(currentScan);
      pdfDoc.save(filename);

      downloadPdfBtn.textContent = '✓ PDF Downloaded';
      setTimeout(() => {
        downloadPdfBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          Download PDF File
        `;
      }, 2500);
    } catch (e) {
      console.error('PDF Export error:', e);
      alert(`PDF Export failed: ${e.message}`);
    }
  });

  function renderReport(scan) {
    reportUrl.textContent = scan.url;
    reportProtocol.textContent = scan.protocol.toUpperCase();
    reportDate.textContent = new Date(scan.timestamp).toLocaleString();
    scoreNum.textContent = scan.score;

    reportRating.textContent = scan.rating;
    
    // Rating colors
    let ratingBg = '#10B981';
    if (scan.score < 50 || scan.counts.CRITICAL > 0) ratingBg = '#EF4444';
    else if (scan.score < 70 || scan.counts.HIGH > 0) ratingBg = '#F97316';
    else if (scan.score < 88 || scan.counts.MEDIUM > 0) ratingBg = '#F59E0B';

    reportRating.style.backgroundColor = ratingBg;
    reportRating.style.color = '#FFFFFF';
    reportScoreBadge.style.backgroundColor = '#0F172A';

    // Summary counts
    sumTotal.textContent = scan.totalIssues;
    sumCritical.textContent = scan.counts.CRITICAL || 0;
    sumHigh.textContent = scan.counts.HIGH || 0;
    sumMedium.textContent = scan.counts.MEDIUM || 0;
    sumLow.textContent = (scan.counts.LOW || 0) + (scan.counts.INFO || 0);

    // Render Detailed Findings
    findingsContainer.innerHTML = '';

    if (scan.vulnerabilities.length === 0) {
      findingsContainer.innerHTML = `
        <div style="padding: 20px; text-align: center; color: #10B981; font-weight: 600;">
          No security vulnerabilities or DOM flaws detected on this page!
        </div>
      `;
      return;
    }

    scan.vulnerabilities.forEach((item, index) => {
      const card = document.createElement('div');
      card.className = 'finding-card';

      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-title">${index + 1}. ${escapeHtml(item.title)}</div>
          <span class="sev-badge ${item.severity}">${item.severity}</span>
        </div>
        <div class="finding-body">
          <div class="finding-meta">
            ID: <strong>${item.id}</strong> &bull; Category: <strong>${escapeHtml(item.category)}</strong>
          </div>
          <div class="field-group">
            <span class="field-label">Description</span>
            <div class="field-text">${escapeHtml(item.description)}</div>
          </div>
          <div class="field-group">
            <span class="field-label">Security Impact</span>
            <div class="field-text impact">${escapeHtml(item.impact)}</div>
          </div>
          <div class="field-group">
            <span class="field-label">Remediation Action</span>
            <div class="field-text recommendation">${escapeHtml(item.recommendation)}</div>
          </div>
          ${item.elementSnippet ? `
            <div class="field-group">
              <span class="field-label">Evidence Snippet</span>
              <div class="snippet-box">${escapeHtml(item.elementSnippet)}</div>
            </div>
          ` : ''}
        </div>
      `;

      findingsContainer.appendChild(card);
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
