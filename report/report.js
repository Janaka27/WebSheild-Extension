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

  const techContainer = document.getElementById('techContainer');
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

    // Render Tech Stack
    techContainer.innerHTML = '';
    const techs = scan.technologies || [];

    if (techs.length === 0) {
      techContainer.innerHTML = `
        <div style="grid-column: 1 / -1; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; color: #64748b; font-size: 12px; text-align: center;">
          No standard technology or framework signatures detected on this target page.
        </div>
      `;
    } else {
      techs.forEach(t => {
        const card = document.createElement('div');
        card.className = 'report-tech-card';
        const iconLetter = (t.name || 'T').charAt(0).toUpperCase();

        card.innerHTML = `
          <div class="report-tech-icon">${iconLetter}</div>
          <div class="report-tech-info">
            <div class="report-tech-title">
              <span class="report-tech-name">${escapeHtml(t.name)}</span>
              ${t.version ? `<span class="report-tech-ver">v${escapeHtml(t.version)}</span>` : ''}
            </div>
            <span class="report-tech-cat">${escapeHtml(t.category)}</span>
            ${t.description ? `<div class="report-tech-desc">${escapeHtml(t.description)}</div>` : ''}
          </div>
        `;
        techContainer.appendChild(card);
      });
    }

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
            <span class="field-label">Exact Location / Path</span>
            <button class="field-text location action-btn" title="Click to jump to target tab and highlight this location">
              📍 ${escapeHtml(item.location || 'Page Source / Global Context')}
              <span class="report-jump-tag">Jump to Target &rarr;</span>
            </button>
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

      // Jump to Location click handler
      const locBtn = card.querySelector('.field-text.location.action-btn');
      if (locBtn) {
        locBtn.addEventListener('click', () => {
          highlightVulnerabilityTarget(scan, item);
        });
      }

      findingsContainer.appendChild(card);
    });
  }

  /**
   * Highlights & jumps to target vulnerability location on active or audit target tab
   */
  async function highlightVulnerabilityTarget(scan, item) {
    try {
      // Find tab matching target scan URL
      const tabs = await chrome.tabs.query({});
      let targetTab = tabs.find(t => t.url === scan.url);
      if (!targetTab) {
        // Fallback to currently active tab
        const activeTabs = await chrome.tabs.query({ active: true, currentWindow: true });
        targetTab = activeTabs[0];
      }

      if (!targetTab || !targetTab.id) {
        alert('Could not locate open tab for target site.');
        return;
      }

      // Switch focus to target website tab
      await chrome.tabs.update(targetTab.id, { active: true });

      // Execute element highlighter script on target page
      await chrome.scripting.executeScript({
        target: { tabId: targetTab.id },
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
    } catch (e) {
      console.error('Error navigating to location from report:', e);
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
