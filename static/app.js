/**
 * Verdict - Autonomous Security Intelligence Frontend Controller
 */

// Automatically use relative root if served over HTTP/HTTPS, or localhost:8000 if opened directly as file://
const API_BASE = window.location.origin.startsWith('http') ? '' : 'http://localhost:8000';

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const form = document.getElementById('intakeForm');
  const input = document.getElementById('queryInput');
  const submitBtn = document.getElementById('runButton');
  const submitText = document.getElementById('submitBtnText');
  const statusLine = document.getElementById('statusLine');
  const errorBox = document.getElementById('errorBox');
  const report = document.getElementById('report');
  const hintBar = document.getElementById('hintBar');
  const quickExample = document.getElementById('quickExample');

  // Catalog Dropdown Elements
  const catalogToggle = document.getElementById('catalogToggle');
  const catalogMenu = document.getElementById('catalogMenu');
  const catalogFilterInput = document.getElementById('catalogFilterInput');
  const catalogClearBtn = document.getElementById('catalogClearBtn');
  const catalogTabs = document.querySelectorAll('.catalog-tab');
  const catalogCountLabel = document.getElementById('catalogCountLabel');
  const catalogItems = Array.from(document.querySelectorAll('.catalog-item'));
  const catalogNoResults = document.getElementById('catalogNoResults');

  // Info Cards Toggle
  const overviewToggle = document.getElementById('overviewToggle');
  const infoCardsGrid = document.getElementById('infoCardsGrid');
  const overviewToggleHint = document.getElementById('overviewToggleHint');

  // Action Buttons & Toast
  const copyMarkdownBtn = document.getElementById('copyMarkdownBtn');
  const toast = document.getElementById('toast');

  let activeCategory = 'all';
  let focusedIndex = -1;
  let currentReportData = null;

  // ========================================================================
  // Catalog Dropdown Interactions
  // ========================================================================
  function openCatalog() {
    catalogMenu.classList.add('open');
    catalogToggle.classList.add('open');
    catalogToggle.setAttribute('aria-expanded', 'true');
    setTimeout(() => {
      catalogFilterInput.focus();
    }, 60);
  }

  function closeCatalog() {
    catalogMenu.classList.remove('open');
    catalogToggle.classList.remove('open');
    catalogToggle.setAttribute('aria-expanded', 'false');
    focusedIndex = -1;
    clearFocus();
  }

  function toggleCatalog(e) {
    if (e) e.stopPropagation();
    if (catalogMenu.classList.contains('open')) {
      closeCatalog();
    } else {
      openCatalog();
    }
  }

  catalogToggle.addEventListener('click', toggleCatalog);

  // Close catalog on click outside
  document.addEventListener('click', (e) => {
    if (!catalogToggle.contains(e.target) && !catalogMenu.contains(e.target)) {
      closeCatalog();
    }
  });

  // Filter Catalog by text and category tab
  function filterCatalog() {
    const term = catalogFilterInput.value.toLowerCase().trim();
    catalogClearBtn.style.display = term ? 'block' : 'none';

    let visibleCount = 0;
    const visibleItems = [];

    catalogItems.forEach(item => {
      const category = item.getAttribute('data-category');
      const query = item.getAttribute('data-query').toLowerCase();
      const content = item.textContent.toLowerCase();

      const matchesText = !term || query.includes(term) || content.includes(term);
      const matchesCategory = (activeCategory === 'all') || (category === activeCategory);

      if (matchesText && matchesCategory) {
        item.style.display = '';
        visibleCount++;
        visibleItems.push(item);
      } else {
        item.style.display = 'none';
      }
    });

    catalogCountLabel.textContent = `Showing ${visibleCount} of ${catalogItems.length}`;
    catalogNoResults.style.display = visibleCount === 0 ? 'block' : 'none';
    focusedIndex = -1;
    clearFocus();
  }

  catalogFilterInput.addEventListener('input', filterCatalog);

  catalogClearBtn.addEventListener('click', () => {
    catalogFilterInput.value = '';
    filterCatalog();
    catalogFilterInput.focus();
  });

  // Category Tabs Filter
  catalogTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      catalogTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeCategory = tab.getAttribute('data-tab');
      filterCatalog();
    });
  });

  // Keyboard navigation inside catalog
  function clearFocus() {
    catalogItems.forEach(item => item.classList.remove('focused'));
  }

  catalogFilterInput.addEventListener('keydown', (e) => {
    const visibleItems = catalogItems.filter(item => item.style.display !== 'none');
    if (!visibleItems.length) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      focusedIndex = (focusedIndex + 1) % visibleItems.length;
      clearFocus();
      visibleItems[focusedIndex].classList.add('focused');
      visibleItems[focusedIndex].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      focusedIndex = (focusedIndex - 1 + visibleItems.length) % visibleItems.length;
      clearFocus();
      visibleItems[focusedIndex].classList.add('focused');
      visibleItems[focusedIndex].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      if (focusedIndex >= 0 && visibleItems[focusedIndex]) {
        e.preventDefault();
        selectCatalogItem(visibleItems[focusedIndex]);
      }
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && catalogMenu.classList.contains('open')) {
      closeCatalog();
      catalogToggle.focus();
    }
  });

  function selectCatalogItem(item) {
    const q = item.getAttribute('data-query');
    input.value = q;
    closeCatalog();
    form.dispatchEvent(new Event('submit'));
  }

  catalogItems.forEach(item => {
    item.addEventListener('click', () => {
      selectCatalogItem(item);
    });
  });

  // Quick example in hint bar
  if (quickExample) {
    quickExample.addEventListener('click', () => {
      input.value = quickExample.getAttribute('data-query') || 'CVE-2026-34486';
      form.dispatchEvent(new Event('submit'));
    });
  }

  // ========================================================================
  // Architecture Overview Accordion Toggle
  // ========================================================================
  if (overviewToggle && infoCardsGrid) {
    overviewToggle.addEventListener('click', () => {
      const isHidden = infoCardsGrid.style.display === 'none';
      infoCardsGrid.style.display = isHidden ? 'grid' : 'none';
      overviewToggleHint.textContent = isHidden ? 'Click to collapse' : 'Click to expand';
    });
  }

  // ========================================================================
  // Toast Helper
  // ========================================================================
  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2400);
  }

  // ========================================================================
  // Form Submission & Analysis Pipeline
  // ========================================================================
  const severityLabels = {
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    UNKNOWN: 'UNKNOWN'
  };

  const exploitLabels = {
    ACTIVELY_EXPLOITED: 'actively exploited',
    POC_PUBLIC: 'proof-of-concept public',
    SUSPECTED: 'exploitation suspected',
    NO_EVIDENCE_OF_EXPLOITATION: 'no evidence of exploitation'
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = input.value.trim();
    if (!query) return;

    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    submitText.textContent = 'Cross-checking…';
    if (hintBar) hintBar.style.display = 'none';
    errorBox.classList.remove('visible');
    report.classList.remove('visible');
    statusLine.textContent = 'Ingesting vendor advisories & live threat telemetry…';

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || `Request failed (${res.status})`);
      }

      statusLine.textContent = '';
      currentReportData = data;
      renderReport(data);

    } catch (err) {
      statusLine.textContent = '';
      errorBox.textContent = `Analysis failed: ${err.message}`;
      errorBox.classList.add('visible');
    } finally {
      submitBtn.disabled = false;
      submitBtn.classList.remove('loading');
      submitText.textContent = 'Run check';
    }
  });

  // Render Report
  function renderReport(data) {
    const r = data.report;

    document.getElementById('caseId').textContent = r.cve_id;
    document.getElementById('vulnName').textContent = r.vulnerability_name;

    const stamp = document.getElementById('severityStamp');
    stamp.textContent = severityLabels[r.severity] || (r.severity ? r.severity.toUpperCase() : 'UNKNOWN');
    stamp.className = 'stamp ' + (r.severity ? r.severity.toLowerCase() : 'unknown');

    document.getElementById('cvssText').textContent =
      r.cvss_score != null ? `CVSS ${r.cvss_score.toFixed(1)}` : 'CVSS not published';

    document.getElementById('exploitStatus').textContent =
      exploitLabels[r.exploitation_status] || r.exploitation_status;

    const disBox = document.getElementById('disagreementBox');
    if (r.has_source_disagreement) {
      disBox.style.display = 'block';
      document.getElementById('disagreementText').textContent = r.disagreement_details || '';
    } else {
      disBox.style.display = 'none';
    }

    document.getElementById('execSummary').textContent = r.executive_summary;
    document.getElementById('vendorPosture').textContent = r.vendor_posture;
    document.getElementById('threatIntel').textContent = r.threat_intelligence;
    document.getElementById('recommendedAction').textContent = r.recommended_action;

    const list = document.getElementById('citationList');
    list.innerHTML = '';
    const citations = r.citations || [];
    if (citations.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'No external citations found.';
      li.style.color = 'var(--ink-soft)';
      list.appendChild(li);
    } else {
      citations.forEach(c => {
        const li = document.createElement('li');
        li.innerHTML = `<a href="${c.url}" target="_blank" rel="noopener">${escapeHtml(c.title)}</a>` +
          (c.snippet_evidence ? `<div class="evidence">${escapeHtml(c.snippet_evidence)}</div>` : '');
        list.appendChild(li);
      });
    }

    const fetchSec = data.fetch_seconds != null ? data.fetch_seconds : '—';
    const synthSec = data.synthesis_seconds != null ? data.synthesis_seconds : '—';
    const totalSec = data.elapsed_seconds != null ? data.elapsed_seconds : '—';

    document.getElementById('timingFooter').textContent =
      `Dual ingestion: ${fetchSec}s · AI synthesis: ${synthSec}s · End-to-end: ${totalSec}s`;

    report.classList.add('visible');
    report.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

  // ========================================================================
  // Markdown Export Action
  // ========================================================================
  if (copyMarkdownBtn) {
    copyMarkdownBtn.addEventListener('click', () => {
      if (!currentReportData || !currentReportData.report) return;
      const r = currentReportData.report;

      let md = `# Verdict Security Dossier: ${r.cve_id}\n`;
      md += `**Target**: ${r.vulnerability_name}\n`;
      md += `**Severity**: ${r.severity} | **CVSS**: ${r.cvss_score != null ? r.cvss_score : 'N/A'} | **Exploitation**: ${r.exploitation_status}\n\n`;

      if (r.has_source_disagreement) {
        md += `> [!WARNING] SOURCES DISAGREE\n> ${r.disagreement_details}\n\n`;
      }

      md += `## Executive Summary\n${r.executive_summary}\n\n`;
      md += `## Vendor Disclosures\n${r.vendor_posture}\n\n`;
      md += `## Live Threat Intelligence\n${r.threat_intelligence}\n\n`;
      md += `## Recommended Action\n${r.recommended_action}\n\n`;

      md += `## Citations\n`;
      (r.citations || []).forEach(c => {
        md += `- [${c.title}](${c.url})\n`;
        if (c.snippet_evidence) md += `  > "${c.snippet_evidence}"\n`;
      });

      navigator.clipboard.writeText(md).then(() => {
        showToast('Report copied as Markdown');
      }).catch(() => {
        showToast('Failed to copy to clipboard');
      });
    });
  }
});
