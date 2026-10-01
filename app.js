import { normalizeUrl, analyzeWebsite } from './analyzer.js';

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const form = document.getElementById('analyzer-form');
  const urlInput = document.getElementById('url-input');
  const analyzerBox = document.querySelector('.analyzer-box');
  const errorEl = document.getElementById('analyzer-error');
  const heroView = document.getElementById('hero-view');
  const scanView = document.getElementById('scan-view');
  const resultsView = document.getElementById('results-view');
  const quickSamples = document.querySelectorAll('.sample-pill');
  
  // Scanning state elements
  const scanTargetUrl = document.getElementById('scan-target-url');
  const scanPhaseDesc = document.getElementById('scan-phase-desc');
  const scanStepItems = document.querySelectorAll('.scan-step-item');

  // Results elements
  const resHostBadge = document.getElementById('results-host-badge');
  const resScoreVal = document.getElementById('results-score-value');
  const resScoreBanner = document.getElementById('score-banner');
  const resRiskBadge = document.getElementById('risk-level-badge');
  const resRiskSummary = document.getElementById('risk-summary-text');
  const resPosList = document.getElementById('positives-list');
  const resWarnList = document.getElementById('warnings-list');
  const resChecksGrid = document.getElementById('checks-grid');
  const resetBtn = document.getElementById('reset-btn');
  const resetTopBtn = document.getElementById('reset-top-btn');

  // Modal elements
  const explainLink = document.getElementById('explain-link');
  const navHowItWorks = document.getElementById('nav-how-it-works');
  const modal = document.getElementById('explain-modal');
  const modalClose = document.getElementById('modal-close');

  // Quick sample pill clicks
  quickSamples.forEach(pill => {
    pill.addEventListener('click', () => {
      const sample = pill.getAttribute('data-url');
      if (sample && urlInput) {
        urlInput.value = sample;
        hideError();
        startScan(sample);
      }
    });
  });

  // Error handling
  function showError(msg) {
    if (errorEl && analyzerBox) {
      errorEl.textContent = msg;
      errorEl.classList.add('visible');
      analyzerBox.classList.add('has-error');
    }
  }

  function hideError() {
    if (errorEl && analyzerBox) {
      errorEl.classList.remove('visible');
      analyzerBox.classList.remove('has-error');
    }
  }

  if (urlInput) {
    urlInput.addEventListener('input', hideError);
  }

  // Handle Form Submission
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const val = urlInput ? urlInput.value : '';
      const normalized = normalizeUrl(val);

      if (!normalized) {
        showError('Please enter a valid website address (e.g., https://example.com or domain.com)');
        return;
      }

      hideError();
      startScan(normalized);
    });
  }

  // Scanning sequence
  const scanPhases = [
    { label: 'Checking domain registry & DNS records...', stepIdx: 0 },
    { label: 'Inspecting SSL/TLS certificate & encryption...', stepIdx: 1 },
    { label: 'Resolving corporate identity & trademarks...', stepIdx: 2 },
    { label: 'Searching corporate registry & merchant data...', stepIdx: 3 },
    { label: 'Querying global threat feeds & reputation databases...', stepIdx: 4 },
    { label: 'Analyzing deceptive heuristics & urgency scripts...', stepIdx: 5 },
    { label: 'Synthesizing evidence & trust indicators...', stepIdx: 6 }
  ];

  async function startScan(targetUrl) {
    // 1. Transition Hero out, Scan view in
    heroView.classList.add('view-hidden');
    scanView.classList.add('view-active');
    resultsView.classList.remove('view-active');

    scanTargetUrl.textContent = targetUrl;

    // Reset step items
    scanStepItems.forEach((el, idx) => {
      el.className = 'scan-step-item is-pending';
      const icon = el.querySelector('.step-status-icon');
      if (icon) icon.innerHTML = `<span style="color:#555">○</span>`;
    });

    // Start background analysis computation
    const analysisPromise = analyzeWebsite(targetUrl);

    // Cinematic step progression
    for (let i = 0; i < scanPhases.length; i++) {
      const phase = scanPhases[i];
      scanPhaseDesc.textContent = phase.label;

      const currentItem = scanStepItems[phase.stepIdx];
      if (currentItem) {
        currentItem.className = 'scan-step-item is-running';
        const icon = currentItem.querySelector('.step-status-icon');
        if (icon) icon.innerHTML = `<div class="spinner-icon"></div>`;
      }

      // Step duration
      await new Promise(r => setTimeout(r, 380));

      if (currentItem) {
        currentItem.className = 'scan-step-item is-done';
        const icon = currentItem.querySelector('.step-status-icon');
        if (icon) icon.innerHTML = `<span style="color:#4ade80">✓</span>`;
      }
    }

    // Finish analysis
    const result = await analysisPromise;

    // Render results
    renderResults(result);

    // Transition Scan out, Results in
    await new Promise(r => setTimeout(r, 200));
    scanView.classList.remove('view-active');
    resultsView.classList.add('view-active');
  }

  function renderResults(res) {
    const modeTag = document.getElementById('analysis-mode-tag');
    const resScoreScale = document.getElementById('results-score-scale');

    if (modeTag) modeTag.textContent = res.isDemo ? 'Demo Analysis' : 'Live Verified';
    if (resHostBadge) resHostBadge.textContent = res.domain || res.hostname || res.url;
    if (resScoreVal) resScoreVal.textContent = typeof res.score === 'number' ? res.score : 0;
    if (resScoreScale) resScoreScale.textContent = '/ 100 Score';
    if (resRiskSummary) resRiskSummary.textContent = res.summary;

    // Deterministic Risk Badge and Color Class
    resScoreBanner.className = 'score-banner';
    const level = res.riskLevel || 'LOW RISK';
    if (level === 'LOW RISK') {
      resScoreBanner.classList.add('risk-low');
      resRiskBadge.textContent = 'LOW RISK';
    } else if (level === 'MEDIUM RISK') {
      resScoreBanner.classList.add('risk-medium');
      resRiskBadge.textContent = 'MEDIUM RISK';
    } else {
      resScoreBanner.classList.add('risk-high');
      resRiskBadge.textContent = 'HIGH RISK';
    }

    // Data Availability Notice Banner
    const daBanner = document.getElementById('data-availability-banner');
    if (daBanner) {
      if (res.dataAvailability?.isLimited && res.dataAvailability?.notice) {
        daBanner.style.display = 'block';
        daBanner.innerHTML = `<strong>Data Availability Note:</strong> ${escapeHtml(res.dataAvailability.notice)}`;
      } else {
        daBanner.style.display = 'none';
      }
    }

    // Transparent Scoring Breakdown Card
    const factorsCard = document.getElementById('scoring-factors-card');
    const factorsList = document.getElementById('factors-list');
    if (factorsCard && factorsList) {
      if (Array.isArray(res.factors) && res.factors.length > 0) {
        factorsCard.style.display = 'block';
        factorsList.innerHTML = res.factors.map(f => {
          let impactClass = 'impact-neutral';
          let prefix = '';
          if (f.impact > 0) {
            impactClass = 'impact-pos';
            prefix = '+';
          } else if (f.impact < 0) {
            impactClass = 'impact-neg';
          }
          return `
            <div class="factor-item">
              <div class="factor-info">
                <span class="factor-name">${escapeHtml(f.factor)}</span>
                <span class="factor-reason">${escapeHtml(f.reason)}</span>
              </div>
              <span class="factor-impact ${impactClass}">${prefix}${f.impact} pts</span>
            </div>
          `;
        }).join('');
      } else {
        factorsCard.style.display = 'none';
      }
    }

    // Populate Real RDAP Data Section
    const rdap = res.rdap || {};
    const rdapBadge = document.getElementById('rdap-status-badge');
    const rdapDomain = document.getElementById('rdap-domain');
    const rdapRegistrar = document.getElementById('rdap-registrar');
    const rdapCreated = document.getElementById('rdap-created');
    const rdapAge = document.getElementById('rdap-age');
    const rdapExpires = document.getElementById('rdap-expires');
    const rdapUpdated = document.getElementById('rdap-updated');

    if (rdapBadge) {
      if (rdap.available) {
        rdapBadge.textContent = 'RDAP Verified';
        rdapBadge.className = 'rdap-badge';
      } else {
        rdapBadge.textContent = 'RDAP Unavailable';
        rdapBadge.className = 'rdap-badge is-unavailable';
      }
    }
    if (rdapDomain) rdapDomain.textContent = rdap.domain || res.hostname || 'Unavailable';
    if (rdapRegistrar) rdapRegistrar.textContent = rdap.registrar || 'Unavailable';
    if (rdapCreated) rdapCreated.textContent = rdap.createdAt || 'Unavailable';
    if (rdapAge) rdapAge.textContent = rdap.ageFormatted || 'Unavailable';
    if (rdapExpires) rdapExpires.textContent = rdap.expiresAt || 'Unavailable';
    if (rdapUpdated) rdapUpdated.textContent = rdap.updatedAt || 'Unavailable';

    // Populate Real Threat Intelligence Telemetry Section
    const ti = res.threatIntel || {};
    const tiBadge = document.getElementById('threat-status-badge');
    const tiProvider = document.getElementById('threat-provider');
    const tiMalicious = document.getElementById('threat-malicious');
    const tiSuspicious = document.getElementById('threat-suspicious');
    const tiHarmless = document.getElementById('threat-harmless');
    const tiUndetected = document.getElementById('threat-undetected');
    const tiTotal = document.getElementById('threat-total');
    const tiNotice = document.getElementById('threat-notice-text');

    if (tiBadge) {
      if (!ti.available) {
        tiBadge.textContent = 'API Not Configured';
        tiBadge.className = 'threat-badge is-unavailable';
      } else if ((ti.malicious || 0) === 0 && (ti.suspicious || 0) === 0) {
        tiBadge.textContent = 'Clean (0 Detections)';
        tiBadge.className = 'threat-badge is-clean';
      } else {
        tiBadge.textContent = `${ti.malicious} Malicious / ${ti.suspicious} Suspicious`;
        tiBadge.className = 'threat-badge is-flagged';
      }
    }

    if (tiProvider) tiProvider.textContent = ti.provider || 'VirusTotal';
    if (tiMalicious) {
      tiMalicious.textContent = ti.malicious !== undefined && ti.malicious !== null ? ti.malicious : 'Unavailable';
      tiMalicious.className = (typeof ti.malicious === 'number' && ti.malicious > 0) ? 'threat-intel-value val-flagged' : 'threat-intel-value';
    }
    if (tiSuspicious) {
      tiSuspicious.textContent = ti.suspicious !== undefined && ti.suspicious !== null ? ti.suspicious : 'Unavailable';
      tiSuspicious.className = (typeof ti.suspicious === 'number' && ti.suspicious > 0) ? 'threat-intel-value val-flagged' : 'threat-intel-value';
    }
    if (tiHarmless) {
      tiHarmless.textContent = ti.harmless !== undefined && ti.harmless !== null ? ti.harmless : 'Unavailable';
      tiHarmless.className = (typeof ti.harmless === 'number' && ti.harmless > 0) ? 'threat-intel-value val-clean' : 'threat-intel-value';
    }
    if (tiUndetected) tiUndetected.textContent = ti.undetected !== undefined && ti.undetected !== null ? ti.undetected : 'Unavailable';
    if (tiTotal) tiTotal.textContent = ti.totalEngines !== undefined && ti.totalEngines !== null ? ti.totalEngines : 'Unavailable';

    if (tiNotice) {
      if (!ti.available) {
        tiNotice.textContent = ti.reason || 'Threat-intelligence analysis unavailable (VIRUSTOTAL_API_KEY is not configured on the server). Unavailable data is not proof of safety.';
        tiNotice.className = 'threat-notice';
      } else if ((ti.malicious || 0) > 0 || (ti.suspicious || 0) > 0) {
        tiNotice.textContent = `Threat-intelligence results indicate that ${ti.malicious} security engine(s) flagged this domain as malicious and ${ti.suspicious} as suspicious. This is a risk signal, not definitive proof that the website is fraudulent.`;
        tiNotice.className = 'threat-notice notice-warning';
      } else {
        tiNotice.textContent = `Zero malicious or suspicious detections reported across all ${ti.totalEngines || 70} security engines in VirusTotal threat telemetry.`;
        tiNotice.className = 'threat-notice';
      }
    }

    // Positives list
    if (resPosList) {
      resPosList.innerHTML = res.positives
        .map(p => `<li><span class="signal-bullet" style="color:#4ade80">✓</span><span>${escapeHtml(p)}</span></li>`)
        .join('');
    }

    // Warnings list
    if (resWarnList) {
      if (res.warnings && res.warnings.length > 0) {
        resWarnList.innerHTML = res.warnings
          .map(w => `<li><span class="signal-bullet" style="color:#f87171">⚠</span><span>${escapeHtml(w)}</span></li>`)
          .join('');
      } else {
        resWarnList.innerHTML = `<li><span class="signal-bullet" style="color:#4ade80">✓</span><span>No active security threats flagged.</span></li>`;
      }
    }

    // Checks grid
    if (resChecksGrid) {
      resChecksGrid.innerHTML = res.checks.map(c => {
        let statusClass = 'status-passed';
        if (c.status === 'Warning') statusClass = 'status-warning';
        if (c.status === 'Needs Review') statusClass = 'status-review';

        return `
          <div class="check-card">
            <div>
              <div class="check-name">${escapeHtml(c.name)}</div>
              <div class="check-detail">${escapeHtml(c.detail)}</div>
            </div>
            <span class="status-pill ${statusClass}">${escapeHtml(c.status)}</span>
          </div>
        `;
      }).join('');
    }
  }

  function resetView() {
    resultsView.classList.remove('view-active');
    scanView.classList.remove('view-active');
    heroView.classList.remove('view-hidden');
    if (urlInput) {
      urlInput.value = '';
      urlInput.focus();
    }
    hideError();
  }

  if (resetBtn) resetBtn.addEventListener('click', resetView);
  if (resetTopBtn) resetTopBtn.addEventListener('click', resetView);

  // Modal interactions
  function openExplainModal() {
    if (modal) modal.classList.add('open');
  }
  function closeExplainModal() {
    if (modal) modal.classList.remove('open');
  }

  // About Modal interactions
  const navAbout = document.getElementById('nav-about');
  const aboutModal = document.getElementById('about-modal');
  const aboutModalClose = document.getElementById('about-modal-close');

  function openAboutModal() {
    if (aboutModal) aboutModal.classList.add('open');
  }
  function closeAboutModal() {
    if (aboutModal) aboutModal.classList.remove('open');
  }

  if (navAbout) navAbout.addEventListener('click', (e) => {
    e.preventDefault();
    openAboutModal();
  });
  if (aboutModalClose) aboutModalClose.addEventListener('click', closeAboutModal);
  if (aboutModal) {
    aboutModal.addEventListener('click', (e) => {
      if (e.target === aboutModal) closeAboutModal();
    });
  }

  // API Key Settings Modal
  const navApiKey = document.getElementById('nav-api-key');
  const apikeyModal = document.getElementById('apikey-modal');
  const apikeyModalClose = document.getElementById('apikey-modal-close');
  const vtKeyInput = document.getElementById('vt-key-input');
  const vtKeyStatus = document.getElementById('vt-key-status');
  const saveVtKeyBtn = document.getElementById('save-vt-key-btn');
  const clearVtKeyBtn = document.getElementById('clear-vt-key-btn');

  function updateKeyStatusUI() {
    const existingKey = localStorage.getItem('vt_api_key') || '';
    if (existingKey.trim()) {
      if (vtKeyInput) vtKeyInput.value = existingKey;
      if (vtKeyStatus) {
        vtKeyStatus.innerHTML = `<span style="color:#4ade80">● Key Configured (${existingKey.length} chars)</span> — Threat intelligence is active for all scans.`;
      }
      if (navApiKey) {
        navApiKey.innerHTML = `⚙️ Key <span style="color:#4ade80;font-size:10px">● Active</span>`;
      }
    } else {
      if (vtKeyInput) vtKeyInput.value = '';
      if (vtKeyStatus) {
        vtKeyStatus.innerHTML = `<span style="color:#94a3b8">○ No custom key configured</span> (Server environment variable or default mode active).`;
      }
      if (navApiKey) {
        navApiKey.innerHTML = `⚙️ API Key`;
      }
    }
  }

  updateKeyStatusUI();

  function openApiKeyModal() {
    updateKeyStatusUI();
    if (apikeyModal) apikeyModal.classList.add('open');
  }
  function closeApiKeyModal() {
    if (apikeyModal) apikeyModal.classList.remove('open');
  }

  if (navApiKey) navApiKey.addEventListener('click', (e) => {
    e.preventDefault();
    openApiKeyModal();
  });
  if (apikeyModalClose) apikeyModalClose.addEventListener('click', closeApiKeyModal);
  if (apikeyModal) {
    apikeyModal.addEventListener('click', (e) => {
      if (e.target === apikeyModal) closeApiKeyModal();
    });
  }

  if (saveVtKeyBtn && vtKeyInput) {
    saveVtKeyBtn.addEventListener('click', () => {
      const val = vtKeyInput.value.trim();
      if (val) {
        localStorage.setItem('vt_api_key', val);
        updateKeyStatusUI();
        if (vtKeyStatus) {
          vtKeyStatus.innerHTML = `<span style="color:#4ade80">✓ Saved successfully!</span> Threat intelligence is now active.`;
        }
        setTimeout(closeApiKeyModal, 1200);
      } else {
        localStorage.removeItem('vt_api_key');
        updateKeyStatusUI();
      }
    });
  }

  if (clearVtKeyBtn) {
    clearVtKeyBtn.addEventListener('click', () => {
      localStorage.removeItem('vt_api_key');
      updateKeyStatusUI();
      if (vtKeyStatus) {
        vtKeyStatus.innerHTML = `<span style="color:#f87171">Key cleared.</span>`;
      }
    });
  }

  if (explainLink) explainLink.addEventListener('click', openExplainModal);
  if (navHowItWorks) navHowItWorks.addEventListener('click', (e) => {
    e.preventDefault();
    openExplainModal();
  });
  if (modalClose) modalClose.addEventListener('click', closeExplainModal);
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeExplainModal();
    });
  }
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (modal && modal.classList.contains('open')) closeExplainModal();
      if (aboutModal && aboutModal.classList.contains('open')) closeAboutModal();
      if (apikeyModal && apikeyModal.classList.contains('open')) closeApiKeyModal();
    }
  });

  // Mobile menu
  const burger = document.querySelector('.burger');
  const backdrop = document.querySelector('.menu-backdrop');
  const siteNav = document.getElementById('site-nav');

  function openMenu() {
    document.body.classList.add('menu-open');
    if (burger) {
      burger.setAttribute('aria-expanded', 'true');
      burger.setAttribute('aria-label', 'Close menu');
    }
  }

  function closeMenu() {
    document.body.classList.remove('menu-open');
    if (burger) {
      burger.setAttribute('aria-expanded', 'false');
      burger.setAttribute('aria-label', 'Open menu');
    }
  }

  if (burger) {
    burger.addEventListener('click', () => {
      if (document.body.classList.contains('menu-open')) {
        closeMenu();
      } else {
        openMenu();
      }
    });
  }

  if (backdrop) backdrop.addEventListener('click', closeMenu);
  if (siteNav) {
    siteNav.querySelectorAll('a').forEach(a => a.addEventListener('click', closeMenu));
  }

  // Animation fallbacks
  const appears = document.querySelectorAll('.appear');
  appears.forEach(el => {
    el.addEventListener('animationend', () => el.classList.add('is-in'), { once: true });
  });

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      let anyRunning = false;
      appears.forEach(el => {
        if (typeof el.getAnimations === 'function') {
          const anims = el.getAnimations();
          if (anims.some(a => a.playState === 'running' || a.playState === 'finished')) {
            anyRunning = true;
          }
        }
      });
      if (!anyRunning) {
        appears.forEach(el => el.classList.add('is-in'));
      }
    });
  });

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
});
