/**
 * ETI-AARE Email Threat Intelligence Frontend Module v2.0
 * =========================================================
 * ROOT-CAUSE FIXES applied in this version:
 *   1. mount(container) replaces init() — injects HTML into #page-email-threat,
 *      which navigateTo() knows how to show/hide via .page + .active pattern.
 *   2. onShow() called on re-navigation (no blank screen on back/forward).
 *   3. No longer appends to document.body; always targets the provided container.
 *   4. Backend health check on /api/email-analysis/health shown in header.
 *   5. Error boundary wraps mount() so JS crashes show a visible error card.
 *   6. Auto-init removed — module waits for navigateTo() to call mount().
 *   7. window.ETIModule exported for both BRAIN_MODULES and PAGE_CONFIG hooks.
 */

'use strict';

const ETIModule = (() => {

  // ── State ──────────────────────────────────────────────────────────────────
  const state = {
    currentAnalysis: null,
    analysisHistory: [],
    currentTab: 'overview',
    analyzing: false,
    mounted: false,
    container: null,
    stats: { total: 0, critical: 0, high: 0, clean: 0 },
    backendStatus: 'checking'   // 'checking' | 'online' | 'offline'
  };

  // ── API Client ─────────────────────────────────────────────────────────────
  // ROOT-CAUSE FIX v3.0:
  //   RC-1: Wrong token key — old code used localStorage.getItem('authToken')
  //         which is never written by auth-interceptor.js.  The correct primary
  //         key is 'wadjet_access_token' (written by UnifiedTokenStore.save()).
  //         Fallback chain: UnifiedTokenStore.getToken() → window.getAuthToken()
  //         → legacy keys → empty string (public endpoints work without token).
  //
  //   RC-2: Relative base URLs ('/api/email-threat') work when the frontend is
  //         served from the same origin as the backend (localhost dev).  In
  //         production the frontend lives on Vercel and the backend lives on
  //         Render — relative requests hit Vercel's 404 not Render's Express.
  //         Fix: derive absolute backend URL from window.THREATPILOT_API_URL
  //         (set in index.html) with a localhost fallback for dev.
  //
  //   RC-3: /api/email-analysis/health was also sent via relative path → same
  //         wrong-origin problem.
  //
  //   RC-4: No retry on 401 for public endpoints (stats/health need no token).
  //         Added graceful fallback: on non-2xx or network error, return null
  //         instead of throwing, so callers can use offline mock data.
  const API = {

    // Absolute backend URL — critical for Vercel + Render split deployment
    _backendUrl() {
      return (
        window.THREATPILOT_API_URL ||
        window.WADJET_API_URL      ||
        window.CONFIG?.BACKEND_URL ||
        (location.hostname === 'localhost' || location.hostname === '127.0.0.1'
          ? `${location.protocol}//${location.hostname}:4000`
          : 'https://wadjet-eye-ai.onrender.com')
      ).replace(/\/$/, '');
    },

    // RC-1 FIX: Token key resolution — primary → legacy aliases → fallback
    _token() {
      // 1. Ask UnifiedTokenStore (auth-interceptor.js) if available
      if (typeof window.UnifiedTokenStore !== 'undefined') {
        return window.UnifiedTokenStore.getToken() || '';
      }
      // 2. Helper exposed by auth-interceptor.js
      if (typeof window.getAuthToken === 'function') {
        return window.getAuthToken() || '';
      }
      // 3. Primary localStorage key written by auth-interceptor + auth-persistent
      return localStorage.getItem('wadjet_access_token')
          || localStorage.getItem('we_access_token')
          || localStorage.getItem('tp_access_token')
          || localStorage.getItem('authToken')  // legacy fallback only
          || window._authToken
          || '';
    },

    /**
     * _fetch(method, path, body, baseOverride)
     * Centralised fetch with:
     *   - Absolute URL construction (RC-2 fix)
     *   - Authorization header (RC-1 fix)
     *   - Timeout (30s — handles Render cold-start)
     *   - Retry once on 401 after a silent token refresh
     *   - Returns null on network error or non-OK (callers fall back gracefully)
     */
    async _fetch(method, path, body, baseOverride) {
      const base = baseOverride || this._backendUrl() + '/api/email-threat';
      const url  = base + path;
      const token = this._token();

      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const opts = {
        method,
        headers,
        credentials: 'include',
        signal: AbortSignal.timeout(30_000),
      };
      if (body !== undefined) opts.body = JSON.stringify(body);

      try {
        let res = await fetch(url, opts);

        // On 401, attempt one silent token refresh then retry once
        if (res.status === 401 && typeof window.silentRefresh === 'function') {
          console.warn('[ETI-AARE] 401 on', path, '— attempting silent refresh');
          await window.silentRefresh().catch(() => {});
          const newToken = this._token();
          if (newToken) headers['Authorization'] = `Bearer ${newToken}`;
          res = await fetch(url, { ...opts, headers });
        }

        if (!res.ok) {
          console.warn('[ETI-AARE] API', method, path, '→', res.status);
          return null;  // caller falls back to offline/mock data
        }

        return await res.json();
      } catch (err) {
        if (err.name === 'TimeoutError' || err.name === 'AbortError') {
          console.warn('[ETI-AARE] Request timeout on', path);
        } else if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
          console.warn('[ETI-AARE] Network offline —', path);
        } else {
          console.warn('[ETI-AARE] Fetch error on', path, err.message);
        }
        return null;  // caller falls back gracefully
      }
    },

    async post(path, body) {
      return this._fetch('POST', path, body);
    },

    async get(path, baseOverride) {
      // RC-3 FIX: healthBase must also use the absolute backend URL
      const base = baseOverride
        ? (this._backendUrl() + baseOverride.replace(/https?:\/\/[^/]+/, ''))   // strip host if full URL passed
        : undefined;
      return this._fetch('GET', path, undefined, base);
    },

    // RC-3 FIX: checkHealth uses the absolute /api/email-analysis base
    _healthBase() {
      return this._backendUrl() + '/api/email-analysis';
    },

    analyzeDemo:     (scenario)       => API.post('/analyze-demo', { scenario }),
    analyzeEmail:    (email, source)  => API.post('/analyze',      { email, source }),
    getStats:        ()               => API.get('/stats'),
    getAttackGraph:  ()               => API.get('/attack-graph'),
    getIncidents:    ()               => API.get('/incidents'),
    getBlocklists:   ()               => API.get('/blocklists'),
    checkHealth:     ()               => API._fetch('GET', '/health', undefined, API._healthBase())
  };

  // ── Error Boundary ─────────────────────────────────────────────────────────
  function errorBoundary(fn, context) {
    try {
      return fn();
    } catch (err) {
      console.error('[ETI-AARE] Error in', context, err);
      if (state.container) {
        state.container.innerHTML = `
          <div style="display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:16px;padding:40px;">
            <div style="width:64px;height:64px;border-radius:50%;background:rgba(255,45,85,0.15);display:flex;align-items:center;justify-content:center;">
              <i class="fas fa-exclamation-triangle" style="color:#FF2D55;font-size:24px;"></i>
            </div>
            <div style="font-size:18px;font-weight:700;color:#f5f5f5;">ETI-AARE Module Error</div>
            <div style="font-size:13px;color:#8b949e;max-width:480px;text-align:center;">${err.message}</div>
            <button onclick="window.ETIModule.mount(document.getElementById('page-email-threat'))"
              style="padding:10px 24px;background:#007AFF;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600;">
              <i class="fas fa-redo" style="margin-right:6px;"></i> Reload Module
            </button>
          </div>`;
      }
    }
  }

  // ── Mount (replaces init) ──────────────────────────────────────────────────
  /**
   * mount(container) — called by PAGE_CONFIG['email-threat'].onEnter
   * Injects the full module HTML into the provided .page container div.
   * Idempotent: calling mount() again on an already-mounted container is safe.
   */
  function mount(container) {
    errorBoundary(() => {
      if (!container) {
        console.error('[ETI-AARE] mount() called with null container');
        return;
      }
      state.container = container;

      // Ensure the page container fills the viewport
      // navigateTo() sets display:'' on the .page div — we need it to be a
      // flex column so #etiModuleRoot (height:100%) can fill the space.
      container.style.height   = '100%';
      container.style.display  = 'flex';
      container.style.flexDirection = 'column';
      container.style.padding  = '0';
      container.style.overflow = 'hidden';

      // Inject HTML
      container.innerHTML = buildModuleHTML();
      state.mounted = true;

      // RC-FIX v4.0: Add .active class to #etiModuleRoot so CSS shows it
      // (.eti-module { display:none } .eti-module.active { display:flex })
      const root = container.querySelector('#etiModuleRoot');
      if (root) root.classList.add('active');

      // Bind events & load data
      bindEvents(container);
      loadInitialStats();
      checkBackendHealth();

      console.log('[ETI-AARE] ✅ Module mounted successfully');
    }, 'mount');
  }

  /**
   * onShow() — called when user navigates back to the page (already mounted).
   * Refreshes stats and health status without re-rendering the whole module.
   */
  function onShow() {
    if (!state.mounted) return;
    loadInitialStats();
    checkBackendHealth();
  }

  // ── Backend Health Check ───────────────────────────────────────────────────
  async function checkBackendHealth() {
    const badge = document.getElementById('etiBackendStatus');
    if (!badge) return;

    badge.innerHTML = '<i class="fas fa-circle-notch fa-spin" style="margin-right:4px;"></i> Checking...';
    badge.style.color = '#8b949e';
    badge.style.borderColor = 'rgba(139,148,158,0.3)';

    try {
      const res = await API.checkHealth();
      if (res && (res.status === 'ok' || res.success || res.healthy)) {
        state.backendStatus = 'online';
        badge.innerHTML = '<i class="fas fa-check-circle" style="margin-right:4px;"></i> Module Connected ✅';
        badge.style.color = '#30D158';
        badge.style.borderColor = 'rgba(48,209,88,0.3)';
      } else {
        throw new Error('Non-ok response');
      }
    } catch {
      state.backendStatus = 'offline';
      badge.innerHTML = '<i class="fas fa-times-circle" style="margin-right:4px;"></i> Backend Not Reachable ❌';
      badge.style.color = '#FF3B30';
      badge.style.borderColor = 'rgba(255,59,48,0.3)';
    }
  }

  // ── HTML Builder ───────────────────────────────────────────────────────────
  function buildModuleHTML() {
    return `
<div class="eti-module" id="etiModuleRoot" role="main" aria-label="Email Threat Intelligence Module">

  <!-- Toast Container -->
  <div class="eti-toast-container" id="etiToastContainer"></div>

  <!-- Analysis Overlay -->
  <div class="eti-analyzing-overlay" id="etiAnalyzingOverlay">
    <div class="eti-spinner"></div>
    <div style="font-size:14px;font-weight:600;color:var(--eti-text-primary);">Analyzing Email Threat...</div>
    <div class="eti-analyzing-steps" id="etiAnalyzingSteps">
      <div class="eti-analyzing-step" data-step="parse">     <div class="eti-step-dot"></div>Parsing email structure &amp; headers</div>
      <div class="eti-analyzing-step" data-step="fingerprint"><div class="eti-step-dot"></div>Behavioral identity fingerprinting</div>
      <div class="eti-analyzing-step" data-step="detect">    <div class="eti-step-dot"></div>Running 24 detection rules</div>
      <div class="eti-analyzing-step" data-step="enrich">    <div class="eti-step-dot"></div>Enriching with threat intelligence</div>
      <div class="eti-analyzing-step" data-step="score">     <div class="eti-step-dot"></div>Computing dynamic risk score</div>
      <div class="eti-analyzing-step" data-step="explain">   <div class="eti-step-dot"></div>Generating AI explanation</div>
      <div class="eti-analyzing-step" data-step="soar">      <div class="eti-step-dot"></div>Executing SOAR response actions</div>
    </div>
  </div>

  <!-- ── Header ── -->
  <header class="eti-header">
    <div class="eti-header-left">
      <div class="eti-logo-badge">
        <i class="fas fa-envelope-open-text eti-logo-icon"></i>
        <div>
          <div class="eti-logo-text">ETI-AARE</div>
          <div class="eti-logo-sub">Email Threat Intelligence &amp; Autonomous Response Engine</div>
        </div>
      </div>
      <!-- Backend health indicator -->
      <div id="etiBackendStatus" style="
        display:inline-flex;align-items:center;font-size:11px;font-weight:600;
        padding:4px 10px;border-radius:20px;border:1px solid rgba(139,148,158,0.3);
        color:#8b949e;margin-left:16px;cursor:pointer;transition:all .2s;
      " onclick="window.ETIModule._checkHealth()" title="Click to recheck backend status">
        <i class="fas fa-circle-notch fa-spin" style="margin-right:4px;"></i> Checking...
      </div>
    </div>
    <div class="eti-header-stats">
      <div class="eti-header-stat total">
        <div class="eti-header-stat-value" id="etiStatTotal">0</div>
        <div class="eti-header-stat-label">Analyzed</div>
      </div>
      <div class="eti-header-stat critical">
        <div class="eti-header-stat-value" id="etiStatCritical">0</div>
        <div class="eti-header-stat-label">Critical</div>
      </div>
      <div class="eti-header-stat high">
        <div class="eti-header-stat-value" id="etiStatHigh">0</div>
        <div class="eti-header-stat-label">High</div>
      </div>
      <div class="eti-header-stat clean">
        <div class="eti-header-stat-value" id="etiStatClean">0</div>
        <div class="eti-header-stat-label">Clean</div>
      </div>
    </div>
    <div class="eti-header-actions">
      <button class="eti-btn eti-btn-ghost" onclick="window.ETIModule.openIncidents()">
        <i class="fas fa-ticket-alt"></i> Incidents
      </button>
      <button class="eti-btn eti-btn-ghost" onclick="window.ETIModule.openBlocklists()">
        <i class="fas fa-ban"></i> Blocklists
      </button>
    </div>
  </header>

  <!-- ── Main 3-Column Layout ── -->
  <div class="eti-layout">

    <!-- LEFT: Ingest Panel -->
    <div class="eti-left-panel">
      <div class="eti-panel-header">
        <div class="eti-panel-title"><i class="fas fa-inbox"></i> Email Ingest</div>
      </div>

      <div class="eti-ingest-tabs">
        <button class="eti-ingest-tab active" data-source="manual">Manual</button>
        <button class="eti-ingest-tab" data-source="m365">M365</button>
        <button class="eti-ingest-tab" data-source="gmail">Gmail</button>
        <button class="eti-ingest-tab" data-source="smtp">SMTP</button>
      </div>

      <div class="eti-upload-zone" id="etiUploadZone">
        <div class="eti-upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>
        <div class="eti-upload-text">Drop .eml or .msg file here</div>
        <div class="eti-upload-sub">or click to browse</div>
        <input type="file" id="etiFileInput" accept=".eml,.msg,.txt" style="display:none">
      </div>

      <div class="eti-demo-scenarios">
        <div class="eti-demo-label">Quick Demo Scenarios</div>
        <div class="eti-demo-grid">
          <button class="eti-demo-btn phishing" onclick="window.ETIModule.runDemo('phishing')">
            <i class="fas fa-fish"></i> Phishing
          </button>
          <button class="eti-demo-btn bec" onclick="window.ETIModule.runDemo('bec')">
            <i class="fas fa-user-secret"></i> BEC
          </button>
          <button class="eti-demo-btn malware" onclick="window.ETIModule.runDemo('malware')">
            <i class="fas fa-bug"></i> Malware
          </button>
          <button class="eti-demo-btn clean" onclick="window.ETIModule.runDemo('clean')">
            <i class="fas fa-check-circle"></i> Clean
          </button>
        </div>
      </div>

      <!-- Analysis Queue -->
      <div class="eti-panel-header" style="border-top:1px solid var(--eti-border);margin-top:auto;">
        <div class="eti-panel-title">
          <i class="fas fa-list"></i>
          Queue <span id="etiQueueCount" style="color:var(--eti-text-tertiary);font-weight:400;">(0)</span>
        </div>
      </div>
      <div class="eti-email-queue" id="etiEmailQueue">
        <div style="padding:20px;text-align:center;color:var(--eti-text-tertiary);font-size:12px;">
          No emails analyzed yet.<br>Use a demo scenario or upload a file.
        </div>
      </div>
    </div>

    <!-- CENTER: Analysis Workspace -->
    <div class="eti-center-panel">
      <div class="eti-analysis-tabs" id="etiAnalysisTabs">
        <button class="eti-tab-btn active" data-tab="overview">    <i class="fas fa-shield-alt"></i> Overview</button>
        <button class="eti-tab-btn" data-tab="evidence">  <i class="fas fa-link"></i> Evidence Chain</button>
        <button class="eti-tab-btn" data-tab="headers">   <i class="fas fa-route"></i> Headers</button>
        <button class="eti-tab-btn" data-tab="intelligence"><i class="fas fa-database"></i> Threat Intel</button>
        <button class="eti-tab-btn" data-tab="behavioral"><i class="fas fa-fingerprint"></i> Behavioral</button>
        <button class="eti-tab-btn" data-tab="graph">     <i class="fas fa-project-diagram"></i> Attack Graph</button>
        <button class="eti-tab-btn" data-tab="narrative"> <i class="fas fa-book-open"></i> AI Narrative</button>
      </div>

      <div class="eti-analysis-content" id="etiAnalysisContent">
        <div class="eti-empty-state" id="etiEmptyState">
          <div class="eti-empty-icon"><i class="fas fa-envelope-open-text"></i></div>
          <div class="eti-empty-title">Email Threat Intelligence Module</div>
          <div class="eti-empty-sub">
            Submit an email for AI-powered threat analysis. Use the demo scenarios below to explore the full
            ETI-AARE pipeline — parsing, detection, enrichment, risk scoring, and autonomous response.
          </div>
          <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:8px;">
            <button class="eti-btn eti-btn-primary" onclick="window.ETIModule.runDemo('phishing')">
              <i class="fas fa-fish"></i> Phishing Demo
            </button>
            <button class="eti-btn eti-btn-ghost" onclick="window.ETIModule.runDemo('bec')">
              <i class="fas fa-user-secret"></i> BEC Demo
            </button>
            <button class="eti-btn eti-btn-ghost" onclick="window.ETIModule.runDemo('malware')">
              <i class="fas fa-bug"></i> Malware Demo
            </button>
          </div>
        </div>
        <div id="etiTabContent" style="display:none;"></div>
      </div>
    </div>

    <!-- RIGHT: Risk + Actions Panel -->
    <div class="eti-right-panel" id="etiRightPanel">
      <div class="eti-risk-panel">
        <div class="eti-risk-panel-title">Risk Score Breakdown</div>
        <div id="etiRiskBreakdown">
          <div style="color:var(--eti-text-tertiary);font-size:11px;text-align:center;padding:20px 0;">
            No analysis yet
          </div>
        </div>
      </div>

      <div class="eti-actions-panel" id="etiActionsPanel">
        <div class="eti-actions-title">Response Actions</div>
        <div id="etiResponseActions">
          <div style="color:var(--eti-text-tertiary);font-size:11px;">Analyze an email to see response options</div>
        </div>
      </div>

      <div class="eti-indicators-panel" id="etiIndicatorsPanel">
        <div class="eti-risk-panel-title">Extracted Indicators</div>
        <div id="etiIndicatorsList">
          <div style="color:var(--eti-text-tertiary);font-size:11px;">No indicators yet</div>
        </div>
      </div>
    </div>

  </div><!-- /.eti-layout -->
</div><!-- /#etiModuleRoot -->`;
  }

  // ── Event Binding ──────────────────────────────────────────────────────────
  function bindEvents(container) {
    // Analysis tab buttons
    container.addEventListener('click', (e) => {
      const tabBtn = e.target.closest('.eti-tab-btn');
      if (tabBtn && tabBtn.closest('#etiAnalysisTabs')) {
        switchTab(tabBtn.dataset.tab);
      }

      const ingestTab = e.target.closest('.eti-ingest-tab');
      if (ingestTab) {
        container.querySelectorAll('.eti-ingest-tab').forEach(t => t.classList.remove('active'));
        ingestTab.classList.add('active');
      }

      const sectionHeader = e.target.closest('.eti-section-card-header');
      if (sectionHeader) {
        sectionHeader.closest('.eti-section-card').classList.toggle('collapsed');
      }
    });

    // Upload zone
    const zone     = container.querySelector('#etiUploadZone');
    const fileInput = container.querySelector('#etiFileInput');
    if (zone && fileInput) {
      zone.addEventListener('click', () => fileInput.click());
      zone.addEventListener('dragover',  (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', ()  => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) handleFileUpload(file);
      });
      fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) handleFileUpload(e.target.files[0]);
      });
    }
  }

  function switchTab(tab) {
    state.currentTab = tab;
    // RC-FIX v4.0: Scope query to container to avoid collisions with other page tabs
    const scope = state.container || document;
    scope.querySelectorAll('.eti-tab-btn').forEach(t =>
      t.classList.toggle('active', t.dataset.tab === tab));
    if (state.currentAnalysis) renderTabContent(tab, state.currentAnalysis);
  }

  // ── File Upload ────────────────────────────────────────────────────────────
  async function handleFileUpload(file) {
    const text = await file.text();
    const rawEmail = parseEmlText(text);
    await analyzeEmail(rawEmail, 'upload');
  }

  function parseEmlText(text) {
    const lines = text.split('\n');
    const headers = [];
    let headersDone = false;
    const bodyLines = [];
    let subject = '';

    for (const line of lines) {
      if (!headersDone) {
        if (line.trim() === '') { headersDone = true; continue; }
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
          const name  = line.slice(0, colonIdx).trim();
          const value = line.slice(colonIdx + 1).trim();
          headers.push({ name, value });
          if (name.toLowerCase() === 'subject') subject = value;
        }
      } else {
        bodyLines.push(line);
      }
    }
    return {
      subject,
      internetMessageHeaders: headers,
      body: { contentType: 'text/plain', content: bodyLines.join('\n') }
    };
  }

  // ── Demo Runner ────────────────────────────────────────────────────────────
  async function runDemo(scenario) {
    if (state.analyzing) return;
    showAnalyzing(true);
    animateAnalyzingSteps();

    try {
      // API._fetch returns null on network/non-OK errors — always fall back to mock
      const result = await API.analyzeDemo(scenario);
      if (result && result.success && result.data) {
        processAnalysisResult(result.data);
        const tier = result.data.risk?.tier || 'unknown';
        showToast(
          `${scenario.toUpperCase()} Scenario`,
          `Risk: ${result.data.risk?.final_score}/100 — ${tier.toUpperCase()}`,
          tier === 'critical' || tier === 'high' ? 'critical' : 'info'
        );
      } else {
        // RC-FIX v4.0: null result (network error) or non-success → use rich offline mock data
        console.info('[ETI-AARE] Backend unreachable or returned non-success — using offline demo data for:', scenario);
        showToast('Demo Mode', `Running ${scenario.toUpperCase()} scenario with demo data`, 'info');
        processMockAnalysis(scenario);
      }
    } catch (err) {
      console.warn('[ETI-AARE] runDemo error, using offline mock data:', err.message);
      showToast('Offline Demo Mode', 'Backend not reachable — showing demo data', 'info');
      processMockAnalysis(scenario);
    } finally {
      showAnalyzing(false);
    }
  }

  async function analyzeEmail(rawEmail, source) {
    if (state.analyzing) return;
    showAnalyzing(true);

    try {
      animateAnalyzingSteps();
      const result = await API.analyzeEmail(rawEmail, source);
      if (result && result.success) {
        processAnalysisResult(result.data);
      } else {
        showToast('Analysis Error', result?.error || 'Analysis failed', 'error');
      }
    } catch (err) {
      showToast('Connection Error', 'API unavailable — check backend', 'error');
    } finally {
      showAnalyzing(false);
    }
  }

  function processAnalysisResult(data) {
    state.currentAnalysis = data;
    state.analysisHistory.unshift(data);

    updateStats(data);
    updateEmailQueue();
    renderAnalysisView(data);
    updateRightPanel(data);

    const emptyState   = document.getElementById('etiEmptyState');
    const tabContent   = document.getElementById('etiTabContent');
    if (emptyState)  emptyState.style.display  = 'none';
    if (tabContent)  tabContent.style.display  = '';
  }

  // ── Mock Data (offline / fallback) ─────────────────────────────────────────
  function processMockAnalysis(scenario) {
    processAnalysisResult(generateMockData(scenario));
  }

  function generateMockData(scenario) {
    const now = new Date().toISOString();

    const phishing = {
      analysis_id: 'ETI-DEMO-PHISH',
      email: {
        message_id: '<demo@phish.example>',
        from: 'admin@m1cr0soft-security.tk',
        from_display: 'Microsoft Security Team',
        subject: 'URGENT: Your Microsoft 365 Account Will Be Suspended',
        received_at: now,
        auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail' },
        routing_hops: 3, attachment_count: 0, url_count: 2,
        indicators: {
          ips: ['185.234.219.123'],
          domains: ['m1cr0soft-security.tk', 'm1cr0s0ft.xyz'],
          urls: ['http://m1cr0s0ft.xyz/verify'],
          hashes: [], emails: []
        }
      },
      detection: {
        rules_triggered: [
          { rule_id: 'ETI-AUTH-001', name: 'Complete Authentication Failure (SPF+DKIM+DMARC)', severity: 'critical', confidence: 85,
            mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
          { rule_id: 'ETI-SPOOF-001', name: 'Display Name Impersonation', severity: 'high', confidence: 80,
            mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
          { rule_id: 'ETI-PHISH-002', name: 'Homograph/Lookalike Domain Attack', severity: 'critical', confidence: 90,
            mitre: { technique: 'T1036', sub: 'T1036.005', name: 'Masquerading', tactic: 'Defense Evasion' } },
          { rule_id: 'ETI-PHISH-003', name: 'Mass Phishing Indicators', severity: 'high', confidence: 70,
            mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
          { rule_id: 'ETI-URL-004', name: 'Lookalike Domain in URL', severity: 'critical', confidence: 90,
            mitre: { technique: 'T1056', name: 'Input Capture', tactic: 'Collection' } }
        ],
        ai_classification: {
          threat_type: 'phishing', confidence: 92,
          intent: 'Credential harvesting via Microsoft 365 impersonation',
          tone_analysis: { urgency: 85, fear_inducement: 70, manipulation_score: 82 },
          explanation: 'High-confidence phishing attack using Microsoft impersonation with authentication failures and lookalike domain.'
        },
        bec_analysis: { is_bec: false, intents_detected: [], confidence: 0 },
        mitre_techniques: [
          { technique_id: 'T1566', sub_technique_id: 'T1566.002', name: 'Phishing: Spearphishing Link',    tactic: 'Initial Access',    confidence: 90, explanation: 'Email contains malicious URL to phishing site' },
          { technique_id: 'T1036', sub_technique_id: 'T1036.005', name: 'Masquerading',                   tactic: 'Defense Evasion',   confidence: 90, explanation: 'Lookalike domain designed to appear as Microsoft' },
          { technique_id: 'T1056', sub_technique_id: 'T1056.003', name: 'Input Capture: Web Portal',      tactic: 'Collection',        confidence: 80, explanation: 'Phishing portal captures user credentials' }
        ],
        final_verdict: { threat_level: 'critical', primary_type: 'phishing', confidence: 95, recommended_action: 'quarantine_and_block' }
      },
      risk: {
        final_score: 97, tier: 'critical', color: '#FF2D55',
        recommended_action: 'quarantine_and_block', sla_minutes: 15, confidence: 95, amplifier: 1.3,
        breakdown: {
          auth:       { score: 28, label: 'Authentication Failures' },
          rules:      { score: 45, by_severity: { critical: 3, high: 2 }, total_rules: 5, label: 'Rule Detections' },
          ai:         { score: 32, ai_confidence: 92, threat_type: 'phishing', label: 'AI Classification' },
          sender:     { score: 20, anomaly_count: 2, label: 'Sender Anomalies' },
          social_eng: { score: 25, urgency_score: 85, label: 'Social Engineering' },
          urls:       { score: 25, url_count: 2, suspicious_count: 2, label: 'URL Analysis' },
          routing:    { score: 5,  suspicious_hops: 1, label: 'Email Routing' },
          threat_intel:{ score: 0, label: 'Threat Intelligence' },
          attachments: { score: 0, label: 'Attachments' },
          amplifier:   { factor: 1.3, applied: ['multiple_indicators', 'auth_all_fail'] }
        }
      },
      explanation: {
        summary: {
          headline: 'CRITICAL RISK: Phishing attack designed to steal Microsoft credentials',
          risk_level: 'critical', risk_score: 97, threat_type: 'phishing',
          in_one_sentence: 'Email from admin@m1cr0soft-security.tk exhibits definitive phishing indicators with a risk score of 97/100.',
          key_facts: [
            'SPF FAIL — sending server not authorized (spoofed sender)',
            'DKIM FAIL — signature invalid (email modified or spoofed)',
            'DMARC FAIL — domain policy violated',
            'Display name impersonates "Microsoft Security Team"',
            'Lookalike domain: m1cr0s0ft.xyz detected in URL',
            '3 critical detection rules triggered'
          ]
        },
        evidence_chain: [
          { step: 1, category: 'Email Authentication', icon: 'shield-alt', verdict: 'fail',
            evidence: ['SPF: FAIL — Server not authorized', 'DKIM: FAIL — Signature invalid', 'DMARC: FAIL — Policy violated'],
            risk_contribution: 'CRITICAL' },
          { step: 2, category: 'Sender Identity', icon: 'user-circle', verdict: 'suspicious',
            evidence: ['Display name "Microsoft" doesn\'t match domain m1cr0soft-security.tk', 'Reply-To redirect to account-recovery-help.ml'],
            risk_contribution: 'HIGH' },
          { step: 3, category: 'Routing Analysis', icon: 'route', verdict: 'suspicious',
            evidence: ['3 relay hops traversed', 'Suspicious hop: 185.234.219.123 (unknown hosting)'],
            risk_contribution: 'LOW' },
          { step: 4, category: 'Content & Intent', icon: 'file-alt', verdict: 'malicious',
            evidence: ['Urgency keywords: urgent, immediately, suspended', 'Credential harvesting: click here, sign in, verify'],
            risk_contribution: 'HIGH' },
          { step: 5, category: 'URL & Domain Analysis', icon: 'link', verdict: 'malicious',
            evidence: ['Lookalike domain m1cr0s0ft.xyz in URL', 'Suspicious URL: http://m1cr0s0ft.xyz/verify'],
            risk_contribution: 'CRITICAL' }
        ],
        attack_narrative: `ATTACK NARRATIVE: Microsoft 365 credential phishing campaign.

The attacker sent email from admin@m1cr0soft-security.tk — a lookalike domain for Microsoft —
which failed SPF authentication, indicating a spoofed or unauthorized sender. The display name
was crafted to read "Microsoft Security Team" while the actual domain is malicious.

The email body uses urgency and fear tactics ("your account will be suspended") to pressure the
victim into clicking a link leading to m1cr0s0ft.xyz — a homograph domain mimicking microsoft.com
— where credentials would be harvested.

MITRE Mapping: T1566.002 (Spearphishing Link), T1036.005 (Masquerading), T1056.003 (Web Portal Capture).`,
        why_flagged: [
          { priority: 1, reason: 'Critical detection rules triggered', detail: ['ETI-AUTH-001: Complete Auth Failure', 'ETI-PHISH-002: Lookalike Domain', 'ETI-URL-004: Suspicious URL'] },
          { priority: 2, reason: 'Email authentication triple failure', detail: ['SPF: fail', 'DKIM: fail', 'DMARC: fail'] },
          { priority: 3, reason: 'AI classification: phishing at 92% confidence', detail: ['High-confidence Microsoft impersonation identified'] }
        ],
        analyst_notes: [
          { type: 'action',        note: 'IMMEDIATE: Quarantine email and notify affected users' },
          { type: 'investigation', note: 'Submit URL http://m1cr0s0ft.xyz/verify to URLScan.io' },
          { type: 'investigation', note: 'Investigate IP 185.234.219.123 in threat intel platforms' },
          { type: 'context',       note: `Email received ${now}` }
        ],
        false_positive_assessment: {
          fp_probability: 5,
          assessment: 'Very likely a real threat',
          factors_suggesting_fp: ['No attachments'],
          factors_against_fp: ['SPF hard fail', 'Critical rules fired', 'Lookalike domain confirmed']
        },
        mitre_explanation: [
          { technique_id: 'T1566', sub_technique_id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', confidence: 90,
            explanation: 'Email contains malicious URL redirecting victims to phishing site' },
          { technique_id: 'T1036', sub_technique_id: 'T1036.005', name: 'Masquerading',       tactic: 'Defense Evasion', confidence: 90,
            explanation: 'Lookalike domain m1cr0s0ft.xyz designed to appear as microsoft.com' }
        ]
      },
      behavioral: { is_new: true, profile_established: true, drift_score: 0, alerts: [] },
      attack_graph: { email_node_id: 'email_demo_phish_001', connected_nodes: [], campaign_id: null },
      response: {
        triggered_playbooks: [{ id: 'PB-PHISH-CRIT', name: 'Critical Phishing Response' }],
        executed_actions: [
          { type: 'quarantine_email',  status: 'executed', auto_executed: true },
          { type: 'block_sender',      status: 'executed', auto_executed: true },
          { type: 'notify_soc',        status: 'executed', auto_executed: true },
          { type: 'create_incident',   status: 'executed', auto_executed: true }
        ],
        pending_actions: [{ type: 'scan_mailbox', status: 'awaiting_approval', requires_approval: true }],
        incident: { incident_id: 'INC-ETI-DEMO001', title: '[PHISHING] admin@m1cr0soft-security.tk', severity: 'CRITICAL', status: 'open' }
      },
      processing_time_ms: 847
    };

    const bec = {
      ...phishing,
      analysis_id: 'ETI-DEMO-BEC',
      email: {
        ...phishing.email,
        from: 'ceo.johnson@company-corp.com',
        from_display: 'Robert Johnson (CEO)',
        subject: 'Urgent Wire Transfer Request — Confidential',
        indicators: { ips: [], domains: ['gmail.com', 'company-corp.com'], urls: [], hashes: [], emails: ['rjohnson.ceo2024@gmail.com'] }
      },
      detection: {
        rules_triggered: [
          { rule_id: 'ETI-SPOOF-002', name: 'Reply-To Domain Mismatch (BEC Indicator)', severity: 'high',     confidence: 85 },
          { rule_id: 'ETI-SPOOF-003', name: 'Executive Impersonation BEC',              severity: 'critical', confidence: 80 },
          { rule_id: 'ETI-BEC-001',   name: 'Wire Transfer Request BEC',                severity: 'critical', confidence: 85 },
          { rule_id: 'ETI-BEC-002',   name: 'Urgent Financial Request',                 severity: 'high',     confidence: 90 }
        ],
        bec_analysis: { is_bec: true, intents_detected: ['financial_fraud', 'wire_transfer'], confidence: 88 },
        ai_classification: { threat_type: 'bec', confidence: 88, intent: 'Executive impersonation for wire transfer fraud',
          tone_analysis: { urgency: 92, fear_inducement: 60, manipulation_score: 79 },
          explanation: 'Classic BEC attack impersonating CEO with urgent wire transfer request redirecting replies to personal Gmail.' },
        mitre_techniques: [
          { technique_id: 'T1566', sub_technique_id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access',  confidence: 85, explanation: 'BEC email targeting finance staff' },
          { technique_id: 'T1078', sub_technique_id: 'T1078.004', name: 'Valid Accounts: Cloud', tactic: 'Persistence', confidence: 70, explanation: 'May indicate compromised executive account' }
        ],
        final_verdict: { threat_level: 'critical', primary_type: 'bec', confidence: 92, recommended_action: 'quarantine_and_block' }
      },
      risk: { ...phishing.risk, final_score: 91, tier: 'critical' },
      explanation: {
        ...phishing.explanation,
        summary: {
          headline: 'CRITICAL RISK: Business Email Compromise — CEO Wire Transfer Fraud',
          risk_level: 'critical', risk_score: 91, threat_type: 'bec',
          in_one_sentence: 'Email impersonating the CEO requests urgent wire transfer; replies redirected to attacker-controlled Gmail.',
          key_facts: [
            'Reply-To redirects to rjohnson.ceo2024@gmail.com (attacker-controlled)',
            'Executive impersonation: Robert Johnson (CEO)',
            'Urgent financial request — hallmark BEC pattern',
            'Wire transfer amount requested (financial fraud intent)',
            '4 BEC-specific detection rules triggered'
          ]
        },
        attack_narrative: `ATTACK NARRATIVE: Business Email Compromise — CEO Wire Transfer Fraud.

The attacker crafted an email appearing to be from CEO Robert Johnson (ceo.johnson@company-corp.com)
but with a Reply-To header pointing to rjohnson.ceo2024@gmail.com — an attacker-controlled account.

The email requests an urgent wire transfer, exploiting executive authority and time pressure to
bypass normal financial controls. This is a textbook BEC (T1566.002) pattern combined with
potential account takeover (T1078.004) or email spoofing.

IMMEDIATE ACTION: Verify with CEO via phone. Do NOT reply to this email or process any transfers.`
      },
      processing_time_ms: 631
    };

    const malware = {
      ...phishing,
      analysis_id: 'ETI-DEMO-MALWARE',
      email: {
        ...phishing.email,
        from: 'hr-portal@staffing-updates.net',
        from_display: 'HR Portal Notifications',
        subject: 'Your Updated Employment Contract — Action Required',
        attachment_count: 1,
        indicators: { ips: ['91.108.4.52'], domains: ['staffing-updates.net'], urls: ['http://staffing-updates.net/contract.exe'], hashes: ['a94b3c8d1e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7b'], emails: [] }
      },
      detection: {
        rules_triggered: [
          { rule_id: 'ETI-ATTACH-001', name: 'Executable Attachment Detected',          severity: 'critical', confidence: 95 },
          { rule_id: 'ETI-AUTH-001',   name: 'Complete Authentication Failure',          severity: 'critical', confidence: 85 },
          { rule_id: 'ETI-ADV-002',    name: 'Low-Reputation TLD Domain',               severity: 'medium',   confidence: 70 },
          { rule_id: 'ETI-PHISH-004',  name: 'Social Engineering — HR/Employment Lure', severity: 'high',     confidence: 80 }
        ],
        ai_classification: { threat_type: 'malware_delivery', confidence: 91, intent: 'Malware delivery via fake employment document',
          tone_analysis: { urgency: 75, fear_inducement: 65, manipulation_score: 70 },
          explanation: 'Malware delivery campaign using HR/employment lure with executable disguised as contract document.' },
        bec_analysis: { is_bec: false, confidence: 0 },
        mitre_techniques: [
          { technique_id: 'T1566', sub_technique_id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access', confidence: 95, explanation: 'Malicious attachment disguised as employment contract' },
          { technique_id: 'T1204', sub_technique_id: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution', confidence: 90, explanation: 'User tricked into running executable' },
          { technique_id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', confidence: 75, explanation: 'Downloader likely fetches secondary payload' }
        ],
        final_verdict: { threat_level: 'critical', primary_type: 'malware_delivery', confidence: 93, recommended_action: 'quarantine_and_block' }
      },
      risk: { ...phishing.risk, final_score: 95, tier: 'critical' },
      processing_time_ms: 1240
    };

    const clean = {
      analysis_id: 'ETI-DEMO-CLEAN',
      email: {
        message_id: '<report@company.com>',
        from: 'reports@company.com',
        from_display: 'Reports System',
        subject: 'Q3 Sales Report — Internal Distribution',
        received_at: now,
        auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
        routing_hops: 2, attachment_count: 0, url_count: 0,
        indicators: { ips: [], domains: ['company.com'], urls: [], hashes: [], emails: [] }
      },
      detection: {
        rules_triggered: [],
        ai_classification: { threat_type: 'legitimate', confidence: 97, intent: 'Internal business communication',
          tone_analysis: { urgency: 5, fear_inducement: 0, manipulation_score: 2 },
          explanation: 'Legitimate internal email with perfect authentication and no threat indicators.' },
        bec_analysis: { is_bec: false, confidence: 0 },
        mitre_techniques: [],
        final_verdict: { threat_level: 'clean', primary_type: 'legitimate', confidence: 97, recommended_action: 'allow' }
      },
      risk: {
        final_score: 2, tier: 'clean', color: '#636366',
        recommended_action: 'allow', confidence: 97, amplifier: 1.0,
        breakdown: { auth: { score: 0 }, rules: { score: 0, total_rules: 0 }, ai: { score: 0 } }
      },
      explanation: {
        summary: {
          headline: 'CLEAN: Email authenticated — no threats detected',
          risk_level: 'clean', risk_score: 2, threat_type: 'legitimate',
          in_one_sentence: 'reports@company.com passed all authentication and contains zero threat indicators.',
          key_facts: ['SPF PASS — sender authorized', 'DKIM PASS — integrity verified', 'DMARC PASS — policy compliant', 'No suspicious URLs or attachments', 'No detection rules triggered']
        },
        evidence_chain: [],
        why_flagged: [],
        analyst_notes: [{ type: 'context', note: 'This email is classified as legitimate business communication.' }],
        false_positive_assessment: { fp_probability: 98, assessment: 'Almost certainly a legitimate email' }
      },
      behavioral: { is_new: false, drift_score: 0, alerts: [] },
      attack_graph: { email_node_id: 'email_demo_clean_001', connected_nodes: [] },
      response: { triggered_playbooks: [], executed_actions: [], pending_actions: [], incident: null },
      processing_time_ms: 120
    };

    const map = { phishing, bec, malware, clean };
    return map[scenario] || phishing;
  }

  // ── Render Functions ───────────────────────────────────────────────────────
  function renderAnalysisView(data) {
    renderTabContent(state.currentTab, data);
  }

  function renderTabContent(tab, data) {
    const container = document.getElementById('etiTabContent');
    if (!container || !data) return;

    const renderers = {
      overview:     () => renderOverview(data),
      evidence:     () => renderEvidenceChain(data),
      headers:      () => renderHeaderAnalysis(data),
      intelligence: () => renderThreatIntel(data),
      behavioral:   () => renderBehavioral(data),
      graph:        () => renderAttackGraph(data),
      narrative:    () => renderNarrative(data)
    };

    container.innerHTML = (renderers[tab] || renderers.overview)();
    container.style.display = '';
  }

  function renderOverview(data) {
    const risk      = data.risk;
    const detection = data.detection;
    const tier      = risk.tier;
    const score     = risk.final_score;

    const circumference = 2 * Math.PI * 30;
    const offset = circumference - (score / 100) * circumference;
    const tierColors = { critical: '#FF2D55', high: '#FF6B35', medium: '#FFD60A', low: '#30D158', clean: '#636366' };
    const color = tierColors[tier] || '#636366';

    const mitreChips = (detection.mitre_techniques || []).map(t => `
      <div class="eti-mitre-chip" title="${t.explanation || ''}">
        <span class="eti-mitre-id">${t.sub_technique_id || t.technique_id}</span>
        <span class="eti-mitre-name">${t.name}</span>
        <span class="eti-mitre-tactic">${t.tactic}</span>
        <span class="eti-mitre-conf">${t.confidence}%</span>
      </div>`).join('');

    const rules = (detection.rules_triggered || []).map(r => `
      <div class="eti-rule-item">
        <span class="eti-rule-id">${r.rule_id}</span>
        <span class="eti-rule-name">${r.name}</span>
        <span class="eti-rule-sev ${r.severity}">${r.severity}</span>
        <span class="eti-rule-conf">${r.confidence}%</span>
      </div>`).join('');

    const keyFacts = (data.explanation?.summary?.key_facts || []).map(f =>
      `<div class="eti-evidence-item"><i class="fas fa-exclamation-triangle" style="color:var(--eti-medium);margin-right:6px;font-size:10px;"></i>${f}</div>`
    ).join('');

    return `
    <div class="eti-animate-in">
      <div class="eti-verdict-card ${tier}">
        <div class="eti-verdict-score-ring">
          <svg width="80" height="80" viewBox="0 0 80 80">
            <circle class="track" cx="40" cy="40" r="30"/>
            <circle class="fill" cx="40" cy="40" r="30"
              stroke="${color}"
              stroke-dasharray="${circumference.toFixed(2)}"
              stroke-dashoffset="${offset.toFixed(2)}"/>
          </svg>
          <div class="eti-verdict-score-center">
            <div class="eti-verdict-score-num" style="color:${color}">${score}</div>
            <div class="eti-verdict-score-max">/100</div>
          </div>
        </div>
        <div class="eti-verdict-info">
          <div class="eti-verdict-type">${(detection.final_verdict?.primary_type || tier).replace(/_/g,' ')}</div>
          <div class="eti-verdict-headline">${data.explanation?.summary?.headline || tier.toUpperCase() + ' THREAT'}</div>
          <div class="eti-verdict-sentence">${data.explanation?.summary?.in_one_sentence || ''}</div>
        </div>
        <div class="eti-verdict-action">
          <div class="eti-action-badge" style="color:${color};">${(risk.recommended_action || 'review').replace(/_/g,' ')}</div>
          <div class="eti-verdict-confidence">Confidence: ${risk.confidence || 0}%</div>
          ${risk.sla_minutes ? `<div style="font-size:10px;color:var(--eti-text-tertiary);">SLA: ${risk.sla_minutes}min</div>` : ''}
        </div>
      </div>

      ${mitreChips ? `<div class="eti-mitre-bar"><div class="eti-mitre-label">MITRE ATT&amp;CK Techniques</div>${mitreChips}</div>` : ''}

      ${keyFacts ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-exclamation-circle"></i> Key Findings</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">${keyFacts}</div>
        </div>` : ''}

      ${rules ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-shield-virus"></i> Detection Rules (${detection.rules_triggered?.length || 0})</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-rules-list">${rules}</div>
          </div>
        </div>` : `<div style="color:var(--eti-low);padding:16px;text-align:center;"><i class="fas fa-check-circle"></i> No threat rules triggered — email appears clean</div>`}

      ${data.detection.ai_classification ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-robot"></i> AI Classification</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-confidence-breakdown">
              <div class="eti-conf-item">
                <div class="eti-conf-label">Threat Type</div>
                <div class="eti-conf-value" style="font-size:14px;color:var(--eti-accent-blue)">${data.detection.ai_classification.threat_type}</div>
              </div>
              <div class="eti-conf-item">
                <div class="eti-conf-label">AI Confidence</div>
                <div class="eti-conf-value" style="color:var(--eti-medium)">${data.detection.ai_classification.confidence}%</div>
                <div class="eti-conf-bar"><div class="eti-conf-bar-fill" style="width:${data.detection.ai_classification.confidence}%"></div></div>
              </div>
              ${data.detection.ai_classification.tone_analysis ? `
              <div class="eti-conf-item">
                <div class="eti-conf-label">Urgency</div>
                <div class="eti-conf-value" style="color:var(--eti-high)">${data.detection.ai_classification.tone_analysis.urgency || 0}%</div>
              </div>
              <div class="eti-conf-item">
                <div class="eti-conf-label">Manipulation</div>
                <div class="eti-conf-value" style="color:var(--eti-critical)">${data.detection.ai_classification.tone_analysis.manipulation_score || 0}%</div>
              </div>` : ''}
            </div>
            ${data.detection.ai_classification.explanation ? `<div class="eti-narrative" style="margin-top:10px;">${data.detection.ai_classification.explanation}</div>` : ''}
          </div>
        </div>` : ''}

      ${data.response ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-bolt"></i> SOAR Response</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            ${(data.response.triggered_playbooks || []).map(pb => `
              <div style="margin-bottom:8px;padding:8px 10px;background:rgba(0,122,255,0.07);border-radius:6px;border:1px solid rgba(0,122,255,0.2);">
                <div style="font-size:11px;font-weight:600;color:var(--eti-accent-blue)"><i class="fas fa-play-circle" style="margin-right:5px;"></i>Playbook: ${pb.name}</div>
              </div>`).join('')}
            ${(data.response.executed_actions || []).map(a => `
              <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--eti-border);">
                <i class="fas fa-check-circle" style="color:var(--eti-low);font-size:12px;"></i>
                <span style="font-size:11px;color:var(--eti-text-secondary);flex:1;">${a.type.replace(/_/g,' ')}</span>
                <span style="font-size:10px;color:var(--eti-low)">AUTO</span>
              </div>`).join('')}
            ${(data.response.pending_actions || []).map(a => `
              <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--eti-border);">
                <i class="fas fa-clock" style="color:var(--eti-medium);font-size:12px;"></i>
                <span style="font-size:11px;color:var(--eti-text-secondary);flex:1;">${a.type.replace(/_/g,' ')}</span>
                <span style="font-size:10px;color:var(--eti-medium)">PENDING APPROVAL</span>
              </div>`).join('')}
            ${data.response.incident ? `
              <div style="margin-top:8px;padding:8px;background:rgba(255,45,85,0.07);border-radius:6px;border:1px solid rgba(255,45,85,0.2);font-size:11px;color:var(--eti-text-secondary);">
                <i class="fas fa-ticket-alt" style="color:var(--eti-critical);margin-right:5px;"></i>
                Incident: ${data.response.incident.incident_id} — ${data.response.incident.severity}
              </div>` : ''}
          </div>
        </div>` : ''}
    </div>`;
  }

  function renderEvidenceChain(data) {
    const chain = data.explanation?.evidence_chain || [];
    if (!chain.length) {
      return `<div class="eti-empty-state" style="padding:40px;">
        <i class="fas fa-check-circle" style="font-size:48px;color:var(--eti-low);margin-bottom:12px;"></i>
        <div style="color:var(--eti-text-secondary)">No evidence chain — email appears clean</div>
      </div>`;
    }

    const verdictIcons = { pass: 'check-circle', fail: 'times-circle', suspicious: 'exclamation-triangle', malicious: 'skull-crossbones', clean: 'check-circle' };
    const steps = chain.map(step => `
      <div class="eti-evidence-step verdict-${step.verdict}">
        <div class="eti-evidence-step-icon"><i class="fas fa-${verdictIcons[step.verdict] || 'question-circle'}"></i></div>
        <div class="eti-evidence-step-content">
          <div class="eti-evidence-step-header">
            <div class="eti-evidence-step-cat">Step ${step.step}: ${step.category}</div>
            <div class="eti-evidence-risk-pill ${(step.risk_contribution || '').toLowerCase()}">${step.risk_contribution}</div>
          </div>
          <div class="eti-evidence-items">
            ${(step.evidence || []).map(e => `<div class="eti-evidence-item"><i class="fas fa-chevron-right" style="font-size:8px;color:var(--eti-text-tertiary);margin-right:6px;"></i>${e}</div>`).join('')}
          </div>
        </div>
      </div>`).join('');

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-link"></i> Evidence Chain (${chain.length} steps)</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div class="eti-evidence-chain">${steps}</div>
        </div>
      </div>

      ${data.explanation?.why_flagged?.length ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-question-circle"></i> Why Was This Flagged?</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            ${data.explanation.why_flagged.map(r => `
              <div style="margin-bottom:12px;">
                <div style="font-size:12px;font-weight:600;color:var(--eti-text-primary);margin-bottom:5px;">${r.priority}. ${r.reason}</div>
                ${(r.detail || []).map(d => `<div class="eti-evidence-item">${d}</div>`).join('')}
              </div>`).join('')}
          </div>
        </div>` : ''}

      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-balance-scale"></i> False Positive Assessment</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div style="font-size:12px;color:var(--eti-text-secondary);margin-bottom:10px;">
            ${data.explanation?.false_positive_assessment?.assessment || 'N/A'}
          </div>
          <div class="eti-fp-meter">
            <div class="eti-fp-label">FP Probability</div>
            <div class="eti-fp-track">
              <div class="eti-fp-fill" style="width:${data.explanation?.false_positive_assessment?.fp_probability || 0}%"></div>
            </div>
            <div class="eti-fp-pct">${data.explanation?.false_positive_assessment?.fp_probability || 0}%</div>
          </div>
        </div>
      </div>
    </div>`;
  }

  function renderHeaderAnalysis(data) {
    const auth = data.email?.auth || {};
    const hops = (data.explanation?.evidence_chain?.find(s => s.category === 'Routing Analysis')?.evidence || []);

    const authBadge = (result, label) => {
      const c = result === 'pass' ? 'var(--eti-low)' : result === 'fail' ? 'var(--eti-critical)' : 'var(--eti-medium)';
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;
        background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--eti-border);margin-bottom:4px;">
        <span style="font-size:12px;color:var(--eti-text-secondary);font-weight:600;">${label}</span>
        <span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:4px;
          background:rgba(255,255,255,0.07);color:${c}">${(result || 'none').toUpperCase()}</span>
      </div>`;
    };

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-shield-alt"></i> Email Authentication (SPF / DKIM / DMARC)</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          ${authBadge(auth.spf,   '🔐 SPF  — Sender Policy Framework')}
          ${authBadge(auth.dkim,  '✏️  DKIM — DomainKeys Identified Mail')}
          ${authBadge(auth.dmarc, '📋 DMARC — Domain-based Auth, Reporting & Conformance')}
          ${auth.arc ? authBadge(auth.arc, '🔗 ARC  — Authenticated Received Chain') : ''}
        </div>
      </div>

      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-route"></i> Routing Hop-by-Hop Analysis</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div class="eti-hop-chain">
            ${hops.length ? hops.map((hop, i) => {
              const suspicious = hop.toLowerCase().includes('suspicious') || hop.toLowerCase().includes('unknown');
              return `<div class="eti-hop-item ${suspicious ? 'suspicious' : ''}">
                <div class="eti-hop-num">${i + 1}</div>
                <div class="eti-hop-info">
                  <div class="eti-hop-hostname">${hop.replace(/^Suspicious hop: /, '')}</div>
                </div>
                ${suspicious ? '<div class="eti-hop-flag">⚠ SUSPICIOUS</div>' : '<div class="eti-hop-flag" style="color:var(--eti-low);">✓ OK</div>'}
              </div>`;
            }).join('') : `<div style="color:var(--eti-text-tertiary);font-size:12px;padding:10px;">
              ${data.email?.routing_hops || 0} routing hop(s) recorded — detailed trace unavailable in demo mode
            </div>`}
          </div>
        </div>
      </div>

      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-user"></i> Sender Details</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
            ${[
              ['From Address',    data.email?.from          || 'N/A', 'var(--eti-accent-cyan)'],
              ['Display Name',    data.email?.from_display  || 'N/A', 'var(--eti-text-secondary)'],
              ['Routing Hops',    data.email?.routing_hops  || 0,     'var(--eti-text-secondary)'],
              ['Attachments',     data.email?.attachment_count || 0,  data.email?.attachment_count > 0 ? 'var(--eti-critical)' : 'var(--eti-low)'],
              ['URLs Found',      data.email?.url_count     || 0,     data.email?.url_count > 0 ? 'var(--eti-medium)' : 'var(--eti-low)']
            ].map(([label, val, clr]) => `
              <div style="padding:8px;background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--eti-border);">
                <div style="font-size:10px;color:var(--eti-text-tertiary);margin-bottom:3px;">${label}</div>
                <div style="font-size:11px;font-family:monospace;color:${clr};word-break:break-all;">${val}</div>
              </div>`).join('')}
          </div>
        </div>
      </div>
    </div>`;
  }

  function renderThreatIntel(data) {
    const enrichment = data.enrichment || {};
    const summary    = enrichment.summary || {};
    const ctx        = enrichment.threat_context || [];

    const stats = [
      { label: 'Malicious IPs',   val: summary.malicious_ips     || 0, color: 'critical' },
      { label: 'Bad Domains',     val: summary.malicious_domains  || 0, color: 'high' },
      { label: 'Malicious URLs',  val: summary.malicious_urls     || 0, color: 'high' },
      { label: 'Known Malware',   val: summary.malicious_hashes   || 0, color: 'critical' }
    ];

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-database"></i> Intelligence Summary</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px;">
            ${stats.map(s => `
              <div style="padding:10px;background:rgba(255,255,255,0.03);border-radius:6px;text-align:center;border:1px solid var(--eti-border);">
                <div style="font-size:22px;font-weight:800;color:var(--eti-${s.color})">${s.val}</div>
                <div style="font-size:10px;color:var(--eti-text-tertiary)">${s.label}</div>
              </div>`).join('')}
          </div>
          ${ctx.length ? ctx.map(c => `
            <div style="display:flex;gap:10px;align-items:center;padding:6px 10px;
              background:rgba(255,45,85,0.07);border:1px solid rgba(255,45,85,0.2);border-radius:6px;margin-bottom:4px;">
              <i class="fas fa-radiation" style="color:var(--eti-critical);font-size:12px;"></i>
              <span style="flex:1;font-size:11px;color:var(--eti-text-secondary);">${c.type.replace(/_/g,' ').toUpperCase()}: ${c.indicator}</span>
              <span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;
                background:rgba(255,45,85,0.2);color:var(--eti-critical)">${c.severity}</span>
            </div>`).join('') :
          `<div style="color:var(--eti-text-tertiary);font-size:12px;text-align:center;padding:20px;">
            ${data.enrichment ? 'No threat intelligence matches found' : '⚠️ Intel APIs not configured (VirusTotal, AbuseIPDB, URLScan keys missing)<br><span style="font-size:11px;">Configure API keys in Settings to enable live enrichment</span>'}
          </div>`}
        </div>
      </div>

      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-fingerprint"></i> Extracted Indicators of Compromise</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          ${renderIOCList(data.email?.indicators || {})}
        </div>
      </div>
    </div>`;
  }

  function renderIOCList(indicators) {
    const groups = [
      { type: 'ips',     label: 'IP Addresses',  icon: 'server'      },
      { type: 'domains', label: 'Domains',        icon: 'globe'       },
      { type: 'urls',    label: 'URLs',           icon: 'link'        },
      { type: 'hashes',  label: 'File Hashes',    icon: 'fingerprint' },
      { type: 'emails',  label: 'Email Addresses',icon: 'at'          }
    ];

    let html = '';
    for (const g of groups) {
      const items = (indicators[g.type] || []).slice(0, 8);
      if (!items.length) continue;
      html += `<div style="margin-bottom:12px;">
        <div style="font-size:11px;font-weight:600;color:var(--eti-text-tertiary);margin-bottom:5px;">
          <i class="fas fa-${g.icon}" style="margin-right:5px;"></i>${g.label} (${items.length})
        </div>
        ${items.map(item => `
          <div style="display:flex;align-items:center;gap:8px;padding:4px 8px;background:rgba(255,255,255,0.03);
            border-radius:4px;border:1px solid var(--eti-border);margin-bottom:2px;">
            <span style="font-size:10px;font-family:monospace;color:var(--eti-accent-cyan);flex:1;word-break:break-all;">
              ${item.length > 60 ? item.substring(0, 57) + '…' : item}
            </span>
          </div>`).join('')}
      </div>`;
    }

    return html || '<div style="color:var(--eti-text-tertiary);font-size:11px;">No indicators extracted</div>';
  }

  function renderBehavioral(data) {
    const beh       = data.behavioral || {};
    const driftDims = beh.drift_dimensions || {};
    const alerts    = beh.alerts || [];

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-fingerprint"></i> Behavioral Identity Fingerprinting</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          ${beh.is_new ? `
            <div style="padding:12px;background:rgba(0,122,255,0.07);border:1px solid rgba(0,122,255,0.2);
              border-radius:6px;font-size:12px;color:var(--eti-accent-blue);">
              <i class="fas fa-user-plus" style="margin-right:6px;"></i>
              <strong>New sender profile established.</strong> Future emails from this sender will be compared
              against this 12-dimensional behavioral baseline (auth pattern, IP subnet, send time, body length,
              reply-to behavior, mailer fingerprint, recipient count, etc.)
            </div>` : `
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;padding:10px 12px;
              background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--eti-border);">
              <div style="flex:1;">
                <div style="font-size:12px;color:var(--eti-text-secondary);">Overall Behavioral Drift from Baseline</div>
              </div>
              <div style="font-size:20px;font-weight:800;color:${beh.drift_score > 0.6 ? 'var(--eti-critical)' : beh.drift_score > 0.3 ? 'var(--eti-medium)' : 'var(--eti-low)'}">
                ${Math.round((beh.drift_score || 0) * 100)}%
              </div>
              <div style="font-size:11px;padding:3px 8px;border-radius:4px;background:rgba(255,255,255,0.07);color:var(--eti-text-tertiary);">
                ${beh.anomaly_detected ? '⚠️ ANOMALY DETECTED' : '✓ NORMAL'}
              </div>
            </div>
            <div class="eti-behavioral-drift">
              ${Object.entries(driftDims).filter(([, d]) => d.drift > 0).map(([dim, d]) => `
                <div class="eti-drift-item ${d.drift > 0.5 ? 'alert' : ''}">
                  <div class="eti-drift-dim">${dim.replace(/_/g, ' ')}</div>
                  <div class="eti-drift-bar">
                    <div class="eti-drift-bar-fill" style="width:${Math.round(d.drift * 100)}%;background:${d.drift > 0.7 ? 'var(--eti-critical)' : d.drift > 0.4 ? 'var(--eti-high)' : 'var(--eti-medium)'};"></div>
                  </div>
                  <div class="eti-drift-score" style="color:${d.drift > 0.7 ? 'var(--eti-critical)' : 'var(--eti-text-secondary)'};">
                    ${Math.round(d.drift * 100)}%
                  </div>
                </div>`).join('') || '<div style="color:var(--eti-low);font-size:12px;"><i class="fas fa-check-circle"></i> No behavioral drift detected</div>'}
            </div>`}

          ${alerts.length ? `
            <div style="margin-top:12px;">
              <div style="font-size:11px;font-weight:600;color:var(--eti-critical);margin-bottom:6px;">
                <i class="fas fa-exclamation-triangle"></i> Behavioral Alerts
              </div>
              ${alerts.map(a => `
                <div style="padding:8px 12px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.3);
                  border-radius:6px;font-size:11px;color:var(--eti-text-secondary);margin-bottom:4px;">
                  <strong style="color:var(--eti-critical)">${a.type.replace(/_/g, ' ').toUpperCase()}</strong>: ${a.message}
                </div>`).join('')}
            </div>` : ''}
        </div>
      </div>
    </div>`;
  }

  function renderAttackGraph(data) {
    const inds = data.email?.indicators || {};
    const nodes = [];
    const edges = [];

    // Build graph nodes
    nodes.push({ id: 'email_0', type: 'email',  label: (data.email?.from || 'unknown').substring(0, 28), color: '#007AFF' });
    (inds.ips     || []).forEach((ip, i)   => { nodes.push({ id: `ip_${i}`,     type: 'ip',     label: ip,                         color: '#FF3B30' }); edges.push({ from: 'email_0', to: `ip_${i}` }); });
    (inds.domains || []).forEach((d, i)    => { nodes.push({ id: `dom_${i}`,    type: 'domain', label: d,                          color: '#FF9500' }); edges.push({ from: 'email_0', to: `dom_${i}` }); });
    (inds.hashes  || []).forEach((h, i)    => { nodes.push({ id: `hash_${i}`,   type: 'hash',   label: h.substring(0, 16) + '…',   color: '#FF2D55' }); edges.push({ from: 'email_0', to: `hash_${i}` }); });
    (inds.emails  || []).forEach((e, i)    => { nodes.push({ id: `email2_${i}`, type: 'sender', label: e,                          color: '#FFD60A' }); edges.push({ from: 'email_0', to: `email2_${i}` }); });

    const nodeHTML = nodes.map((n, idx) => {
      const angle = nodes.length > 1 ? (idx / (nodes.length - 1)) * 2 * Math.PI : 0;
      const r = idx === 0 ? 0 : 110;
      const cx = 200 + r * Math.cos(angle - Math.PI / 2);
      const cy = 140 + r * Math.sin(angle - Math.PI / 2);
      return `<g transform="translate(${cx},${cy})" style="cursor:pointer;">
        <circle r="20" fill="${n.color}" opacity="0.15" stroke="${n.color}" stroke-width="1.5"/>
        <text y="4" text-anchor="middle" fill="${n.color}" font-size="9" font-weight="600">${n.type.toUpperCase()}</text>
        <text y="30" text-anchor="middle" fill="#8b949e" font-size="8">${n.label.length > 20 ? n.label.substring(0, 20) + '…' : n.label}</text>
      </g>`;
    }).join('');

    const edgeHTML = edges.map(e => {
      const src = nodes.find(n => n.id === e.from);
      const dst = nodes.find(n => n.id === e.to);
      if (!src || !dst) return '';
      const srcIdx = nodes.indexOf(src), dstIdx = nodes.indexOf(dst);
      const a1 = srcIdx === 0 ? 0 : (srcIdx / (nodes.length - 1)) * 2 * Math.PI;
      const a2 = (dstIdx / (nodes.length - 1)) * 2 * Math.PI;
      const x1 = 200 + (srcIdx === 0 ? 0 : 110) * Math.cos(a1 - Math.PI / 2);
      const y1 = 140 + (srcIdx === 0 ? 0 : 110) * Math.sin(a1 - Math.PI / 2);
      const x2 = 200 + 110 * Math.cos(a2 - Math.PI / 2);
      const y2 = 140 + 110 * Math.sin(a2 - Math.PI / 2);
      return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="rgba(139,148,158,0.3)" stroke-width="1" stroke-dasharray="3,3"/>`;
    }).join('');

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-project-diagram"></i> Email Attack Graph — ${nodes.length} nodes, ${edges.length} edges</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div class="eti-graph-container">
            <svg width="400" height="280" style="width:100%;max-width:520px;display:block;margin:0 auto;">
              <defs>
                <radialGradient id="bgGrad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stop-color="rgba(0,122,255,0.05)"/>
                  <stop offset="100%" stop-color="transparent"/>
                </radialGradient>
              </defs>
              <rect width="100%" height="100%" fill="url(#bgGrad)" rx="8"/>
              ${edgeHTML}
              ${nodeHTML}
            </svg>
            <div class="eti-graph-legend">
              ${[['#007AFF','Email Node'],['#FF3B30','Malicious IP'],['#FF9500','Domain'],['#FF2D55','Hash'],['#FFD60A','Sender']].map(([c, l]) =>
                `<div class="eti-graph-legend-item">
                  <div class="eti-graph-legend-dot" style="background:${c}"></div>${l}
                </div>`).join('')}
            </div>
          </div>
          ${nodes.length <= 1 ? '<div style="color:var(--eti-text-tertiary);font-size:12px;text-align:center;padding:10px;">No connected indicators to graph</div>' : ''}
        </div>
      </div>
    </div>`;
  }

  function renderNarrative(data) {
    const narrative = data.explanation?.attack_narrative || 'No narrative generated.';
    const notes     = data.explanation?.analyst_notes    || [];
    const mitre     = data.explanation?.mitre_explanation || [];
    const noteIcons = { action: 'exclamation-triangle', warning: 'exclamation-circle', investigation: 'search', context: 'info-circle' };

    return `
    <div class="eti-animate-in">
      <div class="eti-section-card">
        <div class="eti-section-card-header">
          <div class="eti-section-card-title"><i class="fas fa-book-open"></i> AI-Generated Attack Narrative</div>
          <i class="fas fa-chevron-down eti-section-card-chevron"></i>
        </div>
        <div class="eti-section-card-body">
          <div class="eti-narrative">${narrative.replace(/\n/g, '<br>')}</div>
        </div>
      </div>

      ${notes.length ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-clipboard-list"></i> Analyst Action Notes</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-analyst-notes">
              ${notes.map(n => `
                <div class="eti-analyst-note ${n.type}">
                  <i class="fas fa-${noteIcons[n.type] || 'info'} eti-analyst-note-icon"></i>
                  ${n.note}
                </div>`).join('')}
            </div>
          </div>
        </div>` : ''}

      ${mitre.length ? `
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-shield-virus"></i> MITRE ATT&amp;CK Explanation</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            ${mitre.map(t => `
              <div style="margin-bottom:12px;padding:10px 12px;background:rgba(191,90,242,0.07);border:1px solid rgba(191,90,242,0.2);border-radius:6px;">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
                  <span style="font-size:12px;font-weight:700;font-family:monospace;color:#BF5AF2">${t.sub_technique_id || t.technique_id}</span>
                  <span style="font-size:11px;font-weight:600;color:var(--eti-text-primary)">${t.name}</span>
                  <span style="font-size:10px;color:var(--eti-text-tertiary);margin-left:auto">${t.tactic} · ${t.confidence}%</span>
                </div>
                <div style="font-size:11px;color:var(--eti-text-secondary)">${t.explanation}</div>
              </div>`).join('')}
          </div>
        </div>` : ''}
    </div>`;
  }

  // ── Right Panel Updates ────────────────────────────────────────────────────
  function updateRightPanel(data) {
    updateRiskBreakdown(data.risk);
    updateResponseActions(data);
    updateIndicators(data);
  }

  function updateRiskBreakdown(risk) {
    const container = document.getElementById('etiRiskBreakdown');
    if (!container) return;
    const bd = risk.breakdown || {};
    const dims = [
      { label: 'Authentication',    score: bd.auth?.score        || 0, max: 30 },
      { label: 'Detection Rules',   score: bd.rules?.score       || 0, max: 55 },
      { label: 'AI Analysis',       score: bd.ai?.score          || 0, max: 35 },
      { label: 'Threat Intel',      score: bd.threat_intel?.score|| 0, max: 60 },
      { label: 'Sender Anomalies',  score: bd.sender?.score      || 0, max: 30 },
      { label: 'Social Eng.',       score: bd.social_eng?.score  || 0, max: 35 },
      { label: 'Attachments',       score: bd.attachments?.score || 0, max: 50 },
      { label: 'URLs',              score: bd.urls?.score        || 0, max: 40 }
    ].filter(d => d.score > 0 || d.label === 'Detection Rules');

    const getColor = (pct) =>
      pct > 70 ? 'var(--eti-critical)' : pct > 40 ? 'var(--eti-high)' : pct > 15 ? 'var(--eti-medium)' : 'var(--eti-low)';

    container.innerHTML = dims.map(d => {
      const pct   = Math.round((d.score / d.max) * 100);
      const color = getColor(pct);
      return `<div class="eti-risk-dimension">
        <div class="eti-risk-dim-label">${d.label}</div>
        <div class="eti-risk-bar-track">
          <div class="eti-risk-bar-fill" style="width:${Math.min(pct, 100)}%;background:${color};"></div>
        </div>
        <div class="eti-risk-dim-score" style="color:${color}">${d.score}</div>
      </div>`;
    }).join('') +
    `<div style="margin-top:8px;padding:8px;background:rgba(255,255,255,0.03);border-radius:6px;text-align:center;">
       <div style="font-size:10px;color:var(--eti-text-tertiary)">Risk Amplifier</div>
       <div style="font-size:16px;font-weight:700;color:var(--eti-accent-blue)">×${risk.amplifier || 1.0}</div>
       <div style="font-size:10px;color:var(--eti-text-tertiary)">${(bd.amplifier?.applied || []).join(', ') || 'none'}</div>
     </div>`;
  }

  function updateResponseActions(data) {
    const container = document.getElementById('etiResponseActions');
    if (!container) return;
    const executed = data.response?.executed_actions || [];
    const pending  = data.response?.pending_actions  || [];

    const actionDefs = [
      { type: 'quarantine_email', label: 'Quarantine Email',  icon: 'lock',       iconColor: 'red',    danger: true  },
      { type: 'block_sender',     label: 'Block Sender',      icon: 'ban',        iconColor: 'orange', danger: true  },
      { type: 'block_domain',     label: 'Block Domain',      icon: 'globe',      iconColor: 'orange', danger: false },
      { type: 'notify_soc',       label: 'Notify SOC Team',   icon: 'bell',       iconColor: 'blue',   danger: false },
      { type: 'create_incident',  label: 'Create Incident',   icon: 'ticket-alt', iconColor: 'purple', danger: false },
      { type: 'scan_mailbox',     label: 'Scan Mailbox',      icon: 'search',     iconColor: 'blue',   danger: false }
    ];

    container.innerHTML = actionDefs.map(a => {
      const isExecuted = executed.some(e => e.type === a.type);
      const isPending  = pending.some(p  => p.type === a.type);
      const status     = isExecuted ? 'EXECUTED' : isPending ? 'PENDING' : '';
      const statusColor= isExecuted ? 'var(--eti-low)' : 'var(--eti-medium)';
      return `<button class="eti-action-btn ${a.danger ? 'action-critical' : ''}"
          onclick="window.ETIModule.executeAction('${a.type}')">
        <div class="action-icon ${a.iconColor}"><i class="fas fa-${a.icon}"></i></div>
        <span style="flex:1">${a.label}</span>
        ${status ? `<span class="action-status" style="color:${statusColor}">${status}</span>` : ''}
      </button>`;
    }).join('');
  }

  function updateIndicators(data) {
    const container = document.getElementById('etiIndicatorsList');
    if (!container) return;
    container.innerHTML = renderIOCList(data.email?.indicators || {});
  }

  // ── Email Queue ────────────────────────────────────────────────────────────
  function updateEmailQueue() {
    const container = document.getElementById('etiEmailQueue');
    const counter   = document.getElementById('etiQueueCount');
    if (!container) return;
    if (counter) counter.textContent = `(${state.analysisHistory.length})`;

    const tierColors = { critical: 'var(--eti-critical)', high: 'var(--eti-high)', medium: 'var(--eti-medium)', low: 'var(--eti-low)', clean: 'var(--eti-low)' };
    container.innerHTML = state.analysisHistory.slice(0, 20).map((d, i) => {
      const tier  = d.risk?.tier  || 'unknown';
      const score = d.risk?.final_score || 0;
      return `<div class="eti-email-item risk-${tier} ${i === 0 ? 'selected' : ''}"
          onclick="window.ETIModule.selectAnalysis(${i})">
        <div class="eti-email-item-left"></div>
        <div class="eti-email-item-header">
          <div class="eti-email-from">${d.email?.from || 'unknown'}</div>
          <div class="eti-email-tier-badge ${tier}">${tier}</div>
        </div>
        <div class="eti-email-subject">${d.email?.subject || '(no subject)'}</div>
        <div class="eti-email-meta">
          <div class="eti-email-meta-chip">${d.detection?.rules_triggered?.length || 0} rules</div>
          ${d.email?.attachment_count > 0 ? `<div class="eti-email-meta-chip"><i class="fas fa-paperclip"></i> ${d.email.attachment_count}</div>` : ''}
          <div class="eti-email-score-mini" style="color:${tierColors[tier] || 'var(--eti-text-tertiary)'}">${score}</div>
        </div>
      </div>`;
    }).join('');
  }

  // ── Statistics ─────────────────────────────────────────────────────────────
  function updateStats(data) {
    state.stats.total++;
    if (data.risk?.tier === 'critical') state.stats.critical++;
    if (data.risk?.tier === 'high')     state.stats.high++;
    if (data.risk?.tier === 'clean')    state.stats.clean++;

    const s = state.stats;
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('etiStatTotal',    s.total);
    set('etiStatCritical', s.critical);
    set('etiStatHigh',     s.high);
    set('etiStatClean',    s.clean);
  }

  async function loadInitialStats() {
    try {
      const result = await API.getStats();
      if (result && result.success && result.data) {
        const d = result.data;
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('etiStatTotal',    d.total_analyzed       || 0);
        set('etiStatCritical', d.by_tier?.critical    || 0);
        set('etiStatHigh',     d.by_tier?.high        || 0);
        set('etiStatClean',    d.by_tier?.clean       || 0);
      }
    } catch { /* stats not critical */ }
  }

  // ── UI Helpers ─────────────────────────────────────────────────────────────
  function showAnalyzing(visible) {
    state.analyzing = visible;
    const overlay = document.getElementById('etiAnalyzingOverlay');
    if (overlay) overlay.classList.toggle('active', visible);
    if (!visible) {
      // RC-FIX v4.0: Scope to container to avoid conflicts with other pages
      const scope = state.container || document;
      scope.querySelectorAll('.eti-analyzing-step').forEach(s => {
        s.classList.remove('active', 'done');
      });
    }
  }

  function animateAnalyzingSteps() {
    // RC-FIX v4.0: Scope to container
    const scope = state.container || document;
    const steps = scope.querySelectorAll('.eti-analyzing-step');
    let i = 0;
    const iv = setInterval(() => {
      if (i > 0 && steps[i - 1]) steps[i - 1].classList.replace('active', 'done');
      if (i < steps.length) { steps[i].classList.add('active'); i++; }
      else clearInterval(iv);
    }, 180);
  }

  function showToast(title, message, type = 'info') {
    const container = document.getElementById('etiToastContainer');
    if (!container) return;

    const icons = { critical: '🚨', error: '❌', success: '✅', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `eti-toast ${type}`;
    toast.innerHTML = `
      <div class="eti-toast-icon">${icons[type] || 'ℹ️'}</div>
      <div class="eti-toast-text">
        <div class="eti-toast-title">${title}</div>
        <div class="eti-toast-msg">${message}</div>
      </div>
      <button onclick="this.parentElement.remove()"
        style="background:none;border:none;color:var(--eti-text-tertiary);cursor:pointer;padding:4px;font-size:14px;">✕</button>`;
    container.appendChild(toast);
    setTimeout(() => { if (toast.parentElement) toast.remove(); }, 5000);
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  return {
    // Core lifecycle
    mount,
    onShow,
    _checkHealth: checkBackendHealth,

    // User interactions
    runDemo,
    analyzeEmail,

    selectAnalysis(index) {
      const data = state.analysisHistory[index];
      if (!data) return;
      state.currentAnalysis = data;
      document.querySelectorAll('.eti-email-item').forEach((el, i) =>
        el.classList.toggle('selected', i === index));
      renderAnalysisView(data);
      updateRightPanel(data);
    },

    executeAction(type) {
      showToast('Action Initiated', `${type.replace(/_/g, ' ')} submitted to SOAR engine`, 'success');
    },

    openIncidents() {
      showToast('Incidents', 'Opening incident management…', 'info');
      if (typeof window.navigateTo === 'function') {
        setTimeout(() => window.navigateTo('case-management'), 800);
      }
    },

    openBlocklists() {
      showToast('Blocklists', 'Opening IOC database…', 'info');
      if (typeof window.navigateTo === 'function') {
        setTimeout(() => window.navigateTo('ioc-database'), 800);
      }
    }
  };

})();

// Export globally — PAGE_CONFIG and BRAIN_MODULES both reference window.ETIModule
window.ETIModule = ETIModule;

/*
 * NOTE: Auto-init (DOMContentLoaded) intentionally removed.
 * The module is now mounted exclusively via navigateTo('email-threat')
 * → PAGE_CONFIG['email-threat'].onEnter → ETIModule.mount(container)
 * This matches the platform's .page container pattern and prevents
 * the module from injecting itself into document.body on page load.
 */
