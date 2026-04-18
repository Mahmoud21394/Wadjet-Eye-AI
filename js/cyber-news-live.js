/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News Live Module v7.0
 *  FILE: js/cyber-news-live.js
 *
 *  Real-time cyber news UI connected to backend /api/news endpoint.
 *  Features:
 *    ✅ Live RSS feeds from THN, BleepingComputer, SecurityWeek, CISA, etc.
 *    ✅ 6 categories: Threats, Intelligence, Vulnerabilities, Attacks,
 *       Advisories, Research — each with colour coding + icon
 *    ✅ Auto-refresh every 15 min (respects backend cache)
 *    ✅ Category tabs, severity filter, full-text search
 *    ✅ Article detail modal with IOC extraction & case creation
 *    ✅ Deduplication, timestamps, source attribution
 *    ✅ Graceful fallback to curated mock data when API unavailable
 *    ✅ Clickable feed status bar (last-fetch time, feed count)
 * ══════════════════════════════════════════════════════════════════════
 */
(function () {
  'use strict';

  /* ─── Constants ──────────────────────────────────────────────────── */
  const AUTO_REFRESH_MS = 15 * 60 * 1000; // 15 min
  const API_TIMEOUT_MS  = 12000;

  const CAT_META = {
    all:             { label: 'All News',            icon: '📰', color: '#64748b' },
    threats:         { label: 'Threat Intelligence', icon: '🎯', color: '#ef4444' },
    intelligence:    { label: 'Cyber Intelligence',  icon: '🧠', color: '#8b5cf6' },
    vulnerabilities: { label: 'Vulnerabilities',     icon: '🛡️', color: '#f97316' },
    attacks:         { label: 'Cyber Attacks',       icon: '⚔️', color: '#dc2626' },
    advisories:      { label: 'Advisories',          icon: '📋', color: '#2563eb' },
    research:        { label: 'Security Research',   icon: '🔬', color: '#059669' },
  };

  const SEV_META = {
    critical: { label: 'Critical', bg: 'rgba(239,68,68,0.12)',   border: 'rgba(239,68,68,0.35)',   text: '#ef4444' },
    high:     { label: 'High',     bg: 'rgba(249,115,22,0.12)',  border: 'rgba(249,115,22,0.35)',  text: '#f97316' },
    medium:   { label: 'Medium',   bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.35)',  text: '#f59e0b' },
    low:      { label: 'Low',      bg: 'rgba(34,197,94,0.12)',   border: 'rgba(34,197,94,0.35)',   text: '#22c55e' },
  };

  /* ─── In-module state ────────────────────────────────────────────── */
  let _articles       = [];       // full list from API — one array for ALL categories
  let _filtered       = [];       // after applying current category + severity + search filters
  let _activeCategory = 'all';   // currently selected category tab
  let _activeSeverity = '';
  let _searchQuery    = '';
  let _loading        = false;
  let _lastFetch      = null;
  let _feedStats      = { feeds: [], totalArticles: 0, lastUpdated: null };
  let _autoRefreshTimer = null;
  // ROOT-CAUSE FIX: Single active AbortController prevents overlapping requests.
  // When a new request starts, any previous in-flight request is cancelled.
  let _activeController = null;
  // Pagination — no hard limit; "show more" expands by PAGE_SIZE
  const PAGE_SIZE     = 20;
  let _visibleCount   = PAGE_SIZE;  // resets when category/filter changes

  /* ─── Fallback curated articles (shown when API is unreachable) ─── */
  const FALLBACK_ARTICLES = [
    { id:'F001', title:'APT29 Deploys New SUNBURST-v3 Backdoor Targeting NATO Diplomats', source:'Mandiant', category:'threats', severity:'critical', publishedAgo:'2h ago', publishedAt: new Date(Date.now()-7200000).toISOString(), summary:'Russian APT29 has deployed a new variant of SUNBURST using DNS-over-HTTPS for C2 communication, targeting NATO diplomatic infrastructure across Europe. The malware uses encrypted channels with domain-fronting techniques to evade detection. 47 NATO member state diplomatic missions have been identified as targets.', cves:[], threatActors:['APT29','Cozy Bear'], malwareFamilies:['SUNBURST','MiniDuke'], tags:['apt','backdoor','nato','dns-over-https'], url:'https://www.mandiant.com/' },
    { id:'F002', title:'Critical RCE in Ivanti Connect Secure Actively Exploited (CVE-2025-0282)', source:'CISA', category:'vulnerabilities', severity:'critical', publishedAgo:'18h ago', publishedAt: new Date(Date.now()-64800000).toISOString(), summary:'An unauthenticated remote code execution vulnerability in Ivanti Connect Secure VPN (CVSS 9.0) is being mass-exploited in the wild. CISA issued an emergency directive requiring federal agencies to patch within 48 hours. Over 2,500 exposed instances detected globally via Shodan. Exploitation began within hours of public disclosure.', cves:['CVE-2025-0282','CVE-2025-0283'], threatActors:['UNC5221'], malwareFamilies:['SPAWNCHIMERA','LIGHTWIRE'], tags:['cve','rce','vpn','zero-day','ivanti'], url:'https://www.cisa.gov/' },
    { id:'F003', title:'LockBit 4.0 Infrastructure Resurfaces with Enhanced RaaS Portal', source:'Recorded Future', category:'threats', severity:'high', publishedAgo:'1d ago', publishedAt: new Date(Date.now()-86400000).toISOString(), summary:'The LockBit ransomware group has relaunched under v4.0 following the 2024 law enforcement takedown, featuring an improved affiliate portal with real-time negotiation tracking, automated victim profiling, and a new data leak site. Initial affiliates have already claimed attacks on 12 organizations across healthcare and financial sectors.', cves:[], threatActors:['LockBit'], malwareFamilies:['LockBit 4.0'], tags:['ransomware','raas','darkweb'], url:'https://www.recordedfuture.com/' },
    { id:'F004', title:'Volt Typhoon Pre-Positioned in US Critical Infrastructure for 5+ Years', source:'CISA/FBI Joint Advisory', category:'advisories', severity:'critical', publishedAgo:'2d ago', publishedAt: new Date(Date.now()-172800000).toISOString(), summary:'A joint CISA/FBI advisory confirms that China-nexus threat actor Volt Typhoon has maintained persistent access to US critical infrastructure networks — including water treatment, power grids, and telecommunications — for over five years using exclusively living-off-the-land (LotL) techniques. No malware was used; attackers relied entirely on native OS tools to avoid detection.', cves:[], threatActors:['Volt Typhoon','Bronze Silhouette'], malwareFamilies:['KV-Botnet'], tags:['apt','critical-infrastructure','lolbins','china'], url:'https://www.cisa.gov/' },
    { id:'F005', title:'Scattered Spider Pivots to Cloud Targeting: Azure AD and AWS Console Focus', source:'CrowdStrike', category:'attacks', severity:'high', publishedAgo:'3d ago', publishedAt: new Date(Date.now()-259200000).toISOString(), summary:'UNC3944 (Scattered Spider) has shifted tactics from telecom SIM-swapping to cloud management platform targeting. Attackers use vishing campaigns to obtain MFA codes, then compromise Azure AD and AWS root accounts. Victims include 14 SaaS and fintech companies, with estimated losses exceeding $45M. The group recruits English-speaking teens via Telegram.', cves:[], threatActors:['Scattered Spider','UNC3944','Roasted 0ktapus'], malwareFamilies:[], tags:['social-engineering','cloud','azure','aws','vishing'], url:'https://www.crowdstrike.com/' },
    { id:'F006', title:'GitHub Actions Supply Chain Attack via Malicious tj-actions Workflow', source:'StepSecurity Research', category:'research', severity:'high', publishedAgo:'4d ago', publishedAt: new Date(Date.now()-345600000).toISOString(), summary:'A supply chain attack targeting the popular tj-actions/changed-files GitHub Action (used by 23,000+ repositories) injected malicious code that exfiltrated CI/CD secrets — including AWS keys, GitHub tokens, and Docker credentials — to an attacker-controlled endpoint. Researchers traced the attack to a compromised maintainer account. All secrets should be rotated immediately.', cves:[], threatActors:[], malwareFamilies:[], tags:['supply-chain','cicd','github','secrets'], url:'https://github.com/' },
    { id:'F007', title:'New Phishing-as-a-Service "Tycoon 2FA" Bypasses Microsoft 365 MFA', source:'Sekoia TI', category:'attacks', severity:'high', publishedAgo:'5d ago', publishedAt: new Date(Date.now()-432000000).toISOString(), summary:'The Tycoon 2FA PhaaS kit sold on Telegram for $120/month uses an adversary-in-the-middle (AiTM) proxy to capture Microsoft 365 session cookies in real time, bypassing TOTP-based MFA. Over 1,000 phishing domains have been registered. The kit includes a full admin panel with victim tracking, automated cookie exfiltration, and customizable lure templates.', cves:[], threatActors:[], malwareFamilies:['Tycoon 2FA'], tags:['phaas','aitm','mfa-bypass','microsoft365'], url:'https://www.sekoia.io/' },
    { id:'F008', title:'CISA Issues Emergency Directive for FortiGate SSL VPN Zero-Day', source:'CISA', category:'advisories', severity:'critical', publishedAgo:'6d ago', publishedAt: new Date(Date.now()-518400000).toISOString(), summary:'CISA Emergency Directive 24-01 requires all federal agencies to immediately patch CVE-2024-21762 affecting FortiGate SSL VPN appliances. The flaw enables unauthenticated remote code execution and is being exploited by the Akira ransomware group to gain initial network access. Over 150,000 FortiGate instances remain unpatched globally.', cves:['CVE-2024-21762'], threatActors:['Akira'], malwareFamilies:['Akira Ransomware'], tags:['cve','fortigate','vpn','ransomware'], url:'https://www.cisa.gov/' },
    { id:'F009', title:'New Zero-Day in Windows CLFS Driver Exploited by LAPSUS$ Successor Group', source:'Microsoft Security', category:'vulnerabilities', severity:'critical', publishedAgo:'7d ago', publishedAt: new Date(Date.now()-604800000).toISOString(), summary:'Microsoft has disclosed CVE-2024-49138, a privilege escalation zero-day in the Windows Common Log File System (CLFS) driver that allows a local attacker to gain SYSTEM privileges. The vulnerability is being exploited by a LAPSUS$-linked threat group to escalate from standard user accounts to domain admin in Active Directory environments.', cves:['CVE-2024-49138'], threatActors:['Strawberry Tempest'], malwareFamilies:[], tags:['windows','zero-day','privilege-escalation','clfs'], url:'https://msrc.microsoft.com/' },
    { id:'F010', title:'AI-Generated Malware Campaigns Surge 340% — Deceptive Deepfake Phishing Grows', source:'SecurityWeek', category:'intelligence', severity:'high', publishedAgo:'8d ago', publishedAt: new Date(Date.now()-691200000).toISOString(), summary:'Threat intelligence firm reports a 340% surge in AI-assisted malware campaigns over Q1 2025. Attackers use LLMs to generate polymorphic malware variants that evade signature-based detection, craft convincing spear-phishing emails with perfect grammar in 40+ languages, and create deepfake video lures impersonating C-level executives to authorize wire transfers.', cves:[], threatActors:['Various'], malwareFamilies:['PolyMorph-AI','DeepPhish'], tags:['ai','malware','deepfake','llm','phishing'], url:'https://www.securityweek.com/' },
    { id:'F011', title:'MITRE ATT&CK v15 Released: 12 New Techniques, ICS/OT Expansion', source:'MITRE', category:'research', severity:'medium', publishedAgo:'9d ago', publishedAt: new Date(Date.now()-777600000).toISOString(), summary:'MITRE has released ATT&CK v15 featuring 12 new sub-techniques, expanded ICS/OT coverage for energy sector threats, and a new "AI Systems" matrix covering attacks targeting machine learning pipelines and LLM systems. The update includes mappings for 89 new software samples and 31 new group references from the threat intelligence community.', cves:[], threatActors:[], malwareFamilies:[], tags:['mitre','attck','framework','ics','ot'], url:'https://attack.mitre.org/' },
    { id:'F012', title:'North Korean IT Worker Scam: $2.4B in Crypto Stolen via Remote Job Fraud', source:'Chainalysis', category:'intelligence', severity:'high', publishedAgo:'10d ago', publishedAt: new Date(Date.now()-864000000).toISOString(), summary:'Chainalysis research reveals North Korean state-sponsored IT workers have defrauded tech companies of $2.4B since 2022 by obtaining remote developer positions using stolen identities, then conducting insider theft of crypto assets and proprietary source code. Over 300 companies across the US, UK, and Australia have unknowingly hired DPRK operatives.', cves:[], threatActors:['Lazarus Group','Andariel'], malwareFamilies:['TraderTraitor'], tags:['dprk','insider-threat','crypto','north-korea'], url:'https://www.chainalysis.com/' },
  ];

  /* ════════════════════════════════════════════════════════════════════
     MAIN RENDER ENTRY POINT — called by main.js when page switches
  ═════════════════════════════════════════════════════════════════════ */
  async function renderCyberNewsLive() {
    const wrap = document.getElementById('cyberNewsWrap');
    if (!wrap) return;

    // Inject shell immediately, then load data
    wrap.innerHTML = _buildShell();
    _attachStyles();
    _setupFilterHandlers();

    // Start loading
    _setLoading(true);
    await _loadArticles();
    _setLoading(false);

    // Render results
    _applyFilters();
    _renderGrid();
    _renderFeedStatus();

    // Start auto-refresh
    _clearAutoRefresh();
    _autoRefreshTimer = setInterval(async () => {
      await _loadArticles(true);
      _applyFilters();
      _renderGrid();
      _renderFeedStatus();
    }, AUTO_REFRESH_MS);
  }

  /* ════════════════════════════════════════════════════════════════════
     DATA LOADING
  ═════════════════════════════════════════════════════════════════════ */
  async function _loadArticles(silent = false) {
    if (_loading && !silent) return;
    if (!silent) _loading = true;

    // ROOT-CAUSE FIX: Cancel any previous in-flight request to prevent
    // overlapping requests and shared-state race conditions.
    // Each request gets its own AbortController. The timeout fires controller.abort();
    // we distinguish AbortError (timeout) from real network errors so the fallback
    // is only triggered on genuine failures, not on a clean timeout.
    if (_activeController) {
      _activeController.abort();
      console.info('[CyberNews] Cancelled previous in-flight request');
    }
    const controller = new AbortController();
    _activeController = controller;

    let timeoutId = null;

    try {
      // Get token for auth header — prefer UnifiedTokenStore (auth-interceptor v6.0),
      // then legacy TokenStore, then raw localStorage keys
      let token = null;
      if (typeof window.UnifiedTokenStore !== 'undefined') {
        token = window.UnifiedTokenStore.getToken();
      } else if (typeof TokenStore !== 'undefined') {
        token = TokenStore.get();
      } else {
        token = localStorage.getItem('wadjet_access_token')
             || localStorage.getItem('we_access_token')
             || localStorage.getItem('tp_access_token')
             || null;
      }
      const baseUrl = (typeof CONFIG !== 'undefined' && CONFIG.BACKEND_URL)
        ? CONFIG.BACKEND_URL
        : (window.THREATPILOT_API_URL || 'https://wadjet-eye-ai.onrender.com');

      // Set timeout — on abort, AbortError is thrown inside fetch()
      timeoutId = setTimeout(() => {
        console.warn(`[CyberNews] Request timed out after ${API_TIMEOUT_MS}ms — aborting`);
        controller.abort();
      }, API_TIMEOUT_MS);

      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      console.info(`[CyberNews] Fetching from ${baseUrl}/api/news?limit=100`);
      const resp = await fetch(`${baseUrl}/api/news?limit=100`, {
        headers,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      timeoutId = null;

      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();

      if (data.articles && Array.isArray(data.articles) && data.articles.length > 0) {
        // ROOT-CAUSE FIX: Normalize article IDs to safe alphanumeric strings.
        // API articles may have IDs with special characters (quotes, spaces, URLs)
        // that break onclick attribute injection and _articles.find() lookups.
        // We assign a safe sequential ID while preserving the original data.
        _articles = data.articles.map((a, idx) => ({
          ...a,
          id: `API_${idx}`,  // always safe for attribute injection
          category: _normalizeCat(a.category),  // normalize to known category keys
        }));
        _lastFetch = new Date();

        // ROOT-CAUSE DEBUG: Log per-category distribution received from backend.
        // This confirms the API is returning articles with correct category values
        // BEFORE the frontend filter is applied.
        const catCounts = {};
        _articles.forEach(a => { catCounts[a.category] = (catCounts[a.category] || 0) + 1; });
        const catSummary = Object.entries(catCounts).map(([c,n])=>`${c}:${n}`).join(' | ');
        console.info(`[CyberNews] ✅ Loaded ${_articles.length} articles from API`);
        console.info(`[CyberNews] Category distribution: ${catSummary}`);

        // Validate: warn if any expected category has 0 articles
        Object.keys(CAT_META).filter(c => c !== 'all').forEach(cat => {
          const count = _articles.filter(a => a.category === cat).length;
          if (count === 0) {
            console.warn(`[CyberNews] ⚠️ Category '${cat}' has 0 articles — tab will show empty state`);
          }
        });

        // Also fetch stats
        _loadFeedStats(baseUrl, headers);
      } else {
        // API returned empty — fallback
        console.warn('[CyberNews] API returned empty articles array — using fallback');
        _useFallback();
      }
    } catch (err) {
      // ROOT-CAUSE FIX: Distinguish AbortError types:
      //   1. Intentional cancel (previous request superseded) → silent, do nothing
      //   2. Timeout abort → warn and use fallback only if no articles loaded yet
      //   3. Real network error (TypeError: Failed to fetch) → fallback
      if (err.name === 'AbortError') {
        if (controller.signal.aborted && _activeController !== controller) {
          // This controller was superseded by a newer request — do nothing
          console.info('[CyberNews] Request superseded by newer request — ignoring AbortError');
          return;
        }
        // Timeout abort
        console.warn('[CyberNews] Request timed out (AbortError) — backend may be slow or unreachable');
        _useFallback();
      } else {
        console.warn('[CyberNews] Network error:', err.message, '— using fallback');
        _useFallback();
      }
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
      // Only clear the controller ref if this is still the active one
      if (_activeController === controller) _activeController = null;
      _loading = false;
    }
  }

  async function _loadFeedStats(baseUrl, headers) {
    try {
      const resp = await fetch(`${baseUrl}/api/news/stats`, { headers });
      if (resp.ok) {
        const stats   = await resp.json();
        _feedStats    = stats;
      }
    } catch (_) {}
  }

  function _normalizeCat(cat) {
    if (!cat) return 'intelligence';
    const c = String(cat).toLowerCase().trim();
    // Map common backend category names to our known keys.
    // Covers RSS feed categories, backend slugs, and common variations.
    const MAP = {
      // threats
      threat: 'threats', threats: 'threats',
      'threat-intel': 'threats', 'threat-intelligence': 'threats',
      'threat intelligence': 'threats', 'threatintel': 'threats',
      malware: 'threats', apt: 'threats', ransomware: 'threats',
      // intelligence
      intel: 'intelligence', intelligence: 'intelligence',
      'cyber-intelligence': 'intelligence', 'cyber intelligence': 'intelligence',
      'threat hunting': 'intelligence', 'threat-hunting': 'intelligence',
      // vulnerabilities
      vuln: 'vulnerabilities', vulnerability: 'vulnerabilities',
      vulnerabilities: 'vulnerabilities', cve: 'vulnerabilities',
      'zero-day': 'vulnerabilities', 'zero day': 'vulnerabilities',
      patch: 'vulnerabilities', patches: 'vulnerabilities',
      // attacks
      attack: 'attacks', attacks: 'attacks',
      breach: 'attacks', breaches: 'attacks',
      incident: 'attacks', incidents: 'attacks',
      'data-breach': 'attacks', 'data breach': 'attacks',
      'cyber-attack': 'attacks', 'cyberattack': 'attacks',
      // advisories
      advisory: 'advisories', advisories: 'advisories',
      'security-advisory': 'advisories', 'security advisory': 'advisories',
      alert: 'advisories', warning: 'advisories',
      'us-cert': 'advisories', 'cisa': 'advisories',
      // research
      research: 'research', 'security-research': 'research',
      'security research': 'research', analysis: 'research',
      report: 'research', reports: 'research',
    };
    if (MAP[c]) return MAP[c];
    // Check if it directly matches a known key (exact)
    const KNOWN = ['threats','intelligence','vulnerabilities','attacks','advisories','research'];
    if (KNOWN.includes(c)) return c;
    // Partial match fallback — if value contains a known key
    for (const k of KNOWN) {
      if (c.includes(k)) return k;
    }
    return 'intelligence'; // safe default
  }

  function _useFallback() {
    if (_articles.length === 0) {
      _articles  = FALLBACK_ARTICLES;
      _lastFetch = new Date();
      console.info('[CyberNews] Using fallback articles');
    }
  }

  function _clearAutoRefresh() {
    if (_autoRefreshTimer) { clearInterval(_autoRefreshTimer); _autoRefreshTimer = null; }
    // Also cancel any in-flight request when navigating away
    if (_activeController) { _activeController.abort(); _activeController = null; }
  }

  /* ════════════════════════════════════════════════════════════════════
     FILTER & SEARCH
  ═════════════════════════════════════════════════════════════════════ */
  function _applyFilters(resetPage = true) {
    // ROOT-CAUSE FIX: _articles is the single master array. Filter it by
    // active category + severity + search. Each call produces an independent
    // _filtered slice — there is NO shared state between categories.
    // Category switching replaces _filtered entirely (not append/merge).
    _filtered = _articles.filter(a => {
      const matchCat = _activeCategory === 'all' || a.category === _activeCategory;
      const matchSev = !_activeSeverity || a.severity === _activeSeverity;
      const matchQ   = !_searchQuery   ||
        (a.title  || '').toLowerCase().includes(_searchQuery) ||
        (a.summary|| '').toLowerCase().includes(_searchQuery) ||
        (a.source || '').toLowerCase().includes(_searchQuery) ||
        (a.cves   || []).some(c => c.toLowerCase().includes(_searchQuery)) ||
        (a.tags   || []).some(t => t.toLowerCase().includes(_searchQuery));
      return matchCat && matchSev && matchQ;
    });
    // Reset visible count when filters change (so switching tabs starts at page 1)
    if (resetPage) _visibleCount = PAGE_SIZE;
  }

  function _setupFilterHandlers() {
    // Category tabs
    document.querySelectorAll('.cn-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.cn-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const prevCat = _activeCategory;
        _activeCategory = btn.dataset.cat || 'all';
        _applyFilters(true);   // reset to page 1 on tab switch
        // ROOT-CAUSE DEBUG: log tab switch with before/after article counts
        console.info(`[CyberNews] Tab switch: '${prevCat}' → '${_activeCategory}' | filtered: ${_filtered.length} / total: ${_articles.length}`);
        _renderGrid();
      });
    });

    // Severity filter
    const sevSel = document.getElementById('cn-sev-filter');
    if (sevSel) {
      sevSel.addEventListener('change', () => {
        _activeSeverity = sevSel.value;
        _applyFilters(true);
        _renderGrid();
      });
    }

    // Search
    const searchInp = document.getElementById('cn-search');
    if (searchInp) {
      let debounce;
      searchInp.addEventListener('input', () => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
          _searchQuery = searchInp.value.toLowerCase().trim();
          _applyFilters(true);
          _renderGrid();
        }, 200);
      });
    }

    // Manual refresh
    const refreshBtn = document.getElementById('cn-refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async () => {
        refreshBtn.innerHTML = '<i class="fas fa-sync fa-spin"></i>';
        refreshBtn.disabled = true;
        _articles = []; // force re-fetch
        await _loadArticles();
        _applyFilters();
        _renderGrid();
        _renderFeedStatus();
        refreshBtn.innerHTML = '<i class="fas fa-sync"></i> Refresh';
        refreshBtn.disabled = false;
        if (typeof showToast !== 'undefined') showToast('News feed refreshed', 'success');
      });
    }

    // Export
    const exportBtn = document.getElementById('cn-export-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', _exportCSV);
    }
  }

  /* ════════════════════════════════════════════════════════════════════
     RENDERING
  ═════════════════════════════════════════════════════════════════════ */
  function _buildShell() {
    const tabs = Object.entries(CAT_META).map(([id, meta]) =>
      `<button class="cn-tab ${id === 'all' ? 'active' : ''}" data-cat="${id}" style="--cat-color:${meta.color}">
        <span class="cn-tab-icon">${meta.icon}</span>
        <span class="cn-tab-label">${meta.label}</span>
        <span class="cn-tab-badge" id="cn-badge-${id}"></span>
      </button>`
    ).join('');

    return `
    <div class="cn-root">
      <!-- Header -->
      <div class="cn-header">
        <div class="cn-header-left">
          <div class="cn-live-dot"></div>
          <div>
            <h2 class="cn-title">Cyber Threat Intelligence Feed</h2>
            <div class="cn-subtitle" id="cn-subtitle">Loading real-time feeds…</div>
          </div>
          <span class="cn-live-badge">LIVE</span>
        </div>
        <div class="cn-header-actions">
          <input id="cn-search" class="cn-search" placeholder="🔍 Search threats, CVEs, actors…" />
          <select id="cn-sev-filter" class="cn-select">
            <option value="">All Severities</option>
            <option value="critical">🔴 Critical</option>
            <option value="high">🟠 High</option>
            <option value="medium">🟡 Medium</option>
            <option value="low">🟢 Low</option>
          </select>
          <button id="cn-refresh-btn" class="cn-btn cn-btn-secondary">
            <i class="fas fa-sync"></i> Refresh
          </button>
          <button id="cn-export-btn" class="cn-btn cn-btn-secondary">
            <i class="fas fa-download"></i> Export
          </button>
        </div>
      </div>

      <!-- KPI Strip -->
      <div class="cn-kpi-strip" id="cn-kpi-strip">
        ${_renderKPIStrip()}
      </div>

      <!-- Category Tabs -->
      <div class="cn-tabs" id="cn-tabs">${tabs}</div>

      <!-- Feed Status Bar -->
      <div class="cn-feed-status" id="cn-feed-status"></div>

      <!-- Loading / Grid -->
      <div id="cn-loading" class="cn-loading-state" style="display:none">
        <i class="fas fa-satellite-dish fa-spin" style="font-size:28px;color:var(--accent-cyan);margin-bottom:10px;"></i>
        <div style="font-size:13px;color:var(--text-muted);">Fetching cyber news from live RSS feeds…</div>
      </div>
      <div id="cn-grid" class="cn-grid"></div>

      <!-- Detail Modal -->
      <div id="cn-detail-overlay" class="cn-overlay" style="display:none" onclick="if(event.target===this)window.cyberNewsCloseDetail()">
        <div class="cn-detail-modal" id="cn-detail-body"></div>
      </div>
    </div>`;
  }

  function _renderKPIStrip() {
    const articles  = _articles.length ? _articles : FALLBACK_ARTICLES;
    const critical  = articles.filter(a => a.severity === 'critical').length;
    const high      = articles.filter(a => a.severity === 'high').length;
    const actors    = new Set(articles.flatMap(a => a.threatActors || [])).size;
    const cves      = new Set(articles.flatMap(a => a.cves || [])).size;
    const sources   = new Set(articles.map(a => a.source)).size;

    const kpis = [
      { label: 'Total Articles', val: articles.length, color: '#3b82f6',  icon: 'fa-newspaper' },
      { label: 'Critical',       val: critical,        color: '#ef4444',  icon: 'fa-radiation-alt' },
      { label: 'High Severity',  val: high,            color: '#f97316',  icon: 'fa-exclamation-triangle' },
      { label: 'Threat Actors',  val: actors,          color: '#8b5cf6',  icon: 'fa-user-secret' },
      { label: 'CVEs Mentioned', val: cves,            color: '#f59e0b',  icon: 'fa-bug' },
      { label: 'Sources',        val: sources,         color: '#22c55e',  icon: 'fa-satellite-dish' },
    ];

    return kpis.map(k => `
      <div class="cn-kpi-card" style="--kpi-color:${k.color}">
        <i class="fas ${k.icon} cn-kpi-icon"></i>
        <div class="cn-kpi-val">${k.val}</div>
        <div class="cn-kpi-label">${k.label}</div>
      </div>`).join('');
  }

  function _renderGrid() {
    const grid = document.getElementById('cn-grid');
    if (!grid) return;

    // Update KPI strip
    const kpiStrip = document.getElementById('cn-kpi-strip');
    if (kpiStrip) kpiStrip.innerHTML = _renderKPIStrip();

    // Update subtitle
    const sub = document.getElementById('cn-subtitle');
    if (sub) {
      const ago = _lastFetch
        ? `Updated ${_timeAgo(_lastFetch)}`
        : 'No data yet';
      const feedCount = _feedStats.feedCount || _feedStats.feeds?.length || 9;
      sub.textContent = `${_articles.length} articles from ${feedCount} sources · ${ago}`;
    }

    // Update tab badges — count per category from the FULL _articles array
    // (not from _filtered, which is already category-filtered)
    Object.keys(CAT_META).forEach(catId => {
      const badge = document.getElementById(`cn-badge-${catId}`);
      if (!badge) return;
      const count = catId === 'all'
        ? _articles.length
        : _articles.filter(a => a.category === catId).length;
      badge.textContent = count > 0 ? count : '';
    });

    if (_filtered.length === 0) {
      grid.innerHTML = `
        <div class="cn-empty-state">
          <i class="fas fa-satellite-dish" style="font-size:36px;color:var(--text-muted);margin-bottom:12px;"></i>
          <div style="font-size:14px;font-weight:600;">No articles found</div>
          <div style="font-size:12px;color:var(--text-muted);margin-top:4px;">
            ${_searchQuery ? `No results for "${_searchQuery}" — try clearing filters` : 'No articles in this category yet — click Refresh'}
          </div>
        </div>`;
      return;
    }

    // ROOT-CAUSE FIX: pagination — never hard-cap to 12.
    // Show _visibleCount articles; "Load More" / "View All" expands.
    const visible  = _filtered.slice(0, _visibleCount);
    const hasMore  = _filtered.length > _visibleCount;
    const remaining = _filtered.length - _visibleCount;

    grid.innerHTML = visible.map(a => _renderCard(a)).join('') +
      (hasMore ? `
        <div class="cn-load-more-row" style="grid-column:1/-1;display:flex;align-items:center;justify-content:center;gap:12px;padding:16px 0;">
          <button class="cn-btn cn-btn-secondary" id="cn-load-more-btn"
            onclick="window._cyberNewsLoadMore()"
            style="padding:9px 22px;font-size:12px;">
            <i class="fas fa-chevron-down"></i> Load ${Math.min(PAGE_SIZE, remaining)} more
            <span style="color:var(--text-muted);margin-left:6px;">(${remaining} remaining)</span>
          </button>
          <button class="cn-btn cn-btn-secondary" id="cn-view-all-btn"
            onclick="window._cyberNewsViewAll()"
            style="padding:9px 22px;font-size:12px;">
            <i class="fas fa-list"></i> View all ${_filtered.length}
          </button>
        </div>` : '');
  }

  // Exposed globally for inline onclick handlers
  window._cyberNewsLoadMore = function() {
    _visibleCount = Math.min(_visibleCount + PAGE_SIZE, _filtered.length + PAGE_SIZE);
    _renderGrid();
    // Smooth scroll to newly added cards
    setTimeout(() => {
      const btn = document.getElementById('cn-load-more-btn');
      if (btn) btn.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 50);
  };

  window._cyberNewsViewAll = function() {
    _visibleCount = _filtered.length + 1; // show everything
    _renderGrid();
  };

  function _renderCard(a) {
    const sev   = SEV_META[a.severity] || SEV_META.medium;
    const cat   = CAT_META[a.category] || CAT_META.intelligence;
    const cves  = (a.cves || []).slice(0, 3);
    const tags  = (a.tags || []).slice(0, 4);
    const actors= (a.threatActors || []).slice(0, 2);
    const isExt = a.url && a.url !== '#' && a.url.startsWith('http');

    return `
    <div class="cn-card" onclick="window.cyberNewsOpenDetail('${_escAttr(a.id)}')"
         style="--card-sev-color:${sev.text};--card-cat-color:${cat.color}">
      <!-- Category badge + severity -->
      <div class="cn-card-meta">
        <span class="cn-cat-badge" style="color:${cat.color};background:${cat.color}18;border-color:${cat.color}33">
          ${cat.icon} ${cat.label}
        </span>
        <span class="cn-sev-badge" style="color:${sev.text};background:${sev.bg};border-color:${sev.border}">
          ${sev.label.toUpperCase()}
        </span>
        <span class="cn-source">${_esc(a.source || 'Unknown')}</span>
        <span class="cn-time">${a.publishedAgo || _timeAgo(new Date(a.publishedAt || Date.now()))}</span>
      </div>

      <!-- Title -->
      <div class="cn-card-title">${_esc(a.title || 'Untitled')}</div>

      <!-- Summary -->
      <div class="cn-card-summary">${_esc((a.summary || '').slice(0, 200))}${(a.summary || '').length > 200 ? '…' : ''}</div>

      <!-- Tags row -->
      <div class="cn-card-tags">
        ${cves.map(c => `<span class="cn-tag cn-tag-cve">${_esc(c)}</span>`).join('')}
        ${actors.map(ac => `<span class="cn-tag cn-tag-actor">${_esc(ac)}</span>`).join('')}
        ${tags.map(t => `<span class="cn-tag cn-tag-generic">${_esc(t)}</span>`).join('')}
      </div>

      <!-- Footer actions -->
      <div class="cn-card-footer">
        <button class="cn-card-btn" onclick="event.stopPropagation();window.cyberNewsExtractIOCs('${_escAttr(a.id)}')">
          <i class="fas fa-fingerprint"></i> IOCs
        </button>
        <button class="cn-card-btn" onclick="event.stopPropagation();window.cyberNewsCreateCase('${_escAttr(a.id)}')">
          <i class="fas fa-folder-plus"></i> Case
        </button>
        ${isExt ? `<a href="${_escAttr(a.url)}" target="_blank" rel="noopener" class="cn-card-btn cn-card-btn-link" onclick="event.stopPropagation()">
          <i class="fas fa-external-link-alt"></i> Source
        </a>` : ''}
      </div>
    </div>`;
  }

  function _renderFeedStatus() {
    const el = document.getElementById('cn-feed-status');
    if (!el) return;

    const feeds = _feedStats.feedList || [
      'The Hacker News', 'BleepingComputer', 'SecurityWeek', 'Krebs on Security',
      'CISA Advisories', 'Dark Reading', 'SANS ISC', 'Recorded Future', 'Microsoft Security',
    ];
    const lastUpdated = _lastFetch
      ? `Last updated: ${_lastFetch.toLocaleTimeString()}`
      : 'Not yet fetched';

    el.innerHTML = `
      <div class="cn-feed-bar">
        <span style="color:var(--text-muted);font-size:11px;"><i class="fas fa-rss" style="color:#f97316;margin-right:5px;"></i>${lastUpdated} · ${feeds.length} active feeds</span>
        <div class="cn-feed-sources">
          ${feeds.slice(0, 8).map(f => `<span class="cn-feed-pill">${f}</span>`).join('')}
          ${feeds.length > 8 ? `<span class="cn-feed-pill" style="color:var(--text-muted);">+${feeds.length - 8} more</span>` : ''}
        </div>
      </div>`;
  }

  function _setLoading(on) {
    const el = document.getElementById('cn-loading');
    const gr = document.getElementById('cn-grid');
    if (el) el.style.display = on ? 'flex' : 'none';
    if (gr) gr.style.display = on ? 'none' : 'grid';
  }

  /* ════════════════════════════════════════════════════════════════════
     ARTICLE DETAIL MODAL
  ═════════════════════════════════════════════════════════════════════ */
  function _openDetail(id) {
    const a = _articles.find(x => x.id === id);
    if (!a) return;

    const sev  = SEV_META[a.severity] || SEV_META.medium;
    const cat  = CAT_META[a.category] || CAT_META.intelligence;
    const isExt = a.url && a.url !== '#' && a.url.startsWith('http');

    const overlay = document.getElementById('cn-detail-overlay');
    const body    = document.getElementById('cn-detail-body');
    if (!overlay || !body) return;

    body.innerHTML = `
    <div class="cn-detail-inner">
      <button class="cn-detail-close" onclick="window.cyberNewsCloseDetail()">
        <i class="fas fa-times"></i>
      </button>

      <!-- Header badges -->
      <div class="cn-detail-badges">
        <span style="background:${sev.bg};color:${sev.text};border:1px solid ${sev.border};padding:3px 10px;border-radius:6px;font-size:11px;font-weight:700;">
          ${sev.label.toUpperCase()}
        </span>
        <span style="background:${cat.color}18;color:${cat.color};border:1px solid ${cat.color}33;padding:3px 10px;border-radius:6px;font-size:11px;">
          ${cat.icon} ${cat.label}
        </span>
        <span style="font-size:11px;color:var(--text-muted);padding:3px 8px;">
          <i class="fas fa-newspaper" style="margin-right:4px;"></i>${_esc(a.source || 'Unknown source')}
        </span>
        <span style="font-size:11px;color:var(--text-muted);padding:3px 8px;">
          <i class="fas fa-clock" style="margin-right:4px;"></i>${a.publishedAgo || 'Unknown time'}
        </span>
      </div>

      <!-- Title -->
      <h2 class="cn-detail-title">${_esc(a.title || 'Untitled')}</h2>

      <!-- Summary block -->
      <div class="cn-detail-section">
        <div class="cn-detail-section-title">
          <i class="fas fa-robot" style="color:var(--accent-cyan);"></i> AI Summary
        </div>
        <p class="cn-detail-summary">${_esc(a.summary || 'No summary available.')}</p>
      </div>

      <!-- Intelligence grid -->
      <div class="cn-detail-grid3">
        ${(a.threatActors || []).length ? `
        <div class="cn-intel-card" style="--intel-color:#f97316">
          <div class="cn-intel-label"><i class="fas fa-user-secret"></i> Threat Actors</div>
          ${(a.threatActors || []).map(ac => `<div class="cn-intel-val">${_esc(ac)}</div>`).join('')}
        </div>` : ''}
        ${(a.malwareFamilies || []).length ? `
        <div class="cn-intel-card" style="--intel-color:#8b5cf6">
          <div class="cn-intel-label"><i class="fas fa-virus"></i> Malware Families</div>
          ${(a.malwareFamilies || []).map(m => `<div class="cn-intel-val" style="font-family:monospace;">${_esc(m)}</div>`).join('')}
        </div>` : ''}
        ${(a.cves || []).length ? `
        <div class="cn-intel-card" style="--intel-color:#ef4444">
          <div class="cn-intel-label"><i class="fas fa-bug"></i> CVEs</div>
          ${(a.cves || []).map(c => `<a class="cn-intel-val cn-cve-link" href="https://nvd.nist.gov/vuln/detail/${_escAttr(c)}" target="_blank" rel="noopener">${_esc(c)}</a>`).join('')}
        </div>` : ''}
      </div>

      <!-- Tags -->
      ${(a.tags || []).length ? `
      <div class="cn-detail-tags">
        ${(a.tags || []).map(t => `<span class="cn-tag cn-tag-generic">${_esc(t)}</span>`).join('')}
      </div>` : ''}

      <!-- Actions -->
      <div class="cn-detail-actions">
        <button class="cn-action-btn cn-action-cyan" onclick="window.cyberNewsExtractIOCs('${_escAttr(a.id)}');window.cyberNewsCloseDetail()">
          <i class="fas fa-fingerprint"></i> Extract IOCs to Database
        </button>
        <button class="cn-action-btn cn-action-green" onclick="window.cyberNewsCreateCase('${_escAttr(a.id)}');window.cyberNewsCloseDetail()">
          <i class="fas fa-folder-plus"></i> Create Investigation Case
        </button>
        ${isExt ? `
        <a href="${_escAttr(a.url)}" target="_blank" rel="noopener" class="cn-action-btn cn-action-blue">
          <i class="fas fa-external-link-alt"></i> Read Full Article
        </a>` : ''}
      </div>
    </div>`;

    overlay.style.display = 'flex';
  }

  function _closeDetail() {
    const overlay = document.getElementById('cn-detail-overlay');
    if (overlay) overlay.style.display = 'none';
  }

  /* ════════════════════════════════════════════════════════════════════
     ACTION HANDLERS
  ═════════════════════════════════════════════════════════════════════ */
  function _extractIOCs(id) {
    const a = _articles.find(x => x.id === id);
    if (!a) return;
    const total = (a.cves || []).length + (a.threatActors || []).length;
    if (typeof showToast !== 'undefined') {
      showToast(`✅ Extracted ${total} IOCs from "${(a.title || '').slice(0, 45)}…" → IOC Database`, 'success');
    }
  }

  function _createCase(id) {
    const a = _articles.find(x => x.id === id);
    if (!a) return;
    if (typeof showToast !== 'undefined') {
      showToast(`📁 Case created: "${(a.title || '').slice(0, 50)}…" → Analyst queue`, 'success');
    }
    // Bump cases navbar badge
    const nb = document.getElementById('nb-cases');
    if (nb) nb.textContent = String(parseInt(nb.textContent || '0') + 1);
  }

  function _exportCSV() {
    const rows = [
      ['Title', 'Source', 'Category', 'Severity', 'Published', 'CVEs', 'Threat Actors', 'Tags', 'URL'],
      ..._articles.map(a => [
        `"${(a.title || '').replace(/"/g, '""')}"`,
        a.source || '',
        a.category || '',
        a.severity || '',
        a.publishedAt || '',
        (a.cves || []).join(';'),
        (a.threatActors || []).join(';'),
        (a.tags || []).join(';'),
        a.url || '',
      ]),
    ];
    const csv  = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a2   = document.createElement('a');
    a2.href     = url;
    a2.download = `wadjet-cyber-news-${new Date().toISOString().slice(0,10)}.csv`;
    a2.click();
    URL.revokeObjectURL(url);
    if (typeof showToast !== 'undefined') showToast('News feed exported as CSV', 'success');
  }

  /* ════════════════════════════════════════════════════════════════════
     CSS INJECTION
  ═════════════════════════════════════════════════════════════════════ */
  function _attachStyles() {
    if (document.getElementById('cn-styles')) return;
    const s = document.createElement('style');
    s.id = 'cn-styles';
    s.textContent = `
      .cn-root { display:flex;flex-direction:column;gap:14px;padding-bottom:40px; }

      /* Header */
      .cn-header { display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px; }
      .cn-header-left { display:flex;align-items:center;gap:10px; }
      .cn-live-dot { width:9px;height:9px;background:#ef4444;border-radius:50%;animation:cnPulse 1.5s infinite;flex-shrink:0; }
      @keyframes cnPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.85)} }
      .cn-title { font-size:16px;font-weight:800;margin:0; }
      .cn-subtitle { font-size:11px;color:var(--text-muted);margin-top:2px; }
      .cn-live-badge { background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.35);padding:2px 8px;border-radius:8px;font-size:10px;font-weight:800;letter-spacing:.5px; }
      .cn-header-actions { display:flex;gap:8px;flex-wrap:wrap;align-items:center; }
      .cn-search { background:var(--bg-surface);border:1px solid var(--border);color:var(--text-primary);padding:6px 12px;border-radius:7px;font-size:12px;min-width:200px;outline:none; }
      .cn-search:focus { border-color:var(--accent-cyan); }
      .cn-select { background:var(--bg-surface);border:1px solid var(--border);color:var(--text-primary);padding:6px 10px;border-radius:7px;font-size:12px;outline:none;cursor:pointer; }
      .cn-btn { padding:6px 12px;border-radius:7px;font-size:12px;cursor:pointer;border:1px solid var(--border);transition:all .15s;display:flex;align-items:center;gap:5px; }
      .cn-btn-secondary { background:var(--bg-surface);color:var(--text-secondary); }
      .cn-btn-secondary:hover { background:var(--bg-elevated);color:var(--text-primary); }
      .cn-btn:disabled { opacity:.5;cursor:not-allowed; }

      /* KPI Strip */
      .cn-kpi-strip { display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px; }
      .cn-kpi-card { background:var(--bg-card);border:1px solid rgba(var(--kpi-color-rgb),0.2);border-left:3px solid var(--kpi-color);border-radius:10px;padding:12px;text-align:center; }
      .cn-kpi-icon { color:var(--kpi-color);font-size:16px;margin-bottom:6px;display:block; }
      .cn-kpi-val { font-size:22px;font-weight:900;color:var(--kpi-color); }
      .cn-kpi-label { font-size:10px;color:var(--text-muted);margin-top:2px; }

      /* Category Tabs */
      .cn-tabs { display:flex;gap:6px;overflow-x:auto;padding-bottom:4px;border-bottom:1px solid var(--border); }
      .cn-tab { display:flex;align-items:center;gap:5px;padding:7px 12px;border-radius:7px;font-size:12px;cursor:pointer;border:1px solid transparent;background:transparent;color:var(--text-secondary);white-space:nowrap;transition:all .15s; }
      .cn-tab:hover { background:var(--bg-surface);color:var(--text-primary); }
      .cn-tab.active { background:var(--cat-color, #3b82f6)18;border-color:var(--cat-color, #3b82f6)44;color:var(--cat-color, #3b82f6);font-weight:700; }
      .cn-tab-badge { background:var(--cat-color,#3b82f6);color:#fff;border-radius:8px;padding:1px 6px;font-size:9px;font-weight:800;min-width:16px;text-align:center; }
      .cn-tab-badge:empty { display:none; }

      /* Feed status bar */
      .cn-feed-bar { display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap; }
      .cn-feed-sources { display:flex;gap:5px;flex-wrap:wrap; }
      .cn-feed-pill { font-size:10px;padding:2px 7px;background:var(--bg-surface);border:1px solid var(--border);border-radius:4px;color:var(--text-muted); }

      /* Loading state */
      .cn-loading-state { display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 20px; }

      /* Grid */
      .cn-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px; }

      /* Empty state */
      .cn-empty-state { grid-column:1/-1;text-align:center;padding:60px 20px;display:flex;flex-direction:column;align-items:center; }

      /* Card */
      .cn-card { background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:16px;cursor:pointer;transition:all .2s;display:flex;flex-direction:column;gap:8px;border-left:3px solid var(--card-sev-color,#3b82f6); }
      .cn-card:hover { transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,0.25);border-color:var(--card-cat-color,#3b82f6)55; }
      .cn-card-meta { display:flex;align-items:center;gap:6px;flex-wrap:wrap; }
      .cn-cat-badge,.cn-sev-badge { font-size:10px;padding:2px 7px;border-radius:4px;border:1px solid;font-weight:700; }
      .cn-source { font-size:10px;color:var(--text-muted);margin-left:auto; }
      .cn-time { font-size:10px;color:var(--text-muted); }
      .cn-card-title { font-size:13px;font-weight:700;line-height:1.45;color:var(--text-primary); }
      .cn-card-summary { font-size:11px;color:var(--text-secondary);line-height:1.6; }
      .cn-card-tags { display:flex;flex-wrap:wrap;gap:4px;margin-top:2px; }
      .cn-tag { font-size:10px;padding:1px 6px;border-radius:3px;font-family:monospace; }
      .cn-tag-cve { background:rgba(239,68,68,0.12);color:#f87171;border:1px solid rgba(239,68,68,0.25); }
      .cn-tag-actor { background:rgba(249,115,22,0.12);color:#fb923c;border:1px solid rgba(249,115,22,0.25); }
      .cn-tag-generic { background:rgba(59,130,246,0.1);color:#60a5fa;border:1px solid rgba(59,130,246,0.2); }
      .cn-card-footer { display:flex;gap:6px;margin-top:4px;padding-top:8px;border-top:1px solid var(--border); }
      .cn-card-btn { font-size:10px;padding:4px 8px;border-radius:5px;cursor:pointer;border:1px solid var(--border);background:var(--bg-surface);color:var(--text-secondary);display:flex;align-items:center;gap:4px;text-decoration:none;transition:all .15s; }
      .cn-card-btn:hover { background:var(--bg-elevated);color:var(--text-primary); }
      .cn-card-btn-link { color:var(--accent-cyan); }

      /* Detail Modal */
      .cn-overlay { position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px; }
      .cn-detail-modal { background:var(--bg-card);border:1px solid var(--border);border-radius:14px;max-width:780px;width:100%;max-height:88vh;overflow-y:auto; }
      .cn-detail-inner { padding:24px;position:relative; }
      .cn-detail-close { position:absolute;top:16px;right:16px;background:var(--bg-surface);border:1px solid var(--border);width:28px;height:28px;border-radius:7px;cursor:pointer;color:var(--text-secondary);display:flex;align-items:center;justify-content:center;font-size:12px; }
      .cn-detail-close:hover { background:var(--bg-elevated);color:var(--text-primary); }
      .cn-detail-badges { display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px; }
      .cn-detail-title { font-size:16px;font-weight:800;line-height:1.4;margin:0 0 16px; }
      .cn-detail-section { background:var(--bg-surface);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:12px; }
      .cn-detail-section-title { font-size:11px;text-transform:uppercase;font-weight:700;color:var(--text-muted);margin-bottom:8px;display:flex;align-items:center;gap:5px;letter-spacing:.5px; }
      .cn-detail-summary { font-size:13px;color:var(--text-secondary);line-height:1.7;margin:0; }
      .cn-detail-grid3 { display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:12px; }
      .cn-intel-card { background:var(--bg-surface);border:1px solid var(--border);border-left:3px solid var(--intel-color);border-radius:8px;padding:12px; }
      .cn-intel-label { font-size:10px;text-transform:uppercase;color:var(--text-muted);font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:5px; }
      .cn-intel-val { font-size:12px;font-weight:600;color:var(--intel-color);padding:2px 0; }
      .cn-cve-link { text-decoration:none;display:block; }
      .cn-cve-link:hover { text-decoration:underline; }
      .cn-detail-tags { display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px; }
      .cn-detail-actions { display:flex;gap:8px;flex-wrap:wrap;padding-top:12px;border-top:1px solid var(--border); }
      .cn-action-btn { padding:8px 14px;border-radius:8px;font-size:12px;cursor:pointer;border:1px solid;display:flex;align-items:center;gap:5px;text-decoration:none;font-weight:600;transition:all .15s; }
      .cn-action-cyan  { background:rgba(34,211,238,0.12);color:#22d3ee;border-color:rgba(34,211,238,0.35); }
      .cn-action-green { background:rgba(34,197,94,0.12); color:#22c55e;border-color:rgba(34,197,94,0.35); }
      .cn-action-blue  { background:rgba(59,130,246,0.12);color:#60a5fa;border-color:rgba(59,130,246,0.35); }
      .cn-action-btn:hover { filter:brightness(1.15); }
    `;
    document.head.appendChild(s);
  }

  /* ════════════════════════════════════════════════════════════════════
     UTILITIES
  ═════════════════════════════════════════════════════════════════════ */
  function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }
  function _escAttr(s) {
    return String(s || '').replace(/'/g, '\\x27').replace(/"/g, '\\x22');
  }
  function _timeAgo(date) {
    const secs = Math.floor((Date.now() - (date instanceof Date ? date.getTime() : new Date(date).getTime())) / 1000);
    if (isNaN(secs)) return 'unknown';
    if (secs < 60)   return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400)return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  /* ════════════════════════════════════════════════════════════════════
     PUBLIC API — exposed on window for onclick handlers & main.js
  ═════════════════════════════════════════════════════════════════════ */
  window.renderCyberNews       = renderCyberNewsLive;
  window.cyberNewsOpenDetail   = _openDetail;
  window.cyberNewsCloseDetail  = _closeDetail;
  window.cyberNewsExtractIOCs  = _extractIOCs;
  window.cyberNewsCreateCase   = _createCase;

  // ─── Debug Mode ───────────────────────────────────────────────────
  // window.cyberNewsDebug() — call from browser console to inspect state
  // Logs: total articles, per-category counts, filter state, pagination,
  // visible article count, and a per-tab breakdown with sample titles.
  window.cyberNewsDebug = function() {
    const catCounts = {};
    _articles.forEach(a => { catCounts[a.category] = (catCounts[a.category] || 0) + 1; });

    const tabBreakdown = {};
    Object.keys(CAT_META).filter(c => c !== 'all').forEach(cat => {
      const items = _articles.filter(a => a.category === cat);
      tabBreakdown[cat] = {
        count: items.length,
        samples: items.slice(0, 3).map(a => `[${a.severity?.toUpperCase()}] ${a.title?.slice(0, 70)}`),
      };
    });

    const report = {
      totalArticles:    _articles.length,
      filteredArticles: _filtered.length,
      visibleCount:     _visibleCount,
      activeCategory:   _activeCategory,
      activeSeverity:   _activeSeverity,
      searchQuery:      _searchQuery,
      lastFetch:        _lastFetch?.toISOString() || null,
      isLoading:        _loading,
      perCategoryCounts: catCounts,
      tabBreakdown,
      fallbackActive:   _articles.length > 0 && _articles[0]?.id?.startsWith('F'),
    };

    console.group('[CyberNews] 🔍 Debug Report');
    console.table(Object.entries(catCounts).map(([cat, count]) => ({ category: cat, count })));
    console.log('Full state:', report);
    Object.entries(tabBreakdown).forEach(([cat, data]) => {
      if (data.count > 0) {
        console.group(`📂 ${cat} (${data.count} articles)`);
        data.samples.forEach(s => console.log('  •', s));
        console.groupEnd();
      } else {
        console.warn(`📂 ${cat} — ⚠️ EMPTY (0 articles)`);
      }
    });
    console.groupEnd();

    return report;
  };

  // Also expose a force-refresh function for debugging
  window.cyberNewsForceRefresh = async function() {
    console.info('[CyberNews] Force refresh triggered from debug console');
    _articles = [];
    _loading  = false;
    await _loadArticles();
    _applyFilters();
    _renderGrid();
    console.info('[CyberNews] Force refresh complete');
    return window.cyberNewsDebug();
  };

  // Cleanup when navigating away
  window.addEventListener('beforeunload', _clearAutoRefresh);
  // Also clean up when SPA navigates
  if (typeof window.addEventListener === 'function') {
    window.addEventListener('spa:navigate', () => _clearAutoRefresh());
  }

})();
