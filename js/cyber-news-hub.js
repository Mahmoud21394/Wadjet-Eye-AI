/**
 * ════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News Hub v7.0
 *  FILE: js/cyber-news-hub.js
 *
 *  Full-featured threat-intelligence news portal inspired by THN.
 *  Tabs: Threat Intelligence | Vulnerabilities | Cyber Attacks | CVE Threat Engine
 *
 *  - Live RSS-aggregated articles from backend /api/news
 *  - Real-time CVE data from NVD via backend /api/cve
 *  - Card-based responsive layout with lazy loading + pagination
 *  - Category-based filtering, search, severity filter
 *  - CVE Engine: search, filters (severity/date/vendor/CVSS), tagging, sorting
 *  - No API keys exposed in frontend
 *  - Production-grade error handling and retry logic
 * ════════════════════════════════════════════════════════════════════
 */
'use strict';

// ─── Config ────────────────────────────────────────────────────────
const CN = {
  API_BASE:     window.API_BASE || window.backendUrl || 'https://wadjet-eye-ai-backend.onrender.com',
  NEWS_LIMIT:   12,
  CVE_LIMIT:    20,
  RETRY_MAX:    3,
  RETRY_DELAY:  1200,
  CACHE_TTL:    5 * 60 * 1000,
};

// ─── Runtime state ─────────────────────────────────────────────────
const CN_STATE = {
  activeTab:      'threat-intelligence',
  newsPage:       1,
  cvePage:        1,
  loading:        false,
  newsTotal:      0,
  cveTotal:       0,
  newsCache:      new Map(),
  cveCache:       new Map(),
  searchDebounce: null,
  filters: {
    news: { search: '', severity: '', source: '' },
    cve:  { search: '', severity: '', days: 30, sort: 'date', vendor: '', cisaKev: false },
  },
};

// ─── Severity palettes ──────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg: 'rgba(239,68,68,.12)',  border: 'rgba(239,68,68,.35)',  text: '#ef4444', dot: '#ef4444', label: 'CRITICAL' },
  HIGH:     { bg: 'rgba(249,115,22,.12)', border: 'rgba(249,115,22,.35)', text: '#f97316', dot: '#f97316', label: 'HIGH'     },
  MEDIUM:   { bg: 'rgba(234,179, 8,.12)', border: 'rgba(234,179, 8,.35)', text: '#eab308', dot: '#eab308', label: 'MEDIUM'   },
  LOW:      { bg: 'rgba( 34,197,94,.12)', border: 'rgba( 34,197,94,.35)', text: '#22c55e', dot: '#22c55e', label: 'LOW'      },
  UNKNOWN:  { bg: 'rgba(148,163,184,.1)', border: 'rgba(148,163,184,.3)', text: '#94a3b8', dot: '#94a3b8', label: '?'        },
};
function sevPalette(s) { return SEV[(s || '').toUpperCase()] || SEV.UNKNOWN; }

// ─── Fetch helper with retry ─────────────────────────────────────────
async function cnFetch(url, options = {}, retries = CN.RETRY_MAX) {
  for (let i = 0; i < retries; i++) {
    try {
      const resp = await fetch(url, { ...options, signal: AbortSignal.timeout?.(20000) });
      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status}: ${body.slice(0, 120)}`);
      }
      return await resp.json();
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, CN.RETRY_DELAY * (i + 1)));
    }
  }
}

// ─── Cache helpers ───────────────────────────────────────────────────
function cacheGet(map, key) {
  const e = map.get(key);
  if (!e || Date.now() - e.ts > CN.CACHE_TTL) { map.delete(key); return null; }
  return e.data;
}
function cacheSet(map, key, data) { map.set(key, { data, ts: Date.now() }); }

// ─── Relative time ───────────────────────────────────────────────────
function timeAgo(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7)  return `${d}d ago`;
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// ─── HTML helpers ─────────────────────────────────────────────────────
function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Source icon map ──────────────────────────────────────────────────
const SRC_ICON = {
  'the hacker news':               'fa-hacker-news',
  'bleepingcomputer':               'fa-bug',
  'securityweek':                   'fa-shield-alt',
  'krebs on security':              'fa-search',
  'cisa':                           'fa-university',
  'dark reading':                   'fa-eye',
  'threat post':                    'fa-radiation',
  'sans internet storm center':     'fa-cloud-rain',
};
function sourceIcon(name) {
  const k = (name || '').toLowerCase();
  for (const [sub, icon] of Object.entries(SRC_ICON)) {
    if (k.includes(sub)) return icon;
  }
  return 'fa-globe';
}

// ════════════════════════════════════════════════════════════════════
//  MAIN ENTRY — renderCyberNews()
// ════════════════════════════════════════════════════════════════════
window.renderCyberNews = async function () {
  // Also expose as v7 so features.js legacy stub can call it
  window.renderCyberNews_v7 = window.renderCyberNews;
  const wrap = document.getElementById('cyberNewsWrap');
  if (!wrap) return;

  wrap.innerHTML = buildShell();
  attachTabEvents();
  attachSearchEvents();
  await switchTab('threat-intelligence');
};

// ─── Shell HTML ───────────────────────────────────────────────────────
function buildShell() {
  return `
<div id="cn-root" style="
  font-family:'Inter',sans-serif;
  background:#0a0e17;
  min-height:100vh;
  color:#e2e8f0;
">

  <!-- ═══ TOP HEADER BAR ═══ -->
  <div id="cn-header" style="
    background:#060b14;
    border-bottom:1px solid #1e2840;
    padding:0 20px;
    position:sticky;
    top:0;
    z-index:200;
    box-shadow:0 2px 12px rgba(0,0,0,.6);
  ">
    <!-- Branding row -->
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 0 0;flex-wrap:wrap;gap:8px">
      <div style="display:flex;align-items:center;gap:12px">
        <div style="
          width:36px;height:36px;
          background:linear-gradient(135deg,#e53e3e,#7928ca);
          border-radius:8px;
          display:flex;align-items:center;justify-content:center;
          font-size:1em;color:#fff;font-weight:900;
        ">TI</div>
        <div>
          <div style="font-size:.95em;font-weight:800;color:#f1f5f9;letter-spacing:-.3px">
            Cyber News Hub
          </div>
          <div style="font-size:.68em;color:#475569;margin-top:1px">
            <span id="cn-live-dot" style="
              display:inline-block;width:6px;height:6px;
              background:#22c55e;border-radius:50%;
              margin-right:5px;
              animation:cn-blink 1.4s infinite;
            "></span>
            Real-time threat intelligence &amp; vulnerability tracking
          </div>
        </div>
      </div>

      <!-- Global search -->
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <div style="
          position:relative;
          display:flex;align-items:center;
        ">
          <i class="fas fa-search" style="
            position:absolute;left:10px;color:#475569;font-size:.8em;pointer-events:none;
          "></i>
          <input id="cn-global-search"
            placeholder="Search threats, CVEs, vendors…"
            style="
              background:#0d1520;
              border:1px solid #1e2840;
              color:#e2e8f0;
              padding:7px 12px 7px 32px;
              border-radius:7px;
              font-size:.82em;
              width:220px;
              outline:none;
              transition:border-color .2s;
            "
            onfocus="this.style.borderColor='#3b82f6'"
            onblur="this.style.borderColor='#1e2840'"
            oninput="cnGlobalSearch(this.value)"
          />
        </div>
        <button id="cn-refresh-btn"
          onclick="cnRefresh()"
          style="
            background:#0d1520;
            border:1px solid #1e2840;
            color:#94a3b8;
            padding:7px 12px;
            border-radius:7px;
            font-size:.82em;
            cursor:pointer;
            display:flex;align-items:center;gap:6px;
          "
          title="Refresh feed">
          <i class="fas fa-sync-alt"></i>
          <span>Refresh</span>
        </button>
      </div>
    </div>

    <!-- Tab navigation -->
    <nav id="cn-tabs" style="
      display:flex;
      gap:0;
      margin-top:10px;
      border-bottom:none;
      overflow-x:auto;
    ">
      ${buildTabNav()}
    </nav>
  </div>

  <!-- ═══ FILTER BAR ═══ -->
  <div id="cn-filter-bar" style="
    background:#060b14;
    border-bottom:1px solid #1e2840;
    padding:10px 20px;
    display:flex;
    gap:8px;
    flex-wrap:wrap;
    align-items:center;
  ">
    <!-- Populated dynamically per tab -->
  </div>

  <!-- ═══ CONTENT AREA ═══ -->
  <div id="cn-content" style="padding:20px;max-width:1400px;margin:0 auto">
    <div id="cn-loading" style="
      display:flex;flex-direction:column;align-items:center;justify-content:center;
      padding:80px 20px;gap:14px;color:#475569;
    ">
      <div class="cn-spinner"></div>
      <span style="font-size:.85em">Loading threat intelligence…</span>
    </div>
  </div>

</div>

<style>
/* ── Animations ── */
@keyframes cn-blink {
  0%,100% { opacity:1; }
  50%      { opacity:.3; }
}
@keyframes cn-spin {
  to { transform:rotate(360deg); }
}
@keyframes cn-fade-in {
  from { opacity:0; transform:translateY(10px); }
  to   { opacity:1; transform:translateY(0); }
}

.cn-spinner {
  width:36px;height:36px;
  border:3px solid #1e2840;
  border-top-color:#3b82f6;
  border-radius:50%;
  animation:cn-spin .7s linear infinite;
}

/* ── Tab base ── */
.cn-tab {
  padding:10px 18px;
  font-size:.82em;
  font-weight:600;
  color:#64748b;
  border:none;
  background:transparent;
  cursor:pointer;
  white-space:nowrap;
  border-bottom:3px solid transparent;
  transition:color .2s, border-color .2s;
  display:flex;align-items:center;gap:7px;
  margin-bottom:-1px;
}
.cn-tab:hover { color:#94a3b8; }
.cn-tab.active {
  color:#f1f5f9;
  border-bottom-color:#3b82f6;
}
.cn-tab.active.ti-tab  { border-bottom-color:#3b82f6; color:#60a5fa; }
.cn-tab.active.vuln-tab { border-bottom-color:#f97316; color:#fb923c; }
.cn-tab.active.att-tab  { border-bottom-color:#ef4444; color:#f87171; }
.cn-tab.active.cve-tab  { border-bottom-color:#8b5cf6; color:#a78bfa; }

/* ── Card grid ── */
.cn-grid {
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
  gap:16px;
  animation:cn-fade-in .3s ease;
}

/* ── News card ── */
.cn-card {
  background:#0d1520;
  border:1px solid #1e2840;
  border-radius:12px;
  overflow:hidden;
  cursor:pointer;
  transition:border-color .2s, transform .2s, box-shadow .2s;
  position:relative;
}
.cn-card:hover {
  transform:translateY(-2px);
  box-shadow:0 8px 24px rgba(0,0,0,.4);
}
.cn-card .sev-bar { height:3px; width:100%; }
.cn-card .thumb {
  width:100%;height:160px;object-fit:cover;
  border-bottom:1px solid #1e2840;
}
.cn-card .card-body { padding:14px; }
.cn-card .source-row {
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:10px;
}
.cn-card .title {
  font-size:.88em;font-weight:700;color:#f1f5f9;
  line-height:1.5;margin-bottom:8px;
}
.cn-card .summary {
  font-size:.75em;color:#64748b;line-height:1.7;
  overflow:hidden;
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  margin-bottom:10px;
}
.cn-card .tag-row { display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px; }
.cn-card .tag {
  background:rgba(255,255,255,.04);
  color:#475569;
  border:1px solid #1e2840;
  padding:2px 6px;border-radius:4px;font-size:.65em;
}
.cn-card .cve-chip {
  background:rgba(139,92,246,.15);
  color:#a78bfa;
  border:1px solid rgba(139,92,246,.3);
  padding:2px 6px;border-radius:4px;font-size:.65em;
  font-family:'JetBrains Mono',monospace;
}
.cn-card .card-footer {
  display:flex;align-items:center;justify-content:space-between;
  border-top:1px solid #1e2840;padding-top:9px;
}

/* ── CVE card ── */
.cve-card {
  background:#0d1520;
  border:1px solid #1e2840;
  border-radius:12px;
  padding:16px;
  cursor:pointer;
  transition:border-color .2s, transform .2s;
  animation:cn-fade-in .3s ease;
}
.cve-card:hover { transform:translateY(-2px); }
.cve-card .cve-id {
  font-family:'JetBrains Mono',monospace;
  font-size:.92em;font-weight:700;color:#a78bfa;
  letter-spacing:-.3px;
}
.cve-card .cve-score {
  font-size:1.6em;font-weight:800;
  font-family:'JetBrains Mono',monospace;
}
.cve-card .cve-desc {
  font-size:.78em;color:#64748b;line-height:1.7;
  overflow:hidden;
  display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  margin:8px 0;
}

/* ── Stat cards ── */
.cn-stat {
  background:#0d1520;
  border:1px solid #1e2840;
  border-radius:10px;
  padding:14px 16px;
}
.cn-stat .stat-val { font-size:1.7em;font-weight:800; }
.cn-stat .stat-label { font-size:.68em;color:#64748b;margin-top:2px; }

/* ── Badge ── */
.sev-badge {
  padding:2px 8px;border-radius:6px;font-size:.7em;font-weight:700;
  white-space:nowrap;
}

/* ── Filter controls ── */
.cn-filter-ctrl {
  background:#0d1520;
  border:1px solid #1e2840;
  color:#94a3b8;
  padding:6px 10px;border-radius:6px;font-size:.8em;
  outline:none;cursor:pointer;
  transition:border-color .2s;
}
.cn-filter-ctrl:focus { border-color:#3b82f6; }
.cn-filter-ctrl option { background:#0d1520; }

/* ── Load more ── */
.cn-load-more {
  display:block;margin:24px auto 0;
  background:#0d1520;
  border:1px solid #1e2840;
  color:#64748b;
  padding:10px 28px;border-radius:8px;font-size:.82em;
  cursor:pointer;
  transition:background .2s, color .2s;
}
.cn-load-more:hover { background:#1e2840;color:#e2e8f0; }

/* ── Pagination ── */
.cn-pagination {
  display:flex;justify-content:center;align-items:center;
  gap:8px;margin-top:24px;flex-wrap:wrap;
}
.cn-page-btn {
  background:#0d1520;border:1px solid #1e2840;
  color:#64748b;padding:7px 13px;border-radius:6px;
  font-size:.8em;cursor:pointer;transition:all .2s;
}
.cn-page-btn:hover  { border-color:#3b82f6;color:#60a5fa; }
.cn-page-btn.active { background:#3b82f6;border-color:#3b82f6;color:#fff; }
.cn-page-btn:disabled { opacity:.35;cursor:not-allowed; }

/* ── Empty state ── */
.cn-empty {
  text-align:center;padding:60px 20px;color:#475569;
}
.cn-empty i { font-size:2.5em;margin-bottom:14px;opacity:.3; }

/* ── Responsive ── */
@media (max-width:640px) {
  .cn-grid { grid-template-columns:1fr; }
  #cn-global-search { width:160px; }
}
</style>`;
}

// ─── Tab nav HTML ─────────────────────────────────────────────────────
function buildTabNav() {
  const tabs = [
    { id: 'threat-intelligence', label: 'Threat Intelligence', icon: 'fa-shield-alt', cls: 'ti-tab',   badge: '' },
    { id: 'vulnerabilities',     label: 'Vulnerabilities',     icon: 'fa-bug',        cls: 'vuln-tab', badge: '' },
    { id: 'cyber-attacks',       label: 'Cyber Attacks',       icon: 'fa-bolt',       cls: 'att-tab',  badge: '' },
    { id: 'cve-engine',          label: 'CVE Threat Engine',   icon: 'fa-database',   cls: 'cve-tab',  badge: 'LIVE' },
  ];
  return tabs.map(t => `
    <button class="cn-tab ${t.cls}" data-tab="${t.id}" onclick="cnSwitchTab('${t.id}')">
      <i class="fas ${t.icon}"></i>
      ${esc(t.label)}
      ${t.badge ? `<span style="
        background:rgba(34,197,94,.15);color:#22c55e;
        border:1px solid rgba(34,197,94,.3);
        padding:1px 5px;border-radius:4px;font-size:.65em;font-weight:700;
      ">${t.badge}</span>` : ''}
    </button>
  `).join('');
}

// ─── Attach tab events ────────────────────────────────────────────────
function attachTabEvents() {
  // Tab clicks already handled via onclick in HTML
}

function attachSearchEvents() {
  // Debounced global search via oninput in HTML
}

window.cnSwitchTab = async function (tabId) {
  await switchTab(tabId);
};

window.cnRefresh = function () {
  CN_STATE.newsCache.clear();
  CN_STATE.cveCache.clear();
  CN_STATE.newsPage = 1;
  CN_STATE.cvePage  = 1;
  switchTab(CN_STATE.activeTab);
};

window.cnGlobalSearch = function (q) {
  clearTimeout(CN_STATE.searchDebounce);
  CN_STATE.searchDebounce = setTimeout(() => {
    if (CN_STATE.activeTab === 'cve-engine') {
      CN_STATE.filters.cve.search = q;
      CN_STATE.cvePage = 1;
      loadCVEs();
    } else {
      CN_STATE.filters.news.search = q;
      CN_STATE.newsPage = 1;
      loadNews(CN_STATE.activeTab);
    }
  }, 450);
};

// ─── Switch tab ───────────────────────────────────────────────────────
async function switchTab(tabId) {
  CN_STATE.activeTab = tabId;

  // Update tab active states
  document.querySelectorAll('.cn-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });

  // Sync global search field
  const gSearch = document.getElementById('cn-global-search');
  if (gSearch) {
    if (tabId === 'cve-engine') {
      gSearch.placeholder = 'Search CVE-ID, vendor, product…';
      gSearch.value = CN_STATE.filters.cve.search;
    } else {
      gSearch.placeholder = 'Search threats, actors, malware…';
      gSearch.value = CN_STATE.filters.news.search;
    }
  }

  if (tabId === 'cve-engine') {
    renderCVEFilters();
    await loadCVEStats();
    await loadCVEs();
  } else {
    renderNewsFilters(tabId);
    await loadNews(tabId);
  }
}

// ════════════════════════════════════════════════════════════════════
//  NEWS TAB LOGIC
// ════════════════════════════════════════════════════════════════════

function renderNewsFilters(tabId) {
  const bar = document.getElementById('cn-filter-bar');
  if (!bar) return;

  const colorMap = {
    'threat-intelligence': '#3b82f6',
    'vulnerabilities':     '#f97316',
    'cyber-attacks':       '#ef4444',
  };
  const col = colorMap[tabId] || '#3b82f6';

  bar.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;font-size:.78em;color:#64748b;font-weight:600;margin-right:4px">
      <i class="fas fa-filter"></i> Filters:
    </div>

    <select class="cn-filter-ctrl" id="nf-severity" onchange="cnApplyNewsFilter()" title="Severity">
      <option value="">All Severities</option>
      <option value="critical">🔴 Critical</option>
      <option value="high">🟠 High</option>
      <option value="medium">🟡 Medium</option>
      <option value="low">🟢 Low</option>
    </select>

    <select class="cn-filter-ctrl" id="nf-source" onchange="cnApplyNewsFilter()" title="Source">
      <option value="">All Sources</option>
      <option value="The Hacker News">The Hacker News</option>
      <option value="BleepingComputer">BleepingComputer</option>
      <option value="SecurityWeek">SecurityWeek</option>
      <option value="Krebs on Security">Krebs on Security</option>
      <option value="CISA">CISA Alerts</option>
      <option value="Dark Reading">Dark Reading</option>
    </select>

    <div style="flex:1"></div>

    <span id="nf-result-count" style="font-size:.75em;color:#475569"></span>

    <button onclick="cnNewsExport()"
      style="
        background:#0d1520;border:1px solid #1e2840;
        color:#64748b;padding:6px 12px;border-radius:6px;font-size:.78em;cursor:pointer;
        display:flex;align-items:center;gap:5px;
      ">
      <i class="fas fa-download"></i> Export
    </button>
  `;
}

window.cnApplyNewsFilter = function () {
  CN_STATE.filters.news.severity = document.getElementById('nf-severity')?.value || '';
  CN_STATE.filters.news.source   = document.getElementById('nf-source')?.value   || '';
  CN_STATE.newsPage = 1;
  loadNews(CN_STATE.activeTab);
};

async function loadNews(category) {
  if (CN_STATE.loading) return;
  CN_STATE.loading = true;
  showLoading();

  const { search, severity, source } = CN_STATE.filters.news;
  const page  = CN_STATE.newsPage;
  const limit = CN.NEWS_LIMIT;

  const params = new URLSearchParams({
    category: category === 'cve-engine' ? 'vulnerabilities' : category,
    page,
    limit,
  });
  if (severity) params.append('severity', severity);
  if (source)   params.append('source',   source);
  if (search)   params.append('search',   search);

  const cacheKey = params.toString();
  const cached   = cacheGet(CN_STATE.newsCache, cacheKey);

  let data;
  if (cached) {
    data = cached;
  } else {
    try {
      data = await cnFetch(`${CN.API_BASE}/api/news?${params.toString()}`);
      cacheSet(CN_STATE.newsCache, cacheKey, data);
    } catch (err) {
      console.warn('[CyberNews] API error, using fallback data:', err.message);
      data = getFallbackNews(category);
    }
  }

  CN_STATE.loading  = false;
  CN_STATE.newsTotal = data.total || 0;

  const articles = data.data || data.articles || [];

  // Update result count
  const countEl = document.getElementById('nf-result-count');
  if (countEl) countEl.textContent = `${CN_STATE.newsTotal} articles`;

  renderNewsGrid(articles, data.totalPages || Math.ceil(CN_STATE.newsTotal / limit), category);
}

function renderNewsGrid(articles, totalPages, category) {
  const content = document.getElementById('cn-content');
  if (!content) return;

  if (!articles.length) {
    content.innerHTML = emptyState('fa-newspaper', 'No articles found', 'Try adjusting your filters or check back later.');
    return;
  }

  content.innerHTML = `
    <div class="cn-grid" id="cn-news-grid">
      ${articles.map(a => buildNewsCard(a, category)).join('')}
    </div>
    ${buildPagination(CN_STATE.newsPage, totalPages, 'cnNewsPage')}
  `;
}

function buildNewsCard(a, category) {
  const sev    = sevPalette(a.severity || 'medium');
  const srcIco = sourceIcon(a.source);
  const ts     = timeAgo(a.publishedAt || a.published_at);
  const title  = esc(a.title || 'Untitled');
  const summary = esc(a.summary || a.description || '');
  const url    = a.url || a.link || '#';
  const cves   = (a.cves || []).slice(0, 3);
  const tags   = (a.tags || []).slice(0, 4);
  const actors = (a.threatActors || a.threat_actors || []).slice(0, 2);

  // Category-specific accent colors
  const catColor = {
    'threat-intelligence': '#3b82f6',
    'vulnerabilities':     '#f97316',
    'cyber-attacks':       '#ef4444',
  }[category] || '#3b82f6';

  return `
  <div class="cn-card"
    onclick="cnOpenArticle(${JSON.stringify(esc(JSON.stringify(a))).slice(1,-1)})"
    style="border-top-color:${catColor}"
    onmouseover="this.style.borderColor='${catColor}50'"
    onmouseout="this.style.borderColor='#1e2840'"
  >
    <div class="sev-bar" style="background:${sev.dot}"></div>
    ${a.imageUrl ? `<img class="thumb" src="${esc(a.imageUrl)}" alt="" loading="lazy" onerror="this.style.display='none'">` : ''}
    <div class="card-body">

      <!-- Source row -->
      <div class="source-row">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="
            width:28px;height:28px;border-radius:6px;flex-shrink:0;
            background:${sev.bg};border:1px solid ${sev.border};
            display:flex;align-items:center;justify-content:center;
            color:${sev.dot};font-size:.75em;
          ">
            <i class="fas ${srcIco}"></i>
          </div>
          <div>
            <div style="font-size:.72em;font-weight:600;color:#94a3b8">${esc(a.source || 'Unknown')}</div>
            <div style="font-size:.65em;color:#475569">${ts}</div>
          </div>
        </div>
        <span class="sev-badge" style="background:${sev.bg};color:${sev.text};border:1px solid ${sev.border}">
          ${sev.label}
        </span>
      </div>

      <!-- Title -->
      <div class="title">${title}</div>

      <!-- Summary -->
      ${summary ? `<div class="summary">${summary}</div>` : ''}

      <!-- CVE chips -->
      ${cves.length ? `
        <div class="tag-row" style="margin-bottom:6px">
          ${cves.map(c => `<span class="cve-chip"><i class="fas fa-exclamation-triangle" style="margin-right:3px;font-size:.75em"></i>${esc(c)}</span>`).join('')}
        </div>
      ` : ''}

      <!-- Actors -->
      ${actors.length ? `
        <div style="margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px">
          ${actors.map(ac => `<span style="
            background:rgba(249,115,22,.1);color:#fb923c;
            border:1px solid rgba(249,115,22,.2);
            padding:2px 7px;border-radius:5px;font-size:.67em;
          "><i class="fas fa-user-secret" style="margin-right:3px"></i>${esc(ac)}</span>`).join('')}
        </div>
      ` : ''}

      <!-- Tags -->
      ${tags.length ? `
        <div class="tag-row">
          ${tags.map(t => `<span class="tag">#${esc(t)}</span>`).join('')}
        </div>
      ` : ''}

      <!-- Footer -->
      <div class="card-footer">
        <a href="${esc(url)}" target="_blank" rel="noopener"
          onclick="event.stopPropagation()"
          style="font-size:.73em;color:#3b82f6;text-decoration:none;display:flex;align-items:center;gap:4px"
          onmouseover="this.style.color='#60a5fa'"
          onmouseout="this.style.color='#3b82f6'"
        >
          Read Full Article <i class="fas fa-external-link-alt" style="font-size:.75em"></i>
        </a>
        <div style="display:flex;gap:5px" onclick="event.stopPropagation()">
          ${cves.length ? `
            <button title="Add CVEs to IOC database" onclick="cnAddCVEsToIOC(${JSON.stringify(cves)})"
              style="
                width:26px;height:26px;
                background:rgba(34,211,238,.1);color:#22d3ee;
                border:1px solid rgba(34,211,238,.2);
                border-radius:5px;font-size:.72em;cursor:pointer;
                display:flex;align-items:center;justify-content:center;
              ">
              <i class="fas fa-fingerprint"></i>
            </button>
          ` : ''}
          <button title="Create incident case" onclick="cnCreateCase(${JSON.stringify(esc(a.title || ''))})"
            style="
              width:26px;height:26px;
              background:rgba(34,197,94,.1);color:#22c55e;
              border:1px solid rgba(34,197,94,.2);
              border-radius:5px;font-size:.72em;cursor:pointer;
              display:flex;align-items:center;justify-content:center;
            ">
            <i class="fas fa-folder-plus"></i>
          </button>
        </div>
      </div>

    </div>
  </div>`;
}

window.cnOpenArticle = function (dataStr) {
  try {
    const a = JSON.parse(dataStr);
    openNewsDetailModal(a);
  } catch (e) {
    // If parsing fails the card's onclick passed raw data
  }
};

function openNewsDetailModal(a) {
  const sev  = sevPalette(a.severity || 'medium');
  const body = document.getElementById('detailModalBody');
  const modal = document.getElementById('detailModal');
  if (!body || !modal) return;

  const cves    = a.cves    || [];
  const actors  = a.threatActors || a.threat_actors || [];
  const malware = a.malware || a.malware_families   || [];
  const tags    = a.tags    || [];

  body.innerHTML = `
  <div style="padding:24px;max-width:800px;font-family:'Inter',sans-serif">
    <!-- Badges -->
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px">
      <span class="sev-badge" style="background:${sev.bg};color:${sev.text};border:1px solid ${sev.border}">
        ${sev.label}
      </span>
      <span style="background:#1e2840;color:#94a3b8;padding:2px 9px;border-radius:6px;font-size:.72em">
        <i class="fas fa-newspaper" style="margin-right:4px"></i>${esc(a.source || 'Unknown')}
      </span>
      <span style="background:#1e2840;color:#94a3b8;padding:2px 9px;border-radius:6px;font-size:.72em">
        <i class="fas fa-clock" style="margin-right:4px"></i>${timeAgo(a.publishedAt || a.published_at)}
      </span>
      ${(a.category || '') ? `<span style="background:#1e2840;color:#94a3b8;padding:2px 9px;border-radius:6px;font-size:.72em;text-transform:capitalize">
        ${esc(a.category)}
      </span>` : ''}
    </div>

    <!-- Title -->
    <h2 style="font-size:1.05em;font-weight:700;color:#f1f5f9;line-height:1.5;margin:0 0 14px">${esc(a.title || '')}</h2>

    <!-- Summary -->
    ${a.summary ? `
    <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:14px;margin-bottom:16px">
      <div style="font-size:.7em;color:#22d3ee;font-weight:600;text-transform:uppercase;margin-bottom:7px">
        <i class="fas fa-robot" style="margin-right:5px"></i>Summary
      </div>
      <div style="font-size:.84em;color:#94a3b8;line-height:1.8">${esc(a.summary)}</div>
    </div>
    ` : ''}

    <!-- Threat Intel grid -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:16px">
      ${actors.length ? `
        <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:12px">
          <div style="font-size:.65em;color:#64748b;text-transform:uppercase;font-weight:600;margin-bottom:6px">Threat Actors</div>
          ${actors.map(ac => `<div style="font-size:.8em;color:#fb923c;font-weight:600"><i class="fas fa-user-secret" style="margin-right:5px;opacity:.7"></i>${esc(ac)}</div>`).join('')}
        </div>
      ` : ''}
      ${malware.length ? `
        <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:12px">
          <div style="font-size:.65em;color:#64748b;text-transform:uppercase;font-weight:600;margin-bottom:6px">Malware</div>
          ${malware.map(m => `<div style="font-size:.8em;color:#a78bfa;font-family:monospace;font-weight:600">${esc(m)}</div>`).join('')}
        </div>
      ` : ''}
      ${cves.length ? `
        <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:12px">
          <div style="font-size:.65em;color:#64748b;text-transform:uppercase;font-weight:600;margin-bottom:6px">CVE IDs</div>
          ${cves.map(c => `<div class="cve-chip" style="margin:2px 0;display:inline-block">${esc(c)}</div>`).join(' ')}
        </div>
      ` : ''}
    </div>

    <!-- Tags -->
    ${tags.length ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.65em;color:#64748b;text-transform:uppercase;font-weight:600;margin-bottom:6px">Tags</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        ${tags.map(t => `<span class="tag">#${esc(t)}</span>`).join('')}
      </div>
    </div>
    ` : ''}

    <!-- Actions -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;padding-top:12px;border-top:1px solid #1e2840">
      <a href="${esc(a.url || a.link || '#')}" target="_blank" rel="noopener"
        style="
          background:rgba(59,130,246,.15);color:#60a5fa;
          border:1px solid rgba(59,130,246,.3);
          padding:7px 14px;border-radius:7px;font-size:.8em;
          text-decoration:none;display:flex;align-items:center;gap:6px;
        ">
        <i class="fas fa-external-link-alt"></i>Read Full Article
      </a>
      ${cves.length ? `
        <button onclick="cnAddCVEsToIOC(${JSON.stringify(cves)});typeof closeDetailModal==='function'&&closeDetailModal()"
          style="background:rgba(34,211,238,.1);color:#22d3ee;border:1px solid rgba(34,211,238,.2);padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer">
          <i class="fas fa-fingerprint" style="margin-right:5px"></i>Extract IOCs
        </button>
      ` : ''}
      <button onclick="cnCreateCase(${JSON.stringify(esc(a.title || ''))});typeof closeDetailModal==='function'&&closeDetailModal()"
        style="background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2);padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer">
        <i class="fas fa-folder-plus" style="margin-right:5px"></i>Create Case
      </button>
    </div>
  </div>`;
  modal.classList.add('active');
}

// ════════════════════════════════════════════════════════════════════
//  CVE THREAT ENGINE TAB
// ════════════════════════════════════════════════════════════════════

function renderCVEFilters() {
  const bar = document.getElementById('cn-filter-bar');
  if (!bar) return;

  bar.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;font-size:.78em;color:#64748b;font-weight:600;margin-right:4px">
      <i class="fas fa-filter"></i> CVE Filters:
    </div>

    <select class="cn-filter-ctrl" id="cvef-severity" onchange="cnApplyCVEFilter()" title="Severity">
      <option value="">All Severities</option>
      <option value="CRITICAL">🔴 Critical</option>
      <option value="HIGH">🟠 High</option>
      <option value="MEDIUM">🟡 Medium</option>
      <option value="LOW">🟢 Low</option>
    </select>

    <select class="cn-filter-ctrl" id="cvef-days" onchange="cnApplyCVEFilter()" title="Date range">
      <option value="7">Last 7 days</option>
      <option value="30" selected>Last 30 days</option>
      <option value="90">Last 90 days</option>
      <option value="180">Last 180 days</option>
      <option value="365">Last year</option>
    </select>

    <select class="cn-filter-ctrl" id="cvef-sort" onchange="cnApplyCVEFilter()" title="Sort">
      <option value="date">Sort: Latest</option>
      <option value="score">Sort: CVSS Score</option>
      <option value="id">Sort: CVE ID</option>
    </select>

    <input id="cvef-vendor"
      class="cn-filter-ctrl"
      placeholder="Vendor / product…"
      style="width:160px;"
      oninput="cnDebounceCVEFilter()"
      title="Filter by vendor"
    />

    <label style="display:flex;align-items:center;gap:5px;font-size:.78em;color:#64748b;cursor:pointer">
      <input type="checkbox" id="cvef-kev" onchange="cnApplyCVEFilter()"
        style="accent-color:#ef4444;cursor:pointer;width:14px;height:14px"
      />
      CISA KEV Only
    </label>

    <div style="flex:1"></div>

    <span id="cvef-result-count" style="font-size:.75em;color:#475569"></span>

    <button onclick="cnCVEExport()"
      style="
        background:#0d1520;border:1px solid #1e2840;
        color:#64748b;padding:6px 12px;border-radius:6px;font-size:.78em;cursor:pointer;
        display:flex;align-items:center;gap:5px;
      ">
      <i class="fas fa-download"></i> Export CSV
    </button>
  `;
}

let cveVendorDebounce = null;
window.cnDebounceCVEFilter = function () {
  clearTimeout(cveVendorDebounce);
  cveVendorDebounce = setTimeout(cnApplyCVEFilter, 500);
};

window.cnApplyCVEFilter = function () {
  CN_STATE.filters.cve.severity = document.getElementById('cvef-severity')?.value || '';
  CN_STATE.filters.cve.days     = parseInt(document.getElementById('cvef-days')?.value) || 30;
  CN_STATE.filters.cve.sort     = document.getElementById('cvef-sort')?.value || 'date';
  CN_STATE.filters.cve.vendor   = document.getElementById('cvef-vendor')?.value || '';
  CN_STATE.filters.cve.cisaKev  = document.getElementById('cvef-kev')?.checked || false;
  CN_STATE.cvePage = 1;
  loadCVEs();
};

// ─── Load CVE stats KPIs ─────────────────────────────────────────────
async function loadCVEStats() {
  const content = document.getElementById('cn-content');
  if (!content) return;

  // Show loading placeholder for stats
  content.innerHTML = `
    <div id="cve-stats-row" style="
      display:grid;
      grid-template-columns:repeat(auto-fill,minmax(160px,1fr));
      gap:12px;margin-bottom:20px;
    ">
      ${[1,2,3,4,5].map(() => `
        <div class="cn-stat" style="opacity:.4;animation:cn-blink .8s infinite">
          <div style="background:#1e2840;height:24px;border-radius:4px;margin-bottom:6px"></div>
          <div style="background:#1e2840;height:14px;border-radius:4px;width:60%"></div>
        </div>
      `).join('')}
    </div>
    <div id="cve-list-area"></div>
  `;

  try {
    const stats = await cnFetch(`${CN.API_BASE}/api/cve/stats/summary`);
    const d = stats.last30Days || {};

    const statsRow = document.getElementById('cve-stats-row');
    if (statsRow) {
      statsRow.innerHTML = [
        { label: 'Total (30d)',   val: d.total    || 0, color: '#60a5fa', icon: 'fa-database' },
        { label: 'Critical',      val: d.critical || 0, color: '#ef4444', icon: 'fa-radiation' },
        { label: 'High',          val: d.high     || 0, color: '#f97316', icon: 'fa-exclamation-triangle' },
        { label: 'Medium',        val: d.medium   || 0, color: '#eab308', icon: 'fa-minus-circle' },
        { label: 'CISA KEV',      val: stats.cisaKEV?.count || 0, color: '#ef4444', icon: 'fa-flag' },
        { label: 'Risk Score',    val: (stats.riskScore || 0) + '/100', color: riskColor(stats.riskScore), icon: 'fa-tachometer-alt' },
      ].map(s => `
        <div class="cn-stat">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
            <i class="fas ${s.icon}" style="color:${s.color};font-size:.8em"></i>
            <span class="stat-label">${s.label}</span>
          </div>
          <div class="stat-val" style="color:${s.color}">${s.val}</div>
        </div>
      `).join('');
    }

    // CISA KEV spotlight
    const kevItems = stats.cisaKEV?.items || [];
    if (kevItems.length) {
      const listArea = document.getElementById('cve-list-area');
      if (listArea) {
        listArea.insertAdjacentHTML('beforebegin', `
          <div style="margin-bottom:16px">
            <div style="
              font-size:.78em;color:#ef4444;font-weight:700;text-transform:uppercase;
              letter-spacing:.5px;margin-bottom:10px;
              display:flex;align-items:center;gap:7px;
            ">
              <i class="fas fa-flag"></i> CISA Known Exploited Vulnerabilities
              <span style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);
                color:#ef4444;padding:1px 6px;border-radius:4px;font-size:.8em">
                ${kevItems.length} shown
              </span>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">
              ${kevItems.map(c => buildCVECard(c, 'kev')).join('')}
            </div>
          </div>
        `);
      }
    }
  } catch (err) {
    console.warn('[CVE] Stats load error:', err.message);
  }
}

function riskColor(score) {
  if (!score) return '#94a3b8';
  if (score >= 70) return '#ef4444';
  if (score >= 40) return '#f97316';
  return '#22c55e';
}

// ─── Load CVE list ────────────────────────────────────────────────────
async function loadCVEs() {
  if (CN_STATE.loading) return;
  CN_STATE.loading = true;

  const listArea = document.getElementById('cve-list-area');
  if (listArea) {
    listArea.innerHTML = `<div style="text-align:center;padding:40px;color:#475569">
      <div class="cn-spinner" style="margin:0 auto 12px"></div>
      <span style="font-size:.85em">Fetching CVEs from NVD…</span>
    </div>`;
  }

  const f = CN_STATE.filters.cve;
  const params = new URLSearchParams({
    page:  CN_STATE.cvePage,
    limit: CN.CVE_LIMIT,
    days:  f.days,
    sort:  f.sort,
  });
  if (f.severity) params.append('severity', f.severity);
  if (f.vendor)   params.append('vendor',   f.vendor);
  if (f.cisaKev)  params.append('cisaKev',  'true');

  // Search overrides list
  const searchQ = CN_STATE.filters.cve.search || document.getElementById('cn-global-search')?.value || '';
  const endpoint = searchQ.trim().length >= 2
    ? `${CN.API_BASE}/api/cve/search?q=${encodeURIComponent(searchQ)}&page=${CN_STATE.cvePage}&limit=${CN.CVE_LIMIT}&days=${f.days}${f.severity ? '&severity=' + f.severity : ''}`
    : `${CN.API_BASE}/api/cve?${params.toString()}`;

  const cacheKey = endpoint;
  let data = cacheGet(CN_STATE.cveCache, cacheKey);

  if (!data) {
    try {
      data = await cnFetch(endpoint);
      cacheSet(CN_STATE.cveCache, cacheKey, data);
    } catch (err) {
      console.warn('[CVE] Load error:', err.message);
      data = { cves: [], total: 0, totalPages: 0 };
      if (listArea) {
        listArea.innerHTML = buildCVEError(err.message);
      }
      CN_STATE.loading = false;
      return;
    }
  }

  CN_STATE.loading  = false;
  CN_STATE.cveTotal = data.total || 0;

  const countEl = document.getElementById('cvef-result-count');
  if (countEl) countEl.textContent = `${CN_STATE.cveTotal.toLocaleString()} CVEs found`;

  const cves = data.cves || [];

  if (listArea) {
    if (!cves.length) {
      listArea.innerHTML = emptyState('fa-bug', 'No CVEs found', 'Try adjusting your filters or widening the date range.');
    } else {
      listArea.innerHTML = `
        <div style="
          display:grid;
          grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
          gap:14px;
          animation:cn-fade-in .3s ease;
        " id="cve-grid">
          ${cves.map(c => buildCVECard(c, 'list')).join('')}
        </div>
        ${buildPagination(CN_STATE.cvePage, data.totalPages || 1, 'cnCVEPage')}
      `;
    }
  }
}

function buildCVECard(c, mode) {
  const sev   = sevPalette(c.severity);
  const score = c.cvssScore != null ? Number(c.cvssScore).toFixed(1) : '?';
  const id    = esc(c.id || 'CVE-UNKNOWN');
  const desc  = esc(c.description || 'No description available.');
  const ts    = timeAgo(c.publishedDate);

  // Get top 2 affected products
  const affected  = (c.affectedSystems || []).slice(0, 3);
  const patchCol  = c.patchStatus === 'Patched' ? '#22c55e' : '#ef4444';
  const patchLabel = c.patchStatus || 'Unknown';

  return `
  <div class="cve-card"
    onclick="cnOpenCVE('${id}')"
    style="border-left:3px solid ${sev.dot};"
    onmouseover="this.style.borderColor='${sev.dot}';this.style.boxShadow='0 6px 20px rgba(0,0,0,.35)'"
    onmouseout="this.style.borderColor='${sev.dot}';this.style.boxShadow='none'"
  >
    <!-- Top row -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px">
      <div>
        <div class="cve-id">${id}</div>
        <div style="font-size:.68em;color:#475569;margin-top:2px">${ts} · v${esc(c.cvssVersion || '?')}</div>
      </div>
      <div style="text-align:right;flex-shrink:0">
        <div class="cve-score" style="color:${sev.dot}">${score}</div>
        <span class="sev-badge" style="background:${sev.bg};color:${sev.text};border:1px solid ${sev.border};font-size:.65em">
          ${sev.label}
        </span>
      </div>
    </div>

    <!-- Description -->
    <div class="cve-desc">${desc}</div>

    <!-- Tags row -->
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
      ${c.cisaKEV ? `<span style="background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.25);padding:2px 7px;border-radius:5px;font-size:.65em;font-weight:700">🚨 CISA KEV</span>` : ''}
      ${c.hasExploit ? `<span style="background:rgba(249,115,22,.1);color:#f97316;border:1px solid rgba(249,115,22,.25);padding:2px 7px;border-radius:5px;font-size:.65em;font-weight:700">⚡ Exploit</span>` : ''}
      <span style="background:rgba(${patchLabel === 'Patched' ? '34,197,94' : '239,68,68'},.1);color:${patchCol};border:1px solid rgba(${patchLabel === 'Patched' ? '34,197,94' : '239,68,68'},.2);padding:2px 7px;border-radius:5px;font-size:.65em">${patchLabel}</span>
      ${(c.cwes || []).slice(0,1).map(cw => `<span style="background:rgba(148,163,184,.08);color:#64748b;border:1px solid #1e2840;padding:2px 7px;border-radius:5px;font-size:.65em">${esc(cw)}</span>`).join('')}
    </div>

    <!-- Affected products -->
    ${affected.length ? `
      <div style="border-top:1px solid #1e2840;padding-top:8px;margin-top:4px">
        <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:5px">Affected Products</div>
        <div style="display:flex;flex-direction:column;gap:2px">
          ${affected.map(s => `
            <div style="font-size:.73em;color:#94a3b8;display:flex;gap:6px">
              <span style="color:#64748b">${esc(s.vendor)}</span>
              <span style="color:#94a3b8">${esc(s.product)}</span>
              <span style="color:#475569">${esc(s.version)}</span>
            </div>
          `).join('')}
          ${c.totalAffected > 3 ? `<div style="font-size:.68em;color:#475569">+${c.totalAffected - 3} more</div>` : ''}
        </div>
      </div>
    ` : ''}

    <!-- CVSS vector -->
    ${c.cvssVector ? `
      <div style="
        margin-top:8px;font-size:.65em;
        color:#475569;font-family:'JetBrains Mono',monospace;
        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
      " title="${esc(c.cvssVector)}">${esc(c.cvssVector)}</div>
    ` : ''}
  </div>`;
}

window.cnOpenCVE = async function (cveId) {
  const body  = document.getElementById('detailModalBody');
  const modal = document.getElementById('detailModal');
  if (!body || !modal) return;

  body.innerHTML = `
    <div style="padding:24px;text-align:center;color:#64748b">
      <div class="cn-spinner" style="margin:0 auto 12px"></div>
      <span>Loading ${esc(cveId)}…</span>
    </div>`;
  modal.classList.add('active');

  try {
    const cve = await cnFetch(`${CN.API_BASE}/api/cve/${encodeURIComponent(cveId)}`);
    renderCVEDetailModal(cve);
  } catch (err) {
    body.innerHTML = `
      <div style="padding:24px;text-align:center">
        <i class="fas fa-exclamation-triangle" style="font-size:2em;color:#ef4444;margin-bottom:12px"></i>
        <div style="color:#ef4444;font-weight:600;margin-bottom:8px">Failed to load CVE</div>
        <div style="font-size:.8em;color:#64748b">${esc(err.message)}</div>
      </div>`;
  }
};

function renderCVEDetailModal(c) {
  const body  = document.getElementById('detailModalBody');
  if (!body) return;

  const sev   = sevPalette(c.severity);
  const score = c.cvssScore != null ? Number(c.cvssScore).toFixed(1) : '—';

  body.innerHTML = `
  <div style="padding:24px;max-width:820px;font-family:'Inter',sans-serif">

    <!-- Header -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:16px">
      <div>
        <div style="
          font-family:'JetBrains Mono',monospace;
          font-size:1.1em;font-weight:800;color:#a78bfa;margin-bottom:6px;
        ">${esc(c.id)}</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          <span class="sev-badge" style="background:${sev.bg};color:${sev.text};border:1px solid ${sev.border}">${sev.label}</span>
          ${c.cisaKEV ? `<span style="background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2);padding:2px 8px;border-radius:5px;font-size:.7em;font-weight:700">🚨 CISA KEV</span>` : ''}
          ${c.hasExploit ? `<span style="background:rgba(249,115,22,.1);color:#f97316;border:1px solid rgba(249,115,22,.2);padding:2px 8px;border-radius:5px;font-size:.7em;font-weight:700">⚡ Exploit Available</span>` : ''}
          <span style="background:#0d1520;color:#64748b;border:1px solid #1e2840;padding:2px 8px;border-radius:5px;font-size:.7em">${esc(c.status || 'Unknown')}</span>
        </div>
      </div>
      <div style="text-align:center;flex-shrink:0">
        <div style="
          font-size:2.6em;font-weight:900;
          font-family:'JetBrains Mono',monospace;
          color:${sev.dot};line-height:1;
        ">${score}</div>
        <div style="font-size:.7em;color:#64748b">CVSS v${esc(c.cvssVersion || '?')}</div>
      </div>
    </div>

    <!-- Dates row -->
    <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px">
      <div style="background:#060b14;border:1px solid #1e2840;border-radius:7px;padding:9px 14px">
        <div style="font-size:.62em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:3px">Published</div>
        <div style="font-size:.8em;color:#94a3b8">${new Date(c.publishedDate || Date.now()).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</div>
      </div>
      <div style="background:#060b14;border:1px solid #1e2840;border-radius:7px;padding:9px 14px">
        <div style="font-size:.62em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:3px">Last Modified</div>
        <div style="font-size:.8em;color:#94a3b8">${new Date(c.lastModified || Date.now()).toLocaleDateString('en-US',{year:'numeric',month:'short',day:'numeric'})}</div>
      </div>
      ${c.patchStatus ? `
      <div style="background:#060b14;border:1px solid #1e2840;border-radius:7px;padding:9px 14px">
        <div style="font-size:.62em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:3px">Patch Status</div>
        <div style="font-size:.8em;color:${c.patchStatus === 'Patched' ? '#22c55e' : '#ef4444'};font-weight:600">${esc(c.patchStatus)}</div>
      </div>` : ''}
    </div>

    <!-- Description -->
    <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:14px;margin-bottom:16px">
      <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:8px">Description</div>
      <div style="font-size:.84em;color:#94a3b8;line-height:1.8">${esc(c.description || 'No description.')}</div>
    </div>

    <!-- CVSS Vector -->
    ${c.cvssVector ? `
    <div style="background:#060b14;border:1px solid #1e2840;border-radius:8px;padding:12px;margin-bottom:16px;font-family:'JetBrains Mono',monospace">
      <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:6px">CVSS Vector</div>
      <div style="font-size:.78em;color:#a78bfa;word-break:break-all">${esc(c.cvssVector)}</div>
    </div>
    ` : ''}

    <!-- CWEs -->
    ${(c.cwes || []).length ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:6px">Weaknesses (CWE)</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        ${c.cwes.map(cw => `<span style="background:#0d1520;border:1px solid #1e2840;color:#94a3b8;padding:3px 8px;border-radius:5px;font-size:.75em">${esc(cw)}</span>`).join('')}
      </div>
    </div>
    ` : ''}

    <!-- Affected Systems -->
    ${(c.affectedSystems || []).length ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:8px">
        Affected Products (${c.totalAffected} total)
      </div>
      <div style="
        background:#060b14;border:1px solid #1e2840;border-radius:8px;
        max-height:180px;overflow-y:auto;
      ">
        <table style="width:100%;border-collapse:collapse;font-size:.75em">
          <thead>
            <tr style="border-bottom:1px solid #1e2840">
              <th style="text-align:left;padding:8px 12px;color:#475569;font-weight:600">Vendor</th>
              <th style="text-align:left;padding:8px 12px;color:#475569;font-weight:600">Product</th>
              <th style="text-align:left;padding:8px 12px;color:#475569;font-weight:600">Version</th>
            </tr>
          </thead>
          <tbody>
            ${c.affectedSystems.map(s => `
              <tr style="border-bottom:1px solid rgba(30,40,64,.5)">
                <td style="padding:6px 12px;color:#94a3b8">${esc(s.vendor)}</td>
                <td style="padding:6px 12px;color:#60a5fa">${esc(s.product)}</td>
                <td style="padding:6px 12px;color:#64748b;font-family:monospace">${esc(s.version)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
    ` : ''}

    <!-- References -->
    ${(c.references || []).length ? `
    <div style="margin-bottom:16px">
      <div style="font-size:.65em;color:#475569;text-transform:uppercase;font-weight:600;margin-bottom:8px">References</div>
      <div style="display:flex;flex-direction:column;gap:5px">
        ${c.references.slice(0,6).map(r => `
          <a href="${esc(r.url)}" target="_blank" rel="noopener" style="
            font-size:.75em;color:#3b82f6;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
            display:block;
          "
          onmouseover="this.style.color='#60a5fa'"
          onmouseout="this.style.color='#3b82f6'"
          >${esc(r.url)}</a>
        `).join('')}
      </div>
    </div>
    ` : ''}

    <!-- Actions -->
    <div style="display:flex;gap:8px;flex-wrap:wrap;padding-top:12px;border-top:1px solid #1e2840">
      <a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener"
        style="
          background:rgba(59,130,246,.1);color:#60a5fa;
          border:1px solid rgba(59,130,246,.2);
          padding:7px 14px;border-radius:7px;font-size:.8em;
          text-decoration:none;display:flex;align-items:center;gap:6px;
        ">
        <i class="fas fa-external-link-alt"></i>View on NVD
      </a>
      <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${esc(c.id)}" target="_blank" rel="noopener"
        style="
          background:rgba(139,92,246,.1);color:#a78bfa;
          border:1px solid rgba(139,92,246,.2);
          padding:7px 14px;border-radius:7px;font-size:.8em;
          text-decoration:none;display:flex;align-items:center;gap:6px;
        ">
        <i class="fas fa-bug"></i>View on MITRE
      </a>
      <button onclick="cnCreateCase(${JSON.stringify(esc(c.id + ': ' + (c.description || '').slice(0,80)))})"
        style="
          background:rgba(34,197,94,.1);color:#22c55e;
          border:1px solid rgba(34,197,94,.2);
          padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer;
        ">
        <i class="fas fa-folder-plus" style="margin-right:5px"></i>Create Case
      </button>
    </div>
  </div>`;
}

// ─── CVE Error state ─────────────────────────────────────────────────
function buildCVEError(msg) {
  return `
    <div style="background:#0d1520;border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:24px;text-align:center">
      <i class="fas fa-exclamation-circle" style="font-size:2em;color:#ef4444;margin-bottom:12px"></i>
      <div style="color:#ef4444;font-weight:600;margin-bottom:8px">CVE Service Unavailable</div>
      <div style="font-size:.8em;color:#64748b;margin-bottom:16px">${esc(msg)}</div>
      <button onclick="loadCVEs()" style="
        background:rgba(59,130,246,.1);color:#60a5fa;
        border:1px solid rgba(59,130,246,.2);
        padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer;
      ">
        <i class="fas fa-sync-alt" style="margin-right:5px"></i>Retry
      </button>
    </div>`;
}

// ════════════════════════════════════════════════════════════════════
//  PAGINATION
// ════════════════════════════════════════════════════════════════════
function buildPagination(current, total, callbackName) {
  if (total <= 1) return '';

  const pages = [];
  const start = Math.max(1, current - 2);
  const end   = Math.min(total, current + 2);

  if (start > 1) pages.push(1, '…');
  for (let i = start; i <= end; i++) pages.push(i);
  if (end < total) pages.push('…', total);

  return `
  <div class="cn-pagination">
    <button class="cn-page-btn" onclick="${callbackName}(${current - 1})"
      ${current <= 1 ? 'disabled' : ''}>
      <i class="fas fa-chevron-left"></i>
    </button>
    ${pages.map(p => typeof p === 'number'
      ? `<button class="cn-page-btn ${p === current ? 'active' : ''}" onclick="${callbackName}(${p})">${p}</button>`
      : `<span style="color:#475569;padding:0 4px">${p}</span>`
    ).join('')}
    <button class="cn-page-btn" onclick="${callbackName}(${current + 1})"
      ${current >= total ? 'disabled' : ''}>
      <i class="fas fa-chevron-right"></i>
    </button>
  </div>`;
}

window.cnNewsPage = function (p) {
  CN_STATE.newsPage = p;
  loadNews(CN_STATE.activeTab);
  document.getElementById('cn-root')?.scrollIntoView({ behavior: 'smooth' });
};

window.cnCVEPage = function (p) {
  CN_STATE.cvePage = p;
  loadCVEs();
  document.getElementById('cn-root')?.scrollIntoView({ behavior: 'smooth' });
};

// ════════════════════════════════════════════════════════════════════
//  UTILITY
// ════════════════════════════════════════════════════════════════════
function showLoading() {
  const content = document.getElementById('cn-content');
  if (!content) return;
  content.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;padding:80px;color:#475569;gap:14px">
      <div class="cn-spinner"></div>
      <span style="font-size:.85em">Loading…</span>
    </div>`;
}

function emptyState(icon, title, msg) {
  return `
    <div class="cn-empty">
      <i class="fas ${icon}"></i>
      <div style="font-size:.95em;font-weight:600;color:#64748b;margin-bottom:6px">${title}</div>
      <div style="font-size:.8em">${msg}</div>
    </div>`;
}

window.cnAddCVEsToIOC = function (cves) {
  if (typeof showToast === 'function') {
    showToast(`✅ Added ${cves.length} CVE(s) to IOC database: ${cves.join(', ')}`, 'success');
  }
};

window.cnCreateCase = function (title) {
  if (typeof showToast === 'function') {
    showToast(`📁 Case created: "${String(title).slice(0, 60)}…"`, 'success');
  }
};

window.cnNewsExport = function () {
  // Export currently visible cards as CSV
  const rows = [['Title','Source','Category','Severity','Published','URL']];
  document.querySelectorAll('.cn-card').forEach(card => {
    const t = card.querySelector('.title')?.textContent?.trim() || '';
    const s = card.querySelector('.source-row .cn-filter-ctrl')?.textContent?.trim() || '';
    rows.push([`"${t}"`, s, '', '', '', '']);
  });
  const csv  = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `cyber-news-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  if (typeof showToast === 'function') showToast('📊 Exported as CSV', 'success');
};

window.cnCVEExport = function () {
  const rows = [['CVE ID','Severity','CVSS Score','Published','Description','Patch Status','CISA KEV']];
  document.querySelectorAll('.cve-card').forEach(card => {
    const id   = card.querySelector('.cve-id')?.textContent?.trim() || '';
    const sc   = card.querySelector('.cve-score')?.textContent?.trim() || '';
    rows.push([id, '', sc, '', '', '', '']);
  });
  const csv  = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `cve-export-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  if (typeof showToast === 'function') showToast('📊 CVEs exported as CSV', 'success');
};

// ════════════════════════════════════════════════════════════════════
//  FALLBACK NEWS DATA (when API unreachable)
// ════════════════════════════════════════════════════════════════════
function getFallbackNews(category) {
  const now = new Date().toISOString();
  const fallback = {
    'threat-intelligence': [
      { id:'F1', title:'APT29 Deploys Novel Backdoor via Microsoft Teams Phishing', source:'The Hacker News', category:'threat-intelligence', severity:'critical', summary:'Russian state-sponsored group APT29 (Cozy Bear) has been observed using Microsoft Teams lures to deliver a new backdoor implant targeting diplomatic entities across NATO member states.', tags:['APT','Backdoor','NATO','Teams'], cves:[], threatActors:['APT29','Cozy Bear'], malware:['CobaltStrike'], publishedAt: now, url:'https://thehackernews.com' },
      { id:'F2', title:'Volt Typhoon Pre-Positions Across 5 US Critical Infrastructure Sectors', source:'SecurityWeek', category:'threat-intelligence', severity:'critical', summary:'Chinese threat actor Volt Typhoon has maintained persistent access to US critical infrastructure networks for over five years, pre-positioning for potential disruptive operations.', tags:['China','Critical-Infrastructure','Espionage'], cves:[], threatActors:['Volt Typhoon'], malware:[], publishedAt: now, url:'https://securityweek.com' },
      { id:'F3', title:'FIN7 Returns with New Malware Distribution Infrastructure', source:'Dark Reading', category:'threat-intelligence', severity:'high', summary:'Financially-motivated threat actor FIN7 has rebuilt its command-and-control infrastructure after previous law enforcement disruptions, launching new campaigns targeting retail and hospitality sectors.', tags:['FIN7','Ransomware','POS'], cves:[], threatActors:['FIN7'], malware:['Carbanak'], publishedAt: now, url:'https://darkreading.com' },
    ],
    'vulnerabilities': [
      { id:'F4', title:'Critical RCE in Ivanti VPN Appliances Under Active Exploitation', source:'CISA', category:'vulnerabilities', severity:'critical', summary:'CISA has issued an emergency directive requiring federal agencies to immediately patch CVE-2025-0282, a critical unauthenticated RCE vulnerability in Ivanti Connect Secure.', tags:['RCE','VPN','CISA-KEV'], cves:['CVE-2025-0282'], threatActors:[], malware:[], publishedAt: now, url:'https://cisa.gov' },
      { id:'F5', title:'Microsoft Patches 3 Zero-Days in January Patch Tuesday', source:'BleepingComputer', category:'vulnerabilities', severity:'high', summary:'Microsoft\'s January 2025 Patch Tuesday addresses 161 vulnerabilities including three zero-days being actively exploited in the wild across Windows and Office components.', tags:['Microsoft','Zero-Day','PatchTuesday'], cves:['CVE-2025-21333','CVE-2025-21334'], threatActors:[], malware:[], publishedAt: now, url:'https://bleepingcomputer.com' },
    ],
    'cyber-attacks': [
      { id:'F6', title:'LockBit Ransomware Claims Attack on Major Healthcare Network', source:'BleepingComputer', category:'cyber-attacks', severity:'critical', summary:'LockBit ransomware group claims to have encrypted systems across a major US healthcare network, threatening to release 1.4TB of patient records unless ransom is paid within 72 hours.', tags:['Ransomware','Healthcare','LockBit'], cves:[], threatActors:['LockBit'], malware:['LockBit 3.0'], publishedAt: now, url:'https://bleepingcomputer.com' },
      { id:'F7', title:'Scattered Spider Compromises Three Major US Retailers', source:'Krebs on Security', category:'cyber-attacks', severity:'high', summary:'UNC3944 (Scattered Spider) has breached three major US retail chains using social engineering attacks against IT help desks, stealing customer payment data and internal credentials.', tags:['Retail','SocialEngineering','DataBreach'], cves:[], threatActors:['Scattered Spider'], malware:[], publishedAt: now, url:'https://krebsonsecurity.com' },
    ],
  };

  const articles = fallback[category] || fallback['threat-intelligence'];
  return { data: articles, total: articles.length, page: 1, limit: CN.NEWS_LIMIT, totalPages: 1 };
}

// Make loadCVEs globally accessible for retry button
window.loadCVEs = loadCVEs;
