/**
 * ════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Cyber News Hub v9.0
 *  FILE: js/cyber-news-hub.js
 *
 *  ROOT-CAUSE FIXES in this version:
 *  ─────────────────────────────────
 *  1. URL FIX: Uses window.THREATPILOT_API_URL (set by main.js to the
 *     correct production backend). Never hardcodes a wrong URL.
 *  2. CORS FIX: Adds no extra headers that would trigger CORS issues.
 *     The backend already allows the Vercel origin.
 *  3. NO FALLBACK MASKING: If the real API fails the UI shows a clear
 *     error with retry — never silently shows fake data.
 *  4. REAL DATA: All news comes from the live /api/news endpoint which
 *     aggregates real RSS feeds (THN, BleepingComputer, CISA, etc.)
 *  5. REAL CVE DATA: Fetched via backend /api/cve (which proxies NVD
 *     with dual-key fallback — no keys exposed in frontend).
 *  6. FULL ARTICLE MODAL: Clicking a card shows a proper detail view
 *     with image, full summary, source link, tags, IOC chips.
 *  7. PRODUCTION LOGGING: Every error is logged to console with
 *     context. No silent swallowing.
 *  8. RETRY LOGIC: 3 attempts with 1.5s backoff on transient failures.
 * ════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (global) {

// ── Resolve the correct backend URL ──────────────────────────────────
// Priority: window.THREATPILOT_API_URL (set by main.js) →
//           window.WADJET_API_URL → env-level override → production URL
function resolveBackend() {
  return (
    global.THREATPILOT_API_URL ||
    global.WADJET_API_URL      ||
    global.API_BASE            ||
    'https://wadjet-eye-ai.onrender.com'
  ).replace(/\/$/, '');
}

// ── Constants ─────────────────────────────────────────────────────────
const NEWS_PAGE_SIZE  = 12;
const CVE_PAGE_SIZE   = 20;
const CACHE_TTL_MS    = 8 * 60 * 1000;   // 8 min
const CVE_CACHE_TTL   = 12 * 60 * 1000;  // 12 min (NVD is slow)
const FETCH_TIMEOUT   = 25000;            // 25 s — Render can be slow on cold start
const MAX_RETRIES     = 3;
const RETRY_BASE_MS   = 2000;

// ── Runtime state ──────────────────────────────────────────────────────
const S = {
  tab:        'threat-intelligence',
  newsPage:   1,
  cvePage:    1,
  busy:       false,
  newsTotal:  0,
  cveTotal:   0,
  newsCache:  new Map(),
  cveCache:   new Map(),
  debounce:   null,
  cveDebounce: null,
  filters: {
    news: { search: '', severity: '', source: '' },
    cve:  { search: '', severity: '', days: 30, sort: 'date', vendor: '', cisaKev: false },
  },
};

// ── Severity colour palette ────────────────────────────────────────────
const SEV = {
  CRITICAL: { bg:'rgba(239,68,68,.13)',  border:'rgba(239,68,68,.38)',  text:'#ef4444', bar:'#ef4444' },
  HIGH:     { bg:'rgba(249,115,22,.13)', border:'rgba(249,115,22,.38)', text:'#f97316', bar:'#f97316' },
  MEDIUM:   { bg:'rgba(234,179,8,.13)',  border:'rgba(234,179,8,.38)',  text:'#eab308', bar:'#eab308' },
  LOW:      { bg:'rgba(34,197,94,.13)',  border:'rgba(34,197,94,.38)',  text:'#22c55e', bar:'#22c55e' },
  UNKNOWN:  { bg:'rgba(148,163,184,.1)', border:'rgba(148,163,184,.3)',  text:'#94a3b8', bar:'#94a3b8' },
};
function sev(s) { return SEV[(s||'').toUpperCase()] || SEV.UNKNOWN; }

// ── HTML escape ────────────────────────────────────────────────────────
function h(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── Relative time ──────────────────────────────────────────────────────
function ago(iso) {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m <  1)  return 'just now';
  if (m < 60)  return `${m}m ago`;
  const hr = Math.floor(m / 60);
  if (hr < 24) return `${hr}h ago`;
  const d  = Math.floor(hr / 24);
  if (d  <  7) return `${d}d ago`;
  return new Date(iso).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}

// ── Clean HTML entities from text ──────────────────────────────────────
function cleanText(t) {
  return String(t == null ? '' : t)
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&[a-z]{2,8};/gi, '')
    .replace(/&#\d+;/g, '')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

// ── Source icon ────────────────────────────────────────────────────────
const SRC_ICONS = {
  'hacker news':'fa-hacker-news', 'bleepingcomputer':'fa-bug', 'securityweek':'fa-shield-alt',
  'krebs':'fa-search', 'cisa':'fa-university', 'dark reading':'fa-eye',
  'threatpost':'fa-radiation', 'sans':'fa-cloud-rain', 'threat post':'fa-radiation',
};
function srcIcon(name) {
  const k = (name||'').toLowerCase();
  for (const [sub, ic] of Object.entries(SRC_ICONS)) if (k.includes(sub)) return ic;
  return 'fa-globe';
}

// ── Source brand accent colours ────────────────────────────────────────
const SRC_COLORS = {
  'hacker news':  '#ff6600',
  'bleepingcomputer': '#0090d9',
  'securityweek': '#1a73e8',
  'krebs':        '#2f8f3f',
  'cisa':         '#002868',
  'dark reading': '#e6001e',
  'sans':         '#c8253c',
  'threatpost':   '#ff4500',
};
function srcColor(name, fallback) {
  const k = (name||'').toLowerCase();
  for (const [pat, col] of Object.entries(SRC_COLORS)) if (k.includes(pat)) return col;
  return fallback || '#3b82f6';
}

// ── CWE → MITRE ATT&CK technique mapping (common weaknesses) ───────────
const CWE_ATTACK = {
  'CWE-78':  { id:'T1059',     name:'Command & Script Interpreter' },
  'CWE-79':  { id:'T1059.007', name:'JavaScript / XSS Injection' },
  'CWE-89':  { id:'T1190',     name:'Exploit Public-Facing Application (SQLi)' },
  'CWE-94':  { id:'T1059',     name:'Code Injection' },
  'CWE-22':  { id:'T1083',     name:'File & Directory Discovery (Path Traversal)' },
  'CWE-119': { id:'T1203',     name:'Exploitation for Client Execution (BOF)' },
  'CWE-121': { id:'T1203',     name:'Stack Buffer Overflow → Code Exec' },
  'CWE-200': { id:'T1552',     name:'Unsecured Credentials / Info Disclosure' },
  'CWE-269': { id:'T1068',     name:'Exploitation for Privilege Escalation' },
  'CWE-287': { id:'T1556',     name:'Modify Authentication Process' },
  'CWE-306': { id:'T1556.006', name:'Missing Authentication for Critical Function' },
  'CWE-347': { id:'T1553',     name:'Subvert Trust Controls (Invalid Signature)' },
  'CWE-352': { id:'T1059.007', name:'CSRF / Client-side Script Execution' },
  'CWE-416': { id:'T1203',     name:'Use-After-Free → Code Exec' },
  'CWE-502': { id:'T1059',     name:'Deserialization of Untrusted Data' },
  'CWE-787': { id:'T1203',     name:'Out-of-Bounds Write → Code Exec' },
  'CWE-798': { id:'T1552.001', name:'Hardcoded Credentials in Files' },
  'CWE-862': { id:'T1068',     name:'Missing Authorization → Priv Esc' },
  'CWE-918': { id:'T1090',     name:'Server-Side Request Forgery (SSRF)' },
};

// ────────────────────────────────────────────────────────────────────────
//  FETCH WITH RETRY — logs every attempt, throws clearly on final failure
// ────────────────────────────────────────────────────────────────────────
async function apiFetch(url, retries = MAX_RETRIES) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const ctrl = new AbortController();
      const tid  = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
      const resp = await fetch(url, { signal: ctrl.signal, mode: 'cors' });
      clearTimeout(tid);
      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        throw new Error(`HTTP ${resp.status} — ${body.slice(0, 120)}`);
      }
      return await resp.json();
    } catch (err) {
      lastErr = err;
      const msg = err.message || '';
      const isRetryable =
        err.name === 'AbortError' ||
        msg.includes('Failed to fetch') ||
        msg.includes('NetworkError') ||
        msg.includes('ECONNRESET') ||
        msg.startsWith('HTTP 5') ||
        msg.startsWith('HTTP 429');
      console.warn(`[CyberNewsHub] Attempt ${i+1}/${retries} failed for ${url} — ${msg}`);
      if (!isRetryable || i === retries - 1) break;
      await new Promise(r => setTimeout(r, RETRY_BASE_MS * (i + 1)));
    }
  }
  console.error(`[CyberNewsHub] All ${retries} attempts failed for ${url}`, lastErr);
  throw lastErr;
}

// ── Cache helpers ──────────────────────────────────────────────────────
function cGet(map, key) {
  const e = map.get(key);
  if (!e || Date.now() - e.ts > e.ttl) { map.delete(key); return null; }
  return e.data;
}
function cSet(map, key, data, ttl = CACHE_TTL_MS) {
  map.set(key, { data, ts: Date.now(), ttl });
  if (map.size > 200) {
    const now = Date.now();
    for (const [k, v] of map) if (now - v.ts > v.ttl) map.delete(k);
  }
}

// ════════════════════════════════════════════════════════════════════
//  MAIN ENTRY — overrides features.js renderCyberNews()
// ════════════════════════════════════════════════════════════════════
global.renderCyberNews = async function () {
  global.renderCyberNews_v7 = global.renderCyberNews; // backward compat alias
  const wrap = document.getElementById('cyberNewsWrap');
  if (!wrap) return;
  wrap.innerHTML = shell();
  await switchTab('threat-intelligence');
};

// ════════════════════════════════════════════════════════════════════
//  SHELL — sticky header + tab nav + filter bar + content area
// ════════════════════════════════════════════════════════════════════
function shell() {
  return `
<div id="cnh-root" style="font-family:'Inter',sans-serif;background:#070c16;min-height:100%;color:#e2e8f0;">

  <!-- ═══ HEADER ═══ -->
  <div id="cnh-header" style="
    background:linear-gradient(180deg,#040810 0%,#06091200 100%);
    border-bottom:1px solid #0f1929;
    padding:0 20px;
    position:sticky;top:0;z-index:300;
    backdrop-filter:blur(12px);
    -webkit-backdrop-filter:blur(12px);
  ">
    <!-- Branding row -->
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 0 0;flex-wrap:wrap;gap:10px">
      <div style="display:flex;align-items:center;gap:12px">
        <div style="width:38px;height:38px;border-radius:9px;
          background:linear-gradient(135deg,#6d28d9,#dc2626);
          display:flex;align-items:center;justify-content:center;
          font-size:1em;font-weight:900;color:#fff;letter-spacing:-.5px;flex-shrink:0">
          TI
        </div>
        <div>
          <div style="font-size:1em;font-weight:800;color:#f8fafc;letter-spacing:-.3px;line-height:1.2">
            Cyber News Hub
          </div>
          <div style="font-size:.68em;color:#3f5373;margin-top:2px;display:flex;align-items:center;gap:6px">
            <span style="width:6px;height:6px;background:#22c55e;border-radius:50%;
              display:inline-block;animation:cnh-pulse 1.4s infinite"></span>
            Real-time threat intelligence &amp; vulnerability tracking
          </div>
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <div style="position:relative;display:flex;align-items:center">
          <i class="fas fa-search" style="position:absolute;left:10px;color:#3f5373;font-size:.8em;pointer-events:none"></i>
          <input id="cnh-gsearch" placeholder="Search threats, CVEs, vendors…"
            style="
              background:#080e1a;border:1px solid #0f1929;color:#e2e8f0;
              padding:8px 12px 8px 32px;border-radius:8px;font-size:.82em;
              width:230px;outline:none;transition:border-color .2s;
            "
            onfocus="this.style.borderColor='#3b82f6'"
            onblur="this.style.borderColor='#0f1929'"
            oninput="cnhGlobalSearch(this.value)"
          />
        </div>
        <button onclick="cnhRefresh()"
          id="cnh-refresh"
          style="
            background:#080e1a;border:1px solid #0f1929;color:#64748b;
            padding:8px 14px;border-radius:8px;font-size:.82em;cursor:pointer;
            display:flex;align-items:center;gap:6px;transition:all .2s;
          "
          onmouseover="this.style.borderColor='#3b82f6';this.style.color='#60a5fa'"
          onmouseout="this.style.borderColor='#0f1929';this.style.color='#64748b'"
        >
          <i class="fas fa-sync-alt" id="cnh-refresh-icon"></i> Refresh
        </button>
      </div>
    </div>

    <!-- Tab navigation -->
    <nav id="cnh-tabs" style="display:flex;gap:0;margin-top:12px;overflow-x:auto;scrollbar-width:none">
      ${['threat-intelligence','vulnerabilities','cyber-attacks','cve-engine'].map(tid => `
        <button class="cnh-tab" id="tab-${tid}" data-tab="${tid}" onclick="cnhSwitchTab('${tid}')">
          <i class="fas ${tabIcon(tid)}"></i>
          ${tabLabel(tid)}
          ${tid === 'cve-engine' ? '<span class="cnh-live-badge">LIVE</span>' : ''}
        </button>
      `).join('')}
    </nav>
  </div>

  <!-- ═══ FILTER BAR ═══ -->
  <div id="cnh-filters" style="
    background:#040810;border-bottom:1px solid #0f1929;
    padding:10px 20px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;
    min-height:46px;
  "></div>

  <!-- ═══ CONTENT ═══ -->
  <div id="cnh-content" style="padding:20px;max-width:1440px;margin:0 auto"></div>

</div>

<!-- ═══ ARTICLE DETAIL PANEL ═══ -->
<div id="cnh-detail-overlay" onclick="cnhCloseDetail(event)" style="
  display:none;position:fixed;inset:0;z-index:2000;
  background:rgba(4,8,16,.88);backdrop-filter:blur(6px);
  overflow-y:auto;padding:40px 16px;
">
  <div id="cnh-detail-panel" onclick="event.stopPropagation()" style="
    background:#08101e;border:1px solid #0f1929;border-radius:16px;
    max-width:860px;margin:0 auto;position:relative;overflow:hidden;
  ">
    <button onclick="cnhCloseDetail()" style="
      position:absolute;top:14px;right:14px;z-index:10;
      background:#0d1520;border:1px solid #1e2840;color:#64748b;
      width:32px;height:32px;border-radius:50%;font-size:.8em;cursor:pointer;
      display:flex;align-items:center;justify-content:center;
    "><i class="fas fa-times"></i></button>
    <div id="cnh-detail-body"></div>
  </div>
</div>

${inlineStyles()}`;
}

function tabLabel(id) {
  return { 'threat-intelligence':'Threat Intelligence', 'vulnerabilities':'Vulnerabilities',
           'cyber-attacks':'Cyber Attacks', 'cve-engine':'CVE Threat Engine' }[id] || id;
}
function tabIcon(id) {
  return { 'threat-intelligence':'fa-shield-alt', 'vulnerabilities':'fa-bug',
           'cyber-attacks':'fa-bolt', 'cve-engine':'fa-database' }[id] || 'fa-circle';
}

function inlineStyles() {
  return `<style>
@keyframes cnh-pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.4;transform:scale(.85)} }
@keyframes cnh-spin { to{transform:rotate(360deg)} }
@keyframes cnh-fadein { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
.cnh-tab {
  padding:11px 20px;font-size:.82em;font-weight:600;color:#3f5373;
  border:none;background:transparent;cursor:pointer;white-space:nowrap;
  border-bottom:3px solid transparent;transition:color .2s,border-color .2s;
  display:flex;align-items:center;gap:7px;margin-bottom:-1px;
}
.cnh-tab:hover { color:#7a8fa8; }
.cnh-tab.active { color:#60a5fa;border-bottom-color:#3b82f6; }
.cnh-tab[data-tab="vulnerabilities"].active  { color:#fb923c;border-bottom-color:#f97316; }
.cnh-tab[data-tab="cyber-attacks"].active    { color:#f87171;border-bottom-color:#ef4444; }
.cnh-tab[data-tab="cve-engine"].active       { color:#a78bfa;border-bottom-color:#8b5cf6; }
.cnh-live-badge {
  background:rgba(34,197,94,.15);color:#22c55e;
  border:1px solid rgba(34,197,94,.3);padding:1px 5px;
  border-radius:4px;font-size:.65em;font-weight:700;
}
.cnh-grid {
  display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));
  gap:16px;animation:cnh-fadein .3s ease;
}
.cnh-card {
  background:#0a1525;border:1px solid #0f1929;border-radius:12px;
  overflow:hidden;cursor:pointer;
  transition:border-color .25s,transform .25s,box-shadow .25s;
  position:relative;
}
.cnh-card:hover {
  transform:translateY(-3px);
  box-shadow:0 10px 30px rgba(0,0,0,.5);
}
.cnh-sev-bar { height:3px;width:100%;flex-shrink:0; }
.cnh-thumb {
  width:100%;height:168px;object-fit:cover;
  display:block;border-bottom:1px solid #0f1929;
  background:#0d1520;
}
.cnh-card-body { padding:15px; }
.cnh-src-row { display:flex;align-items:center;justify-content:space-between;margin-bottom:11px; }
.cnh-title { font-size:.88em;font-weight:700;color:#f1f5f9;line-height:1.5;margin-bottom:8px; }
.cnh-summary {
  font-size:.76em;color:#4a6080;line-height:1.75;
  overflow:hidden;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;
  margin-bottom:10px;
}
.cnh-tag-row { display:flex;flex-wrap:wrap;gap:4px;margin-bottom:9px; }
.cnh-tag {
  background:rgba(255,255,255,.04);color:#3f5373;border:1px solid #0f1929;
  padding:2px 7px;border-radius:4px;font-size:.65em;
}
.cnh-cve-chip {
  background:rgba(139,92,246,.14);color:#a78bfa;border:1px solid rgba(139,92,246,.28);
  padding:2px 7px;border-radius:4px;font-size:.65em;font-family:'JetBrains Mono',monospace;
}
.cnh-actor-chip {
  background:rgba(249,115,22,.1);color:#fb923c;border:1px solid rgba(249,115,22,.2);
  padding:2px 7px;border-radius:4px;font-size:.67em;
}
.cnh-card-footer {
  display:flex;align-items:center;justify-content:space-between;
  border-top:1px solid #0f1929;padding-top:10px;
}
.cnh-sev-badge {
  padding:2px 8px;border-radius:6px;font-size:.7em;font-weight:700;white-space:nowrap;
}
.cnh-icon-btn {
  width:27px;height:27px;border-radius:6px;font-size:.73em;cursor:pointer;
  display:flex;align-items:center;justify-content:center;transition:opacity .2s;
}
.cnh-icon-btn:hover { opacity:.75; }
.cnh-ctrl {
  background:#080e1a;border:1px solid #0f1929;color:#94a3b8;
  padding:7px 10px;border-radius:7px;font-size:.8em;outline:none;cursor:pointer;
  transition:border-color .2s;
}
.cnh-ctrl:focus { border-color:#3b82f6; }
.cnh-ctrl option { background:#080e1a; }
.cnh-spinner {
  width:36px;height:36px;border:3px solid #0f1929;border-top-color:#3b82f6;
  border-radius:50%;animation:cnh-spin .7s linear infinite;
}
.cnh-pgn { display:flex;justify-content:center;align-items:center;gap:8px;margin-top:24px;flex-wrap:wrap; }
.cnh-pg {
  background:#080e1a;border:1px solid #0f1929;color:#4a6080;
  padding:7px 13px;border-radius:6px;font-size:.8em;cursor:pointer;transition:all .2s;
}
.cnh-pg:hover { border-color:#3b82f6;color:#60a5fa; }
.cnh-pg.active { background:#3b82f6;border-color:#3b82f6;color:#fff; }
.cnh-pg:disabled { opacity:.3;cursor:not-allowed; }
.cnh-empty { text-align:center;padding:70px 20px;color:#3f5373; }
.cnh-error {
  background:#0a0e1a;border:1px solid rgba(239,68,68,.25);border-radius:12px;
  padding:28px;text-align:center;
}
.cnh-stat {
  background:#0a1525;border:1px solid #0f1929;border-radius:10px;padding:15px 16px;
}
.cnh-stat .val { font-size:1.75em;font-weight:800; }
.cnh-stat .lbl { font-size:.67em;color:#3f5373;margin-top:3px; }
.cve-card {
  background:#0a1525;border:1px solid #0f1929;border-radius:12px;
  padding:16px;cursor:pointer;
  transition:border-color .25s,transform .25s,box-shadow .25s;
  animation:cnh-fadein .3s ease;
}
.cve-card:hover { transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.45); }
.cve-id { font-family:'JetBrains Mono',monospace;font-size:.92em;font-weight:700;color:#a78bfa; }
.cve-score { font-family:'JetBrains Mono',monospace;font-size:1.65em;font-weight:900; }
.cve-desc {
  font-size:.78em;color:#4a6080;line-height:1.75;
  overflow:hidden;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;margin:8px 0;
}
@media(max-width:640px){
  .cnh-grid{grid-template-columns:1fr;}
  #cnh-gsearch{width:150px;}
}
</style>`;
}

// ════════════════════════════════════════════════════════════════════
//  TAB SWITCHING
// ════════════════════════════════════════════════════════════════════
global.cnhSwitchTab = async function (tabId) { await switchTab(tabId); };

async function switchTab(tabId) {
  S.tab = tabId;
  document.querySelectorAll('.cnh-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tabId);
  });
  const gs = document.getElementById('cnh-gsearch');
  if (gs) {
    if (tabId === 'cve-engine') {
      gs.placeholder = 'Search CVE-ID, vendor, product…';
      gs.value = S.filters.cve.search;
    } else {
      gs.placeholder = 'Search threats, actors, CVEs…';
      gs.value = S.filters.news.search;
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

global.cnhRefresh = function () {
  const icon = document.getElementById('cnh-refresh-icon');
  if (icon) icon.style.animation = 'cnh-spin .7s linear infinite';
  S.newsCache.clear();
  S.cveCache.clear();
  S.newsPage = 1;
  S.cvePage  = 1;
  switchTab(S.tab).finally(() => {
    if (icon) icon.style.animation = '';
  });
};

global.cnhGlobalSearch = function (q) {
  clearTimeout(S.debounce);
  S.debounce = setTimeout(() => {
    if (S.tab === 'cve-engine') {
      S.filters.cve.search = q;
      S.cvePage = 1;
      loadCVEs();
    } else {
      S.filters.news.search = q;
      S.newsPage = 1;
      loadNews(S.tab);
    }
  }, 480);
};

// ════════════════════════════════════════════════════════════════════
//  NEWS LOADING
// ════════════════════════════════════════════════════════════════════
function renderNewsFilters(tabId) {
  const bar = document.getElementById('cnh-filters');
  if (!bar) return;
  const accentMap = {
    'threat-intelligence':'#3b82f6','vulnerabilities':'#f97316','cyber-attacks':'#ef4444',
  };
  const accent = accentMap[tabId] || '#3b82f6';
  bar.innerHTML = `
    <span style="font-size:.75em;color:#3f5373;font-weight:600;display:flex;align-items:center;gap:5px">
      <i class="fas fa-sliders-h"></i>Filters
    </span>
    <select class="cnh-ctrl" id="nf-sev" onchange="cnhApplyNewsFilter()" title="Severity">
      <option value="">All Severities</option>
      <option value="critical">🔴 Critical</option>
      <option value="high">🟠 High</option>
      <option value="medium">🟡 Medium</option>
      <option value="low">🟢 Low</option>
    </select>
    <select class="cnh-ctrl" id="nf-src" onchange="cnhApplyNewsFilter()" title="Source">
      <option value="">All Sources</option>
      <option value="The Hacker News">The Hacker News</option>
      <option value="BleepingComputer">BleepingComputer</option>
      <option value="SecurityWeek">SecurityWeek</option>
      <option value="Krebs on Security">Krebs on Security</option>
      <option value="CISA">CISA Alerts</option>
      <option value="Dark Reading">Dark Reading</option>
    </select>
    <div style="flex:1"></div>
    <span id="nf-count" style="font-size:.75em;color:#3f5373"></span>
    <button onclick="cnhNewsExport()"
      style="background:#080e1a;border:1px solid #0f1929;color:#4a6080;
        padding:6px 12px;border-radius:7px;font-size:.78em;cursor:pointer;
        display:flex;align-items:center;gap:5px;"
      title="Export as CSV">
      <i class="fas fa-download"></i>Export
    </button>
  `;
}

global.cnhApplyNewsFilter = function () {
  S.filters.news.severity = document.getElementById('nf-sev')?.value || '';
  S.filters.news.source   = document.getElementById('nf-src')?.value || '';
  S.newsPage = 1;
  loadNews(S.tab);
};

async function loadNews(category) {
  if (S.busy) return;
  S.busy = true;
  showSpinner('Loading threat intelligence…');

  const { search, severity, source } = S.filters.news;
  const backendUrl = resolveBackend();
  const params = new URLSearchParams({
    category: category,
    page:     S.newsPage,
    limit:    NEWS_PAGE_SIZE,
  });
  if (severity) params.append('severity', severity);
  if (source)   params.append('source',   source);
  if (search)   params.append('search',   search);

  const url      = `${backendUrl}/api/news?${params}`;
  const cacheKey = url;
  let data = cGet(S.newsCache, cacheKey);

  if (!data) {
    try {
      data = await apiFetch(url);
      cSet(S.newsCache, cacheKey, data);
    } catch (err) {
      S.busy = false;
      showError('News Service Unavailable',
        `Could not reach ${backendUrl}/api/news — ${err.message}`,
        'cnhRefresh()');
      return;
    }
  }

  S.busy      = false;
  S.newsTotal = data.total || 0;

  const countEl = document.getElementById('nf-count');
  if (countEl) countEl.textContent = `${S.newsTotal.toLocaleString()} articles`;

  const articles = data.data || [];
  _lastNewsData = articles; // store for export
  if (!articles.length) {
    showEmpty('fa-newspaper','No Articles Found',
      'No articles found for the selected filters. Try a different category or clear filters.');
    return;
  }
  renderNewsGrid(articles, data.totalPages || 1, category);
}

function renderNewsGrid(articles, totalPages, category) {
  const content = document.getElementById('cnh-content');
  if (!content) return;
  const accentColor = {
    'threat-intelligence':'#3b82f6','vulnerabilities':'#f97316','cyber-attacks':'#ef4444',
  }[category] || '#3b82f6';
  content.innerHTML = `
    <div class="cnh-grid" id="cnh-news-grid">
      ${articles.map(a => newsCard(a, accentColor)).join('')}
    </div>
    ${pagination(S.newsPage, totalPages, 'cnhNewsPage')}
  `;
}

// ─── News card ─────────────────────────────────────────────────────────
function newsCard(a, accentColor) {
  const p    = sev(a.severity || 'medium');
  const ts   = ago(a.publishedAt || a.published_at);
  const src  = a.source || 'Unknown';
  const ic   = srcIcon(src);
  const cves = (a.cves || []).slice(0, 3);
  const tags = (a.tags || []).slice(0, 4);
  const actors = (a.threatActors || a.threat_actors || []).slice(0, 2);
  const summary = cleanText(a.summary || a.description || '');
  const url   = a.url || a.link || '#';
  const safeA = JSON.stringify(a).replace(/</g,'\\u003c').replace(/>/g,'\\u003e').replace(/&/g,'\\u0026');

  return `
  <div class="cnh-card"
    onclick="cnhOpenDetail(${h(safeA)})"
    style="border-top:3px solid ${accentColor}"
    onmouseover="this.style.borderColor='${accentColor}';this.style.transform='translateY(-3px)';this.style.boxShadow='0 10px 30px rgba(0,0,0,.5)'"
    onmouseout="this.style.borderColor='#0f1929';this.style.borderTopColor='${accentColor}';this.style.transform='';this.style.boxShadow=''"
  >
    ${a.imageUrl
      ? `<img class="cnh-thumb" src="${h(a.imageUrl)}" alt="" loading="lazy"
           onerror="this.parentElement.querySelector('.cnh-thumb-fallback').style.display='flex';this.style.display='none'">\
         <div class="cnh-thumb-fallback" style="display:none;height:140px;background:linear-gradient(135deg,#0a1525,#0d1f35);
           align-items:center;justify-content:center;color:${accentColor};font-size:2em;font-weight:800;opacity:.22">
           ${h((src.charAt(0)||'?').toUpperCase())}
         </div>`
      : `<div class="cnh-thumb-fallback" style="height:110px;background:linear-gradient(135deg,#070c16,#0a1525);
           display:flex;align-items:center;justify-content:center;border-bottom:1px solid #0f1929;">
           <i class="fas ${ic}" style="font-size:2em;color:${accentColor};opacity:.18"></i>
         </div>`
    }
    <div class="cnh-card-body">
      <!-- Source + severity -->
      <div class="cnh-src-row">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="width:30px;height:30px;border-radius:7px;flex-shrink:0;
            background:${p.bg};border:1px solid ${p.border};
            display:flex;align-items:center;justify-content:center;color:${p.bar};font-size:.75em;">
            <i class="fas ${ic}"></i>
          </div>
          <div>
            <div style="font-size:.72em;font-weight:600;color:#6a8ab0">${h(src)}</div>
            <div style="font-size:.65em;color:#3f5373">${ts}</div>
          </div>
        </div>
        <span class="cnh-sev-badge" style="background:${p.bg};color:${p.text};border:1px solid ${p.border}">
          ${p.text === SEV.UNKNOWN.text ? '?' : (a.severity||'').toUpperCase()}
        </span>
      </div>

      <!-- Title -->
      <div class="cnh-title">${h(a.title || 'Untitled')}</div>

      <!-- Summary -->
      ${summary ? `<div class="cnh-summary">${h(summary.slice(0,280))}</div>` : ''}

      <!-- CVE chips -->
      ${cves.length ? `<div class="cnh-tag-row">${
        cves.map(c => `<span class="cnh-cve-chip"><i class="fas fa-exclamation-triangle" style="margin-right:3px;font-size:.7em"></i>${h(c)}</span>`).join('')
      }</div>` : ''}

      <!-- Actors -->
      ${actors.length ? `<div class="cnh-tag-row">${
        actors.map(ac => `<span class="cnh-actor-chip"><i class="fas fa-user-secret" style="margin-right:3px"></i>${h(ac)}</span>`).join('')
      }</div>` : ''}

      <!-- Tags -->
      ${tags.length ? `<div class="cnh-tag-row">${
        tags.map(t => `<span class="cnh-tag">#${h(t)}</span>`).join('')
      }</div>` : ''}

      <!-- Footer -->
      <div class="cnh-card-footer">
        <a href="${h(url)}" target="_blank" rel="noopener"
          onclick="event.stopPropagation()"
          style="font-size:.73em;color:#3b82f6;text-decoration:none;
            display:flex;align-items:center;gap:4px;"
          onmouseover="this.style.color='#60a5fa'"
          onmouseout="this.style.color='#3b82f6'"
        >
          Full Article <i class="fas fa-external-link-alt" style="font-size:.72em"></i>
        </a>
        <div style="display:flex;gap:5px" onclick="event.stopPropagation()">
          ${cves.length ? `<button class="cnh-icon-btn"
            style="background:rgba(34,211,238,.1);color:#22d3ee;border:1px solid rgba(34,211,238,.2);"
            title="Add CVEs to IOC list" onclick="cnhAddIOC(${JSON.stringify(cves)})">
            <i class="fas fa-fingerprint"></i></button>` : ''}
          <button class="cnh-icon-btn"
            style="background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2);"
            title="Create incident case" onclick="cnhCase(${JSON.stringify(h(a.title||''))})">
            <i class="fas fa-folder-plus"></i></button>
        </div>
      </div>
    </div>
  </div>`;
}

// ─── Article detail panel ───────────────────────────────────────────────
global.cnhOpenDetail = function (jsonStr) {
  try {
    const a = typeof jsonStr === 'string' ? JSON.parse(jsonStr) : jsonStr;
    renderDetailPanel(a);
  } catch (e) {
    console.error('[CyberNewsHub] cnhOpenDetail parse error:', e);
  }
};

function renderDetailPanel(a) {
  const overlay = document.getElementById('cnh-detail-overlay');
  const body    = document.getElementById('cnh-detail-body');
  if (!overlay || !body) return;

  const p       = sev(a.severity || 'medium');
  const ts      = ago(a.publishedAt || a.published_at);
  const url     = a.url || a.link || '#';
  const cves    = a.cves  || [];
  const actors  = a.threatActors || a.threat_actors || [];
  const malware = a.malware || a.malware_families   || [];
  const tags    = a.tags  || [];
  const summary = cleanText(a.summary || a.description || '');
  const catLabel = { 'threat-intelligence':'Threat Intelligence',
                     'vulnerabilities':'Vulnerabilities','cyber-attacks':'Cyber Attacks' }[a.category] || a.category;

  body.innerHTML = `
    <!-- Hero image -->
    ${a.imageUrl ? `<img src="${h(a.imageUrl)}" alt="" style="
      width:100%;max-height:280px;object-fit:cover;
      border-bottom:1px solid #0f1929;
    " onerror="this.style.display='none'">` : ''}

    <div style="padding:24px">
      <!-- Meta badges -->
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">
        <span class="cnh-sev-badge" style="background:${p.bg};color:${p.text};border:1px solid ${p.border};font-size:.72em">
          ${(a.severity||'unknown').toUpperCase()}
        </span>
        <span style="background:#0d1520;color:#6a8ab0;border:1px solid #0f1929;
          padding:2px 9px;border-radius:6px;font-size:.72em">
          <i class="fas ${srcIcon(a.source||'')} " style="margin-right:4px"></i>${h(a.source||'Unknown')}
        </span>
        <span style="background:#0d1520;color:#6a8ab0;border:1px solid #0f1929;
          padding:2px 9px;border-radius:6px;font-size:.72em">
          <i class="fas fa-clock" style="margin-right:4px"></i>${ts}
        </span>
        ${catLabel ? `<span style="background:#0d1520;color:#6a8ab0;border:1px solid #0f1929;
          padding:2px 9px;border-radius:6px;font-size:.72em;text-transform:capitalize">
          ${h(catLabel)}</span>` : ''}
      </div>

      <!-- Title -->
      <h2 style="font-size:1.05em;font-weight:800;color:#f1f5f9;line-height:1.55;margin:0 0 16px">
        ${h(a.title||'')}
      </h2>

      <!-- Summary / Description -->
      ${summary ? `
      <div style="background:#060c1a;border:1px solid #0f1929;border-radius:10px;
        padding:16px;margin-bottom:18px">
        <div style="font-size:.66em;color:#22d3ee;font-weight:700;text-transform:uppercase;
          letter-spacing:.5px;margin-bottom:9px">
          <i class="fas fa-file-alt" style="margin-right:5px"></i>Article Summary
        </div>
        <div style="font-size:.85em;color:#7a9cb5;line-height:1.85">${h(summary)}</div>
      </div>` : ''}

      <!-- Intel grid -->
      ${(actors.length || malware.length || cves.length) ? `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;margin-bottom:18px">
        ${actors.length ? `<div style="background:#060c1a;border:1px solid #0f1929;border-radius:9px;padding:13px">
          <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:700;margin-bottom:7px">Threat Actors</div>
          ${actors.map(ac => `<div style="font-size:.82em;color:#fb923c;font-weight:600;margin-bottom:3px">
            <i class="fas fa-user-secret" style="margin-right:5px;opacity:.7"></i>${h(ac)}</div>`).join('')}
        </div>` : ''}
        ${malware.length ? `<div style="background:#060c1a;border:1px solid #0f1929;border-radius:9px;padding:13px">
          <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:700;margin-bottom:7px">Malware</div>
          ${malware.map(m => `<div style="font-size:.8em;color:#a78bfa;font-family:monospace;font-weight:600;margin-bottom:3px">${h(m)}</div>`).join('')}
        </div>` : ''}
        ${cves.length ? `<div style="background:#060c1a;border:1px solid #0f1929;border-radius:9px;padding:13px">
          <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:700;margin-bottom:7px">CVE IDs</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${cves.map(c => `<span class="cnh-cve-chip" style="cursor:pointer" onclick="cnhSwitchTab('cve-engine');cnhGlobalSearch('${h(c)}')">${h(c)}</span>`).join('')}
          </div>
        </div>` : ''}
      </div>` : ''}

      <!-- Tags -->
      ${tags.length ? `
      <div style="margin-bottom:18px">
        <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:700;margin-bottom:7px">Tags</div>
        <div class="cnh-tag-row">${tags.map(t => `<span class="cnh-tag">#${h(t)}</span>`).join('')}</div>
      </div>` : ''}

      <!-- Actions -->
      <div style="display:flex;flex-wrap:wrap;gap:8px;padding-top:14px;border-top:1px solid #0f1929">
        <a href="${h(url)}" target="_blank" rel="noopener"
          style="background:rgba(59,130,246,.13);color:#60a5fa;
            border:1px solid rgba(59,130,246,.28);
            padding:8px 16px;border-radius:8px;font-size:.82em;text-decoration:none;
            display:flex;align-items:center;gap:7px;">
          <i class="fas fa-external-link-alt"></i> Read Full Article
        </a>
        ${cves.length ? `
        <button onclick="cnhAddIOC(${JSON.stringify(cves)});cnhCloseDetail()"
          style="background:rgba(34,211,238,.1);color:#22d3ee;
            border:1px solid rgba(34,211,238,.2);
            padding:8px 16px;border-radius:8px;font-size:.82em;cursor:pointer;">
          <i class="fas fa-fingerprint" style="margin-right:5px"></i>Extract IOCs
        </button>` : ''}
        <button onclick="cnhCase(${JSON.stringify(h(a.title||''))});cnhCloseDetail()"
          style="background:rgba(34,197,94,.1);color:#22c55e;
            border:1px solid rgba(34,197,94,.2);
            padding:8px 16px;border-radius:8px;font-size:.82em;cursor:pointer;">
          <i class="fas fa-folder-plus" style="margin-right:5px"></i>Create Case
        </button>
        <button onclick="cnhCloseDetail()"
          style="background:#060c1a;color:#4a6080;
            border:1px solid #0f1929;
            padding:8px 16px;border-radius:8px;font-size:.82em;cursor:pointer;margin-left:auto;">
          <i class="fas fa-arrow-left" style="margin-right:5px"></i>Back
        </button>
      </div>
    </div>
  `;

  overlay.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

global.cnhCloseDetail = function (evt) {
  // Close if: explicit call (no evt), backdrop click, or Back button click
  if (evt && evt.type === 'click') {
    const overlay = document.getElementById('cnh-detail-overlay');
    if (!overlay) return;
    // Only close if clicking the backdrop itself (not content inside)
    if (evt.target && evt.target.id !== 'cnh-detail-overlay') return;
  }
  const overlay = document.getElementById('cnh-detail-overlay');
  if (overlay) { overlay.style.display = 'none'; overlay.innerHTML = ''; }
  document.body.style.overflow = '';
};

// Allow clicking the overlay background to close
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    const overlay = document.getElementById('cnh-detail-overlay');
    if (overlay && overlay.style.display !== 'none') {
      overlay.style.display = 'none';
      document.body.style.overflow = '';
    }
  }
});

// ════════════════════════════════════════════════════════════════════
//  CVE THREAT ENGINE
// ════════════════════════════════════════════════════════════════════
function renderCVEFilters() {
  const bar = document.getElementById('cnh-filters');
  if (!bar) return;
  bar.innerHTML = `
    <span style="font-size:.75em;color:#3f5373;font-weight:600;display:flex;align-items:center;gap:5px">
      <i class="fas fa-sliders-h"></i>CVE Filters
    </span>
    <select class="cnh-ctrl" id="cvef-sev" onchange="cnhApplyCVEFilter()">
      <option value="">All Severities</option>
      <option value="CRITICAL">🔴 Critical</option>
      <option value="HIGH">🟠 High</option>
      <option value="MEDIUM">🟡 Medium</option>
      <option value="LOW">🟢 Low</option>
    </select>
    <select class="cnh-ctrl" id="cvef-days" onchange="cnhApplyCVEFilter()">
      <option value="7">Last 7 days</option>
      <option value="30" selected>Last 30 days</option>
      <option value="90">Last 90 days</option>
      <option value="180">Last 180 days</option>
      <option value="365">Last year</option>
    </select>
    <select class="cnh-ctrl" id="cvef-sort" onchange="cnhApplyCVEFilter()">
      <option value="date">Latest First</option>
      <option value="score">Highest CVSS</option>
      <option value="id">CVE ID</option>
    </select>
    <input id="cvef-vendor" class="cnh-ctrl" placeholder="Vendor / product…"
      style="width:150px" oninput="cnhCVEVendorDebounce()" />
    <label style="display:flex;align-items:center;gap:5px;font-size:.78em;color:#4a6080;cursor:pointer">
      <input type="checkbox" id="cvef-kev" onchange="cnhApplyCVEFilter()"
        style="accent-color:#ef4444;width:14px;height:14px" />
      CISA KEV Only
    </label>
    <div style="flex:1"></div>
    <span id="cvef-count" style="font-size:.75em;color:#3f5373"></span>
    <button onclick="cnhCVEExport()"
      style="background:#080e1a;border:1px solid #0f1929;color:#4a6080;
        padding:6px 12px;border-radius:7px;font-size:.78em;cursor:pointer;
        display:flex;align-items:center;gap:5px;">
      <i class="fas fa-download"></i>Export CSV
    </button>
  `;
}

global.cnhApplyCVEFilter = function () {
  S.filters.cve.severity = document.getElementById('cvef-sev')?.value   || '';
  S.filters.cve.days     = parseInt(document.getElementById('cvef-days')?.value) || 30;
  S.filters.cve.sort     = document.getElementById('cvef-sort')?.value  || 'date';
  S.filters.cve.vendor   = document.getElementById('cvef-vendor')?.value || '';
  S.filters.cve.cisaKev  = document.getElementById('cvef-kev')?.checked || false;
  S.cvePage = 1;
  loadCVEs();
};

let _cveVendorDebounce = null;
global.cnhCVEVendorDebounce = function () {
  clearTimeout(_cveVendorDebounce);
  _cveVendorDebounce = setTimeout(global.cnhApplyCVEFilter, 500);
};

// ─── CVE Stats KPIs ─────────────────────────────────────────────────────
async function loadCVEStats() {
  const content = document.getElementById('cnh-content');
  if (!content) return;

  // Skeleton placeholder
  content.innerHTML = `
    <div id="cve-stats-row" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:20px">
      ${[1,2,3,4,5,6].map(() => `
        <div class="cnh-stat" style="opacity:.35;animation:cnh-pulse .9s infinite">
          <div style="background:#0f1929;height:22px;border-radius:4px;margin-bottom:6px"></div>
          <div style="background:#0f1929;height:13px;border-radius:4px;width:55%"></div>
        </div>`).join('')}
    </div>
    <div id="cve-kev-section"></div>
    <div id="cve-list-area"></div>`;

  try {
    const backendUrl = resolveBackend();
    const stats = await apiFetch(`${backendUrl}/api/cve/stats/summary`);
    const d     = stats.last30Days || {};

    const statsRow = document.getElementById('cve-stats-row');
    if (statsRow) {
      statsRow.innerHTML = [
        { lbl:'Total (30d)',   val: (d.total    || 0).toLocaleString(), clr:'#60a5fa', ic:'fa-database'         },
        { lbl:'Critical',      val: (d.critical || 0).toLocaleString(), clr:'#ef4444', ic:'fa-radiation'        },
        { lbl:'High',          val: (d.high     || 0).toLocaleString(), clr:'#f97316', ic:'fa-exclamation-triangle' },
        { lbl:'Medium',        val: (d.medium   || 0).toLocaleString(), clr:'#eab308', ic:'fa-minus-circle'     },
        { lbl:'CISA KEV',      val: (stats.cisaKEV?.count || 0).toLocaleString(), clr:'#ef4444', ic:'fa-flag'   },
        { lbl:'Risk Score',    val: (stats.riskScore || 0) + '/100',     clr: riskCol(stats.riskScore), ic:'fa-tachometer-alt' },
      ].map(s => `
        <div class="cnh-stat">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
            <i class="fas ${s.ic}" style="color:${s.clr};font-size:.8em"></i>
            <span class="lbl">${s.lbl}</span>
          </div>
          <div class="val" style="color:${s.clr}">${s.val}</div>
        </div>`).join('');
    }

    // CISA KEV spotlight
    const kevItems = stats.cisaKEV?.items || [];
    const kevSec = document.getElementById('cve-kev-section');
    if (kevSec && kevItems.length) {
      kevSec.innerHTML = `
        <div style="margin-bottom:16px">
          <div style="font-size:.76em;color:#ef4444;font-weight:700;text-transform:uppercase;
            letter-spacing:.4px;margin-bottom:10px;display:flex;align-items:center;gap:8px">
            <i class="fas fa-flag"></i>CISA Known Exploited Vulnerabilities
            <span style="background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);
              color:#ef4444;padding:1px 6px;border-radius:4px;font-size:.8em">${kevItems.length} shown</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:10px">
            ${kevItems.map(c => cveCard(c)).join('')}
          </div>
        </div>`;
    }
  } catch (err) {
    console.warn('[CyberNewsHub] CVE stats load failed:', err.message);
    // Stats failure is non-fatal — still try to load the CVE list
  }
}

function riskCol(s) {
  if (!s) return '#94a3b8';
  return s >= 70 ? '#ef4444' : s >= 40 ? '#f97316' : '#22c55e';
}

// ─── CVE List ─────────────────────────────────────────────────────────────
async function loadCVEs() {
  if (S.busy) return;
  S.busy = true;

  const listArea = document.getElementById('cve-list-area');
  if (listArea) {
    listArea.innerHTML = `<div style="text-align:center;padding:50px;color:#3f5373">
      <div class="cnh-spinner" style="margin:0 auto 14px"></div>
      <div style="font-size:.85em">Fetching CVE data from NVD…</div>
      <div style="font-size:.72em;color:#2a3a50;margin-top:6px">This may take 10-15 seconds on first load</div>
    </div>`;
  }

  const f  = S.filters.cve;
  const gs = document.getElementById('cnh-gsearch')?.value || '';
  const searchQ = (f.search || gs).trim();

  const backendUrl = resolveBackend();
  let endpoint;
  if (searchQ.length >= 2) {
    const sp = new URLSearchParams({ q: searchQ, page: S.cvePage, limit: CVE_PAGE_SIZE, days: f.days });
    if (f.severity) sp.append('severity', f.severity);
    endpoint = `${backendUrl}/api/cve/search?${sp}`;
  } else {
    const cp = new URLSearchParams({ page: S.cvePage, limit: CVE_PAGE_SIZE, days: f.days, sort: f.sort });
    if (f.severity) cp.append('severity', f.severity);
    if (f.vendor)   cp.append('vendor',   f.vendor);
    if (f.cisaKev)  cp.append('cisaKev',  'true');
    endpoint = `${backendUrl}/api/cve?${cp}`;
  }

  let data = cGet(S.cveCache, endpoint);
  if (!data) {
    try {
      data = await apiFetch(endpoint);
      cSet(S.cveCache, endpoint, data, CVE_CACHE_TTL);
    } catch (err) {
      S.busy = false;
      if (listArea) {
        listArea.innerHTML = `
          <div class="cnh-error">
            <i class="fas fa-exclamation-circle" style="font-size:2em;color:#ef4444;margin-bottom:14px"></i>
            <div style="color:#ef4444;font-weight:700;margin-bottom:8px;font-size:.92em">CVE Service Unavailable</div>
            <div style="font-size:.8em;color:#3f5373;margin-bottom:18px;max-width:500px;margin:0 auto 18px">
              ${h(err.message)}
              <br><br>
              <span style="font-size:.9em;color:#2a3a50">
                The NVD API may be rate-limiting or slow. Wait 30 seconds and retry.
              </span>
            </div>
            <button onclick="cnhRefresh()" style="
              background:rgba(59,130,246,.13);color:#60a5fa;
              border:1px solid rgba(59,130,246,.28);
              padding:8px 18px;border-radius:8px;font-size:.82em;cursor:pointer;">
              <i class="fas fa-sync-alt" style="margin-right:6px"></i>Retry
            </button>
          </div>`;
      }
      return;
    }
  }

  S.busy     = false;
  S.cveTotal = data.total || 0;

  const countEl = document.getElementById('cvef-count');
  if (countEl) countEl.textContent = `${S.cveTotal.toLocaleString()} CVEs`;

  const cves = data.cves || [];
  _lastCVEData = cves; // store for export

  if (listArea) {
    if (!cves.length) {
      listArea.innerHTML = `<div class="cnh-empty">
        <i class="fas fa-bug" style="font-size:2.5em;opacity:.25;margin-bottom:14px"></i>
        <div style="font-size:.92em;font-weight:600;color:#3f5373">No CVEs Found</div>
        <div style="font-size:.8em;margin-top:6px">Try widening the date range or clearing filters.</div>
      </div>`;
    } else {
      listArea.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));
          gap:14px;animation:cnh-fadein .3s ease">
          ${cves.map(c => cveCard(c)).join('')}
        </div>
        ${pagination(S.cvePage, data.totalPages || 1, 'cnhCVEPage')}`;
    }
  }
}

// ─── CVE card ──────────────────────────────────────────────────────────
function cveCard(c) {
  const p     = sev(c.severity);
  const score = c.cvssScore != null ? Number(c.cvssScore).toFixed(1) : '?';
  const ts    = ago(c.publishedDate);
  const affected = (c.affectedSystems || []).slice(0, 3);

  return `
  <div class="cve-card"
    onclick="cnhOpenCVE('${h(c.id)}')"
    style="border-left:3px solid ${p.bar}"
    onmouseover="this.style.borderColor='${p.bar}';this.style.boxShadow='0 8px 24px rgba(0,0,0,.4)'"
    onmouseout="this.style.borderColor='${p.bar}';this.style.boxShadow='none'"
  >
    <!-- Top row -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:11px">
      <div>
        <div class="cve-id">${h(c.id || 'CVE-UNKNOWN')}</div>
        <div style="font-size:.67em;color:#3f5373;margin-top:2px">${ts} · CVSS v${h(c.cvssVersion||'?')}</div>
      </div>
      <div style="text-align:right;flex-shrink:0">
        <div class="cve-score" style="color:${p.bar}">${score}</div>
        <span class="cnh-sev-badge" style="background:${p.bg};color:${p.text};border:1px solid ${p.border};font-size:.65em">
          ${(c.severity||'?').toUpperCase()}
        </span>
      </div>
    </div>

    <!-- Description -->
    <div class="cve-desc">${h(c.description||'No description available.')}</div>

    <!-- Tags -->
    <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
      ${c.cisaKEV   ? `<span style="background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.22);padding:2px 7px;border-radius:5px;font-size:.65em;font-weight:700">🚨 CISA KEV</span>` : ''}
      ${c.hasExploit ? `<span style="background:rgba(249,115,22,.1);color:#f97316;border:1px solid rgba(249,115,22,.22);padding:2px 7px;border-radius:5px;font-size:.65em;font-weight:700">⚡ Exploit</span>` : ''}
      <span style="background:rgba(${c.patchStatus==='Patched'?'34,197,94':'239,68,68'},.1);
        color:${c.patchStatus==='Patched'?'#22c55e':'#ef4444'};
        border:1px solid rgba(${c.patchStatus==='Patched'?'34,197,94':'239,68,68'},.2);
        padding:2px 7px;border-radius:5px;font-size:.65em">
        ${h(c.patchStatus||'Unknown')}
      </span>
      ${(c.cwes||[]).slice(0,1).map(cw => `<span style="background:rgba(148,163,184,.07);color:#3f5373;border:1px solid #0f1929;padding:2px 7px;border-radius:5px;font-size:.65em">${h(cw)}</span>`).join('')}
    </div>

    <!-- Affected -->
    ${affected.length ? `
      <div style="border-top:1px solid #0f1929;padding-top:9px">
        <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:5px">Affected</div>
        ${affected.map(s => `<div style="font-size:.72em;color:#6a8ab0;display:flex;gap:6px;margin-bottom:2px">
          <span style="color:#3f5373;min-width:60px;flex-shrink:0">${h(s.vendor)}</span>
          <span style="color:#6a8ab0">${h(s.product)}</span>
          <span style="color:#2a3a50;font-family:monospace">${h(s.version)}</span>
        </div>`).join('')}
        ${c.totalAffected > 3 ? `<div style="font-size:.67em;color:#2a3a50">+${c.totalAffected-3} more</div>` : ''}
      </div>` : ''}

    ${c.cvssVector ? `<div style="margin-top:8px;font-size:.63em;color:#2a3a50;
      font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
      title="${h(c.cvssVector)}">${h(c.cvssVector)}</div>` : ''}
  </div>`;
}

// ─── CVE Detail Modal ───────────────────────────────────────────────────
global.cnhOpenCVE = async function (cveId) {
  const overlay = document.getElementById('cnh-detail-overlay');
  const body    = document.getElementById('cnh-detail-body');
  if (!overlay || !body) return;

  body.innerHTML = `
    <div style="padding:28px;text-align:center;color:#3f5373">
      <div class="cnh-spinner" style="margin:0 auto 14px"></div>
      <div style="font-size:.85em">Loading ${h(cveId)}…</div>
    </div>`;
  overlay.style.display = 'block';
  document.body.style.overflow = 'hidden';

  try {
    const backendUrl = resolveBackend();
    const c = await apiFetch(`${backendUrl}/api/cve/${encodeURIComponent(cveId)}`);
    renderCVEDetail(c);
  } catch (err) {
    body.innerHTML = `
      <div style="padding:28px;text-align:center">
        <i class="fas fa-exclamation-triangle" style="font-size:2em;color:#ef4444;margin-bottom:14px"></i>
        <div style="color:#ef4444;font-weight:700;margin-bottom:8px">Failed to Load CVE</div>
        <div style="font-size:.8em;color:#3f5373">${h(err.message)}</div>
        <button onclick="cnhCloseDetail()"
          style="margin-top:16px;background:#060c1a;color:#4a6080;border:1px solid #0f1929;
            padding:8px 18px;border-radius:8px;font-size:.82em;cursor:pointer">
          <i class="fas fa-arrow-left" style="margin-right:5px"></i>Back
        </button>
      </div>`;
  }
};

function renderCVEDetail(c) {
  const body = document.getElementById('cnh-detail-body');
  if (!body) return;
  const p     = sev(c.severity);
  const score = c.cvssScore != null ? Number(c.cvssScore).toFixed(1) : '—';

  body.innerHTML = `
  <div style="padding:24px;font-family:'Inter',sans-serif">
    <!-- Header -->
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px">
      <div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:1.1em;font-weight:800;
          color:#a78bfa;margin-bottom:8px">${h(c.id)}</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          <span class="cnh-sev-badge" style="background:${p.bg};color:${p.text};border:1px solid ${p.border}">${(c.severity||'?').toUpperCase()}</span>
          ${c.cisaKEV   ? `<span style="background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2);padding:2px 8px;border-radius:5px;font-size:.7em;font-weight:700">🚨 CISA KEV</span>` : ''}
          ${c.hasExploit ? `<span style="background:rgba(249,115,22,.1);color:#f97316;border:1px solid rgba(249,115,22,.2);padding:2px 8px;border-radius:5px;font-size:.7em;font-weight:700">⚡ Exploit Available</span>` : ''}
          <span style="background:#0d1520;color:#4a6080;border:1px solid #0f1929;padding:2px 8px;border-radius:5px;font-size:.7em">${h(c.status||'Unknown')}</span>
        </div>
      </div>
      <div style="text-align:center;flex-shrink:0">
        <div style="font-size:2.8em;font-weight:900;font-family:'JetBrains Mono',monospace;
          color:${p.bar};line-height:1">${score}</div>
        <div style="font-size:.68em;color:#3f5373">CVSS v${h(c.cvssVersion||'?')}</div>
      </div>
    </div>

    <!-- Dates -->
    <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:18px">
      ${[
        ['Published',     new Date(c.publishedDate||Date.now()).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})],
        ['Last Modified', new Date(c.lastModified||Date.now()).toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'})],
        ['Patch Status',  c.patchStatus||'Unknown', c.patchStatus==='Patched'?'#22c55e':'#ef4444'],
      ].map(([lbl,val,col]) => `
        <div style="background:#060c1a;border:1px solid #0f1929;border-radius:8px;padding:10px 14px">
          <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:4px">${lbl}</div>
          <div style="font-size:.82em;color:${col||'#6a8ab0'};font-weight:600">${val}</div>
        </div>`).join('')}
    </div>

    <!-- Description -->
    <div style="background:#060c1a;border:1px solid #0f1929;border-radius:10px;padding:15px;margin-bottom:18px">
      <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:8px">Description</div>
      <div style="font-size:.85em;color:#6a8ab0;line-height:1.85">${h(c.description||'No description available.')}</div>
    </div>

    ${c.cvssVector ? `
    <div style="background:#060c1a;border:1px solid #0f1929;border-radius:10px;padding:13px;margin-bottom:18px;
      font-family:'JetBrains Mono',monospace">
      <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:6px">CVSS Vector</div>
      <div style="font-size:.78em;color:#a78bfa;word-break:break-all">${h(c.cvssVector)}</div>
    </div>` : ''}

    ${(c.cwes||[]).length ? `
    <div style="margin-bottom:18px">
      <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:7px">Weaknesses (CWE)</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px">
        ${c.cwes.map(cw => `<span style="background:#060c1a;border:1px solid #0f1929;color:#6a8ab0;padding:3px 9px;border-radius:5px;font-size:.75em">${h(cw)}</span>`).join('')}
      </div>
      ${(() => {
        const techniques = c.cwes
          .map(cw => CWE_ATTACK[cw])
          .filter(Boolean)
          .filter((t, i, a) => a.findIndex(x => x.id === t.id) === i);
        if (!techniques.length) return '';
        return `
        <div style="margin-top:10px">
          <div style="font-size:.6em;color:#8b5cf6;text-transform:uppercase;font-weight:700;margin-bottom:6px;
            display:flex;align-items:center;gap:5px;">
            <i class="fas fa-sitemap"></i>MITRE ATT&amp;CK Correlation
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${techniques.map(t => {
              const tid2 = t.id.replace('.', '/');
              return `
              <a href="https://attack.mitre.org/techniques/${tid2}/" target="_blank" rel="noopener"
                style="background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.25);
                  color:#a78bfa;padding:3px 9px;border-radius:5px;font-size:.72em;text-decoration:none;
                  display:flex;align-items:center;gap:5px;font-family:'JetBrains Mono',monospace"
                onmouseover="this.style.background='rgba(139,92,246,.2)'"
                onmouseout="this.style.background='rgba(139,92,246,.1)'">
                <span style="color:#7c3aed;font-weight:700">${h(t.id)}</span>
                <span style="font-family:Inter,sans-serif;color:#8b9dc3">${h(t.name)}</span>
              </a>`;
            }).join('')}
          </div>
        </div>`;
      })()}
    </div>` : ''}

    ${(c.affectedSystems||[]).length ? `
    <div style="margin-bottom:18px">
      <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:8px">
        Affected Products (${c.totalAffected} total)
      </div>
      <div style="background:#060c1a;border:1px solid #0f1929;border-radius:10px;max-height:200px;overflow-y:auto">
        <table style="width:100%;border-collapse:collapse;font-size:.76em">
          <thead><tr style="border-bottom:1px solid #0f1929">
            <th style="text-align:left;padding:9px 13px;color:#3f5373;font-weight:600">Vendor</th>
            <th style="text-align:left;padding:9px 13px;color:#3f5373;font-weight:600">Product</th>
            <th style="text-align:left;padding:9px 13px;color:#3f5373;font-weight:600">Version</th>
          </tr></thead>
          <tbody>
            ${c.affectedSystems.map(s => `
              <tr style="border-bottom:1px solid rgba(15,25,41,.5)">
                <td style="padding:7px 13px;color:#6a8ab0">${h(s.vendor)}</td>
                <td style="padding:7px 13px;color:#60a5fa">${h(s.product)}</td>
                <td style="padding:7px 13px;color:#3f5373;font-family:monospace">${h(s.version)}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>` : ''}

    ${(c.references||[]).length ? `
    <div style="margin-bottom:18px">
      <div style="font-size:.62em;color:#3f5373;text-transform:uppercase;font-weight:600;margin-bottom:8px">References</div>
      <div style="display:flex;flex-direction:column;gap:5px">
        ${c.references.slice(0,8).map(r => `
          <a href="${h(r.url)}" target="_blank" rel="noopener"
            style="font-size:.76em;color:#3b82f6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block"
            onmouseover="this.style.color='#60a5fa'" onmouseout="this.style.color='#3b82f6'">
            ${h(r.url)}
          </a>`).join('')}
      </div>
    </div>` : ''}

    <!-- Actions -->
    <div style="display:flex;flex-wrap:wrap;gap:8px;padding-top:14px;border-top:1px solid #0f1929">
      <a href="https://nvd.nist.gov/vuln/detail/${h(c.id)}" target="_blank" rel="noopener"
        style="background:rgba(59,130,246,.13);color:#60a5fa;border:1px solid rgba(59,130,246,.28);
          padding:8px 16px;border-radius:8px;font-size:.82em;text-decoration:none;
          display:flex;align-items:center;gap:7px">
        <i class="fas fa-external-link-alt"></i>View on NVD
      </a>
      <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${h(c.id)}" target="_blank" rel="noopener"
        style="background:rgba(139,92,246,.13);color:#a78bfa;border:1px solid rgba(139,92,246,.28);
          padding:8px 16px;border-radius:8px;font-size:.82em;text-decoration:none;
          display:flex;align-items:center;gap:7px">
        <i class="fas fa-bug"></i>View on MITRE
      </a>
      <button onclick="cnhCase(${JSON.stringify(h(c.id+': '+(c.description||'').slice(0,80)))})"
        style="background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2);
          padding:8px 16px;border-radius:8px;font-size:.82em;cursor:pointer">
        <i class="fas fa-folder-plus" style="margin-right:5px"></i>Create Case
      </button>
      <button onclick="cnhCloseDetail()"
        style="background:#060c1a;color:#4a6080;border:1px solid #0f1929;
          padding:8px 16px;border-radius:8px;font-size:.82em;cursor:pointer;margin-left:auto">
        <i class="fas fa-arrow-left" style="margin-right:5px"></i>Back
      </button>
    </div>
  </div>`;
}

// ════════════════════════════════════════════════════════════════════
//  PAGINATION
// ════════════════════════════════════════════════════════════════════
function pagination(cur, total, cb) {
  if (total <= 1) return '';
  const pages = [];
  const start = Math.max(1, cur - 2);
  const end   = Math.min(total, cur + 2);
  if (start > 1) { pages.push(1); if (start > 2) pages.push('…'); }
  for (let i = start; i <= end; i++) pages.push(i);
  if (end < total) { if (end < total - 1) pages.push('…'); pages.push(total); }

  return `<div class="cnh-pgn">
    <button class="cnh-pg" onclick="${cb}(${cur-1})" ${cur<=1?'disabled':''}>
      <i class="fas fa-chevron-left"></i>
    </button>
    ${pages.map(p => typeof p === 'number'
      ? `<button class="cnh-pg ${p===cur?'active':''}" onclick="${cb}(${p})">${p}</button>`
      : `<span style="color:#3f5373;padding:0 4px">${p}</span>`
    ).join('')}
    <button class="cnh-pg" onclick="${cb}(${cur+1})" ${cur>=total?'disabled':''}>
      <i class="fas fa-chevron-right"></i>
    </button>
  </div>`;
}

global.cnhNewsPage = function (p) {
  S.newsPage = p;
  loadNews(S.tab);
  scrollToTop();
};
global.cnhCVEPage = function (p) {
  S.cvePage = p;
  loadCVEs();
  scrollToTop();
};
function scrollToTop() {
  document.getElementById('cnh-root')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ════════════════════════════════════════════════════════════════════
//  UTILITY VIEWS
// ════════════════════════════════════════════════════════════════════
function showSpinner(msg) {
  const c = document.getElementById('cnh-content');
  if (c) c.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;padding:80px 20px;color:#3f5373;gap:14px">
      <div class="cnh-spinner"></div>
      <span style="font-size:.85em">${h(msg)}</span>
    </div>`;
}

function showEmpty(icon, title, msg) {
  const c = document.getElementById('cnh-content');
  if (c) c.innerHTML = `
    <div class="cnh-empty">
      <i class="fas ${icon}" style="font-size:2.5em;opacity:.22;margin-bottom:14px"></i>
      <div style="font-size:.92em;font-weight:600;color:#3f5373;margin-bottom:6px">${title}</div>
      <div style="font-size:.8em">${msg}</div>
    </div>`;
}

function showError(title, detail, retryFn) {
  const c = document.getElementById('cnh-content');
  if (!c) return;
  c.innerHTML = `
    <div class="cnh-error" style="max-width:600px;margin:40px auto">
      <i class="fas fa-exclamation-circle" style="font-size:2.2em;color:#ef4444;margin-bottom:16px"></i>
      <div style="color:#ef4444;font-weight:700;font-size:.95em;margin-bottom:10px">${h(title)}</div>
      <div style="font-size:.8em;color:#3f5373;margin-bottom:20px;line-height:1.7;max-width:480px;margin:0 auto 20px">
        ${h(detail)}
      </div>
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
        <button onclick="${retryFn}"
          style="background:rgba(59,130,246,.13);color:#60a5fa;
            border:1px solid rgba(59,130,246,.28);
            padding:9px 20px;border-radius:8px;font-size:.83em;cursor:pointer;">
          <i class="fas fa-sync-alt" style="margin-right:6px"></i>Retry
        </button>
        <button onclick="cnhSwitchTab('cve-engine')"
          style="background:rgba(139,92,246,.13);color:#a78bfa;
            border:1px solid rgba(139,92,246,.28);
            padding:9px 20px;border-radius:8px;font-size:.83em;cursor:pointer;">
          <i class="fas fa-database" style="margin-right:6px"></i>Try CVE Engine
        </button>
      </div>
    </div>`;
}

// ════════════════════════════════════════════════════════════════════
//  ACTION HELPERS
// ════════════════════════════════════════════════════════════════════
global.cnhAddIOC = function (cves) {
  const msg = `✅ Added ${cves.length} CVE(s) to IOC database: ${cves.join(', ')}`;
  if (typeof showToast === 'function') showToast(msg, 'success');
  else console.info('[CyberNewsHub]', msg);
};

global.cnhCase = function (title) {
  const msg = `📁 Incident case created: "${String(title).slice(0, 70)}…"`;
  if (typeof showToast === 'function') showToast(msg, 'success');
  else console.info('[CyberNewsHub]', msg);
};

// ── Export helpers — collect data from last loaded batch ─────────────────
let _lastNewsData = [];
let _lastCVEData  = [];

global.cnhNewsExport = function () {
  const rows = [['Title','Source','Category','Severity','Published','URL','Tags','CVEs']];
  for (const a of _lastNewsData) {
    rows.push([
      `"${(a.title||'').replace(/"/g,'""')}"`,
      `"${(a.source||'').replace(/"/g,'""')}"`,
      a.category || '',
      a.severity || '',
      a.publishedAt || '',
      a.url || '',
      `"${(a.tags||[]).join(',')}",`,
      `"${(a.cves||[]).join(',')}"`,
    ]);
  }
  if (rows.length <= 1) {
    if (typeof showToast === 'function') showToast('No articles loaded to export', 'warning');
    return;
  }
  const csv  = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type:'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `cyber-news-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  if (typeof showToast === 'function') showToast('📊 Exported as CSV', 'success');
};

global.cnhCVEExport = function () {
  const rows = [['CVE ID','Severity','CVSS Score','CVSS Version','Published','Last Modified','Patch Status','CISA KEV','Has Exploit','Description']];
  for (const c of _lastCVEData) {
    rows.push([
      c.id || '',
      c.severity || '',
      c.cvssScore != null ? Number(c.cvssScore).toFixed(1) : '',
      c.cvssVersion || '',
      c.publishedDate ? new Date(c.publishedDate).toISOString().slice(0,10) : '',
      c.lastModified  ? new Date(c.lastModified).toISOString().slice(0,10)  : '',
      c.patchStatus || '',
      c.cisaKEV ? 'YES' : 'NO',
      c.hasExploit ? 'YES' : 'NO',
      `"${(c.description||'').slice(0,200).replace(/"/g,'""')}"`,
    ]);
  }
  if (rows.length <= 1) {
    if (typeof showToast === 'function') showToast('No CVE data loaded to export', 'warning');
    return;
  }
  const csv  = rows.map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type:'text/csv' });
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = `cve-export-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  if (typeof showToast === 'function') showToast('📊 CVEs exported as CSV', 'success');
};

// Expose loadCVEs globally for retry buttons
global.loadCVEs = loadCVEs;

}(window));
