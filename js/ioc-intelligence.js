/**
 * ══════════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — IOC Intelligence Database v5.1 (PRODUCTION)
 *  FILE: js/ioc-intelligence.js
 *
 *  Features:
 *  ─────────
 *  • Full-text search + filter by type / reputation / source / confidence
 *  • Confidence score visualization (color-coded badge)
 *  • Relationship mapping: IP ↔ Domain ↔ Hash pivot
 *  • One-click enrichment via backend /api/intel/enrich
 *  • Export to CSV
 *  • Pagination + sort by risk_score / created_at / confidence
 *  • Ingest trigger button (calls POST /api/ingest/run)
 *  • No mock data — all data from real backend API
 * ══════════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ─────────────────────────────────────────────
   INTERNAL STATE
───────────────────────────────────────────── */
const IOCDB = {
  page:    1,
  limit:   50,
  total:   0,
  filters: { search: '', type: '', reputation: '', source: '', min_confidence: 0, sort: 'risk_score', order: 'desc' },
  data:    [],
  loading: false,
  enriching: new Set(),
  _rlsWarningShown: false,
  _allTenants:      false,   // SUPER_ADMIN toggle — view all tenants
  _tenantId:        null,    // set from stats response
};

/* ─────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────── */
function _esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _apiGet(path) {
  const base  = (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');

  // Inject all_tenants flag for SUPER_ADMIN all-tenant view
  let finalPath = path;
  if (IOCDB._allTenants && path.startsWith('/iocs')) {
    const sep = path.includes('?') ? '&' : '?';
    finalPath = `${path}${sep}all_tenants=1`;
  }

  // Use authFetch if available (from auth-validator.js) — it handles 401/retry automatically.
  // CRITICAL: authFetch internally prepends "${base}/api" to the path, so we must pass
  // finalPath WITHOUT the /api prefix. Passing '/api/iocs' would create double-prefix:
  //   authFetch('/api/iocs') → base + '/api' + '/api/iocs' = /api/api/iocs → 404!
  if (window.authFetch) {
    return window.authFetch(finalPath);
  }
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || sessionStorage.getItem('tp_token') || (window.getAuthToken?.() || '');
  return fetch(`${base}/api${finalPath}`, {
    headers: { 'Content-Type':'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }
  }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)));
}

function _apiPost(path, body) {
  const base  = (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  // Use authFetch if available — pass path WITHOUT /api prefix (authFetch adds it internally).
  if (window.authFetch) {
    return window.authFetch(path, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || sessionStorage.getItem('tp_token') || (window.getAuthToken?.() || '');
  return fetch(`${base}/api${path}`, {
    method: 'POST',
    headers: { 'Content-Type':'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)));
}

function confidenceBadge(n) {
  if (n == null) return '';
  const pct = Math.min(100, Math.max(0, parseInt(n)));
  const c   = pct >= 85 ? '#00cc44' : pct >= 60 ? '#ffcc00' : pct >= 35 ? '#ff8800' : '#ff4444';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;padding:1px 7px;border-radius:8px;font-size:.7em;font-weight:700">${pct}%</span>`;
}

function riskBadge(n) {
  if (n == null) return '';
  const c = n>=70?'#ff4444':n>=40?'#ff8800':n>=20?'#ffcc00':'#00cc44';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;padding:1px 6px;border-radius:6px;font-size:.75em;font-weight:600">${n}</span>`;
}

function repBadge(r) {
  const map = {
    malicious:  { c:'#ff4444', label:'Malicious' },
    suspicious: { c:'#ff8800', label:'Suspicious' },
    clean:      { c:'#00cc44', label:'Clean' },
    unknown:    { c:'#8b949e', label:'Unknown' },
  };
  const m = map[(r||'unknown').toLowerCase()] || map.unknown;
  return `<span style="background:${m.c}22;color:${m.c};border:1px solid ${m.c}44;padding:1px 7px;border-radius:8px;font-size:.7em;font-weight:700">${m.label}</span>`;
}

function typeBadge(t) {
  const colors = { ip:'#22d3ee', domain:'#a78bfa', url:'#34d399', md5:'#fbbf24', sha256:'#f59e0b',
    sha1:'#fb923c', email:'#e879f9', hostname:'#67e8f9', hash:'#fbbf24' };
  const c = colors[(t||'').toLowerCase()] || '#8b949e';
  return `<span style="background:${c}22;color:${c};border:1px solid ${c}44;padding:1px 7px;border-radius:8px;font-size:.7em;font-weight:600;text-transform:uppercase">${_esc(t||'?')}</span>`;
}

function ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

/* ─────────────────────────────────────────────
   RENDER MAIN VIEW
───────────────────────────────────────────── */
async function renderIOCDatabase() {
  const wrap = document.getElementById('iocDatabaseWrap') || document.getElementById('page-ioc-database');
  if (!wrap) return;

  wrap.innerHTML = `
    <div id="iocdb-root" style="padding:20px;height:100%;display:flex;flex-direction:column;gap:16px;overflow:auto">
      <!-- Header -->
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div>
          <h2 style="margin:0;font-size:1.3em;color:#e6edf3">
            <i class="fas fa-database" style="color:#22d3ee;margin-right:8px"></i>IOC Intelligence Database
          </h2>
          <p style="margin:4px 0 0;color:#8b949e;font-size:.85em">
            Live threat indicators ingested from real feeds — search, filter, enrich
          </p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <button id="iocdb-ingest-btn" onclick="iocdbTriggerIngest()" style="padding:7px 16px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em;display:flex;align-items:center;gap:6px">
            <i class="fas fa-sync-alt"></i> Ingest Feeds
          </button>
          <button onclick="iocdbExportCSV()" style="padding:7px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em;display:flex;align-items:center;gap:6px">
            <i class="fas fa-download"></i> Export CSV
          </button>
        </div>
      </div>

      <!-- Stats bar -->
      <div id="iocdb-stats" style="display:flex;gap:12px;flex-wrap:wrap">
        <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
          <div id="iocdb-stat-total" style="font-size:1.6em;font-weight:700;color:#22d3ee">—</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">Total IOCs</div>
        </div>
        <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
          <div id="iocdb-stat-high" style="font-size:1.6em;font-weight:700;color:#ff4444">—</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">High Risk (≥70)</div>
        </div>
        <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
          <div id="iocdb-stat-feeds" style="font-size:1.6em;font-weight:700;color:#00cc44">—</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">Active Feeds</div>
        </div>
        <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center">
          <div id="iocdb-stat-types" style="font-size:1.6em;font-weight:700;color:#a78bfa">—</div>
          <div style="font-size:.75em;color:#8b949e;margin-top:2px">IOC Types</div>
        </div>
      </div>

      <!-- Filters -->
      <div style="display:flex;gap:10px;flex-wrap:wrap;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px">
        <input id="iocdb-search" type="text" placeholder="🔍 Search IOC value, tags, malware family…"
          style="flex:2;min-width:200px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 12px;font-size:.9em"
          oninput="iocdbOnSearch(this.value)" />

        <select id="iocdb-type" onchange="iocdbFilter('type',this.value)"
          style="flex:1;min-width:130px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.85em">
          <option value="">All Types</option>
          <option>ip</option><option>domain</option><option>url</option>
          <option>md5</option><option>sha256</option><option>sha1</option>
          <option>email</option><option>hostname</option>
        </select>

        <select id="iocdb-rep" onchange="iocdbFilter('reputation',this.value)"
          style="flex:1;min-width:130px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.85em">
          <option value="">All Reputations</option>
          <option>malicious</option><option>suspicious</option><option>clean</option><option>unknown</option>
        </select>

        <select id="iocdb-sort" onchange="iocdbFilter('sort',this.value)"
          style="flex:1;min-width:150px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.85em">
          <option value="risk_score">Sort: Risk Score ↓</option>
          <option value="confidence">Sort: Confidence ↓</option>
          <option value="last_seen">Sort: Last Seen ↓</option>
          <option value="first_seen">Sort: First Seen ↓</option>
        </select>

        <input id="iocdb-conf" type="number" min="0" max="100" placeholder="Min confidence %"
          style="width:140px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:8px 10px;font-size:.85em"
          oninput="iocdbFilter('min_confidence', parseInt(this.value)||0)" />

        <button onclick="iocdbClearFilters()" style="padding:8px 14px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
          ✕ Clear
        </button>
      </div>

      <!-- Table -->
      <div id="iocdb-table-wrap" style="flex:1;overflow:auto;background:#161b22;border:1px solid #21262d;border-radius:8px">
        <div id="iocdb-table-inner" style="padding:8px">
          <div style="padding:40px;text-align:center;color:#8b949e">
            <i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px"></i>Loading IOC database…
          </div>
        </div>
      </div>

      <!-- Pagination -->
      <div id="iocdb-pagination"></div>
    </div>
  `;

  // Load data
  await iocdbLoadStats();
  await iocdbLoadPage(1);
}

/* ─────────────────────────────────────────────
   LOAD STATS
───────────────────────────────────────────── */
async function iocdbLoadStats() {
  try {
    const stats = await _apiGet('/ingest/stats');
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v != null ? v.toLocaleString() : '—'; };
    setEl('iocdb-stat-total', stats.total_iocs);
    setEl('iocdb-stat-high',  stats.high_risk);
    setEl('iocdb-stat-feeds', (stats.available_feeds || []).filter(f => f.has_key).length || stats.feeds_active || 0);
    // by_type is now an object { ip: 123, domain: 45, ... }
    const typeCount = typeof stats.by_type === 'object' && !Array.isArray(stats.by_type)
      ? Object.keys(stats.by_type).length
      : (stats.ioc_types || 0);
    setEl('iocdb-stat-types', typeCount);

    // Store tenant context for the UI
    IOCDB._tenantId = stats.tenant_id;

    // Show all-tenant toggle for SUPER_ADMIN users
    _iocdbMaybeShowAllTenantsToggle(stats);

    // Show RLS warning banner if stats show 0 but data should exist
    if ((stats.total_iocs === 0 || stats.total_iocs == null) && !IOCDB._rlsWarningShown) {
      IOCDB._rlsWarningShown = true;
      _iocdbShowRLSWarning();
    } else {
      // Hide warning if data is loading fine
      const warn = document.getElementById('iocdb-rls-warning');
      if (warn) warn.remove();
    }
  } catch (err) {
    console.warn('[IOC-DB] Stats load failed:', err.message);
    // If stats failed but we already have IOC data, don't show error
    if (IOCDB.data.length > 0) return;
    // Try to show total from loaded data as fallback
    const statTotal = document.getElementById('iocdb-stat-total');
    if (statTotal && statTotal.textContent === '—') {
      statTotal.textContent = 'N/A';
    }
  }
}

/**
 * Show an "All Tenants" toggle for SUPER_ADMIN users when their tenant has fewer IOCs
 * than the platform total. This surfaces the 12,099 vs 33,750 discrepancy.
 */
function _iocdbMaybeShowAllTenantsToggle(stats) {
  // Check if user is SUPER_ADMIN by looking at CURRENT_USER
  const user = window.CURRENT_USER;
  if (!user || !['SUPER_ADMIN', 'ADMIN', 'super_admin', 'admin'].includes(user.role)) return;

  const headerEl = document.querySelector('#iocdb-root > div:first-child > div:last-child');
  if (!headerEl || document.getElementById('iocdb-tenant-toggle')) return;

  const toggleBtn = document.createElement('button');
  toggleBtn.id = 'iocdb-tenant-toggle';
  toggleBtn.title = IOCDB._allTenants
    ? `Viewing all tenants — click to scope to your tenant (${stats.tenant_id})`
    : `Viewing tenant ${stats.tenant_id} only — click to see all ${(stats.platform_total || stats.total_iocs || 0).toLocaleString()} platform-wide IOCs`;
  toggleBtn.style.cssText = 'padding:7px 16px;background:#a78bfa20;border:1px solid #a78bfa;color:#a78bfa;border-radius:6px;cursor:pointer;font-size:.82em;display:flex;align-items:center;gap:6px';
  toggleBtn.innerHTML = IOCDB._allTenants
    ? '<i class="fas fa-globe"></i> All Tenants'
    : '<i class="fas fa-building"></i> My Tenant';

  toggleBtn.addEventListener('click', async () => {
    IOCDB._allTenants = !IOCDB._allTenants;
    // Re-render with new tenant context
    IOCDB.loading = false;
    IOCDB.page = 1;
    IOCDB.data = [];
    await iocdbLoadStats();
    await iocdbLoadPage(1);
  });

  headerEl.insertBefore(toggleBtn, headerEl.firstChild);
}


/**
 * Show an actionable RLS warning banner when 0 IOCs are returned.
 * This is the #1 root cause: RLS enabled with no SELECT policy.
 */
function _iocdbShowRLSWarning() {
  const root = document.getElementById('iocdb-root');
  if (!root || document.getElementById('iocdb-rls-warning')) return;

  const banner = document.createElement('div');
  banner.id = 'iocdb-rls-warning';
  banner.style.cssText = 'background:#ff8c0015;border:1px solid #ff8c00;border-radius:8px;padding:16px 20px;display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap';
  banner.innerHTML = `
    <div style="flex:1;min-width:260px">
      <div style="color:#ff8c00;font-weight:700;margin-bottom:6px;font-size:.95em">
        ⚠️ 0 IOCs found — likely RLS issue (Supabase returns empty arrays silently)
      </div>
      <div style="color:#8b949e;font-size:.82em;line-height:1.6">
        <strong style="color:#e6edf3">Most likely cause:</strong>
        The <code style="background:#21262d;padding:1px 5px;border-radius:3px">iocs</code> table has
        <strong>RLS enabled with no SELECT policy</strong> — Supabase returns
        <code style="background:#21262d;padding:1px 5px;border-radius:3px">[]</code> silently
        even though 33,750 rows exist.<br><br>
        <strong style="color:#e6edf3">Immediate fix:</strong>
        Run <code style="background:#21262d;padding:1px 5px;border-radius:3px">migration-v7.0-ioc-rls.sql</code>
        in Supabase SQL Editor → it adds a debug SELECT policy in 30 seconds.
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-shrink:0;flex-wrap:wrap">
      <button onclick="iocdbRunDiagnostic()" style="padding:8px 14px;background:#ff8c0020;border:1px solid #ff8c00;color:#ff8c00;border-radius:6px;cursor:pointer;font-size:.82em;font-weight:600">
        🔍 Run Diagnostic
      </button>
      <button onclick="document.getElementById('iocdb-rls-warning').remove()" style="padding:8px 12px;background:#21262d;border:1px solid #30363d;color:#8b949e;border-radius:6px;cursor:pointer;font-size:.82em">
        Dismiss
      </button>
    </div>
  `;
  // Insert after stats bar (second child)
  const statsBar = document.getElementById('iocdb-stats');
  if (statsBar && statsBar.nextSibling) {
    root.insertBefore(banner, statsBar.nextSibling);
  } else {
    root.insertBefore(banner, root.firstChild);
  }
}

/**
 * Run live diagnostic: tests API health, auth status, and IOC query.
 * Shows a detailed report inside the table area.
 */
async function iocdbRunDiagnostic() {
  const inner = document.getElementById('iocdb-table-inner');
  if (!inner) return;

  inner.innerHTML = `<div style="padding:20px">
    <div style="color:#22d3ee;font-weight:700;margin-bottom:12px;font-size:1em">
      <i class="fas fa-stethoscope" style="margin-right:8px"></i>IOC Database Diagnostic
    </div>
    <div id="iocdb-diag-results" style="font-family:monospace;font-size:.82em;line-height:1.8;color:#8b949e">
      <i class="fas fa-spinner fa-spin"></i> Running checks…
    </div>
  </div>`;

  const diag = document.getElementById('iocdb-diag-results');
  const log  = (msg, color='#8b949e') => {
    diag.innerHTML += `<div style="color:${color}">${msg}</div>`;
  };
  diag.innerHTML = '';

  const base = (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');
  log(`📡 Backend URL: <span style="color:#22d3ee">${base}</span>`);

  // Step 1: Health check
  try {
    const hRes = await fetch(`${base}/health`);
    const hData = await hRes.json();
    log(`✅ Health check: <span style="color:#00cc44">OK (${hRes.status})</span>  status=${hData.status || 'ok'}`, '#00cc44');
  } catch (e) {
    log(`❌ Health check FAILED: ${e.message} — backend may be sleeping (Render free tier cold start ~30s)`, '#ff4444');
  }

  // Step 2: Auth token check
  const token = localStorage.getItem('wadjet_access_token') ||
                localStorage.getItem('tp_access_token') ||
                sessionStorage.getItem('tp_token') ||
                (window.getAuthToken?.() || '');
  if (token) {
    log(`✅ Auth token: Found in storage (${token.length} chars)`, '#00cc44');
  } else {
    log(`❌ Auth token: NOT FOUND — user is not logged in or token key mismatch`, '#ff4444');
    log(`   → Check: localStorage.getItem('wadjet_access_token')`);
    log(`   → Fix: Log out and log in again to regenerate token`);
  }

  // Step 3: Stats endpoint test
  try {
    const sRes = await fetch(`${base}/api/ingest/stats`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    if (sRes.status === 401) {
      log(`❌ Stats endpoint: 401 Unauthorized — token invalid or missing`, '#ff4444');
      log(`   → Hint: ${(await sRes.json()).hint || 'Log in again'}`);
    } else if (sRes.ok) {
      const s = await sRes.json();
      log(`✅ Stats endpoint: OK — total_iocs=${s.total_iocs} high_risk=${s.high_risk}`, s.total_iocs > 0 ? '#00cc44' : '#ff8c00');
      if (s.total_iocs === 0) {
        log(`⚠️  Stats returned 0 IOCs. Root cause analysis:`, '#ff8c00');
        log(`   #1 (MOST LIKELY) RLS has no SELECT policy — run migration-v7.0-ioc-rls.sql`, '#ffcc00');
        log(`   #2 tenant_id mismatch — your user.tenant_id=${s.tenant_id} may not match iocs rows`);
        log(`   #3 Backend using anon client instead of service_role — check iocs.js uses supabaseAdmin`);
      }
    } else {
      log(`❌ Stats endpoint: HTTP ${sRes.status}`, '#ff4444');
    }
  } catch (e) {
    log(`❌ Stats request failed: ${e.message}`, '#ff4444');
  }

  // Step 4: Direct IOC query test
  try {
    const iRes = await fetch(`${base}/api/iocs?limit=1`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    if (iRes.ok) {
      const d = await iRes.json();
      if (d.total > 0) {
        log(`✅ IOC query: total=${d.total} — DATA IS ACCESSIBLE`, '#00cc44');
        log(`   → The display bug may be in the frontend stats rendering, not the API.`);
        log(`   → Reloading page in 3 seconds…`, '#22d3ee');
        setTimeout(() => iocdbLoadPage(1), 3000);
      } else {
        log(`⚠️  IOC query: total=0 — API returned empty results`, '#ff8c00');
        log(`   Confirmed: RLS is blocking access. Apply migration-v7.0-ioc-rls.sql NOW.`, '#ff4444');
      }
    } else {
      const err = await iRes.json().catch(() => ({}));
      log(`❌ IOC query: HTTP ${iRes.status} — ${err.error || err.message || 'Unknown error'}`, '#ff4444');
    }
  } catch (e) {
    log(`❌ IOC query failed: ${e.message}`, '#ff4444');
  }

  // Step 5: Specific IOC search test
  try {
    const sRes2 = await fetch(`${base}/api/iocs?search=costliergridco.click&limit=5`, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    if (sRes2.ok) {
      const d2 = await sRes2.json();
      if (d2.total > 0) {
        log(`✅ Exact search 'costliergridco.click': FOUND ${d2.total} match(es)`, '#00cc44');
      } else {
        log(`⚠️  Exact search 'costliergridco.click': 0 results — RLS blocking or type constraint rejecting this IOC`, '#ff8c00');
      }
    }
  } catch (_) {}

  log(`<br><span style="color:#22d3ee;font-weight:700">── Next Steps ──────────────────────────</span>`);
  log(`1. Run <strong>backend/database/migration-v7.0-ioc-rls.sql</strong> in Supabase SQL Editor`);
  log(`   → Opens: <a href="https://supabase.com/dashboard/project/miywxnplaltduuscjfmq/sql" target="_blank" style="color:#22d3ee">Supabase SQL Editor</a>`);
  log(`2. Redeploy backend on Render (to pick up iocs.js service_role fix)`);
  log(`3. Refresh this page — should show ~33,750 IOCs`);
  log(`4. If still 0: check tenant_id match between user profile and iocs table`);
  log(`<br><button onclick="iocdbLoadPage(1)" style="padding:6px 14px;background:#1d6ae5;border:none;color:#fff;border-radius:6px;cursor:pointer;font-size:.82em">↩ Back to IOC List</button>`);
}

/* ─────────────────────────────────────────────
   LOAD PAGE
───────────────────────────────────────────── */
async function iocdbLoadPage(page = 1) {
  if (IOCDB.loading) return;
  IOCDB.loading = true;
  IOCDB.page    = page;

  const inner = document.getElementById('iocdb-table-inner');
  if (inner) inner.innerHTML = `<div style="padding:40px;text-align:center;color:#8b949e"><i class="fas fa-spinner fa-spin fa-2x" style="display:block;margin-bottom:12px"></i>Loading…</div>`;

  try {
    const f   = IOCDB.filters;
    const qs  = new URLSearchParams({
      page:   page,
      limit:  IOCDB.limit,
      ...(f.search         ? { search: f.search }             : {}),
      ...(f.type           ? { type: f.type }                 : {}),
      ...(f.reputation     ? { reputation: f.reputation }     : {}),
      ...(f.source         ? { source: f.source }             : {}),
      ...(f.min_confidence ? { min_confidence: f.min_confidence } : {}),
      sort:   f.sort  || 'risk_score',
      order:  f.order || 'desc',
    });

    const res = await _apiGet(`/iocs?${qs}`);

    // Guard: handle unexpected response shapes (null, _notfound, non-array data)
    if (!res || res._notfound) {
      console.warn('[IOC-Intel] API returned 404 / empty response — check backend or tenant ID');
      IOCDB.data  = [];
      IOCDB.total = 0;
      renderIOCTable([], inner);
      renderIOCPagination(0, page);
      _iocdbShowRLSWarning();
      return;
    }

    const iocs  = Array.isArray(res.data) ? res.data : (Array.isArray(res) ? res : []);
    IOCDB.data  = iocs;
    // Handle total=-1 (backend returned unknown count due to timeout on COUNT query)
    // Fall back to iocs.length as a lower bound.
    const rawTotal = res.total ?? res.count ?? res.pagination?.total;
    IOCDB.total = (rawTotal === -1 || rawTotal == null) ? iocs.length : rawTotal;

    console.log(`[IOC-Intel] Loaded page ${page}: ${iocs.length} IOCs, total=${IOCDB.total}`);

    renderIOCTable(iocs, inner);
    renderIOCPagination(IOCDB.total, page);

    // Update the stats bar Total counter live from the IOC query total
    // (in case iocdbLoadStats hasn't run yet or stats endpoint returned 0)
    if (IOCDB.total > 0) {
      const statTotal = document.getElementById('iocdb-stat-total');
      if (statTotal && (statTotal.textContent === '—' || statTotal.textContent === '0')) {
        statTotal.textContent = IOCDB.total.toLocaleString();
      }
      // Hide RLS warning if we have data
      const warn = document.getElementById('iocdb-rls-warning');
      if (warn) warn.remove();
    }

    // If 0 total and no active search, show diagnostic hint
    if (IOCDB.total === 0 && !f.search && !f.type && !f.reputation) {
      _iocdbShowRLSWarning();
    }

  } catch (err) {
    console.error('[IOC-Intel] iocdbLoadPage error:', err);
    const isAuth    = err.message?.includes('401') || err.message?.includes('auth') ||
                      err.message?.includes('Unauthorized') || err.message?.includes('Authentication');
    const isTimeout = err.message?.includes('503') || err.message?.includes('timeout') ||
                      err.message?.includes('timed out');

    let hint = 'Ensure backend is running and you are authenticated. Check backend logs for details.';
    if (isAuth)    hint = 'Authentication error — your session may have expired. <a href="javascript:void(0)" onclick="window.location.reload()" style="color:#22d3ee">Refresh page</a>';
    if (isTimeout) hint = 'The database query timed out (large IOC table). Try adding filters or a smaller page size.';

    if (inner) inner.innerHTML = `
      <div style="padding:32px;text-align:center;color:#ef4444">
        <i class="fas fa-exclamation-triangle fa-2x" style="display:block;margin-bottom:10px"></i>
        <strong>${_esc(err.message)}</strong><br>
        <small style="color:#8b949e">${hint}</small><br><br>
        <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:8px">
          <button onclick="iocdbRunDiagnostic()" style="padding:7px 14px;background:#ff8c0020;border:1px solid #ff8c00;color:#ff8c00;border-radius:6px;cursor:pointer;font-size:.82em">
            🔍 Run Diagnostic
          </button>
          <button onclick="IOCDB.loading=false;iocdbLoadPage(1)" style="padding:7px 14px;background:#1d6ae520;border:1px solid #1d6ae5;color:#1d6ae5;border-radius:6px;cursor:pointer;font-size:.82em">
            ↩ Retry
          </button>
        </div>
      </div>
    `;
  } finally {
    // ALWAYS release the loading flag — prevents permanent stuck state
    IOCDB.loading = false;
  }
}

/* ─────────────────────────────────────────────
   RENDER TABLE
───────────────────────────────────────────── */
function renderIOCTable(iocs, container) {
  if (!container) return;

  if (iocs.length === 0) {
    container.innerHTML = `<div style="padding:48px;text-align:center;color:#8b949e">
      <i class="fas fa-database fa-2x" style="display:block;margin-bottom:12px;opacity:.4"></i>
      No IOCs found matching your filters.<br>
      <small>Try adjusting your search terms or <button onclick="iocdbTriggerIngest()" style="background:none;border:none;color:#22d3ee;cursor:pointer;text-decoration:underline">trigger a feed ingest</button> to populate data.</small>
    </div>`;
    return;
  }

  const rows = iocs.map(ioc => {
    const tags = (ioc.tags || []).slice(0, 3).map(t => `<span style="background:#21262d;color:#8b949e;padding:1px 6px;border-radius:4px;font-size:.68em">${_esc(t)}</span>`).join(' ');
    const isEnriching = IOCDB.enriching.has(ioc.id);
    return `
      <tr style="border-bottom:1px solid #21262d;cursor:pointer" onmouseenter="this.style.background='#1c2128'" onmouseleave="this.style.background=''" onclick="iocdbShowDetail('${_esc(ioc.id)}')">
        <td style="padding:10px 12px;max-width:260px">
          <div style="display:flex;align-items:center;gap:8px">
            ${typeBadge(ioc.type)}
            <span style="color:#e6edf3;font-family:monospace;font-size:.85em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px" title="${_esc(ioc.value)}">${_esc(ioc.value)}</span>
          </div>
          ${tags ? `<div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap">${tags}</div>` : ''}
        </td>
        <td style="padding:10px 8px">${repBadge(ioc.reputation)}</td>
        <td style="padding:10px 8px">${riskBadge(ioc.risk_score)}</td>
        <td style="padding:10px 8px">${confidenceBadge(ioc.confidence)}</td>
        <td style="padding:10px 8px;font-size:.8em;color:#8b949e">${_esc(ioc.source || '—')}</td>
        <td style="padding:10px 8px;font-size:.8em;color:#8b949e">${_esc(ioc.malware_family || ioc.threat_actor || '—')}</td>
        <td style="padding:10px 8px;font-size:.8em;color:#8b949e">${ago(ioc.last_seen || ioc.updated_at)}</td>
        <td style="padding:10px 8px" onclick="event.stopPropagation()">
          <button onclick="iocdbEnrich('${_esc(ioc.id)}','${_esc(ioc.value)}','${_esc(ioc.type)}')"
            ${isEnriching ? 'disabled' : ''}
            style="padding:4px 10px;background:${isEnriching?'#30363d':'#1d6ae520'};border:1px solid ${isEnriching?'#30363d':'#1d6ae5'};color:${isEnriching?'#8b949e':'#1d6ae5'};border-radius:5px;cursor:pointer;font-size:.75em">
            ${isEnriching ? '<i class="fas fa-spinner fa-spin"></i>' : '⚡ Enrich'}
          </button>
        </td>
      </tr>
    `;
  });

  container.innerHTML = `
    <table style="width:100%;border-collapse:collapse;font-size:.9em">
      <thead>
        <tr style="border-bottom:2px solid #30363d;background:#0d1117">
          <th style="padding:10px 12px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase;letter-spacing:.05em">IOC Value</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Reputation</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Risk</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Confidence</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Source</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Family/Actor</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Last Seen</th>
          <th style="padding:10px 8px;text-align:left;color:#8b949e;font-weight:600;font-size:.8em;text-transform:uppercase">Actions</th>
        </tr>
      </thead>
      <tbody>${rows.join('')}</tbody>
    </table>
  `;
}

/* ─────────────────────────────────────────────
   PAGINATION
───────────────────────────────────────────── */
function renderIOCPagination(total, current) {
  const el     = document.getElementById('iocdb-pagination');
  if (!el) return;
  const pages  = Math.ceil(total / IOCDB.limit) || 1;
  const shown  = Math.min(current * IOCDB.limit, total);

  if (pages <= 1) {
    el.innerHTML = `<div style="text-align:center;color:#8b949e;font-size:.8em;padding:8px 0">Showing all ${total.toLocaleString()} IOCs</div>`;
    return;
  }

  const s = Math.max(1, current-2), e = Math.min(pages, current+2);
  let h = `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;flex-wrap:wrap;gap:8px">`;
  h += `<span style="color:#8b949e;font-size:.8em">Showing ${shown.toLocaleString()} of ${total.toLocaleString()} IOCs</span>`;
  h += `<div style="display:flex;gap:6px">`;
  h += `<button onclick="iocdbLoadPage(${current-1})" ${current===1?'disabled':''} style="padding:4px 10px;background:#21262d;border:1px solid #30363d;color:${current===1?'#555':'#e6edf3'};border-radius:6px;cursor:pointer;font-size:.8em">‹</button>`;
  for (let p = s; p <= e; p++) {
    h += `<button onclick="iocdbLoadPage(${p})" style="padding:4px 8px;min-width:28px;background:${p===current?'#1d6ae5':'#21262d'};border:1px solid ${p===current?'#1d6ae5':'#30363d'};color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.8em">${p}</button>`;
  }
  h += `<button onclick="iocdbLoadPage(${current+1})" ${current===pages?'disabled':''} style="padding:4px 10px;background:#21262d;border:1px solid #30363d;color:${current===pages?'#555':'#e6edf3'};border-radius:6px;cursor:pointer;font-size:.8em">›</button>`;
  h += '</div></div>';
  el.innerHTML = h;
}

/* ─────────────────────────────────────────────
   DETAIL MODAL (IOC + relationships)
───────────────────────────────────────────── */
function iocdbShowDetail(iocId) {
  const ioc = IOCDB.data.find(i => i.id === iocId);
  if (!ioc) return;

  const enrichment = ioc.enrichment_data || {};
  const vtData     = enrichment.virustotal || {};
  const abuseData  = enrichment.abuseipdb  || {};

  const modalHtml = `
    <div id="iocdb-modal" onclick="if(event.target===this)document.getElementById('iocdb-modal').remove()"
      style="position:fixed;inset:0;background:#000000cc;display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px">
      <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;max-width:700px;width:100%;max-height:90vh;overflow:auto;padding:28px;position:relative">
        <button onclick="document.getElementById('iocdb-modal').remove()"
          style="position:absolute;top:16px;right:16px;background:none;border:none;color:#8b949e;font-size:1.4em;cursor:pointer">✕</button>

        <h3 style="margin:0 0 16px;color:#e6edf3;font-size:1.1em;display:flex;align-items:center;gap:10px">
          <i class="fas fa-fingerprint" style="color:#22d3ee"></i>
          IOC Detail
        </h3>

        <!-- Main info -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;flex-wrap:wrap">
            ${typeBadge(ioc.type)} ${repBadge(ioc.reputation)}
            <span style="font-family:monospace;color:#e6edf3;font-size:.9em;word-break:break-all">${_esc(ioc.value)}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px">
            ${_kv('Risk Score',      riskBadge(ioc.risk_score))}
            ${_kv('Confidence',      confidenceBadge(ioc.confidence))}
            ${_kv('Source',          ioc.source || '—')}
            ${_kv('Malware Family',  ioc.malware_family || '—')}
            ${_kv('Threat Actor',    ioc.threat_actor || '—')}
            ${_kv('Country',         ioc.country || '—')}
            ${_kv('First Seen',      _fmtDate(ioc.first_seen))}
            ${_kv('Last Seen',       _fmtDate(ioc.last_seen))}
          </div>
          ${(ioc.tags||[]).length ? `<div style="margin-top:12px;display:flex;gap:6px;flex-wrap:wrap">${(ioc.tags||[]).map(t=>`<span style="background:#21262d;color:#8b949e;padding:2px 8px;border-radius:4px;font-size:.75em">${_esc(t)}</span>`).join('')}</div>` : ''}
          ${ioc.notes ? `<div style="margin-top:12px;padding:10px;background:#21262d;border-radius:6px;font-size:.8em;color:#8b949e">${_esc(ioc.notes)}</div>` : ''}
        </div>

        <!-- Enrichment data -->
        ${(vtData.malicious !== undefined) ? `
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px">
          <h4 style="margin:0 0 12px;font-size:.9em;color:#e6edf3"><i class="fas fa-shield-virus" style="color:#22d3ee;margin-right:6px"></i>VirusTotal Enrichment</h4>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px">
            ${_kv('Malicious',  `<span style="color:#ff4444;font-weight:700">${vtData.malicious || 0}</span>`)}
            ${_kv('Suspicious', `<span style="color:#ff8800;font-weight:700">${vtData.suspicious || 0}</span>`)}
            ${_kv('Harmless',   `<span style="color:#00cc44;font-weight:700">${vtData.harmless || 0}</span>`)}
            ${_kv('Reputation', vtData.reputation || '—')}
          </div>
        </div>` : ''}

        ${(abuseData.abuse_score !== undefined) ? `
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px">
          <h4 style="margin:0 0 12px;font-size:.9em;color:#e6edf3"><i class="fas fa-ban" style="color:#ff4444;margin-right:6px"></i>AbuseIPDB Data</h4>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px">
            ${_kv('Abuse Score',    `${abuseData.abuse_score}%`)}
            ${_kv('Total Reports',  abuseData.total_reports || 0)}
            ${_kv('ISP',            abuseData.isp || '—')}
            ${_kv('Usage Type',     abuseData.usage_type || '—')}
          </div>
        </div>` : ''}

        <!-- Relationship map -->
        <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:16px;margin-bottom:16px">
          <h4 style="margin:0 0 12px;font-size:.9em;color:#e6edf3"><i class="fas fa-project-diagram" style="color:#a78bfa;margin-right:6px"></i>Relationship Map</h4>
          <div id="iocdb-rel-${_esc(iocId)}" style="color:#8b949e;font-size:.85em">
            <i class="fas fa-spinner fa-spin"></i> Loading related IOCs…
          </div>
        </div>

        <!-- Actions -->
        <div style="display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap">
          <button onclick="iocdbEnrich('${_esc(ioc.id)}','${_esc(ioc.value)}','${_esc(ioc.type)}')"
            style="padding:8px 16px;background:#1d6ae5;border:1px solid #1d6ae5;color:#fff;border-radius:6px;cursor:pointer;font-size:.85em">
            ⚡ Re-Enrich
          </button>
          <button onclick="iocdbBlockIOC('${_esc(ioc.id)}','${_esc(ioc.value)}')"
            style="padding:8px 16px;background:#ff444420;border:1px solid #ff4444;color:#ff4444;border-radius:6px;cursor:pointer;font-size:.85em">
            🚫 Block IOC
          </button>
          <button onclick="document.getElementById('iocdb-modal').remove()"
            style="padding:8px 16px;background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;cursor:pointer;font-size:.85em">
            Close
          </button>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modalHtml);

  // Load relationships
  iocdbLoadRelationships(iocId, ioc.value, ioc.type);
}

function _kv(label, value) {
  return `<div><div style="font-size:.7em;color:#8b949e;margin-bottom:3px;text-transform:uppercase;letter-spacing:.04em">${_esc(label)}</div><div style="font-size:.85em;color:#e6edf3">${value}</div></div>`;
}

function _fmtDate(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' }); }
  catch { return iso; }
}

/* ─────────────────────────────────────────────
   RELATIONSHIP MAP
───────────────────────────────────────────── */
async function iocdbLoadRelationships(iocId, value, type) {
  const el = document.getElementById(`iocdb-rel-${iocId}`);
  if (!el) return;

  try {
    // Search for related IOCs by shared tags or domain name
    const searchTerm = type === 'ip' || type === 'domain' ? value.split('.').slice(0,2).join('.') : value.slice(0, 8);
    const res = await _apiGet(`/iocs?search=${encodeURIComponent(searchTerm)}&limit=10`);
    const related = (res.data || []).filter(i => i.id !== iocId).slice(0, 8);

    if (related.length === 0) {
      el.innerHTML = '<span style="color:#555">No related IOCs found in database</span>';
      return;
    }

    el.innerHTML = `
      <div style="display:flex;flex-direction:column;gap:6px">
        ${related.map(r => `
          <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:#21262d;border-radius:6px;cursor:pointer"
            onclick="document.getElementById('iocdb-modal').remove();iocdbShowDetail('${_esc(r.id)}')">
            ${typeBadge(r.type)}
            <span style="font-family:monospace;font-size:.82em;color:#e6edf3;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_esc(r.value)}</span>
            ${riskBadge(r.risk_score)}
            <span style="font-size:.72em;color:#8b949e">${_esc(r.source)}</span>
          </div>
        `).join('')}
      </div>
    `;
  } catch (_) {
    el.innerHTML = '<span style="color:#555">Could not load relationships</span>';
  }
}

/* ─────────────────────────────────────────────
   ENRICH IOC
───────────────────────────────────────────── */
async function iocdbEnrich(iocId, value, type) {
  if (IOCDB.enriching.has(iocId)) return;
  IOCDB.enriching.add(iocId);

  // Close modal if open
  const modal = document.getElementById('iocdb-modal');
  if (modal) modal.remove();

  if (typeof showToast === 'function') showToast(`⚡ Enriching ${value}…`, 'info', 3000);

  try {
    await _apiPost('/intel/enrich', { value, type });
    if (typeof showToast === 'function') showToast(`✅ ${value} enriched successfully`, 'success', 3000);
    // Reload current page to show updated data
    await iocdbLoadPage(IOCDB.page);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Enrichment failed: ${err.message}`, 'error');
  }

  IOCDB.enriching.delete(iocId);
}

/* ─────────────────────────────────────────────
   BLOCK IOC
───────────────────────────────────────────── */
async function iocdbBlockIOC(iocId, value) {
  if (!confirm(`Block IOC: ${value}?\n\nThis will mark it as blocked in the IOC registry and trigger SOAR notifications.`)) return;

  try {
    await _apiPost('/soar/trigger', {
      event_type:  'ioc_blocked_manual',
      ioc_value:   value,
      ioc_id:      iocId,
      reason:      'Manually blocked by SOC analyst',
    });
    if (typeof showToast === 'function') showToast(`🚫 IOC ${value} blocked and SOAR notified`, 'success', 4000);
    const modal = document.getElementById('iocdb-modal');
    if (modal) modal.remove();
    await iocdbLoadPage(IOCDB.page);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Block failed: ${err.message}`, 'error');
  }
}

/* ─────────────────────────────────────────────
   TRIGGER INGEST
───────────────────────────────────────────── */
async function iocdbTriggerIngest() {
  const btn = document.getElementById('iocdb-ingest-btn');
  if (btn) { btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running…'; btn.disabled = true; }

  try {
    const result = await _apiPost('/ingest/run', { wait: false });
    if (typeof showToast === 'function')
      showToast(`✅ Ingest started for ${result.feeds?.length || 0} feeds. IOCs will appear shortly.`, 'success', 5000);
  } catch (err) {
    if (typeof showToast === 'function') showToast(`❌ Ingest failed: ${err.message}`, 'error');
  }

  if (btn) { btn.innerHTML = '<i class="fas fa-sync-alt"></i> Ingest Feeds'; btn.disabled = false; }

  // Reload stats after 5s to show new counts
  setTimeout(async () => {
    await iocdbLoadStats();
    await iocdbLoadPage(1);
  }, 5000);
}

/* ─────────────────────────────────────────────
   FILTER HANDLERS (debounced)
───────────────────────────────────────────── */
let _iocdbSearchTimer = null;

function iocdbOnSearch(val) {
  clearTimeout(_iocdbSearchTimer);
  _iocdbSearchTimer = setTimeout(() => {
    IOCDB.filters.search = val;
    iocdbLoadPage(1);
  }, 300);
}

function iocdbFilter(key, val) {
  IOCDB.filters[key] = val;
  iocdbLoadPage(1);
}

function iocdbClearFilters() {
  IOCDB.filters = { search: '', type: '', reputation: '', source: '', min_confidence: 0, sort: 'risk_score', order: 'desc' };
  const inputs = ['iocdb-search','iocdb-type','iocdb-rep','iocdb-sort','iocdb-conf'];
  inputs.forEach(id => { const el = document.getElementById(id); if (el) el.value = id === 'iocdb-sort' ? 'risk_score' : ''; });
  iocdbLoadPage(1);
}

/* ─────────────────────────────────────────────
   EXPORT CSV
───────────────────────────────────────────── */
function iocdbExportCSV() {
  if (IOCDB.data.length === 0) {
    if (typeof showToast === 'function') showToast('No data to export', 'warning');
    return;
  }
  const headers = ['value','type','reputation','risk_score','confidence','source','malware_family','threat_actor','country','first_seen','last_seen','tags'];
  const rows = IOCDB.data.map(i => headers.map(h => {
    const v = h === 'tags' ? (i.tags || []).join('|') : (i[h] || '');
    return `"${String(v).replace(/"/g,'""')}"`;
  }));
  const csv  = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `wadjet-iocs-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Mark this module as loaded so live-pages.js shim doesn't re-override ──
window._iocIntelligenceLoaded = true;

// ── CRITICAL: Expose IOCDB as window.IOCDB so that main.js PAGE_CONFIG.onEnter
//    (and any other script) can safely reference it without a ReferenceError.
//    main.js loads BEFORE ioc-intelligence.js, so bare 'IOCDB' in main.js closures
//    would throw ReferenceError at call-time if not exposed on window. ──
window.IOCDB = IOCDB;

// ── Export to global scope (authoritative — loaded last, wins the override race) ──
window.renderIOCDatabase    = renderIOCDatabase;
window.iocdbLoadPage        = iocdbLoadPage;
window.iocdbOnSearch        = iocdbOnSearch;
window.iocdbFilter          = iocdbFilter;
window.iocdbClearFilters    = iocdbClearFilters;
window.iocdbEnrich          = iocdbEnrich;
window.iocdbBlockIOC        = iocdbBlockIOC;
window.iocdbTriggerIngest   = iocdbTriggerIngest;
window.iocdbShowDetail      = iocdbShowDetail;
window.iocdbExportCSV       = iocdbExportCSV;
window.iocdbRunDiagnostic   = iocdbRunDiagnostic;

// ── Override PAGE_CONFIG to ensure this version is always called ──
// main.js defines PAGE_CONFIG before this file loads, so we patch it here.
(function _patchPageConfig() {
  function _install() {
    if (window.PAGE_CONFIG && window.PAGE_CONFIG['ioc-database']) {
      window.PAGE_CONFIG['ioc-database'].onEnter = function() {
        // Reset stuck loading flag (safety guard)
        IOCDB.loading = false;
        renderIOCDatabase();
      };
      console.log('[IOC-Intel] PAGE_CONFIG[ioc-database].onEnter patched ✅');
    } else {
      // PAGE_CONFIG not yet available — retry after a short delay
      setTimeout(_install, 100);
    }
  }
  // Run after current script execution, before user navigates
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _install);
  } else {
    setTimeout(_install, 0);
  }
})();

// ── Safety: reset IOCDB.loading if it gets stuck for > 15s ──
setInterval(function _iocdbLoadingWatchdog() {
  if (IOCDB.loading) {
    const el = document.getElementById('iocdb-table-inner');
    // Only reset if the table is showing "Loading…" with no data
    if (el && el.textContent.includes('Loading') && IOCDB.data.length === 0) {
      console.warn('[IOC-Intel] IOCDB.loading watchdog triggered — resetting stuck state');
      IOCDB.loading = false;
    }
  }
}, 15000);

// ── Re-render on auth:restored / auth:login events ──
// This handles the case where the user lands on the IOC page before auth is ready
['auth:restored', 'auth:login', 'auth:token-refreshed'].forEach(evt => {
  window.addEventListener(evt, function _iocAuthReadyHandler() {
    // Only re-render if we're currently on the IOC page and have no data loaded
    const wrap = document.getElementById('iocDatabaseWrap') || document.getElementById('page-ioc-database');
    if (wrap && IOCDB.data.length === 0 && !IOCDB.loading) {
      const iocPage = document.getElementById('page-ioc-database');
      const isVisible = iocPage && (iocPage.classList.contains('active') || iocPage.style.display !== 'none');
      if (isVisible) {
        console.log(`[IOC-Intel] ${evt} received — re-rendering IOC page with fresh auth`);
        IOCDB.loading = false;
        renderIOCDatabase();
      }
    }
  });
});

console.log('[IOC-Intel v5.2] ioc-intelligence.js loaded — window.renderIOCDatabase set to production version ✅');
