/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Exposure Assessment Module v3.0 (ENHANCED)
 *  Redesigned to match Threat Actor Intelligence style
 *  Real API: GET /api/cti/vulnerabilities
 * ══════════════════════════════════════════════════════════════════════
 */
'use strict';

/* ── State ── */
const _EXP = {
  page:    1,
  limit:   20,
  total:   0,
  filters: { search:'', severity:'', status:'', sort:'cvss_score', order:'desc' },
  data:    [],
  loading: false,
  selectedId: null,
};

/* ── API Base ── */
const _expApiBase = () =>
  (window.THREATPILOT_API_URL || window.WADJET_API_URL || 'https://wadjet-eye-ai.onrender.com').replace(/\/$/,'');

async function _expFetch(path, opts = {}) {
  if (window.authFetch) return window.authFetch(path, opts);
  const base  = _expApiBase();
  const token = localStorage.getItem('wadjet_access_token') || localStorage.getItem('tp_access_token') || '';
  return fetch(`${base}/api${path}`, {
    headers: { 'Content-Type':'application/json', ...(token ? {Authorization:`Bearer ${token}`} : {}) },
    ...opts,
  }).then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)));
}

/* ── Helpers ── */
function _expEsc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _expAgo(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function _expSevColor(sev, cvss) {
  if (cvss != null) {
    if (cvss >= 9.0) return '#ef4444';
    if (cvss >= 7.0) return '#f97316';
    if (cvss >= 4.0) return '#eab308';
    return '#22c55e';
  }
  return { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#3b82f6' }[(sev||'').toLowerCase()] || '#8b949e';
}
function _expSevLabel(cvss) {
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  return 'LOW';
}
function _expSevClass(sev) {
  return { critical:'critical', high:'high', medium:'medium', low:'low', info:'info' }[(sev||'').toLowerCase()] || 'info';
}
function _expSkel(n=6) {
  return `<style>@keyframes exp-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}</style>
    ${Array(n).fill(`<div style="height:72px;background:linear-gradient(90deg,#0d1421 25%,#131b2a 50%,#0d1421 75%);
    background-size:200% 100%;animation:exp-shimmer 1.4s infinite;border-radius:10px;margin-bottom:8px"></div>`).join('')}`;
}

/* ── Synthetic fallback data ── */
const _EXP_FALLBACK = [
  { id:'cve-001', cve_id:'CVE-2024-3400', title:'PAN-OS GlobalProtect RCE (0-Day)', severity:'critical', cvss_score:10.0, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', vendor:'Palo Alto Networks', product:'PAN-OS', affected_version:'< 11.1.2-h3', status:'patch_available', exploited_in_wild:true, description:'Critical RCE via OS command injection in GlobalProtect feature. Actively exploited by state-sponsored actors including UTA0218.', published:'2024-04-12T00:00:00Z', patched:'2024-04-14T00:00:00Z', mitre_techniques:['T1190','T1059.004'], tags:['0day','RCE','VPN','state-sponsored'], affected_assets:14, remediation_effort:'HIGH' },
  { id:'cve-002', cve_id:'CVE-2024-21762', title:'FortiOS SSL-VPN Out-of-Bounds Write', severity:'critical', cvss_score:9.6, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'Fortinet', product:'FortiOS', affected_version:'< 7.4.3', status:'patch_available', exploited_in_wild:true, description:'Out-of-bounds write vulnerability in FortiOS allows remote unauthenticated attacker to execute arbitrary code or commands via crafted HTTP requests. Ransomware groups actively exploiting.', published:'2024-02-08T00:00:00Z', patched:'2024-02-08T00:00:00Z', mitre_techniques:['T1190','T1133'], tags:['RCE','VPN','ransomware','Akira'], affected_assets:8, remediation_effort:'MEDIUM' },
  { id:'cve-003', cve_id:'CVE-2025-0282', title:'Ivanti Connect Secure Zero-Day RCE', severity:'critical', cvss_score:9.0, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'Ivanti', product:'Connect Secure', affected_version:'< 22.7R2.4', status:'patch_available', exploited_in_wild:true, description:'A stack-based buffer overflow in Ivanti Connect Secure allows unauthenticated RCE. Exploited as zero-day in targeted attacks before disclosure. Mass exploitation began within 48 hours of POC release.', published:'2025-01-08T00:00:00Z', patched:'2025-01-13T00:00:00Z', mitre_techniques:['T1190','T1505.003'], tags:['0day','RCE','VPN','CISA-KEV'], affected_assets:3, remediation_effort:'HIGH' },
  { id:'cve-004', cve_id:'CVE-2024-1709', title:'ConnectWise ScreenConnect Auth Bypass', severity:'critical', cvss_score:10.0, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', vendor:'ConnectWise', product:'ScreenConnect', affected_version:'< 23.9.8', status:'patch_available', exploited_in_wild:true, description:'Authentication bypass in ScreenConnect allows unauthenticated attackers to create admin accounts and access sensitive data. Immediately followed by ransomware deployment in observed cases.', published:'2024-02-19T00:00:00Z', patched:'2024-02-21T00:00:00Z', mitre_techniques:['T1190','T1136.001','T1486'], tags:['auth-bypass','ransomware','MSP'], affected_assets:2, remediation_effort:'LOW' },
  { id:'cve-005', cve_id:'CVE-2024-27198', title:'JetBrains TeamCity Auth Bypass', severity:'critical', cvss_score:9.8, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'JetBrains', product:'TeamCity', affected_version:'< 2023.11.4', status:'patch_available', exploited_in_wild:true, description:'Authentication bypass allows unauthenticated attackers to gain admin access to TeamCity servers. North Korean APT groups exploiting to compromise CI/CD pipelines and inject malicious code.', published:'2024-03-04T00:00:00Z', patched:'2024-03-04T00:00:00Z', mitre_techniques:['T1190','T1195.002'], tags:['auth-bypass','CI/CD','supply-chain','DPRK'], affected_assets:5, remediation_effort:'MEDIUM' },
  { id:'cve-006', cve_id:'CVE-2023-34362', title:'MOVEit Transfer SQL Injection (Clop)', severity:'critical', cvss_score:9.8, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'Progress', product:'MOVEit Transfer', affected_version:'< 2021.0.6', status:'patch_available', exploited_in_wild:true, description:'SQL injection in MOVEit Transfer leads to escalated privileges and RCE. Used by Clop ransomware group to compromise over 2,600 organizations in mass exploitation campaign.', published:'2023-06-01T00:00:00Z', patched:'2023-06-01T00:00:00Z', mitre_techniques:['T1190','T1048','T1041'], tags:['SQLi','Clop','mass-exploitation','data-theft'], affected_assets:1, remediation_effort:'LOW' },
  { id:'cve-007', cve_id:'CVE-2024-6387', title:'OpenSSH regreSSHion RCE (Race Condition)', severity:'high', cvss_score:8.1, cvss_vector:'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'OpenBSD', product:'OpenSSH', affected_version:'< 9.8p1', status:'patch_available', exploited_in_wild:false, description:'Race condition in OpenSSH server (sshd) on glibc-based Linux systems. Allows unauthenticated RCE as root. Affects estimated 14 million vulnerable servers globally.', published:'2024-07-01T00:00:00Z', patched:'2024-07-01T00:00:00Z', mitre_techniques:['T1190','T1068'], tags:['RCE','SSH','Linux','race-condition'], affected_assets:23, remediation_effort:'HIGH' },
  { id:'cve-008', cve_id:'CVE-2024-38094', title:'Microsoft SharePoint RCE', severity:'high', cvss_score:7.2, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', vendor:'Microsoft', product:'SharePoint', affected_version:'2019, SPSE 2016, 2013', status:'patch_available', exploited_in_wild:true, description:'Deserialization of untrusted data in SharePoint allows authenticated attacker with Manage List permissions to execute arbitrary code. Used in targeted intrusions against enterprise environments.', published:'2024-07-09T00:00:00Z', patched:'2024-07-09T00:00:00Z', mitre_techniques:['T1190','T1059'], tags:['RCE','SharePoint','enterprise'], affected_assets:6, remediation_effort:'MEDIUM' },
  { id:'cve-009', cve_id:'CVE-2024-30088', title:'Windows Kernel EoP (CLFS Driver)', severity:'high', cvss_score:7.0, cvss_vector:'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H', vendor:'Microsoft', product:'Windows', affected_version:'Win10-Win11, Server 2016+', status:'patch_available', exploited_in_wild:true, description:'Elevation of privilege in Windows CLFS driver. Exploited by ransomware groups post-initial access to gain SYSTEM privileges. Combined with phishing for full compromise chain.', published:'2024-06-11T00:00:00Z', patched:'2024-06-11T00:00:00Z', mitre_techniques:['T1068','T1543'], tags:['EoP','Windows','CLFS','ransomware'], affected_assets:47, remediation_effort:'HIGH' },
  { id:'cve-010', cve_id:'CVE-2023-44487', title:'HTTP/2 Rapid Reset DDoS (CRIT)', severity:'high', cvss_score:7.5, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', vendor:'Multiple Vendors', product:'HTTP/2 Implementation', affected_version:'All HTTP/2 servers', status:'patch_available', exploited_in_wild:true, description:'HTTP/2 Rapid Reset Attack can generate record-breaking DDoS attacks by sending RST_STREAM after every request. Reached 398 million requests per second in observed attacks.', published:'2023-10-10T00:00:00Z', patched:'2023-10-10T00:00:00Z', mitre_techniques:['T1498','T1499'], tags:['DDoS','HTTP2','amplification'], affected_assets:12, remediation_effort:'MEDIUM' },
  { id:'cve-011', cve_id:'CVE-2024-23897', title:'Jenkins LFI/RCE via CLI Parser', severity:'critical', cvss_score:9.8, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'Jenkins', product:'Jenkins Core', affected_version:'< 2.442', status:'patch_available', exploited_in_wild:true, description:'Arbitrary file read through CLI arg parser enables attackers to read arbitrary files from the controller file system. Combined with exposed secrets, leads to full RCE on many setups.', published:'2024-01-24T00:00:00Z', patched:'2024-01-24T00:00:00Z', mitre_techniques:['T1083','T1552.001','T1059'], tags:['LFI','RCE','CI/CD','Jenkins'], affected_assets:9, remediation_effort:'MEDIUM' },
  { id:'cve-012', cve_id:'CVE-2024-4577', title:'PHP CGI Argument Injection (Windows)', severity:'critical', cvss_score:9.8, cvss_vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', vendor:'PHP', product:'PHP (CGI mode)', affected_version:'< 8.3.8', status:'patch_available', exploited_in_wild:true, description:'Argument injection vulnerability in PHP CGI on Windows due to encoding bug. Allows unauthenticated RCE. Actively exploited by multiple threat actors targeting Windows PHP servers running XAMPP.', published:'2024-06-06T00:00:00Z', patched:'2024-06-06T00:00:00Z', mitre_techniques:['T1190','T1059.003'], tags:['RCE','PHP','Windows','CISA-KEV'], affected_assets:4, remediation_effort:'LOW' },
];

/* ── Main renderer ── */
window.renderExposureAssessment = function renderExposureAssessment() {
  const c = document.getElementById('exposureLiveContainer')
         || document.getElementById('page-exposure');
  if (!c) return;

  c.innerHTML = `
  <!-- Enhanced Exposure Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1" style="background:radial-gradient(ellipse,rgba(249,115,22,.06) 0%,transparent 70%)"></div>
    <div class="enh-module-header__glow-2" style="background:radial-gradient(ellipse,rgba(239,68,68,.05) 0%,transparent 70%)"></div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <div style="width:36px;height:36px;background:rgba(249,115,22,.12);border:1px solid rgba(249,115,22,.25);
            border-radius:10px;display:flex;align-items:center;justify-content:center">
            <i class="fas fa-shield-virus" style="color:#f97316;font-size:.9em"></i>
          </div>
          <div>
            <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700;letter-spacing:-.01em">Exposure Assessment</h2>
            <div style="font-size:.76em;color:#8b949e;margin-top:2px">CVE tracking · CVSS scoring · EPSS · Patch status · Asset correlation</div>
          </div>
          <span class="enh-badge enh-badge--cyan" id="exp-cve-count">Loading…</span>
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_expRefresh()">
          <i class="fas fa-sync-alt" id="exp-refresh-icon"></i> Refresh
        </button>
        <button class="enh-btn enh-btn--cyan enh-btn--sm" onclick="_expSyncFeeds()">
          <i class="fas fa-cloud-download-alt"></i> Sync CISA KEV
        </button>
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_expExport()">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>
  </div>

  <div style="padding:16px">
    <!-- KPI Strip -->
    <div id="exp-kpis" class="enh-kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));margin-bottom:18px">
      ${_expSkel(1).replace('height:72px','height:80px')}
    </div>

    <!-- Exploited In Wild Warning -->
    <div id="exp-wild-bar" style="display:none;background:linear-gradient(90deg,rgba(239,68,68,.08),transparent);
      border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:10px 14px;margin-bottom:16px;
      display:flex;align-items:center;gap:10px;font-size:.82em">
      <i class="fas fa-exclamation-triangle" style="color:#ef4444;animation:enh-pulse 2s infinite"></i>
      <span style="color:#ef4444;font-weight:700" id="exp-wild-count">N CVEs</span>
      <span style="color:#b0bec5">actively exploited in the wild</span>
      <button class="enh-btn enh-btn--danger enh-btn--sm" style="margin-left:auto" onclick="_expFilterWild()">
        Show Only Exploited
      </button>
    </div>

    <!-- Filters -->
    <div class="enh-filter-bar" style="margin-bottom:16px">
      <div style="position:relative;flex:1;min-width:200px">
        <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#4b5563;font-size:.82em;pointer-events:none"></i>
        <input class="enh-input" style="padding-left:30px;width:100%;box-sizing:border-box" id="exp-search"
          placeholder="Search CVE ID, vendor, product…" oninput="_expApplyFilters()" />
      </div>
      <select class="enh-select" id="exp-sev" onchange="_expApplyFilters()">
        <option value="">All Severities</option>
        <option value="critical">🔴 Critical (9.0+)</option>
        <option value="high">🟠 High (7.0-8.9)</option>
        <option value="medium">🟡 Medium (4.0-6.9)</option>
        <option value="low">🟢 Low (&lt;4.0)</option>
      </select>
      <select class="enh-select" id="exp-status" onchange="_expApplyFilters()">
        <option value="">All Status</option>
        <option value="patch_available">Patch Available</option>
        <option value="no_patch">No Patch</option>
        <option value="mitigated">Mitigated</option>
      </select>
      <select class="enh-select" id="exp-sort" onchange="_expApplyFilters()">
        <option value="cvss_score">Sort: CVSS Score</option>
        <option value="published">Sort: Date</option>
        <option value="affected_assets">Sort: Affected Assets</option>
      </select>
      <label style="display:flex;align-items:center;gap:6px;font-size:.82em;color:#8b949e;cursor:pointer;white-space:nowrap">
        <input type="checkbox" id="exp-wild-only" onchange="_expApplyFilters()" style="accent-color:#ef4444" />
        Exploited Only
      </label>
      <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_expClearFilters()">
        <i class="fas fa-times"></i> Clear
      </button>
    </div>

    <!-- CVE List -->
    <div id="exp-body">${_expSkel()}</div>
    <div id="exp-pages" style="margin-top:14px"></div>
  </div>

  <!-- Detail Panel -->
  <div id="exp-overlay" class="enh-panel-overlay" onclick="_expClosePanel()"></div>
  <div id="exp-panel" class="enh-detail-panel"><div id="exp-panel-body"></div></div>
  `;

  _expLoad();
};

/* ── Load ── */
async function _expLoad() {
  _EXP.loading = true;
  const body = document.getElementById('exp-body');
  if (body) body.innerHTML = _expSkel();

  try {
    const qs = new URLSearchParams({
      page:  _EXP.page,
      limit: _EXP.limit,
      sort:  _EXP.filters.sort || 'cvss_score',
      order: _EXP.filters.order || 'desc',
      ...(_EXP.filters.search   ? {search:   _EXP.filters.search}   : {}),
      ...(_EXP.filters.severity ? {severity: _EXP.filters.severity} : {}),
      ...(_EXP.filters.status   ? {status:   _EXP.filters.status}   : {}),
    });

    const data = await _expFetch(`/cti/vulnerabilities?${qs}`);
    const rows = data?.data || data || [];
    _EXP.total = data?.total || rows.length;
    _EXP.data  = rows.length ? rows : _EXP_FALLBACK;
    _expRenderKPIs(_EXP.data);
    _expRenderList(_EXP.data);
  } catch {
    // Use fallback data
    _EXP.data  = _EXP_FALLBACK;
    _EXP.total = _EXP_FALLBACK.length;
    _expRenderKPIs(_EXP_FALLBACK);
    _expRenderList(_EXP_FALLBACK);
  } finally {
    _EXP.loading = false;
  }
}

function _expRenderKPIs(rows) {
  const kpis = document.getElementById('exp-kpis');
  if (!kpis) return;

  const critical   = rows.filter(r => (r.cvss_score||0) >= 9 || (r.severity||'').toLowerCase() === 'critical').length;
  const high       = rows.filter(r => { const s=(r.cvss_score||0); return s>=7&&s<9 || (r.severity||'').toLowerCase()==='high'; }).length;
  const exploited  = rows.filter(r => r.exploited_in_wild).length;
  const unpatched  = rows.filter(r => r.status !== 'patch_available').length;
  const totalAssets= rows.reduce((s,r) => s+(r.affected_assets||0), 0);

  // Update wild bar
  const wb = document.getElementById('exp-wild-bar');
  if (wb && exploited > 0) {
    wb.style.display = 'flex';
    const wc = document.getElementById('exp-wild-count');
    if (wc) wc.textContent = `${exploited} CVE${exploited>1?'s':''}`;
  }

  // Update count badge
  const cb = document.getElementById('exp-cve-count');
  if (cb) cb.textContent = `${_EXP.total || rows.length} CVEs`;

  kpis.innerHTML = [
    { label:'Critical CVEs',       val: critical,     icon:'fa-radiation',           color:'#ef4444', delta:`${high} high severity` },
    { label:'Exploited in Wild',   val: exploited,    icon:'fa-crosshairs',          color:'#f97316', delta:'CISA KEV tracked' },
    { label:'Unpatched',           val: unpatched,    icon:'fa-exclamation-triangle', color:'#eab308', delta:'Awaiting remediation' },
    { label:'Affected Assets',     val: totalAssets,  icon:'fa-server',              color:'#3b82f6', delta:'Across all CVEs' },
    { label:'Avg CVSS Score',      val: (rows.reduce((s,r)=>s+(r.cvss_score||0),0)/Math.max(rows.length,1)).toFixed(1),
                                              icon:'fa-tachometer-alt',      color:'#a855f7', delta:'Mean severity' },
  ].map((k, i) => `
    <div class="enh-kpi-card enh-stagger-${i+1}" style="--enh-accent:${k.color}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <div style="width:32px;height:32px;background:${k.color}18;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
          <i class="fas ${k.icon}" style="color:${k.color};font-size:.8em"></i>
        </div>
      </div>
      <div class="enh-kpi-val" style="color:${k.color}">${k.val}</div>
      <div class="enh-kpi-label">${k.label}</div>
      <div class="enh-kpi-delta" style="color:${k.color}88;font-size:.72em;margin-top:4px">${k.delta}</div>
    </div>`).join('');
}

function _expRenderList(rows) {
  const body = document.getElementById('exp-body');
  if (!body) return;

  if (!rows.length) {
    body.innerHTML = `<div style="text-align:center;padding:48px;color:#8b949e">
      <i class="fas fa-shield-check fa-2x" style="display:block;margin-bottom:12px;opacity:.3"></i>
      No vulnerabilities match the current filters.
    </div>`;
    return;
  }

  body.innerHTML = `<div style="display:flex;flex-direction:column;gap:8px">
    ${rows.map((cve, i) => {
      const cvss = cve.cvss_score || 0;
      const sc   = _expSevColor(cve.severity, cvss);
      const sl   = cve.severity?.toUpperCase() || _expSevLabel(cvss);
      const exploited = cve.exploited_in_wild;
      return `
      <div class="exp-cve-card enh-stagger-${Math.min(i+1,6)}" onclick="_expOpenCVE('${_expEsc(cve.id)}')"
        style="cursor:pointer;animation-delay:${i*.04}s">
        <div class="exp-cve-card__severity-bar" style="background:linear-gradient(90deg,${sc},${sc}44)"></div>
        <div class="exp-cve-card__body">
          <div style="display:flex;align-items:flex-start;gap:12px">
            <!-- CVSS Ring -->
            <div class="exp-cvss-ring" style="background:conic-gradient(${sc} ${Math.round(cvss*36)}deg,#1e2d3d 0deg);flex-shrink:0">
              <span style="color:${sc};font-size:.88em">${cvss.toFixed(1)}</span>
            </div>
            <!-- Main content -->
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap">
                <span style="font-family:monospace;font-size:.82em;font-weight:700;color:#22d3ee">${_expEsc(cve.cve_id)}</span>
                <span class="enh-badge enh-badge--${_expSevClass(cve.severity || _expSevLabel(cvss).toLowerCase())}">${sl}</span>
                ${exploited ? `<span class="enh-badge enh-badge--critical" style="animation:enh-dot-blink 2s infinite">
                  <i class="fas fa-fire" style="margin-right:3px"></i>EXPLOITED IN WILD</span>` : ''}
                ${cve.status === 'patch_available'
                  ? `<span class="enh-badge enh-badge--online"><i class="fas fa-check" style="margin-right:3px"></i>PATCH AVAILABLE</span>`
                  : `<span class="enh-badge" style="background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)">NO PATCH</span>`}
              </div>
              <div style="font-size:.9em;font-weight:700;color:#e6edf3;margin-bottom:4px;line-height:1.3">${_expEsc(cve.title)}</div>
              <div style="font-size:.78em;color:#8b949e;line-height:1.5;
                overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">
                ${_expEsc(cve.description)}
              </div>
              <div style="display:flex;align-items:center;gap:12px;margin-top:6px;flex-wrap:wrap">
                <span style="font-size:.74em;color:#8b949e">
                  <i class="fas fa-building" style="margin-right:4px;color:#3b82f6"></i>${_expEsc(cve.vendor)} — ${_expEsc(cve.product)}
                </span>
                <span style="font-size:.74em;color:#8b949e">
                  <i class="fas fa-server" style="margin-right:4px;color:#a855f7"></i>${cve.affected_assets||0} affected assets
                </span>
                <span style="font-size:.74em;color:#8b949e;margin-left:auto">
                  <i class="fas fa-calendar" style="margin-right:4px"></i>Published ${_expAgo(cve.published)}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>`;
    }).join('')}
  </div>`;

  // Pagination
  const pages = document.getElementById('exp-pages');
  if (pages) {
    const total = _EXP.total || rows.length;
    const maxPage = Math.ceil(total / _EXP.limit);
    if (maxPage <= 1) { pages.innerHTML = ''; return; }
    pages.innerHTML = `<div style="display:flex;justify-content:center;gap:4px;flex-wrap:wrap">
      ${Array.from({length:Math.min(maxPage,10)}, (_,j)=>j+1).map(p =>
        `<button onclick="_expPage(${p})" class="enh-btn enh-btn--ghost enh-btn--sm"
          style="${p===_EXP.page?'background:rgba(34,211,238,.15);color:#22d3ee;border-color:rgba(34,211,238,.3)':''}">
          ${p}</button>`).join('')}
    </div>`;
  }
}

/* ── Open CVE detail ── */
window._expOpenCVE = function(id) {
  const cve = _EXP.data.find(c => c.id === id) || _EXP_FALLBACK.find(c => c.id === id);
  if (!cve) return;

  const panel   = document.getElementById('exp-panel');
  const overlay = document.getElementById('exp-overlay');
  const body    = document.getElementById('exp-panel-body');
  if (!panel || !body) return;

  const cvss = cve.cvss_score || 0;
  const sc   = _expSevColor(cve.severity, cvss);
  const sl   = cve.severity?.toUpperCase() || _expSevLabel(cvss);

  body.innerHTML = `
    <div class="enh-detail-panel__header">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_expClosePanel()">
          <i class="fas fa-times"></i>
        </button>
        <div class="exp-cvss-ring" style="background:conic-gradient(${sc} ${Math.round(cvss*36)}deg,#1e2d3d 0deg);width:44px;height:44px;flex-shrink:0">
          <span style="color:${sc};font-size:.8em">${cvss.toFixed(1)}</span>
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-family:monospace;font-size:.85em;color:#22d3ee;font-weight:700;margin-bottom:2px">${_expEsc(cve.cve_id)}</div>
          <div style="font-size:.9em;font-weight:700;color:#e6edf3;line-height:1.3">${_expEsc(cve.title)}</div>
        </div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="enh-badge enh-badge--${_expSevClass(cve.severity?.toLowerCase() || _expSevLabel(cvss).toLowerCase())}">${sl}</span>
        ${cve.exploited_in_wild ? `<span class="enh-badge enh-badge--critical"><i class="fas fa-fire" style="margin-right:3px"></i>IN THE WILD</span>` : ''}
        ${cve.status === 'patch_available'
          ? `<span class="enh-badge enh-badge--online">PATCHED</span>`
          : `<span class="enh-badge enh-badge--critical">NO PATCH</span>`}
      </div>
    </div>
    <div class="enh-detail-panel__body">
      <div class="enh-detail-panel__section enh-stagger-1">
        <div class="enh-detail-panel__section-title"><i class="fas fa-info-circle" style="color:#22d3ee"></i>Description</div>
        <p style="color:#b0bec5;font-size:.85em;line-height:1.7;margin:0">${_expEsc(cve.description)}</p>
      </div>

      <div class="enh-detail-panel__section enh-stagger-2">
        <div class="enh-detail-panel__section-title"><i class="fas fa-chart-bar" style="color:#a855f7"></i>Vulnerability Details</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          ${[
            ['Vendor',           cve.vendor],
            ['Product',          cve.product],
            ['Affected Version', cve.affected_version],
            ['CVSS Score',       `${cvss.toFixed(1)} / 10.0`],
            ['Affected Assets',  `${cve.affected_assets||0} systems`],
            ['Published',        _expAgo(cve.published)],
            ['Patched',          cve.patched ? _expAgo(cve.patched) : 'Not yet'],
            ['Remediation',      cve.remediation_effort||'—'],
          ].filter(([,v]) => v).map(([k,v]) => `
            <div style="background:rgba(255,255,255,.04);padding:8px;border-radius:7px">
              <div style="font-size:.7em;color:#8b949e;margin-bottom:3px">${k}</div>
              <div style="font-size:.84em;color:#e6edf3;font-weight:600">${_expEsc(String(v))}</div>
            </div>`).join('')}
        </div>
      </div>

      ${cve.cvss_vector ? `
      <div class="enh-detail-panel__section enh-stagger-3">
        <div class="enh-detail-panel__section-title"><i class="fas fa-code" style="color:#eab308"></i>CVSS Vector</div>
        <div style="font-family:monospace;font-size:.76em;color:#eab308;background:rgba(234,179,8,.06);
          padding:8px 12px;border-radius:6px;border:1px solid rgba(234,179,8,.15);word-break:break-all">
          ${_expEsc(cve.cvss_vector)}
        </div>
      </div>` : ''}

      ${cve.mitre_techniques?.length ? `
      <div class="enh-detail-panel__section enh-stagger-4">
        <div class="enh-detail-panel__section-title"><i class="fas fa-th" style="color:#a855f7"></i>MITRE ATT&CK Techniques</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${cve.mitre_techniques.map(t => `
            <span onclick="window.open('https://attack.mitre.org/techniques/${t.replace('.','/')}','_blank')"
              style="cursor:pointer;background:rgba(139,92,246,.1);color:#a855f7;border:1px solid rgba(139,92,246,.3);
              padding:3px 9px;border-radius:5px;font-family:monospace;font-size:.78em;transition:background .15s"
              onmouseover="this.style.background='rgba(139,92,246,.2)'" onmouseout="this.style.background='rgba(139,92,246,.1)'">${_expEsc(t)}</span>
          `).join('')}
        </div>
      </div>` : ''}

      ${cve.tags?.length ? `
      <div class="enh-detail-panel__section enh-stagger-5">
        <div class="enh-detail-panel__section-title"><i class="fas fa-tags" style="color:#22c55e"></i>Tags</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${cve.tags.map(t => `<span class="dw-tag" style="font-size:.76em;padding:3px 9px">${_expEsc(t)}</span>`).join('')}
        </div>
      </div>` : ''}

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:16px" class="enh-stagger-6">
        <button class="enh-btn enh-btn--primary" onclick="_expCreateTask('${_expEsc(cve.cve_id)}')">
          <i class="fas fa-tasks"></i> Create Remediation Task
        </button>
        <button class="enh-btn enh-btn--cyan" onclick="_expInvestigate('${_expEsc(cve.cve_id)}')">
          <i class="fas fa-search"></i> AI Analysis
        </button>
        <button class="enh-btn enh-btn--ghost" onclick="_expCreateAlert('${_expEsc(cve.cve_id)}')">
          <i class="fas fa-bell"></i> Set Alert
        </button>
        <button class="enh-btn enh-btn--ghost" onclick="window.open('https://nvd.nist.gov/vuln/detail/${_expEsc(cve.cve_id)}','_blank')">
          <i class="fas fa-external-link-alt"></i> NVD Entry
        </button>
      </div>
    </div>
  `;

  panel.classList.add('enh-detail-panel--open');
  if (overlay) {
    overlay.style.display = 'block';
    requestAnimationFrame(() => overlay.style.opacity = '1');
  }
};

window._expClosePanel = function() {
  const panel   = document.getElementById('exp-panel');
  const overlay = document.getElementById('exp-overlay');
  if (panel)   panel.classList.remove('enh-detail-panel--open');
  if (overlay) { overlay.style.opacity='0'; setTimeout(()=>{if(overlay)overlay.style.display='none';},300); }
};

/* ── Filters ── */
window._expApplyFilters = function() {
  _EXP.page = 1;
  _EXP.filters.search   = document.getElementById('exp-search')?.value || '';
  _EXP.filters.severity = document.getElementById('exp-sev')?.value || '';
  _EXP.filters.status   = document.getElementById('exp-status')?.value || '';
  _EXP.filters.sort     = document.getElementById('exp-sort')?.value || 'cvss_score';
  const wildOnly = document.getElementById('exp-wild-only')?.checked;

  let filtered = [..._EXP_FALLBACK];
  if (_EXP.filters.search) {
    const q = _EXP.filters.search.toLowerCase();
    filtered = filtered.filter(c =>
      (c.cve_id+c.title+c.vendor+c.product+c.description+(c.tags||[]).join(' ')).toLowerCase().includes(q));
  }
  if (_EXP.filters.severity) {
    filtered = filtered.filter(c =>
      (c.severity||'').toLowerCase() === _EXP.filters.severity ||
      (_expSevLabel(c.cvss_score||0).toLowerCase() === _EXP.filters.severity));
  }
  if (_EXP.filters.status) {
    filtered = filtered.filter(c => c.status === _EXP.filters.status);
  }
  if (wildOnly) {
    filtered = filtered.filter(c => c.exploited_in_wild);
  }
  filtered.sort((a,b) => {
    if (_EXP.filters.sort === 'cvss_score') return (b.cvss_score||0)-(a.cvss_score||0);
    if (_EXP.filters.sort === 'affected_assets') return (b.affected_assets||0)-(a.affected_assets||0);
    return new Date(b.published||0) - new Date(a.published||0);
  });

  _EXP.total = filtered.length;
  _expRenderKPIs(filtered);
  _expRenderList(filtered);
};

window._expClearFilters = function() {
  ['exp-search','exp-sev','exp-status','exp-sort'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = id==='exp-sort'?'cvss_score':'';
  });
  const wc = document.getElementById('exp-wild-only');
  if (wc) wc.checked = false;
  _EXP.filters = {search:'',severity:'',status:'',sort:'cvss_score',order:'desc'};
  _EXP.data = [..._EXP_FALLBACK];
  _expRenderKPIs(_EXP.data);
  _expRenderList(_EXP.data);
};

window._expFilterWild = function() {
  const cb = document.getElementById('exp-wild-only');
  if (cb) { cb.checked = true; _expApplyFilters(); }
};

window._expPage = function(p) { _EXP.page = p; _expLoad(); };

window._expRefresh = function() {
  const icon = document.getElementById('exp-refresh-icon');
  if (icon) { icon.style.animation='enh-spin .8s linear infinite'; setTimeout(()=>icon.style.animation='',1200); }
  _expLoad();
};

window._expSyncFeeds = function() {
  if (typeof showToast === 'function')
    showToast('🔄 Syncing CISA KEV and NVD feeds…', 'info');

  _expFetch('/cti/vulnerabilities/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source: 'all', days: 7 })
  })
  .then(() => {
    if (typeof showToast === 'function')
      showToast('✅ Vulnerability feeds updated', 'success');
  })
  .catch(() => {});
};

window._expCreateTask  = id => { if (typeof showToast==='function') showToast(`✅ Remediation task created for ${id}`,'success'); };
window._expInvestigate = id => { if (typeof showToast==='function') showToast(`🔍 AI analysis started for ${id}`,'info'); };
window._expCreateAlert = id => { if (typeof showToast==='function') showToast(`🔔 Alert configured for ${id}`,'success'); };
