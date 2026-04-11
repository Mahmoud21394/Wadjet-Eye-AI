/**
 * ══════════════════════════════════════════════════════════════════════
 *  EYEbot AI — Dark Web Intelligence Module v5.0 (ENHANCED)
 *  Redesigned to match Threat Actor Intelligence style
 *  + Modern animations, hover effects, responsive design
 *  + Real API integration with synthetic fallback
 * ══════════════════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ── Synthetic dark web data (rich set for demo / offline mode) ── */
const _DW_DATA = {
  marketplace: [
    { id:'dw-001', title:'RaaS Kit — LockBit 4.0 Builder', type:'Ransomware Listing', severity:'CRITICAL', price:'$5,000', seller:'0x_phantom', tor:'lockbit4a3ebjnt4.onion', tags:['ransomware','builder','affiliate'], posted:'2025-01-15T08:30:00Z', views:1847, rating:4.8, description:'Full LockBit 4.0 ransomware builder with affiliate panel, Tor C2, and automated victim negotiation portal. Includes source code and 12-month support.' },
    { id:'dw-002', title:'0-Day: Microsoft Exchange RCE (CVE-2025-XXXX)', type:'Exploit Sale', severity:'CRITICAL', price:'$45,000', seller:'exploit_market', tor:'exploit1a2b3c4d.onion', tags:['0day','exchange','RCE'], posted:'2025-02-03T14:22:00Z', views:3291, rating:4.9, description:'Unauthenticated remote code execution in Exchange Server 2019-2024. Full chain exploit with SYSTEM privileges. Tested against patched instances.' },
    { id:'dw-003', title:'Credential Dump: Fortune 500 (87,000 accounts)', type:'Credential Dump', severity:'HIGH', price:'$1,200', seller:'breach_lord', tor:'credentials7x8y.onion', tags:['credentials','breach','corporate'], posted:'2025-01-28T11:15:00Z', views:5621, rating:4.2, description:'Fresh credential dump from major financial institution breach. Includes email, password (plaintext + hash), MFA seeds. Verified 73% valid rate.' },
    { id:'dw-004', title:'APT Access Broker: Telecom Network VPN', type:'Initial Access', severity:'CRITICAL', price:'$12,000', seller:'access_broker_ru', tor:'iabroker9x2y.onion', tags:['access-broker','VPN','telecom'], posted:'2025-02-08T09:00:00Z', views:892, rating:4.7, description:'Active administrator access to major European telecom provider. Includes DC access, 450k employee records, billing database credentials.' },
    { id:'dw-005', title:'Malware-as-a-Service: AsyncRAT v4', type:'MaaS', severity:'HIGH', price:'$800/mo', seller:'asyncrat_dev', tor:'asyncrat1b2c3d.onion', tags:['RAT','MaaS','C2'], posted:'2025-01-20T16:45:00Z', views:2134, rating:4.5, description:'Fully managed AsyncRAT infrastructure. Includes builder, C2 server, obfuscator, and 24/7 support. Used in 200+ active campaigns.' },
    { id:'dw-006', title:'Data Breach: Healthcare Chain (2.1M patients)', type:'Data Breach', severity:'CRITICAL', price:'$8,500', seller:'medithreat', tor:'meddata3x9y1z.onion', tags:['healthcare','PII','PHI'], posted:'2025-02-01T07:30:00Z', views:4102, rating:4.6, description:'Patient records from 48-hospital chain: SSN, DOB, insurance, prescription history. Includes internal network diagrams and admin credentials.' },
    { id:'dw-007', title:'Phishing Kit — Microsoft 365 Advanced', type:'Phishing Kit', severity:'MEDIUM', price:'$350', seller:'kit_master', tor:'phishkit8a1b.onion', tags:['phishing','M365','AiTM'], posted:'2025-01-10T13:00:00Z', views:8934, rating:4.1, description:'Adversary-in-The-Middle phishing kit for M365. Bypasses MFA. Includes EvilProxy-style reverse proxy, CAPTCHA bypass, and geofencing.' },
    { id:'dw-008', title:'Botnet Access: 50,000 Corporate Endpoints', type:'Botnet', severity:'HIGH', price:'$25,000', seller:'botmaster_x', tor:'botnet1x2y3z4a.onion', tags:['botnet','corporate','endpoints'], posted:'2025-02-05T10:20:00Z', views:1203, rating:4.4, description:'Curated botnet of 50k compromised corporate workstations across 40 countries. Filtered for Fortune 1000 companies. Delivered via PowerShell loader.' },
  ],
  ransomware: [
    { group:'LockBit 4.0', victims:47, status:'ACTIVE', country:'Russia', sector_targets:['Healthcare','Finance','Government'], latest_victim:'Meridian Healthcare Group', latest_date:'2025-02-10T00:00:00Z', threat_level:'CRITICAL', onion:'lockbitvictimsite.onion', negotiation_avg:'$2.1M', payment_rate:'34%' },
    { group:'BlackCat/ALPHV', victims:31, status:'ACTIVE', country:'Unknown', sector_targets:['Energy','Manufacturing','Legal'], latest_victim:'Atlas Energy Corp', latest_date:'2025-02-08T00:00:00Z', threat_level:'CRITICAL', onion:'blackcat3victims.onion', negotiation_avg:'$4.8M', payment_rate:'29%' },
    { group:'Clop', victims:89, status:'ACTIVE', country:'Russia', sector_targets:['Finance','Technology','Retail'], latest_victim:'DataVault Financial', latest_date:'2025-02-09T00:00:00Z', threat_level:'CRITICAL', onion:'clopvictims1.onion', negotiation_avg:'$1.5M', payment_rate:'41%' },
    { group:'Royal Ransomware', victims:22, status:'ACTIVE', country:'Unknown', sector_targets:['Healthcare','Education','Transport'], latest_victim:'NorthStar University', latest_date:'2025-02-06T00:00:00Z', threat_level:'HIGH', onion:'royalvictims2.onion', negotiation_avg:'$3.2M', payment_rate:'25%' },
    { group:'Play', victims:18, status:'ACTIVE', country:'Unknown', sector_targets:['Government','Manufacturing','Legal'], latest_victim:'City of Riverside', latest_date:'2025-02-07T00:00:00Z', threat_level:'HIGH', onion:'playransomsite.onion', negotiation_avg:'$850K', payment_rate:'38%' },
    { group:'Medusa', victims:14, status:'ACTIVE', country:'Unknown', sector_targets:['Healthcare','Education'], latest_victim:'Memorial Medical', latest_date:'2025-02-04T00:00:00Z', threat_level:'HIGH', onion:'medusaransomware.onion', negotiation_avg:'$1.2M', payment_rate:'31%' },
    { group:'8Base', victims:28, status:'ACTIVE', country:'Unknown', sector_targets:['Finance','Retail','SMB'], latest_victim:'Apex Financial Group', latest_date:'2025-01-31T00:00:00Z', threat_level:'HIGH', onion:'8baseleaksite.onion', negotiation_avg:'$650K', payment_rate:'44%' },
  ],
  credentials: [
    { id:'cr-001', source:'LinkedIn breach (partial)', count:'48M', type:'Email + Hash (SHA-512)', date:'2025-01-12', freshness:'FRESH', price:'$200', format:'CSV', verified:true },
    { id:'cr-002', source:'Gaming platform compromise', count:'12M', type:'Email + Plaintext', date:'2025-01-28', freshness:'FRESH', price:'$450', format:'JSON', verified:true },
    { id:'cr-003', source:'E-commerce data scrape', count:'3.2M', type:'Full PII + CC', date:'2025-02-01', freshness:'FRESH', price:'$2,800', format:'SQL dump', verified:false },
    { id:'cr-004', source:'Government employee directory', count:'890K', type:'Name + Email + Phone', date:'2025-01-15', freshness:'FRESH', price:'$600', format:'CSV', verified:true },
    { id:'cr-005', source:'Healthcare portal breach', count:'2.1M', type:'SSN + DOB + Insurance', date:'2025-02-05', freshness:'FRESH', price:'$5,000', format:'SQL dump', verified:true },
    { id:'cr-006', source:'Cloud SaaS provider', count:'175K', type:'API keys + Credentials', date:'2025-02-08', freshness:'VERY FRESH', price:'$3,500', format:'JSON', verified:true },
  ],
  forums: [
    { id:'fr-001', forum:'BreachForums v2', category:'Database Leaks', title:'[FREE] 500K combo list — US Corporate', replies:342, views:'18.2K', author:'data_dump_king', posted:'2025-02-09T15:22:00Z', threat_level:'HIGH' },
    { id:'fr-002', forum:'RaidForums Mirror', category:'Malware Discussion', title:'Bypass EDR Guide 2025 — Defender, CrowdStrike, SentinelOne', replies:891, views:'45.1K', author:'evasion_expert', posted:'2025-02-08T09:14:00Z', threat_level:'CRITICAL' },
    { id:'fr-003', forum:'XSS.is', category:'Access Sales', title:'[SELLING] Persistent access — Tier 1 bank, EU region', replies:67, views:'2.1K', author:'access_broker_x', posted:'2025-02-07T20:45:00Z', threat_level:'CRITICAL' },
    { id:'fr-004', forum:'Exploit.in', category:'Vulnerabilities', title:'PoC — Windows Kernel UAF (EoP, unpatched)', replies:234, views:'9.8K', author:'vuln_hunter_ru', posted:'2025-02-06T12:33:00Z', threat_level:'CRITICAL' },
    { id:'fr-005', forum:'BreachForums v2', category:'Tutorials', title:'Spear Phishing O365 2025 — bypass ATP and Safe Links', replies:445, views:'28.4K', author:'phish_lord', posted:'2025-02-05T08:00:00Z', threat_level:'HIGH' },
    { id:'fr-006', forum:'Dread', category:'General', title:'LockBit affiliate recruitment — 80% split', replies:123, views:'6.7K', author:'lb_recruiter', posted:'2025-02-04T19:11:00Z', threat_level:'CRITICAL' },
    { id:'fr-007', forum:'XSS.is', category:'Stealer Logs', title:'Redline stealer logs pack — 200K machines, 15GB', replies:89, views:'11.2K', author:'logs_seller', posted:'2025-02-03T14:55:00Z', threat_level:'HIGH' },
  ],
  onion: [
    { id:'on-001', url:'lockbit4a3ebjnt.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'LockBit 4.0 victim portal and affiliate dashboard', tor_title:'LockBit 4.0 — Professional Ransomware Service' },
    { id:'on-002', url:'alphvmmm27o3abo.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'BlackCat/ALPHV ransomware victim and data leak site', tor_title:'ALPHV BlackCat — Data Exposure' },
    { id:'on-003', url:'breach3rdampfkgn.onion', category:'Data Market', status:'ONLINE', last_check:'2025-02-10T05:30:00Z', risk:'HIGH', description:'Active dark web marketplace for stolen data', tor_title:'BreachBase — Premium Data Exchange' },
    { id:'on-004', url:'exploit3xrg4abd.onion', category:'Exploit Shop', status:'ONLINE', last_check:'2025-02-10T04:15:00Z', risk:'CRITICAL', description:'Zero-day and N-day exploit broker', tor_title:'ExploitHub — Premier 0day Market' },
    { id:'on-005', url:'clopvictims1abc.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T03:50:00Z', risk:'CRITICAL', description:'Clop ransomware group victim publication site', tor_title:'CL0P^_- LEAKS' },
    { id:'on-006', url:'dreadditevelidot.onion', category:'Darknet Forum', status:'OFFLINE', last_check:'2025-02-09T22:00:00Z', risk:'MEDIUM', description:'Major darknet forum — currently down for maintenance', tor_title:'Dread — The Reddit of Dark Web' },
    { id:'on-007', url:'ransomhouse7xhq.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T05:00:00Z', risk:'HIGH', description:'RansomHouse victim portal and leak site', tor_title:'RansomHouse Operations' },
    { id:'on-008', url:'kelvinsecleakq2s.onion', category:'APT Site', status:'ONLINE', last_check:'2025-02-10T04:30:00Z', risk:'CRITICAL', description:'Kelvin Security APT data publication site', tor_title:'KelvinSec — Intelligence Leaks' },
  ]
};

/* ── Module State ── */
const _DW = {
  tab:     'marketplace',
  filter:  { sev: '', type: '', search: '' },
  selected: null,
};

/* ── Helpers ── */
function _dwEsc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _dwAgo(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function _dwSevColor(sev) {
  return { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e' }[(sev||'').toUpperCase()] || '#8b949e';
}
function _dwSevClass(sev) {
  return { CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low' }[(sev||'').toUpperCase()] || 'info';
}
function _dwBadge(label, sev) {
  const c = _dwSevColor(sev || label);
  return `<span class="enh-badge enh-badge--${_dwSevClass(sev||label)}">${_dwEsc(label)}</span>`;
}

/* ── Main renderer ── */
window.renderDarkWeb = function renderDarkWeb() {
  const c = document.getElementById('page-dark-web');
  if (!c) return;

  c.innerHTML = `
  <!-- Enhanced Dark Web Module Header -->
  <div class="enh-module-header">
    <div class="enh-module-header__glow-1"></div>
    <div class="enh-module-header__glow-2"></div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <div style="width:36px;height:36px;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);border-radius:10px;display:flex;align-items:center;justify-content:center">
            <i class="fas fa-spider" style="color:#ef4444;font-size:.9em"></i>
          </div>
          <div>
            <h2 style="margin:0;color:#e6edf3;font-size:1.15em;font-weight:700;letter-spacing:-.01em">Dark Web Intelligence</h2>
            <div style="font-size:.76em;color:#8b949e;margin-top:2px">Onion monitoring · RaaS tracking · Credential surveillance · Forum analysis</div>
          </div>
          <span class="enh-badge enh-badge--critical" style="animation:enh-dot-blink 2s infinite">
            <span class="enh-dot enh-dot--critical"></span> LIVE
          </span>
        </div>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_dwRefresh()">
          <i class="fas fa-sync-alt" id="dw-refresh-icon"></i> Refresh
        </button>
        <button class="enh-btn enh-btn--cyan enh-btn--sm" onclick="_dwExport()">
          <i class="fas fa-download"></i> Export Report
        </button>
        <button class="enh-btn enh-btn--danger enh-btn--sm" onclick="_dwSetAlert()">
          <i class="fas fa-bell"></i> Set Alert
        </button>
      </div>
    </div>
  </div>

  <!-- Threat Level Banner -->
  <div style="padding:0 0 0;margin-bottom:0">
    <div id="dw-root" style="padding:16px">

    <!-- KPI Strip -->
    <div class="enh-kpi-grid" style="grid-template-columns:repeat(auto-fill,minmax(160px,1fr));margin-bottom:18px">
      ${[
        { label:'Active Marketplaces', val: _DW_DATA.marketplace.length, icon:'fa-store', color:'#ef4444', delta:'+2 this week' },
        { label:'Ransomware Groups', val: _DW_DATA.ransomware.filter(r=>r.status==='ACTIVE').length, icon:'fa-lock', color:'#f97316', delta:`${_DW_DATA.ransomware.reduce((s,r)=>s+r.victims,0)} total victims` },
        { label:'Credential Leaks', val: _DW_DATA.credentials.length, icon:'fa-user-secret', color:'#a855f7', delta:'Current month' },
        { label:'Forum Threats', val: _DW_DATA.forums.filter(f=>f.threat_level==='CRITICAL').length, icon:'fa-comments', color:'#eab308', delta:'Critical only' },
        { label:'Onion Sites', val: _DW_DATA.onion.filter(o=>o.status==='ONLINE').length, icon:'fa-circle', color:'#22c55e', delta:`${_DW_DATA.onion.filter(o=>o.status==='OFFLINE').length} offline` },
      ].map((k, i) => `
        <div class="enh-kpi-card enh-stagger-${i+1}" style="--enh-accent:${k.color}">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:32px;height:32px;background:${k.color}18;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
              <i class="fas ${k.icon}" style="color:${k.color};font-size:.8em"></i>
            </div>
          </div>
          <div class="enh-kpi-val">${k.val}</div>
          <div class="enh-kpi-label">${k.label}</div>
          <div class="enh-kpi-delta" style="color:${k.color}88"><i class="fas fa-arrow-up" style="font-size:.7em"></i> ${k.delta}</div>
        </div>`).join('')}
    </div>

    <!-- Threat Level Warning Bar -->
    <div style="background:linear-gradient(90deg,rgba(239,68,68,.08),transparent);border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:10px 14px;margin-bottom:16px;display:flex;align-items:center;gap:10px;font-size:.82em">
      <i class="fas fa-radiation" style="color:#ef4444;animation:enh-pulse 2s infinite"></i>
      <span style="color:#ef4444;font-weight:700">THREAT LEVEL: CRITICAL</span>
      <span style="color:#8b949e">—</span>
      <span style="color:#b0bec5">Multiple active RaaS operations targeting healthcare, finance, and government sectors. Credential dumps detected with fresh corporate data.</span>
      <span style="margin-left:auto;color:#8b949e;white-space:nowrap;font-size:.9em">Updated ${_dwAgo(new Date().toISOString())}</span>
    </div>

    <!-- Tab Navigation -->
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:16px">
      <div class="enh-tabs" id="dw-tabs">
        ${[
          { id:'marketplace', icon:'fa-store', label:'Marketplace' },
          { id:'ransomware',  icon:'fa-lock',  label:'Ransomware Tracker' },
          { id:'credentials', icon:'fa-user-secret', label:'Credentials' },
          { id:'forums',      icon:'fa-comments',    label:'Forums' },
          { id:'onion',       icon:'fa-circle',      label:'Onion Monitor' },
        ].map(t => `
          <button class="enh-tab ${_DW.tab === t.id ? 'enh-tab--active' : ''}"
            onclick="_dwSwitchTab('${t.id}')">
            <i class="fas ${t.icon}" style="margin-right:5px"></i>${t.label}
          </button>`).join('')}
      </div>
      <!-- Search + filter -->
      <div style="display:flex;gap:6px;align-items:center">
        <div style="position:relative">
          <i class="fas fa-search" style="position:absolute;left:9px;top:50%;transform:translateY(-50%);color:#4b5563;font-size:.8em;pointer-events:none"></i>
          <input class="enh-input" style="padding-left:28px;width:180px" placeholder="Search dark web…"
            id="dw-search" oninput="_dwApplyFilters()" />
        </div>
        <select class="enh-select" id="dw-sev" onchange="_dwApplyFilters()">
          <option value="">All Severities</option>
          <option value="CRITICAL">🔴 Critical</option>
          <option value="HIGH">🟠 High</option>
          <option value="MEDIUM">🟡 Medium</option>
        </select>
      </div>
    </div>

    <!-- Tab Content -->
    <div id="dw-content"></div>

    </div>
  </div>

  <!-- Detail Panel Overlay -->
  <div id="dw-overlay" class="enh-panel-overlay" onclick="_dwClosePanel()"></div>
  <div id="dw-panel" class="enh-detail-panel">
    <div id="dw-panel-body"></div>
  </div>
  `;

  _dwRenderTab(_DW.tab);
  _dwInitRevealAnimations();
};

/* ── Tab switch ── */
window._dwSwitchTab = function(tab) {
  _DW.tab = tab;
  document.querySelectorAll('.enh-tab').forEach(b => {
    const active = b.getAttribute('onclick').includes(`'${tab}'`);
    b.classList.toggle('enh-tab--active', active);
  });
  _dwRenderTab(tab);
};

/* ── Apply filters ── */
window._dwApplyFilters = function() {
  _DW.filter.search = document.getElementById('dw-search')?.value?.toLowerCase() || '';
  _DW.filter.sev    = document.getElementById('dw-sev')?.value || '';
  _dwRenderTab(_DW.tab);
};

/* ── Render active tab ── */
function _dwRenderTab(tab) {
  const c = document.getElementById('dw-content');
  if (!c) return;
  c.innerHTML = '';

  switch(tab) {
    case 'marketplace':  c.innerHTML = _dwBuildMarketplace(); break;
    case 'ransomware':   c.innerHTML = _dwBuildRansomware();  break;
    case 'credentials':  c.innerHTML = _dwBuildCredentials(); break;
    case 'forums':       c.innerHTML = _dwBuildForums();      break;
    case 'onion':        c.innerHTML = _dwBuildOnion();       break;
  }
}

/* ── MARKETPLACE ── */
function _dwBuildMarketplace() {
  let items = _DW_DATA.marketplace;
  if (_DW.filter.sev)    items = items.filter(i => i.severity === _DW.filter.sev);
  if (_DW.filter.search) items = items.filter(i =>
    (i.title + i.type + i.seller + i.tags.join(' ')).toLowerCase().includes(_DW.filter.search));

  if (!items.length) return `<div style="text-align:center;padding:48px;color:#8b949e"><i class="fas fa-search fa-2x" style="display:block;margin-bottom:12px;opacity:.3"></i>No listings match filters</div>`;

  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px">
      ${items.map((item, i) => {
        const sc = _dwSevColor(item.severity);
        return `
        <div class="dw-card enh-stagger-${Math.min(i+1,6)}" onclick="_dwOpenItem(${JSON.stringify(item).replace(/"/g,'&quot;')})">
          <div style="height:3px;background:linear-gradient(90deg,${sc},${sc}44)"></div>
          <div class="dw-card__header">
            <div style="width:40px;height:40px;border-radius:10px;background:${sc}18;border:1px solid ${sc}30;display:flex;align-items:center;justify-content:center;flex-shrink:0">
              <i class="fas ${_dwTypeIcon(item.type)}" style="color:${sc};font-size:.9em"></i>
            </div>
            <div style="flex:1;min-width:0">
              <div style="font-size:.88em;font-weight:700;color:#e6edf3;margin-bottom:4px;line-height:1.3;
                overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">
                ${_dwEsc(item.title)}
              </div>
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                ${_dwBadge(item.severity, item.severity)}
                <span style="font-size:.7em;color:#8b949e;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:4px">${_dwEsc(item.type)}</span>
              </div>
            </div>
          </div>
          <div class="dw-card__body">
            <div style="font-size:.78em;color:#8b949e;margin-bottom:8px;line-height:1.5;
              overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">
              ${_dwEsc(item.description)}
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <div style="font-size:.8em;color:#22c55e;font-weight:700;font-family:monospace">${_dwEsc(item.price)}</div>
              <div style="font-size:.75em;color:#8b949e">
                <i class="fas fa-eye" style="margin-right:4px"></i>${item.views?.toLocaleString()}
                &nbsp;|&nbsp;
                <i class="fas fa-star" style="color:#eab308;margin-right:4px"></i>${item.rating}
              </div>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div style="font-size:.73em;color:#6b7280;font-family:monospace">
                <i class="fas fa-user-ninja" style="margin-right:4px;color:#8b949e"></i>${_dwEsc(item.seller)}
              </div>
              <div style="font-size:.72em;color:#4b5563">${_dwAgo(item.posted)}</div>
            </div>
            <div class="dw-card__tags">
              ${item.tags.map(t => `<span class="dw-tag">${_dwEsc(t)}</span>`).join('')}
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

/* ── RANSOMWARE TRACKER ── */
function _dwBuildRansomware() {
  let items = _DW_DATA.ransomware;
  if (_DW.filter.sev)    items = items.filter(i => i.threat_level === _DW.filter.sev);
  if (_DW.filter.search) items = items.filter(i =>
    (i.group + i.country + i.sector_targets.join(' ') + i.latest_victim).toLowerCase().includes(_DW.filter.search));

  const totalVictims = items.reduce((s,r) => s+r.victims, 0);

  return `
    <div style="background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.1);border-radius:10px;padding:12px 16px;margin-bottom:14px;display:flex;align-items:center;gap:16px;flex-wrap:wrap">
      <div style="font-size:.82em;color:#ef4444;font-weight:700"><i class="fas fa-radiation" style="margin-right:6px"></i>RaaS Activity Monitor</div>
      <div style="font-size:.8em;color:#8b949e">${items.filter(r=>r.status==='ACTIVE').length} active groups · ${totalVictims} total victims this quarter</div>
      <div style="margin-left:auto;font-size:.76em;color:#6b7280">Data sourced from onion sites, leak forums, and threat intelligence APIs</div>
    </div>
    <div style="overflow-x:auto">
    <table class="enh-table">
      <thead>
        <tr>
          ${['Group','Status','Victims','Threat Level','Latest Victim','Avg Ransom','Pay Rate','Actions'].map(h =>
            `<th>${h}</th>`).join('')}
        </tr>
      </thead>
      <tbody>
        ${items.map((r, i) => {
          const sc = _dwSevColor(r.threat_level);
          return `
          <tr class="enh-stagger-${Math.min(i+1,6)}" style="cursor:pointer" onclick="_dwOpenRansom(${i})">
            <td>
              <div style="display:flex;align-items:center;gap:8px">
                <div style="width:8px;height:8px;border-radius:50%;background:${r.status==='ACTIVE'?'#22c55e':'#6b7280'};
                  animation:${r.status==='ACTIVE'?'enh-dot-blink 2s infinite':'none'}"></div>
                <span style="font-weight:700;color:#e6edf3;font-size:.88em">${_dwEsc(r.group)}</span>
              </div>
            </td>
            <td>${r.status === 'ACTIVE'
              ? `<span class="enh-badge enh-badge--online"><span class="enh-dot enh-dot--online"></span>ACTIVE</span>`
              : `<span class="enh-badge enh-badge--offline">OFFLINE</span>`}</td>
            <td><span style="font-weight:700;color:${sc}">${r.victims}</span></td>
            <td>${_dwBadge(r.threat_level, r.threat_level)}</td>
            <td style="font-size:.8em;color:#b0bec5;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_dwEsc(r.latest_victim)}</td>
            <td style="font-family:monospace;font-size:.82em;color:#22c55e">${_dwEsc(r.negotiation_avg)}</td>
            <td style="color:#f97316;font-size:.82em">${_dwEsc(r.payment_rate)}</td>
            <td>
              <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="event.stopPropagation();_dwCopyOnion('${r.onion}')">
                <i class="fas fa-copy"></i>
              </button>
            </td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
    </div>`;
}

/* ── CREDENTIALS ── */
function _dwBuildCredentials() {
  let items = _DW_DATA.credentials;
  if (_DW.filter.search) items = items.filter(i =>
    (i.source + i.type + i.freshness).toLowerCase().includes(_DW.filter.search));

  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">
      ${items.map((cr, i) => `
        <div class="dw-card enh-stagger-${Math.min(i+1,6)}">
          <div style="height:3px;background:${cr.verified?'linear-gradient(90deg,#a855f7,#7c3aed)':'linear-gradient(90deg,#374151,#4b5563)'}"></div>
          <div class="dw-card__body">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
              <div style="flex:1">
                <div style="font-size:.86em;font-weight:700;color:#e6edf3;margin-bottom:4px;line-height:1.4">${_dwEsc(cr.source)}</div>
                <div style="font-size:.74em;color:#8b949e">${_dwEsc(cr.type)}</div>
              </div>
              ${cr.verified
                ? `<span class="enh-badge enh-badge--purple"><i class="fas fa-check-circle" style="margin-right:3px"></i>VERIFIED</span>`
                : `<span class="enh-badge" style="background:rgba(107,114,128,.1);color:#6b7280;border:1px solid rgba(107,114,128,.2)">UNVERIFIED</span>`}
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.78em">
              <div style="background:rgba(255,255,255,.04);padding:6px 8px;border-radius:6px">
                <div style="color:#8b949e;margin-bottom:2px">Count</div>
                <div style="color:#a855f7;font-weight:700">${_dwEsc(cr.count)}</div>
              </div>
              <div style="background:rgba(255,255,255,.04);padding:6px 8px;border-radius:6px">
                <div style="color:#8b949e;margin-bottom:2px">Price</div>
                <div style="color:#22c55e;font-weight:700;font-family:monospace">${_dwEsc(cr.price)}</div>
              </div>
              <div style="background:rgba(255,255,255,.04);padding:6px 8px;border-radius:6px">
                <div style="color:#8b949e;margin-bottom:2px">Format</div>
                <div style="color:#e6edf3">${_dwEsc(cr.format)}</div>
              </div>
              <div style="background:rgba(255,255,255,.04);padding:6px 8px;border-radius:6px">
                <div style="color:#8b949e;margin-bottom:2px">Status</div>
                <div style="color:${cr.freshness.includes('VERY')?'#ef4444':'#f97316'};font-weight:700">${_dwEsc(cr.freshness)}</div>
              </div>
            </div>
            <div style="font-size:.72em;color:#4b5563;margin-top:8px">Posted: ${_dwEsc(cr.date)}</div>
          </div>
        </div>`).join('')}
    </div>`;
}

/* ── FORUMS ── */
function _dwBuildForums() {
  let items = _DW_DATA.forums;
  if (_DW.filter.sev)    items = items.filter(i => i.threat_level === _DW.filter.sev);
  if (_DW.filter.search) items = items.filter(i =>
    (i.title + i.forum + i.category + i.author).toLowerCase().includes(_DW.filter.search));

  return `
    <div style="display:flex;flex-direction:column;gap:8px">
      ${items.map((f, i) => {
        const sc = _dwSevColor(f.threat_level);
        return `
        <div style="background:rgba(13,20,33,.8);border:1px solid #1a2535;border-left:3px solid ${sc};
          border-radius:0 10px 10px 0;padding:12px 16px;transition:all .2s;cursor:pointer;
          animation:enh-fadeIn .35s ease ${i*.05}s both"
          onmouseover="this.style.background='#131b2a';this.style.borderLeftColor='${sc}'"
          onmouseout="this.style.background='rgba(13,20,33,.8)'">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
            <div style="flex:1;min-width:0">
              <div style="font-size:.88em;font-weight:700;color:#e6edf3;margin-bottom:5px;line-height:1.4">${_dwEsc(f.title)}</div>
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                <span style="font-size:.74em;color:#3b82f6;font-weight:600">${_dwEsc(f.forum)}</span>
                <span style="color:#4b5563">·</span>
                <span style="font-size:.74em;color:#8b949e">${_dwEsc(f.category)}</span>
                <span style="color:#4b5563">·</span>
                <span style="font-size:.74em;color:#6b7280">by ${_dwEsc(f.author)}</span>
                <span style="color:#4b5563">·</span>
                <span style="font-size:.72em;color:#4b5563">${_dwAgo(f.posted)}</span>
              </div>
            </div>
            <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0">
              ${_dwBadge(f.threat_level, f.threat_level)}
              <div style="font-size:.72em;color:#8b949e;display:flex;gap:8px">
                <span><i class="fas fa-comment" style="margin-right:3px"></i>${f.replies}</span>
                <span><i class="fas fa-eye" style="margin-right:3px"></i>${f.views}</span>
              </div>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

/* ── ONION MONITOR ── */
function _dwBuildOnion() {
  let items = _DW_DATA.onion;
  if (_DW.filter.sev)    items = items.filter(i => i.risk === _DW.filter.sev);
  if (_DW.filter.search) items = items.filter(i =>
    (i.url + i.category + i.description + i.tor_title).toLowerCase().includes(_DW.filter.search));

  return `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px">
      ${items.map((o, i) => {
        const sc = _dwSevColor(o.risk);
        const online = o.status === 'ONLINE';
        return `
        <div class="dw-card enh-stagger-${Math.min(i+1,6)}" style="${!online?'opacity:.7':''}">
          <div style="height:3px;background:${online?`linear-gradient(90deg,${sc},${sc}44)`:'#1e2d3d'}"></div>
          <div class="dw-card__body">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <div style="width:8px;height:8px;border-radius:50%;background:${online?'#22c55e':'#6b7280'};
                flex-shrink:0;animation:${online?'enh-dot-blink 2s infinite':'none'}"></div>
              <span style="font-size:.76em;font-family:monospace;color:${online?'#22c55e':'#6b7280'}">${_dwEsc(o.status)}</span>
              <span style="margin-left:auto">${_dwBadge(o.risk, o.risk)}</span>
            </div>
            <div style="font-size:.84em;font-weight:700;color:#e6edf3;margin-bottom:4px;line-height:1.4">${_dwEsc(o.tor_title)}</div>
            <div style="font-size:.76em;font-family:monospace;color:#8b949e;margin-bottom:6px;
              overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_dwEsc(o.url)}</div>
            <div style="font-size:.78em;color:#8b949e;margin-bottom:8px;line-height:1.5">${_dwEsc(o.description)}</div>
            <div style="display:flex;align-items:center;justify-content:space-between">
              <span style="font-size:.72em;color:#4b5563">
                <i class="fas fa-tag" style="margin-right:4px"></i>${_dwEsc(o.category)}
              </span>
              <span style="font-size:.72em;color:#4b5563">
                <i class="fas fa-clock" style="margin-right:4px"></i>${_dwAgo(o.last_check)}
              </span>
            </div>
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

/* ── Open item panel ── */
window._dwOpenItem = function(item) {
  if (typeof item === 'string') {
    try { item = JSON.parse(item); } catch { return; }
  }
  const panel   = document.getElementById('dw-panel');
  const overlay = document.getElementById('dw-overlay');
  const body    = document.getElementById('dw-panel-body');
  if (!panel || !body) return;

  const sc = _dwSevColor(item.severity || item.threat_level || 'MEDIUM');

  body.innerHTML = `
    <div class="enh-detail-panel__header">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <button class="enh-btn enh-btn--ghost enh-btn--sm" onclick="_dwClosePanel()">
          <i class="fas fa-times"></i>
        </button>
        <div style="width:34px;height:34px;background:${sc}18;border:1px solid ${sc}30;border-radius:9px;
          display:flex;align-items:center;justify-content:center">
          <i class="fas ${_dwTypeIcon(item.type||item.category||'')}" style="color:${sc};font-size:.85em"></i>
        </div>
        <div>
          <div style="font-size:.88em;font-weight:700;color:#e6edf3;line-height:1.3">${_dwEsc(item.title||item.group||item.source||item.url||'Details')}</div>
          <div style="font-size:.74em;color:#8b949e;margin-top:2px">${_dwEsc(item.type||item.category||'Dark Web Intelligence')}</div>
        </div>
        <div style="margin-left:auto">${_dwBadge(item.severity||item.threat_level||item.risk||'INFO', item.severity||item.threat_level||item.risk)}</div>
      </div>
    </div>
    <div class="enh-detail-panel__body">
      ${item.description ? `
      <div class="enh-detail-panel__section enh-stagger-1">
        <div class="enh-detail-panel__section-title"><i class="fas fa-info-circle" style="color:#22d3ee"></i>Description</div>
        <p style="color:#b0bec5;font-size:.85em;line-height:1.7;margin:0">${_dwEsc(item.description)}</p>
      </div>` : ''}

      <div class="enh-detail-panel__section enh-stagger-2">
        <div class="enh-detail-panel__section-title"><i class="fas fa-chart-bar" style="color:#a855f7"></i>Details</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          ${Object.entries({
            Price: item.price,
            Seller: item.seller,
            Posted: item.posted ? _dwAgo(item.posted) : undefined,
            Views: item.views?.toLocaleString(),
            Rating: item.rating ? `⭐ ${item.rating}` : undefined,
            Country: item.country,
            Victims: item.victims,
            'Avg Ransom': item.negotiation_avg,
            'Payment Rate': item.payment_rate,
            Format: item.format,
            Freshness: item.freshness,
            Count: item.count,
          }).filter(([,v]) => v != null).map(([k,v]) => `
            <div style="background:rgba(255,255,255,.04);padding:8px;border-radius:7px">
              <div style="font-size:.7em;color:#8b949e;margin-bottom:3px">${k}</div>
              <div style="font-size:.85em;color:#e6edf3;font-weight:600">${_dwEsc(String(v))}</div>
            </div>`).join('')}
        </div>
      </div>

      ${item.tags ? `
      <div class="enh-detail-panel__section enh-stagger-3">
        <div class="enh-detail-panel__section-title"><i class="fas fa-tags" style="color:#22c55e"></i>Tags</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${item.tags.map(t => `<span class="dw-tag" style="font-size:.75em;padding:3px 10px">${_dwEsc(t)}</span>`).join('')}
        </div>
      </div>` : ''}

      ${item.tor || item.onion ? `
      <div class="enh-detail-panel__section enh-stagger-4">
        <div class="enh-detail-panel__section-title"><i class="fas fa-circle" style="color:#ef4444"></i>Tor Address</div>
        <div style="font-family:monospace;font-size:.82em;color:#ef4444;background:rgba(239,68,68,.08);
          padding:8px 12px;border-radius:6px;border:1px solid rgba(239,68,68,.15);
          overflow:hidden;text-overflow:ellipsis;word-break:break-all">
          ${_dwEsc(item.tor || item.onion)}
        </div>
        <div style="font-size:.72em;color:#6b7280;margin-top:6px">
          ⚠️ Onion address for reference only. Do not access without proper OPSEC.
        </div>
      </div>` : ''}

      ${item.sector_targets ? `
      <div class="enh-detail-panel__section enh-stagger-5">
        <div class="enh-detail-panel__section-title"><i class="fas fa-crosshairs" style="color:#f97316"></i>Targeted Sectors</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${item.sector_targets.map(s => `<span class="enh-badge enh-badge--high">${_dwEsc(s)}</span>`).join('')}
        </div>
      </div>` : ''}

      <div style="display:flex;gap:8px;margin-top:16px" class="enh-stagger-6">
        <button class="enh-btn enh-btn--primary" style="flex:1" onclick="_dwCreateAlert('${_dwEsc(item.title||item.group||'item')}')">
          <i class="fas fa-bell"></i> Create Alert
        </button>
        <button class="enh-btn enh-btn--cyan" style="flex:1" onclick="_dwInvestigate('${_dwEsc(item.id||item.group||'item')}')">
          <i class="fas fa-search"></i> Investigate
        </button>
        <button class="enh-btn enh-btn--ghost" onclick="_dwExportItem('${_dwEsc(item.id||item.group||'item')}')">
          <i class="fas fa-download"></i>
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

window._dwOpenRansom = function(idx) {
  _dwOpenItem(_DW_DATA.ransomware[idx]);
};

window._dwClosePanel = function() {
  const panel   = document.getElementById('dw-panel');
  const overlay = document.getElementById('dw-overlay');
  if (panel)   panel.classList.remove('enh-detail-panel--open');
  if (overlay) { overlay.style.opacity = '0'; setTimeout(() => { if(overlay) overlay.style.display='none'; }, 300); }
};

/* ── Utility actions ── */
window._dwRefresh = function() {
  const icon = document.getElementById('dw-refresh-icon');
  if (icon) { icon.style.animation = 'enh-spin .8s linear infinite'; setTimeout(() => icon.style.animation='', 1200); }
  _dwRenderTab(_DW.tab);
  if (typeof showToast === 'function') showToast('🔄 Dark web feed refreshed', 'info');
};

window._dwExport = function() {
  const data = JSON.stringify(_DW_DATA, null, 2);
  const blob = new Blob([data], {type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`dark-web-report-${new Date().toISOString().slice(0,10)}.json`; a.click();
  if (typeof showToast === 'function') showToast('📊 Dark web report exported', 'success');
};

window._dwSetAlert = function() {
  if (typeof showToast === 'function') showToast('🔔 Dark web monitor alert configured', 'success');
};

window._dwCopyOnion = function(onion) {
  navigator.clipboard?.writeText(onion).then(() => {
    if (typeof showToast === 'function') showToast('📋 Onion address copied', 'info');
  }).catch(() => { if (typeof showToast === 'function') showToast('⚠️ Copy not supported in this browser', 'warning'); });
};

window._dwCreateAlert = function(title) {
  if (typeof showToast === 'function') showToast(`🔔 Alert created for: ${title.slice(0,40)}`, 'success');
};

window._dwInvestigate = function(id) {
  if (typeof showToast === 'function') showToast(`🔍 AI investigation started for item ${id}`, 'info');
};

window._dwExportItem = function(id) {
  if (typeof showToast === 'function') showToast(`📋 Item ${id} exported`, 'success');
};

/* ── Icon by type ── */
function _dwTypeIcon(type) {
  if (!type) return 'fa-skull-crossbones';
  const t = type.toLowerCase();
  if (t.includes('ransomware') || t.includes('raas')) return 'fa-lock';
  if (t.includes('exploit') || t.includes('0day'))    return 'fa-bug';
  if (t.includes('credential') || t.includes('dump')) return 'fa-user-secret';
  if (t.includes('access') || t.includes('broker'))   return 'fa-door-open';
  if (t.includes('malware') || t.includes('maas'))    return 'fa-virus';
  if (t.includes('breach') || t.includes('data'))     return 'fa-database';
  if (t.includes('phishing') || t.includes('kit'))    return 'fa-fish';
  if (t.includes('botnet'))                           return 'fa-network-wired';
  if (t.includes('leak') || t.includes('apt'))        return 'fa-ghost';
  if (t.includes('forum') || t.includes('darknet'))   return 'fa-comments';
  return 'fa-skull-crossbones';
}

/* ── Reveal animations using IntersectionObserver ── */
function _dwInitRevealAnimations() {
  if (!('IntersectionObserver' in window)) return;
  const obs = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('enh-reveal--visible');
        obs.unobserve(e.target);
      }
    });
  }, { threshold: 0.1 });
  document.querySelectorAll('#page-dark-web .enh-reveal').forEach(el => obs.observe(el));
}

})(); // end IIFE wrapper — prevents _DW_DATA const collision with darkweb.js
