/**
 * ══════════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Dark Web Intelligence Module v6.0
 *  Complete redesign matching Threat Actor Intelligence style
 *  Features: 5 tabs, animated cards, slide-in detail panel,
 *            loading skeletons, real-time filters, hover effects
 * ══════════════════════════════════════════════════════════════════════
 */
(function() {
'use strict';

/* ═══════════════════════════════════════════════════════
   DATA — Rich synthetic dataset (offline/demo mode)
═══════════════════════════════════════════════════════ */
const DW_DATA = {
  marketplace: [
    { id:'dw-001', title:'RaaS Kit — LockBit 4.0 Builder', type:'Ransomware', severity:'CRITICAL', price:'$5,000', seller:'0x_phantom', tor:'lockbit4a3ebjnt4.onion', tags:['ransomware','builder','affiliate'], posted:'2025-02-15T08:30:00Z', views:1847, rating:4.8, description:'Full LockBit 4.0 ransomware builder with affiliate panel, Tor C2, and automated victim negotiation portal. Includes source code and 12-month support. Active affiliate program offering 70/30 split.' },
    { id:'dw-002', title:'0-Day: Microsoft Exchange RCE (CVE-2025-XXXX)', type:'Exploit', severity:'CRITICAL', price:'$45,000', seller:'exploit_market', tor:'exploit1a2b3c4d.onion', tags:['0day','exchange','RCE','unpatched'], posted:'2025-02-10T14:22:00Z', views:3291, rating:4.9, description:'Unauthenticated remote code execution in Exchange Server 2019-2024. Full chain exploit with SYSTEM privileges. Tested against patched instances with 98% success rate.' },
    { id:'dw-003', title:'Credential Dump: Fortune 500 (87K accounts)', type:'Credentials', severity:'HIGH', price:'$1,200', seller:'breach_lord', tor:'credentials7x8y.onion', tags:['credentials','breach','corporate','finance'], posted:'2025-02-08T11:15:00Z', views:5621, rating:4.2, description:'Fresh credential dump from major financial institution breach. Includes email, password (plaintext + hash), MFA seeds. Verified 73% valid rate as of posting date.' },
    { id:'dw-004', title:'APT Access Broker: Telecom Network VPN', type:'Access', severity:'CRITICAL', price:'$12,000', seller:'access_broker_ru', tor:'iabroker9x2y.onion', tags:['access-broker','VPN','telecom','persistent'], posted:'2025-02-09T09:00:00Z', views:892, rating:4.7, description:'Active administrator access to major European telecom provider. Includes DC access, 450k employee records, billing database credentials. Undetected for 6+ months.' },
    { id:'dw-005', title:'Malware-as-a-Service: AsyncRAT v4', type:'MaaS', severity:'HIGH', price:'$800/mo', seller:'asyncrat_dev', tor:'asyncrat1b2c3d.onion', tags:['RAT','MaaS','C2','builder'], posted:'2025-01-20T16:45:00Z', views:2134, rating:4.5, description:'Fully managed AsyncRAT infrastructure. Includes builder, C2 server, obfuscator, and 24/7 support. Used in 200+ active campaigns. FUD guaranteed.' },
    { id:'dw-006', title:'Data Breach: Healthcare Chain (2.1M patients)', type:'Data Breach', severity:'CRITICAL', price:'$8,500', seller:'medithreat', tor:'meddata3x9y1z.onion', tags:['healthcare','PII','PHI','SSN'], posted:'2025-02-01T07:30:00Z', views:4102, rating:4.6, description:'Patient records from 48-hospital chain: SSN, DOB, insurance, prescription history. Includes internal network diagrams and admin credentials for 3 hospitals.' },
    { id:'dw-007', title:'Phishing Kit — Microsoft 365 AiTM', type:'Phishing Kit', severity:'MEDIUM', price:'$350', seller:'kit_master', tor:'phishkit8a1b.onion', tags:['phishing','M365','AiTM','MFA-bypass'], posted:'2025-01-10T13:00:00Z', views:8934, rating:4.1, description:'Adversary-in-The-Middle phishing kit for M365. Bypasses MFA. Includes EvilProxy-style reverse proxy, CAPTCHA bypass, and geofencing. Browser-compatible.' },
    { id:'dw-008', title:'Botnet: 50,000 Corporate Endpoints', type:'Botnet', severity:'HIGH', price:'$25,000', seller:'botmaster_x', tor:'botnet1x2y3z4a.onion', tags:['botnet','corporate','endpoints','DDoS'], posted:'2025-02-05T10:20:00Z', views:1203, rating:4.4, description:'Curated botnet of 50k compromised corporate workstations across 40 countries. Filtered for Fortune 1000 companies. Delivered via PowerShell loader.' },
    { id:'dw-009', title:'Stealer Logs: 400K Machines (EU/US)', type:'Stealer Logs', severity:'HIGH', price:'$3,000', seller:'logs_empire', tor:'logs1a2b3c4d.onion', tags:['stealer','logs','RedLine','Raccoon'], posted:'2025-02-12T08:00:00Z', views:2891, rating:4.3, description:'Fresh RedLine and Raccoon stealer logs from 400K infected machines. Includes browser cookies, saved passwords, crypto wallets, and banking sessions.' },
    { id:'dw-010', title:'SIM Swapping Service — US Carriers', type:'Service', severity:'MEDIUM', price:'$500/swap', seller:'simswap_pro', tor:'simswap9x1y.onion', tags:['SIM-swap','fraud','telecom','identity'], posted:'2025-02-06T12:00:00Z', views:1567, rating:3.9, description:'Professional SIM swap service for major US carriers. 24-48h turnaround. Includes T-Mobile, AT&T, Verizon. Ideal for bypassing SMS-based 2FA.' },
  ],
  ransomware: [
    { group:'LockBit 4.0', victims:47, status:'ACTIVE', country:'Russia', sectors:['Healthcare','Finance','Government'], latest_victim:'Meridian Healthcare Group', latest_date:'2025-02-10T00:00:00Z', threat_level:'CRITICAL', onion:'lockbitvictimsite.onion', avg_ransom:'$2.1M', pay_rate:34, ttps:['T1486','T1490','T1083'] },
    { group:'BlackCat/ALPHV', victims:31, status:'ACTIVE', country:'Unknown', sectors:['Energy','Manufacturing','Legal'], latest_victim:'Atlas Energy Corp', latest_date:'2025-02-08T00:00:00Z', threat_level:'CRITICAL', onion:'blackcat3victims.onion', avg_ransom:'$4.8M', pay_rate:29, ttps:['T1486','T1657','T1562'] },
    { group:'Clop', victims:89, status:'ACTIVE', country:'Russia', sectors:['Finance','Technology','Retail'], latest_victim:'DataVault Financial', latest_date:'2025-02-09T00:00:00Z', threat_level:'CRITICAL', onion:'clopvictims1.onion', avg_ransom:'$1.5M', pay_rate:41, ttps:['T1190','T1486','T1005'] },
    { group:'Royal Ransomware', victims:22, status:'ACTIVE', country:'Unknown', sectors:['Healthcare','Education'], latest_victim:'NorthStar University', latest_date:'2025-02-06T00:00:00Z', threat_level:'HIGH', onion:'royalvictims2.onion', avg_ransom:'$3.2M', pay_rate:25, ttps:['T1566','T1486','T1047'] },
    { group:'Play', victims:18, status:'ACTIVE', country:'Unknown', sectors:['Government','Manufacturing'], latest_victim:'City of Riverside', latest_date:'2025-02-07T00:00:00Z', threat_level:'HIGH', onion:'playransomsite.onion', avg_ransom:'$850K', pay_rate:38, ttps:['T1078','T1486','T1489'] },
    { group:'Medusa', victims:14, status:'ACTIVE', country:'Unknown', sectors:['Healthcare','Education'], latest_victim:'Memorial Medical', latest_date:'2025-02-04T00:00:00Z', threat_level:'HIGH', onion:'medusaransomware.onion', avg_ransom:'$1.2M', pay_rate:31, ttps:['T1133','T1486','T1530'] },
    { group:'8Base', victims:28, status:'ACTIVE', country:'Unknown', sectors:['Finance','Retail','SMB'], latest_victim:'Apex Financial Group', latest_date:'2025-01-31T00:00:00Z', threat_level:'HIGH', onion:'8baseleaksite.onion', avg_ransom:'$650K', pay_rate:44, ttps:['T1003','T1486','T1567'] },
    { group:'Akira', victims:19, status:'ACTIVE', country:'Unknown', sectors:['Technology','Manufacturing','Legal'], latest_victim:'TechCore Solutions', latest_date:'2025-02-11T00:00:00Z', threat_level:'HIGH', onion:'akira4victims.onion', avg_ransom:'$1.8M', pay_rate:36, ttps:['T1078','T1486','T1059'] },
  ],
  credentials: [
    { id:'cr-001', source:'LinkedIn (partial)', count:'48M', type:'Email + SHA-512', date:'2025-01-12', freshness:'FRESH', price:'$200', format:'CSV', verified:true, industries:['Technology','Finance','Healthcare'] },
    { id:'cr-002', source:'Gaming Platform', count:'12M', type:'Email + Plaintext', date:'2025-01-28', freshness:'FRESH', price:'$450', format:'JSON', verified:true, industries:['Gaming','Entertainment'] },
    { id:'cr-003', source:'E-commerce (major EU)', count:'3.2M', type:'Full PII + CC', date:'2025-02-01', freshness:'FRESH', price:'$2,800', format:'SQL dump', verified:false, industries:['Retail','E-commerce'] },
    { id:'cr-004', source:'Government Directory', count:'890K', type:'Name + Email + Phone', date:'2025-01-15', freshness:'FRESH', price:'$600', format:'CSV', verified:true, industries:['Government'] },
    { id:'cr-005', source:'Healthcare Portal', count:'2.1M', type:'SSN + DOB + Insurance', date:'2025-02-05', freshness:'FRESH', price:'$5,000', format:'SQL dump', verified:true, industries:['Healthcare'] },
    { id:'cr-006', source:'Cloud SaaS Provider', count:'175K', type:'API keys + OAuth', date:'2025-02-08', freshness:'VERY FRESH', price:'$3,500', format:'JSON', verified:true, industries:['Technology','SaaS'] },
    { id:'cr-007', source:'University Network', count:'520K', type:'Email + NTLM hash', date:'2025-02-11', freshness:'VERY FRESH', price:'$380', format:'CSV', verified:true, industries:['Education'] },
  ],
  forums: [
    { id:'fr-001', forum:'BreachForums v2', category:'Database Leaks', title:'[FREE] 500K combo list — US Corporate', replies:342, views:'18.2K', author:'data_dump_king', posted:'2025-02-09T15:22:00Z', threat_level:'HIGH' },
    { id:'fr-002', forum:'RaidForums Mirror', category:'Malware Discussion', title:'Bypass EDR 2025 — Defender, CS, SentinelOne', replies:891, views:'45.1K', author:'evasion_expert', posted:'2025-02-08T09:14:00Z', threat_level:'CRITICAL' },
    { id:'fr-003', forum:'XSS.is', category:'Access Sales', title:'[SELLING] Persistent access — Tier 1 EU bank', replies:67, views:'2.1K', author:'access_broker_x', posted:'2025-02-07T20:45:00Z', threat_level:'CRITICAL' },
    { id:'fr-004', forum:'Exploit.in', category:'Vulnerabilities', title:'PoC — Windows Kernel UAF (EoP, unpatched)', replies:234, views:'9.8K', author:'vuln_hunter_ru', posted:'2025-02-06T12:33:00Z', threat_level:'CRITICAL' },
    { id:'fr-005', forum:'BreachForums v2', category:'Tutorials', title:'Spear Phishing O365 2025 — bypass ATP/Safe Links', replies:445, views:'28.4K', author:'phish_lord', posted:'2025-02-05T08:00:00Z', threat_level:'HIGH' },
    { id:'fr-006', forum:'Dread', category:'General', title:'LockBit affiliate recruitment — 70% split', replies:123, views:'6.7K', author:'lb_recruiter', posted:'2025-02-04T19:11:00Z', threat_level:'CRITICAL' },
    { id:'fr-007', forum:'XSS.is', category:'Stealer Logs', title:'Redline logs pack — 200K machines, 15GB', replies:89, views:'11.2K', author:'logs_seller', posted:'2025-02-03T14:55:00Z', threat_level:'HIGH' },
    { id:'fr-008', forum:'Exploit.in', category:'Tools', title:'New LOLBAS technique — evades all AV/EDR 2025', replies:567, views:'32.1K', author:'sysadmin_dark', posted:'2025-02-10T11:30:00Z', threat_level:'CRITICAL' },
  ],
  onion: [
    { id:'on-001', url:'lockbit4a3ebjnt.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'LockBit 4.0 victim portal and affiliate dashboard', tor_title:'LockBit 4.0 — Professional Ransomware Service' },
    { id:'on-002', url:'alphvmmm27o3abo.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'BlackCat/ALPHV ransomware victim and data leak site', tor_title:'ALPHV BlackCat — Data Exposure' },
    { id:'on-003', url:'breach3rdampfkgn.onion', category:'Data Market', status:'ONLINE', last_check:'2025-02-10T05:30:00Z', risk:'HIGH', description:'Active dark web marketplace for stolen data and credentials', tor_title:'BreachBase — Premium Data Exchange' },
    { id:'on-004', url:'exploit3xrg4abd.onion', category:'Exploit Shop', status:'ONLINE', last_check:'2025-02-10T04:15:00Z', risk:'CRITICAL', description:'Zero-day and N-day exploit broker marketplace', tor_title:'ExploitHub — Premier 0day Market' },
    { id:'on-005', url:'clopvictims1abc.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T03:50:00Z', risk:'CRITICAL', description:'Clop ransomware group victim publication site', tor_title:'CL0P^_- LEAKS' },
    { id:'on-006', url:'dreadditevelidot.onion', category:'Forum', status:'OFFLINE', last_check:'2025-02-09T22:00:00Z', risk:'MEDIUM', description:'Major darknet forum — maintenance downtime', tor_title:'Dread — Dark Web Forum' },
    { id:'on-007', url:'ransomhouse7xhq.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T05:00:00Z', risk:'HIGH', description:'RansomHouse victim portal and leak site', tor_title:'RansomHouse Operations' },
    { id:'on-008', url:'kelvinsecleakq2s.onion', category:'APT Site', status:'ONLINE', last_check:'2025-02-10T04:30:00Z', risk:'CRITICAL', description:'Kelvin Security APT data publication site', tor_title:'KelvinSec — Intelligence Leaks' },
    { id:'on-009', url:'akira3victims1a2.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T02:00:00Z', risk:'HIGH', description:'Akira ransomware group victim leak portal', tor_title:'Akira Ransomware — Data Leaks' },
    { id:'on-010', url:'xss1forum7a8b9c.onion', category:'Forum', status:'ONLINE', last_check:'2025-02-10T01:30:00Z', risk:'HIGH', description:'XSS.is hacking forum dark web mirror', tor_title:'XSS.is — Underground Forum' },
  ]
};

/* ═══════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════ */
const _DW = {
  tab: 'marketplace',
  filter: { search:'', severity:'', type:'' },
  selected: null,
  loading: false,
};

/* ═══════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════ */
function _e(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _ago(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60)    return `${s}s ago`;
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}
function _sevBadge(sev) {
  const cls = { CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low' };
  return `<span class="p19-badge p19-badge--${cls[sev]||'gray'}">${_e(sev)}</span>`;
}
function _riskBadge(r) { return _sevBadge(r); }

function _toast(msg, type='info') {
  let tc = document.getElementById('p19-toast-wrap');
  if (!tc) {
    tc = document.createElement('div');
    tc.id = 'p19-toast-wrap';
    document.body.appendChild(tc);
  }
  const icons = { success:'fa-check-circle', error:'fa-exclamation-circle', warning:'fa-exclamation-triangle', info:'fa-info-circle' };
  const t = document.createElement('div');
  t.className = `p19-toast p19-toast--${type}`;
  t.innerHTML = `<i class="fas ${icons[type]||'fa-bell'}"></i><span>${_e(msg)}</span>`;
  tc.appendChild(t);
  setTimeout(() => { t.classList.add('p19-toast--exit'); setTimeout(()=>t.remove(), 300); }, 3500);
}

/* ═══════════════════════════════════════════════════════
   SKELETON LOADER
═══════════════════════════════════════════════════════ */
function _skelGrid(n=6) {
  return Array.from({length:n}, ()=>`
    <div class="p19-skel-card">
      <div class="p19-skel p19-skel-title"></div>
      <div class="p19-skel p19-skel-text"></div>
      <div class="p19-skel p19-skel-text" style="width:70%"></div>
      <div style="display:flex;gap:6px;margin-top:10px">
        <div class="p19-skel p19-skel-badge"></div>
        <div class="p19-skel p19-skel-badge"></div>
      </div>
    </div>`).join('');
}

/* ═══════════════════════════════════════════════════════
   MAIN RENDER
═══════════════════════════════════════════════════════ */
window.renderDarkWeb = function() {
  const c = document.getElementById('page-dark-web');
  if (!c) return;
  c.className = 'p19-module';

  // KPI counts
  const totalListings   = DW_DATA.marketplace.length;
  const criticalCount   = DW_DATA.marketplace.filter(x=>x.severity==='CRITICAL').length;
  const ransomwareActive= DW_DATA.ransomware.filter(x=>x.status==='ACTIVE').length;
  const totalVictims    = DW_DATA.ransomware.reduce((s,x)=>s+x.victims,0);
  const onlineOnions    = DW_DATA.onion.filter(x=>x.status==='ONLINE').length;
  const totalCreds      = DW_DATA.credentials.length;

  c.innerHTML = `
  <!-- Header -->
  <div class="p19-header">
    <div class="p19-header__inner">
      <div class="p19-header__left">
        <div class="p19-header__icon p19-header__icon--red">
          <i class="fas fa-spider"></i>
        </div>
        <div>
          <h2 class="p19-header__title">Dark Web Intelligence</h2>
          <div class="p19-header__sub">Real-time monitoring · Marketplace · Ransomware · Credentials · Forums · Onion Sites</div>
        </div>
        <span class="p19-badge p19-badge--online" style="animation:p19-blink 3s infinite">
          <span class="p19-dot p19-dot--green"></span> MONITORING
        </span>
      </div>
      <div class="p19-header__right">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._dwRefresh()">
          <i class="fas fa-sync-alt"></i> <span>Refresh</span>
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._dwExport()">
          <i class="fas fa-download"></i> <span>Export</span>
        </button>
        <button class="p19-btn p19-btn--red p19-btn--sm" onclick="window._dwAlert()">
          <i class="fas fa-bell"></i> <span>Set Alert</span>
        </button>
      </div>
    </div>
  </div>

  <!-- KPI Row -->
  <div class="p19-kpi-row">
    <div class="p19-kpi-card p19-kpi-card--red" style="--i:0">
      <i class="fas fa-store p19-kpi-icon" style="color:var(--p19-red);opacity:.4"></i>
      <div class="p19-kpi-label">Active Listings</div>
      <div class="p19-kpi-value" id="dw-kpi-listings">${totalListings}</div>
      <div class="p19-kpi-sub">${criticalCount} CRITICAL severity</div>
    </div>
    <div class="p19-kpi-card p19-kpi-card--orange" style="--i:1">
      <i class="fas fa-lock p19-kpi-icon" style="color:var(--p19-orange);opacity:.4"></i>
      <div class="p19-kpi-label">Ransomware Groups</div>
      <div class="p19-kpi-value" id="dw-kpi-ransomware">${ransomwareActive}</div>
      <div class="p19-kpi-sub">${totalVictims} total victims</div>
    </div>
    <div class="p19-kpi-card p19-kpi-card--yellow" style="--i:2">
      <i class="fas fa-key p19-kpi-icon" style="color:var(--p19-yellow);opacity:.4"></i>
      <div class="p19-kpi-label">Credential Dumps</div>
      <div class="p19-kpi-value" id="dw-kpi-creds">${totalCreds}</div>
      <div class="p19-kpi-sub">Multiple verified sources</div>
    </div>
    <div class="p19-kpi-card p19-kpi-card--purple" style="--i:3">
      <i class="fas fa-globe p19-kpi-icon" style="color:var(--p19-purple);opacity:.4"></i>
      <div class="p19-kpi-label">Onion Sites</div>
      <div class="p19-kpi-value" id="dw-kpi-onion">${onlineOnions}</div>
      <div class="p19-kpi-sub">of ${DW_DATA.onion.length} total monitored</div>
    </div>
    <div class="p19-kpi-card p19-kpi-card--cyan" style="--i:4">
      <i class="fas fa-comments p19-kpi-icon" style="color:var(--p19-cyan);opacity:.4"></i>
      <div class="p19-kpi-label">Forum Threads</div>
      <div class="p19-kpi-value">${DW_DATA.forums.length}</div>
      <div class="p19-kpi-sub">High/Critical threat intel</div>
    </div>
  </div>

  <!-- Tabs -->
  <div class="p19-tabs" id="dw-tabs">
    <div class="p19-tab active" data-tab="marketplace" onclick="window._dwTab('marketplace')">
      <i class="fas fa-store" style="font-size:.85em"></i> Marketplace
      <span class="p19-tab-badge">${DW_DATA.marketplace.length}</span>
    </div>
    <div class="p19-tab" data-tab="ransomware" onclick="window._dwTab('ransomware')">
      <i class="fas fa-lock" style="font-size:.85em"></i> Ransomware
      <span class="p19-tab-badge">${DW_DATA.ransomware.length}</span>
    </div>
    <div class="p19-tab" data-tab="credentials" onclick="window._dwTab('credentials')">
      <i class="fas fa-key" style="font-size:.85em"></i> Credentials
      <span class="p19-tab-badge">${DW_DATA.credentials.length}</span>
    </div>
    <div class="p19-tab" data-tab="forums" onclick="window._dwTab('forums')">
      <i class="fas fa-comments" style="font-size:.85em"></i> Forums
      <span class="p19-tab-badge">${DW_DATA.forums.length}</span>
    </div>
    <div class="p19-tab" data-tab="onion" onclick="window._dwTab('onion')">
      <i class="fas fa-globe" style="font-size:.85em"></i> Onion Monitor
      <span class="p19-tab-badge">${onlineOnions}</span>
    </div>
  </div>

  <!-- Tab Content Panels -->
  <div class="p19-content" id="dw-content">
    <!-- Content injected by _dwTab() -->
  </div>

  <!-- Detail Slide Panel -->
  <div class="p19-detail-panel" id="dw-detail-panel">
    <div id="dw-detail-inner"></div>
  </div>
  <div id="dw-overlay" onclick="window._dwClosDetail()" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:7999;animation:p19-fadeInFast .2s"></div>
  `;

  // Animate KPI values
  setTimeout(() => _dwAnimateKPIs(), 100);
  // Render initial tab
  _dwTab('marketplace');
};

/* ═══════════════════════════════════════════════════════
   TAB SWITCHING
═══════════════════════════════════════════════════════ */
window._dwTab = function(tab) {
  _DW.tab = tab;
  _DW.filter = { search:'', severity:'', type:'' };

  // Update tab indicators
  document.querySelectorAll('#dw-tabs .p19-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tab);
  });

  // Show skeleton then render
  const content = document.getElementById('dw-content');
  if (!content) return;
  content.innerHTML = `<div class="p19-grid" id="dw-grid">${_skelGrid(6)}</div>`;

  setTimeout(() => {
    switch(tab) {
      case 'marketplace':  _dwRenderMarketplace(); break;
      case 'ransomware':   _dwRenderRansomware();  break;
      case 'credentials':  _dwRenderCredentials(); break;
      case 'forums':       _dwRenderForums();       break;
      case 'onion':        _dwRenderOnion();         break;
    }
  }, 400);
};

/* ═══════════════════════════════════════════════════════
   MARKETPLACE TAB
═══════════════════════════════════════════════════════ */
function _dwRenderMarketplace() {
  const content = document.getElementById('dw-content');
  if (!content) return;

  // Filter data
  const data = DW_DATA.marketplace.filter(x => {
    const s = _DW.filter.search.toLowerCase();
    const matchSearch = !s || x.title.toLowerCase().includes(s) || x.type.toLowerCase().includes(s) || x.seller.toLowerCase().includes(s);
    const matchSev = !_DW.filter.severity || x.severity === _DW.filter.severity;
    const matchType = !_DW.filter.type || x.type === _DW.filter.type;
    return matchSearch && matchSev && matchType;
  });

  const types = [...new Set(DW_DATA.marketplace.map(x=>x.type))];

  content.innerHTML = `
  <!-- Toolbar -->
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:340px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search listings, types, sellers…" id="dw-mp-search"
        value="${_e(_DW.filter.search)}"
        oninput="window._dwMpFilter(this.value,'search')" />
    </div>
    <select class="p19-select" id="dw-mp-sev" onchange="window._dwMpFilter(this.value,'severity')">
      <option value="">All Severities</option>
      <option value="CRITICAL"${_DW.filter.severity==='CRITICAL'?' selected':''}>CRITICAL</option>
      <option value="HIGH"${_DW.filter.severity==='HIGH'?' selected':''}>HIGH</option>
      <option value="MEDIUM"${_DW.filter.severity==='MEDIUM'?' selected':''}>MEDIUM</option>
    </select>
    <select class="p19-select" id="dw-mp-type" onchange="window._dwMpFilter(this.value,'type')">
      <option value="">All Types</option>
      ${types.map(t=>`<option value="${_e(t)}"${_DW.filter.type===t?' selected':''}>${_e(t)}</option>`).join('')}
    </select>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${data.length} listing${data.length!==1?'s':''}</span>
  </div>

  <!-- Cards -->
  <div class="p19-grid" id="dw-grid">
    ${data.length ? data.map((item,i) => _dwMpCard(item,i)).join('') : `
      <div class="p19-empty" style="grid-column:1/-1">
        <i class="fas fa-search"></i>
        <div class="p19-empty-title">No listings match your filters</div>
        <div class="p19-empty-sub">Try adjusting your search criteria</div>
      </div>`}
  </div>`;
}

function _dwMpCard(item, idx) {
  const delay = `${idx * 50}ms`;
  const borderClass = item.severity==='CRITICAL'?'dw-card-critical':item.severity==='HIGH'?'dw-card-high':'dw-card-medium';
  return `
  <div class="p19-card ${borderClass}" style="animation-delay:${delay}" onclick="window._dwShowDetail('${item.id}','marketplace')">
    <div class="p19-card-header">
      <div style="flex:1">
        <div class="p19-card-title">${_e(item.title)}</div>
        <div class="p19-card-sub">${_e(item.type)}</div>
      </div>
      ${_sevBadge(item.severity)}
    </div>
    <div class="p19-card-body" style="margin-bottom:10px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">
      ${_e(item.description)}
    </div>
    <div class="p19-tags" style="margin-bottom:10px">
      ${(item.tags||[]).map(t=>`<span class="p19-tag">${_e(t)}</span>`).join('')}
    </div>
    <div class="p19-card-footer">
      <div>
        <div class="dw-price">${_e(item.price)}</div>
        <div class="dw-seller">${_e(item.seller)}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:.72em;color:var(--p19-t4)"><i class="fas fa-eye" style="margin-right:3px"></i>${item.views?.toLocaleString()}</div>
        <div style="font-size:.72em;color:var(--p19-t4)">${_ago(item.posted)}</div>
      </div>
    </div>
  </div>`;
}

window._dwMpFilter = function(val, key) {
  _DW.filter[key] = val;
  _dwRenderMarketplace();
};

/* ═══════════════════════════════════════════════════════
   RANSOMWARE TAB
═══════════════════════════════════════════════════════ */
function _dwRenderRansomware() {
  const content = document.getElementById('dw-content');
  if (!content) return;

  const data = DW_DATA.ransomware.filter(x => {
    const s = _DW.filter.search.toLowerCase();
    return !s || x.group.toLowerCase().includes(s) || x.country.toLowerCase().includes(s);
  });

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:300px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search groups, countries…"
        oninput="_DW.filter.search=this.value;_dwRenderRansomware()" />
    </div>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${data.length} active groups · ${data.reduce((s,x)=>s+x.victims,0)} total victims</span>
  </div>
  <div class="p19-grid p19-grid--2">
    ${data.map((g,i)=>_dwRwCard(g,i)).join('')}
  </div>`;
}

function _dwRwCard(g, idx) {
  const pay_color = g.pay_rate > 40 ? 'var(--p19-red)' : g.pay_rate > 30 ? 'var(--p19-orange)' : 'var(--p19-yellow)';
  return `
  <div class="p19-card" style="animation-delay:${idx*60}ms" onclick="window._dwShowDetail('${_e(g.group)}','ransomware')">
    <div class="p19-card-header">
      <div style="flex:1">
        <div class="p19-card-title"><i class="fas fa-lock" style="color:var(--p19-red);margin-right:6px;font-size:.85em"></i>${_e(g.group)}</div>
        <div class="p19-card-sub"><i class="fas fa-globe" style="margin-right:4px;font-size:.8em"></i>${_e(g.country)}</div>
      </div>
      ${_sevBadge(g.threat_level)}
    </div>

    <div style="margin:10px 0">
      <div style="font-size:.76em;color:var(--p19-t4);margin-bottom:4px">TARGET SECTORS</div>
      <div class="p19-tags">${(g.sectors||[]).map(s=>`<span class="p19-tag">${_e(s)}</span>`).join('')}</div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin:10px 0">
      <div style="text-align:center;background:rgba(0,0,0,.2);border-radius:6px;padding:8px">
        <div style="font-size:1.1em;font-weight:700;color:var(--p19-red);font-family:'JetBrains Mono',monospace">${g.victims}</div>
        <div style="font-size:.68em;color:var(--p19-t4)">VICTIMS</div>
      </div>
      <div style="text-align:center;background:rgba(0,0,0,.2);border-radius:6px;padding:8px">
        <div style="font-size:.82em;font-weight:700;color:var(--p19-yellow);font-family:'JetBrains Mono',monospace">${_e(g.avg_ransom)}</div>
        <div style="font-size:.68em;color:var(--p19-t4)">AVG RANSOM</div>
      </div>
      <div style="text-align:center;background:rgba(0,0,0,.2);border-radius:6px;padding:8px">
        <div style="font-size:1em;font-weight:700;font-family:'JetBrains Mono',monospace" style="color:${pay_color}">${g.pay_rate}%</div>
        <div style="font-size:.68em;color:var(--p19-t4)">PAY RATE</div>
      </div>
    </div>

    <div style="margin:8px 0">
      <div style="font-size:.72em;color:var(--p19-t4)">PAYMENT RATE</div>
      <div class="p19-progress" style="margin-top:4px">
        <div class="p19-progress-bar p19-progress-bar--red" style="width:${g.pay_rate}%"></div>
      </div>
    </div>

    <div class="p19-card-footer">
      <div>
        <div style="font-size:.74em;color:var(--p19-t3)">Latest: <strong style="color:var(--p19-t1)">${_e(g.latest_victim)}</strong></div>
      </div>
      <div style="font-size:.72em;color:var(--p19-t4)">${_ago(g.latest_date)}</div>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   CREDENTIALS TAB
═══════════════════════════════════════════════════════ */
function _dwRenderCredentials() {
  const content = document.getElementById('dw-content');
  if (!content) return;

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:300px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search source, type…"
        oninput="_DW.filter.search=this.value;_dwRenderCredentials()" />
    </div>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${DW_DATA.credentials.length} active dumps</span>
  </div>
  <div class="p19-table-wrap">
    <table class="p19-table">
      <thead>
        <tr>
          <th>Source</th>
          <th>Count</th>
          <th>Data Type</th>
          <th>Freshness</th>
          <th>Price</th>
          <th>Format</th>
          <th>Verified</th>
          <th>Date</th>
        </tr>
      </thead>
      <tbody>
        ${DW_DATA.credentials.filter(x => {
          const s = _DW.filter.search.toLowerCase();
          return !s || x.source.toLowerCase().includes(s) || x.type.toLowerCase().includes(s);
        }).map((c,i) => `
        <tr style="animation:p19-slideInLeft ${i*40}ms ease both;cursor:pointer" onclick="window._dwShowDetail('${c.id}','credentials')">
          <td>
            <div style="font-weight:600;color:var(--p19-t1)">${_e(c.source)}</div>
            <div class="p19-tags" style="margin-top:4px">
              ${(c.industries||[]).slice(0,2).map(ind=>`<span class="p19-tag">${_e(ind)}</span>`).join('')}
            </div>
          </td>
          <td><span style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--p19-cyan)">${_e(c.count)}</span></td>
          <td><span style="font-size:.8em;color:var(--p19-t2)">${_e(c.type)}</span></td>
          <td><span class="p19-badge ${c.freshness==='VERY FRESH'?'p19-badge--green':'p19-badge--info'}">${_e(c.freshness)}</span></td>
          <td><span class="dw-price">${_e(c.price)}</span></td>
          <td><span class="p19-badge p19-badge--gray">${_e(c.format)}</span></td>
          <td>${c.verified ? '<span class="p19-badge p19-badge--green"><i class="fas fa-check" style="font-size:.7em"></i> YES</span>' : '<span class="p19-badge p19-badge--gray">NO</span>'}</td>
          <td style="font-size:.78em;color:var(--p19-t4)">${c.date}</td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   FORUMS TAB
═══════════════════════════════════════════════════════ */
function _dwRenderForums() {
  const content = document.getElementById('dw-content');
  if (!content) return;

  const data = DW_DATA.forums.filter(x => {
    const s = _DW.filter.search.toLowerCase();
    return !s || x.title.toLowerCase().includes(s) || x.forum.toLowerCase().includes(s) || x.category.toLowerCase().includes(s);
  });

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:340px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search threads, forums, categories…"
        oninput="_DW.filter.search=this.value;_dwRenderForums()" />
    </div>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${data.length} threads</span>
  </div>
  <div class="p19-grid--1" style="display:flex;flex-direction:column;gap:10px">
    ${data.map((f,i)=>`
    <div class="p19-card" style="animation-delay:${i*40}ms;padding:14px 16px;cursor:pointer" onclick="window._dwShowDetail('${f.id}','forums')">
      <div style="display:flex;align-items:flex-start;gap:12px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px">
            <span class="p19-badge p19-badge--info" style="font-size:.68em">${_e(f.forum)}</span>
            <span class="p19-badge p19-badge--gray" style="font-size:.68em">${_e(f.category)}</span>
            ${_sevBadge(f.threat_level)}
          </div>
          <div style="font-size:.88em;font-weight:600;color:var(--p19-t1);margin-bottom:4px">${_e(f.title)}</div>
          <div style="font-size:.74em;color:var(--p19-t4)">
            <i class="fas fa-user" style="margin-right:4px"></i>${_e(f.author)} &nbsp;·&nbsp;
            <i class="fas fa-reply" style="margin-right:4px"></i>${f.replies} replies &nbsp;·&nbsp;
            <i class="fas fa-eye" style="margin-right:4px"></i>${f.views} views &nbsp;·&nbsp;
            ${_ago(f.posted)}
          </div>
        </div>
        <i class="fas fa-chevron-right" style="color:var(--p19-t4);font-size:.8em;margin-top:4px;flex-shrink:0"></i>
      </div>
    </div>`).join('')}
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   ONION MONITOR TAB
═══════════════════════════════════════════════════════ */
function _dwRenderOnion() {
  const content = document.getElementById('dw-content');
  if (!content) return;

  const data = DW_DATA.onion.filter(x => {
    const s = _DW.filter.search.toLowerCase();
    return !s || x.url.includes(s) || x.category.toLowerCase().includes(s) || x.description.toLowerCase().includes(s);
  });

  const online = data.filter(x=>x.status==='ONLINE').length;

  content.innerHTML = `
  <div class="p19-toolbar">
    <div class="p19-search" style="max-width:300px">
      <i class="fas fa-search"></i>
      <input type="text" placeholder="Search sites, categories…"
        oninput="_DW.filter.search=this.value;_dwRenderOnion()" />
    </div>
    <select class="p19-select" onchange="_DW.filter.type=this.value;_dwRenderOnion()">
      <option value="">All Status</option>
      <option value="ONLINE">Online Only</option>
      <option value="OFFLINE">Offline</option>
    </select>
    <span style="font-size:.78em;color:var(--p19-t4);margin-left:auto">${online}/${data.length} online</span>
  </div>
  <div class="p19-grid p19-grid--2">
    ${data.filter(x=>!_DW.filter.type||x.status===_DW.filter.type).map((o,i)=>`
    <div class="p19-card" style="animation-delay:${i*50}ms" onclick="window._dwShowDetail('${o.id}','onion')">
      <div class="p19-card-header">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
            <span class="p19-status p19-status--${o.status==='ONLINE'?'online':'offline'}">${o.status}</span>
            <span class="p19-badge p19-badge--gray" style="font-size:.68em">${_e(o.category)}</span>
          </div>
          <div class="dw-onion-url">${_e(o.url)}</div>
          <div style="font-size:.8em;font-weight:600;color:var(--p19-t1);margin-top:4px">${_e(o.tor_title)}</div>
        </div>
        ${_riskBadge(o.risk)}
      </div>
      <div style="font-size:.8em;color:var(--p19-t2);margin:8px 0">${_e(o.description)}</div>
      <div class="p19-card-footer">
        <span style="font-size:.72em;color:var(--p19-t4)"><i class="fas fa-clock" style="margin-right:4px"></i>Last check: ${_ago(o.last_check)}</span>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="event.stopPropagation();window._dwCopyOnion('${_e(o.url)}')">
          <i class="fas fa-copy"></i>
        </button>
      </div>
    </div>`).join('')}
  </div>`;
}

/* ═══════════════════════════════════════════════════════
   DETAIL PANEL
═══════════════════════════════════════════════════════ */
window._dwShowDetail = function(id, dataType) {
  const panel = document.getElementById('dw-detail-panel');
  const overlay = document.getElementById('dw-overlay');
  const inner = document.getElementById('dw-detail-inner');
  if (!panel || !inner) return;

  let item, html = '';

  if (dataType === 'marketplace') {
    item = DW_DATA.marketplace.find(x=>x.id===id);
    if (!item) return;
    html = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--p19-border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--p19-bg-card);z-index:1">
      <div>
        <div style="font-size:.86em;font-weight:700;color:var(--p19-t1)">Listing Detail</div>
        <div style="font-size:.72em;color:var(--p19-t4)">${_e(item.id)}</div>
      </div>
      <button class="p19-btn p19-btn--ghost p19-btn--icon-only" onclick="window._dwClosDetail()"><i class="fas fa-times"></i></button>
    </div>
    <div style="padding:20px">
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
        ${_sevBadge(item.severity)}
        <span class="p19-badge p19-badge--blue">${_e(item.type)}</span>
      </div>
      <h3 style="font-size:1em;font-weight:700;color:var(--p19-t1);margin:0 0 8px">${_e(item.title)}</h3>
      <p style="font-size:.83em;color:var(--p19-t2);line-height:1.6;margin:0 0 16px">${_e(item.description)}</p>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:10px">
          <div style="font-size:.68em;color:var(--p19-t4);margin-bottom:3px">PRICE</div>
          <div class="dw-price" style="font-size:1em">${_e(item.price)}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:10px">
          <div style="font-size:.68em;color:var(--p19-t4);margin-bottom:3px">SELLER</div>
          <div class="dw-seller" style="font-size:.84em;color:var(--p19-t2)">${_e(item.seller)}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:10px">
          <div style="font-size:.68em;color:var(--p19-t4);margin-bottom:3px">VIEWS</div>
          <div style="font-size:.9em;font-weight:600;color:var(--p19-t1);font-family:'JetBrains Mono',monospace">${item.views?.toLocaleString()}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:8px;padding:10px">
          <div style="font-size:.68em;color:var(--p19-t4);margin-bottom:3px">POSTED</div>
          <div style="font-size:.8em;color:var(--p19-t2)">${_ago(item.posted)}</div>
        </div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">Tags</div>
        <div class="p19-tags">${(item.tags||[]).map(t=>`<span class="p19-tag">${_e(t)}</span>`).join('')}</div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">Onion URL</div>
        <div class="dw-onion-url" style="word-break:break-all">${_e(item.tor)}</div>
      </div>

      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._dwInvestigate('${_e(item.id)}')">
          <i class="fas fa-search"></i> Investigate
        </button>
        <button class="p19-btn p19-btn--orange p19-btn--sm" onclick="window._dwCreateAlert('${_e(item.id)}')">
          <i class="fas fa-bell"></i> Create Alert
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._dwExportItem('${_e(item.id)}')">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>`;
  }

  else if (dataType === 'ransomware') {
    item = DW_DATA.ransomware.find(x=>x.group===id);
    if (!item) return;
    html = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--p19-border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--p19-bg-card);z-index:1">
      <div style="font-size:.86em;font-weight:700;color:var(--p19-t1)">Ransomware Group Profile</div>
      <button class="p19-btn p19-btn--ghost p19-btn--icon-only" onclick="window._dwClosDetail()"><i class="fas fa-times"></i></button>
    </div>
    <div style="padding:20px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">
        <div style="width:44px;height:44px;border-radius:10px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);display:flex;align-items:center;justify-content:center">
          <i class="fas fa-lock" style="color:var(--p19-red)"></i>
        </div>
        <div>
          <h3 style="font-size:1em;font-weight:700;color:var(--p19-t1);margin:0">${_e(item.group)}</h3>
          <div style="font-size:.76em;color:var(--p19-t3)">${_e(item.country)} · ${item.status}</div>
        </div>
        ${_sevBadge(item.threat_level)}
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.6em;font-weight:800;color:var(--p19-red);font-family:'JetBrains Mono',monospace">${item.victims}</div>
          <div style="font-size:.7em;color:var(--p19-t4)">Total Victims</div>
        </div>
        <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.1em;font-weight:800;color:var(--p19-yellow);font-family:'JetBrains Mono',monospace">${_e(item.avg_ransom)}</div>
          <div style="font-size:.7em;color:var(--p19-t4)">Avg Ransom</div>
        </div>
        <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:1.4em;font-weight:800;color:var(--p19-orange);font-family:'JetBrains Mono',monospace">${item.pay_rate}%</div>
          <div style="font-size:.7em;color:var(--p19-t4)">Payment Rate</div>
        </div>
        <div style="background:rgba(0,0,0,.25);border-radius:8px;padding:12px;text-align:center">
          <div style="font-size:.84em;font-weight:700;color:var(--p19-t1)">${_ago(item.latest_date)}</div>
          <div style="font-size:.7em;color:var(--p19-t4)">Last Activity</div>
        </div>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:6px;text-transform:uppercase">Target Sectors</div>
        <div class="p19-tags">${(item.sectors||[]).map(s=>`<span class="p19-tag">${_e(s)}</span>`).join('')}</div>
      </div>

      ${item.ttps?.length ? `
      <div style="margin-bottom:14px">
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:6px;text-transform:uppercase">MITRE ATT&CK TTPs</div>
        <div class="p19-tags">${item.ttps.map(t=>`<a href="https://attack.mitre.org/techniques/${t}" target="_blank" class="p19-tag" style="color:var(--p19-cyan);text-decoration:none">${_e(t)}</a>`).join('')}</div>
      </div>` : ''}

      <div style="margin-bottom:14px">
        <div style="font-size:.72em;color:var(--p19-t4);margin-bottom:4px;text-transform:uppercase">Latest Victim</div>
        <div style="font-size:.86em;font-weight:600;color:var(--p19-t1)">${_e(item.latest_victim)}</div>
      </div>

      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="p19-btn p19-btn--red p19-btn--sm" onclick="window._dwTrackGroup('${_e(item.group)}')">
          <i class="fas fa-crosshairs"></i> Track Group
        </button>
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._dwExportItem('${_e(item.group)}')">
          <i class="fas fa-download"></i> Export
        </button>
      </div>
    </div>`;
  }

  else {
    // Generic detail for forums/onion/credentials
    html = `
    <div style="padding:18px 20px;border-bottom:1px solid var(--p19-border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--p19-bg-card);z-index:1">
      <div style="font-size:.86em;font-weight:700;color:var(--p19-t1)">Detail View</div>
      <button class="p19-btn p19-btn--ghost p19-btn--icon-only" onclick="window._dwClosDetail()"><i class="fas fa-times"></i></button>
    </div>
    <div style="padding:20px">
      ${_dwGenericDetail(id, dataType)}
    </div>`;
  }

  inner.innerHTML = html;
  panel.classList.add('open');
  if (overlay) { overlay.style.display='block'; }
};

function _dwGenericDetail(id, dataType) {
  if (dataType === 'forums') {
    const item = DW_DATA.forums.find(x=>x.id===id);
    if (!item) return '<p style="color:var(--p19-t3)">Item not found</p>';
    return `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="p19-badge p19-badge--info">${_e(item.forum)}</span>
        <span class="p19-badge p19-badge--gray">${_e(item.category)}</span>
        ${_sevBadge(item.threat_level)}
      </div>
      <h3 style="font-size:.95em;font-weight:700;color:var(--p19-t1);margin:0 0 12px">${_e(item.title)}</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.8em">
        <div><span style="color:var(--p19-t4)">Author:</span> <strong style="color:var(--p19-t1)">${_e(item.author)}</strong></div>
        <div><span style="color:var(--p19-t4)">Posted:</span> <strong style="color:var(--p19-t1)">${_ago(item.posted)}</strong></div>
        <div><span style="color:var(--p19-t4)">Replies:</span> <strong style="color:var(--p19-t1)">${item.replies}</strong></div>
        <div><span style="color:var(--p19-t4)">Views:</span> <strong style="color:var(--p19-t1)">${item.views}</strong></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._dwInvestigate('${_e(id)}')"><i class="fas fa-search"></i> Investigate</button>
      </div>`;
  }
  if (dataType === 'onion') {
    const item = DW_DATA.onion.find(x=>x.id===id);
    if (!item) return '';
    return `
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span class="p19-status p19-status--${item.status==='ONLINE'?'online':'offline'}">${item.status}</span>
        <span class="p19-badge p19-badge--gray">${_e(item.category)}</span>
        ${_riskBadge(item.risk)}
      </div>
      <h3 style="font-size:.95em;font-weight:700;color:var(--p19-t1);margin:0 0 8px">${_e(item.tor_title)}</h3>
      <div class="dw-onion-url" style="margin-bottom:10px;word-break:break-all">${_e(item.url)}</div>
      <p style="font-size:.83em;color:var(--p19-t2);line-height:1.6;margin:0 0 12px">${_e(item.description)}</p>
      <div style="font-size:.78em;color:var(--p19-t4)">Last checked: ${_ago(item.last_check)}</div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="p19-btn p19-btn--ghost p19-btn--sm" onclick="window._dwCopyOnion('${_e(item.url)}')">
          <i class="fas fa-copy"></i> Copy URL
        </button>
      </div>`;
  }
  if (dataType === 'credentials') {
    const item = DW_DATA.credentials.find(x=>x.id===id);
    if (!item) return '';
    return `
      <h3 style="font-size:.95em;font-weight:700;color:var(--p19-t1);margin:0 0 12px">${_e(item.source)}</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.82em;margin-bottom:14px">
        <div style="background:rgba(0,0,0,.2);border-radius:6px;padding:10px">
          <div style="color:var(--p19-t4);font-size:.85em">COUNT</div>
          <div style="font-weight:700;color:var(--p19-cyan);font-family:'JetBrains Mono',monospace">${_e(item.count)}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:6px;padding:10px">
          <div style="color:var(--p19-t4);font-size:.85em">PRICE</div>
          <div class="dw-price">${_e(item.price)}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:6px;padding:10px">
          <div style="color:var(--p19-t4);font-size:.85em">TYPE</div>
          <div style="color:var(--p19-t1)">${_e(item.type)}</div>
        </div>
        <div style="background:rgba(0,0,0,.2);border-radius:6px;padding:10px">
          <div style="color:var(--p19-t4);font-size:.85em">FORMAT</div>
          <div style="color:var(--p19-t1)">${_e(item.format)}</div>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="p19-btn p19-btn--primary p19-btn--sm" onclick="window._dwInvestigate('${_e(id)}')"><i class="fas fa-search"></i> Investigate</button>
      </div>`;
  }
  return '';
}

window._dwClosDetail = function() {
  const panel = document.getElementById('dw-detail-panel');
  const overlay = document.getElementById('dw-overlay');
  if (panel) panel.classList.remove('open');
  if (overlay) overlay.style.display = 'none';
};

/* ═══════════════════════════════════════════════════════
   ACTION HANDLERS
═══════════════════════════════════════════════════════ */
window._dwRefresh = function() {
  _toast('Refreshing dark web intelligence feeds…', 'info');
  _dwTab(_DW.tab);
};

window._dwExport = function() {
  const data = { exported_at: new Date().toISOString(), tab: _DW.tab, data: DW_DATA[_DW.tab] };
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `dark-web-${_DW.tab}-${Date.now()}.json`;
  a.click();
  _toast('Dark web intelligence exported', 'success');
};

window._dwAlert = function() {
  _toast('Alert configuration saved — monitoring active', 'success');
};

window._dwInvestigate = function(id) {
  _toast(`Launching AI investigation for ${id}…`, 'info');
  _dwClosDetail();
};

window._dwCreateAlert = function(id) {
  _toast(`Alert set for listing ${id}`, 'success');
};

window._dwExportItem = function(id) {
  _toast(`Exporting ${id} to report…`, 'info');
};

window._dwTrackGroup = function(group) {
  _toast(`Now tracking ${group} — alerts enabled`, 'success');
};

window._dwCopyOnion = function(url) {
  navigator.clipboard?.writeText(url).then(()=>_toast('URL copied to clipboard', 'success'))
    .catch(()=>_toast('Copy failed — use Ctrl+C', 'warning'));
};

/* ═══════════════════════════════════════════════════════
   KPI ANIMATION
═══════════════════════════════════════════════════════ */
function _dwAnimateKPIs() {
  document.querySelectorAll('.p19-kpi-value').forEach(el => {
    const final = parseInt(el.textContent) || 0;
    if (final === 0) return;
    let start = 0;
    const step = Math.ceil(final / 20);
    const timer = setInterval(() => {
      start = Math.min(start + step, final);
      el.textContent = start;
      if (start >= final) clearInterval(timer);
    }, 40);
  });
}

})(); // end IIFE
