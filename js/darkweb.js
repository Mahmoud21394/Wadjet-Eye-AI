/**
 * ══════════════════════════════════════════════════════════
 *  EYEbot AI — Dark Web Intelligence Module v4.0
 *  High-fidelity hacker-style GUI with active tabs
 *  Tabs: Marketplace | Ransomware | Credentials | Forums | Onion Monitor
 * ══════════════════════════════════════════════════════════
 */
'use strict';

/* ── Synthetic dark web data (rich set for demo / offline mode) ── */
const _DW_DATA = {
  marketplace: [
    { id:'dw-001', title:'RaaS Kit — LockBit 4.0 Builder', type:'Ransomware Listing', severity:'CRITICAL', price:'$5,000', seller:'0x_phantom', tor:'http://lockbit4a3ebjnt4.onion', tags:['ransomware','builder','affiliate'], posted:'2025-01-15T08:30:00Z', views:1847, rating:4.8, description:'Full LockBit 4.0 ransomware builder with affiliate panel, Tor C2, and automated victim negotiation portal. Includes source code and 12-month support.' },
    { id:'dw-002', title:'0-Day: Microsoft Exchange RCE (CVE-2025-XXXX)', type:'Exploit Sale', severity:'CRITICAL', price:'$45,000', seller:'exploit_market', tor:'http://exploit1a2b3c4d.onion', tags:['0day','exchange','RCE'], posted:'2025-02-03T14:22:00Z', views:3291, rating:4.9, description:'Unauthenticated remote code execution in Exchange Server 2019-2024. Full chain exploit with SYSTEM privileges. Tested against patched instances.' },
    { id:'dw-003', title:'Credential Dump: Fortune 500 (87,000 accounts)', type:'Credential Dump', severity:'HIGH', price:'$1,200', seller:'breach_lord', tor:'http://credentials7x8y.onion', tags:['credentials','breach','corporate'], posted:'2025-01-28T11:15:00Z', views:5621, rating:4.2, description:'Fresh credential dump from major financial institution breach. Includes email, password (plaintext + hash), MFA seeds. Verified 73% valid rate.' },
    { id:'dw-004', title:'APT Access Broker: Telecom Network VPN', type:'Initial Access', severity:'CRITICAL', price:'$12,000', seller:'access_broker_ru', tor:'http://iabroker9x2y.onion', tags:['access-broker','VPN','telecom'], posted:'2025-02-08T09:00:00Z', views:892, rating:4.7, description:'Active administrator access to major European telecom provider. Includes DC access, 450k employee records, billing database credentials.' },
    { id:'dw-005', title:'Malware-as-a-Service: AsyncRAT v4', type:'MaaS', severity:'HIGH', price:'$800/mo', seller:'asyncrat_dev', tor:'http://asyncrat1b2c3d.onion', tags:['RAT','MaaS','C2'], posted:'2025-01-20T16:45:00Z', views:2134, rating:4.5, description:'Fully managed AsyncRAT infrastructure. Includes builder, C2 server, obfuscator, and 24/7 support. Used in 200+ active campaigns.' },
    { id:'dw-006', title:'Data Breach: Healthcare Chain (2.1M patients)', type:'Data Breach', severity:'CRITICAL', price:'$8,500', seller:'medithreat', tor:'http://meddata3x9y1z.onion', tags:['healthcare','PII','PHI'], posted:'2025-02-01T07:30:00Z', views:4102, rating:4.6, description:'Patient records from 48-hospital chain: SSN, DOB, insurance, prescription history. Includes internal network diagrams and admin credentials.' },
    { id:'dw-007', title:'Phishing Kit — Microsoft 365 Advanced', type:'Phishing Kit', severity:'MEDIUM', price:'$350', seller:'kit_master', tor:'http://phishkit8a1b.onion', tags:['phishing','M365','AiTM'], posted:'2025-01-10T13:00:00Z', views:8934, rating:4.1, description:'Adversary-in-The-Middle phishing kit for M365. Bypasses MFA. Includes EvilProxy-style reverse proxy, CAPTCHA bypass, and geofencing.' },
    { id:'dw-008', title:'Botnet Access: 50,000 Corporate Endpoints', type:'Botnet', severity:'HIGH', price:'$25,000', seller:'botmaster_x', tor:'http://botnet1x2y3z4a.onion', tags:['botnet','corporate','endpoints'], posted:'2025-02-05T10:20:00Z', views:1203, rating:4.4, description:'Curated botnet of 50k compromised corporate workstations across 40 countries. Filtered for Fortune 1000 companies. Delivered via PowerShell loader.' },
  ],
  ransomware: [
    { group:'LockBit 4.0', victims:47, status:'ACTIVE', country:'Russia', sector_targets:['Healthcare','Finance','Government'], latest_victim:'Meridian Healthcare Group', latest_date:'2025-02-10T00:00:00Z', threat_level:'CRITICAL', onion:'http://lockbitvictimsite.onion', negotiation_avg:'$2.1M', payment_rate:'34%' },
    { group:'BlackCat/ALPHV', victims:31, status:'ACTIVE', country:'Unknown', sector_targets:['Energy','Manufacturing','Legal'], latest_victim:'Atlas Energy Corp', latest_date:'2025-02-08T00:00:00Z', threat_level:'CRITICAL', onion:'http://blackcat3victims.onion', negotiation_avg:'$4.8M', payment_rate:'29%' },
    { group:'Clop', victims:89, status:'ACTIVE', country:'Russia', sector_targets:['Finance','Technology','Retail'], latest_victim:'DataVault Financial', latest_date:'2025-02-09T00:00:00Z', threat_level:'CRITICAL', onion:'http://clopvictims1.onion', negotiation_avg:'$1.5M', payment_rate:'41%' },
    { group:'Royal Ransomware', victims:22, status:'ACTIVE', country:'Unknown', sector_targets:['Healthcare','Education','Transport'], latest_victim:'NorthStar University', latest_date:'2025-02-06T00:00:00Z', threat_level:'HIGH', onion:'http://royalvictims2.onion', negotiation_avg:'$3.2M', payment_rate:'25%' },
    { group:'Play', victims:18, status:'ACTIVE', country:'Unknown', sector_targets:['Government','Manufacturing','Legal'], latest_victim:'City of Riverside', latest_date:'2025-02-07T00:00:00Z', threat_level:'HIGH', onion:'http://playransomsite.onion', negotiation_avg:'$850K', payment_rate:'38%' },
    { group:'Medusa', victims:14, status:'ACTIVE', country:'Unknown', sector_targets:['Healthcare','Education'], latest_victim:'Memorial Medical', latest_date:'2025-02-04T00:00:00Z', threat_level:'HIGH', onion:'http://medusaransomware.onion', negotiation_avg:'$1.2M', payment_rate:'31%' },
    { group:'8Base', victims:28, status:'ACTIVE', country:'Unknown', sector_targets:['Finance','Retail','SMB'], latest_victim:'Apex Financial Group', latest_date:'2025-01-31T00:00:00Z', threat_level:'HIGH', onion:'http://8baseleaksite.onion', negotiation_avg:'$650K', payment_rate:'44%' },
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
    { id:'on-001', url:'http://lockbit4a3ebjnt.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'LockBit 4.0 victim portal and affiliate dashboard', tor_title:'LockBit 4.0 — Professional Ransomware Service' },
    { id:'on-002', url:'http://alphvmmm27o3abo.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T06:00:00Z', risk:'CRITICAL', description:'BlackCat/ALPHV ransomware victim and data leak site', tor_title:'ALPHV BlackCat — Data Exposure' },
    { id:'on-003', url:'http://breach3rdampfkgn.onion', category:'Data Market', status:'ONLINE', last_check:'2025-02-10T05:30:00Z', risk:'HIGH', description:'Active dark web marketplace for stolen data', tor_title:'BreachBase — Premium Data Exchange' },
    { id:'on-004', url:'http://exploit3xrg4abd.onion', category:'Exploit Shop', status:'ONLINE', last_check:'2025-02-10T04:15:00Z', risk:'CRITICAL', description:'Zero-day and N-day exploit broker', tor_title:'ExploitHub — Premier 0day Market' },
    { id:'on-005', url:'http://clopvictims1abc.onion', category:'Leak Site', status:'ONLINE', last_check:'2025-02-10T03:50:00Z', risk:'CRITICAL', description:'Clop ransomware group victim publication site', tor_title:'CL0P^_- LEAKS' },
    { id:'on-006', url:'http://dreadditevelidot.onion', category:'Darknet Forum', status:'OFFLINE', last_check:'2025-02-09T22:00:00Z', risk:'MEDIUM', description:'Major darknet forum — currently down for maintenance', tor_title:'Dread — The Reddit of Dark Web' },
    { id:'on-007', url:'http://ransomhouse7xhq.onion', category:'RaaS Portal', status:'ONLINE', last_check:'2025-02-10T05:00:00Z', risk:'HIGH', description:'RansomHouse victim portal and leak site', tor_title:'RansomHouse Operations' },
    { id:'on-008', url:'http://kelvinsecleakq2s.onion', category:'APT Site', status:'ONLINE', last_check:'2025-02-10T04:30:00Z', risk:'CRITICAL', description:'Kelvin Security APT data publication site', tor_title:'KelvinSec — Intelligence Leaks' },
  ]
};

/* ── Active tab state ── */
let _dwTab = 'marketplace';
let _dwFilter = { sev: '', type: '', search: '' };

/* ── Main renderer ── */
window.renderDarkWeb = function renderDarkWeb() {
  const c = document.getElementById('page-dark-web');
  if (!c) return;

  c.innerHTML = `
  <!-- Dark Web Header -->
  <div style="background:linear-gradient(135deg,#0a0a0f 0%,#0d0d1a 50%,#080c14 100%);
    border-bottom:1px solid #1a1a2e;padding:20px 24px;margin:-4px -16px 0;position:relative;overflow:hidden">
    <!-- Scanline effect -->
    <div style="position:absolute;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,.015) 2px,rgba(0,255,65,.015) 4px);pointer-events:none"></div>
    <!-- Glow -->
    <div style="position:absolute;top:-40px;left:20%;width:300px;height:120px;background:rgba(255,0,80,.05);border-radius:50%;filter:blur(40px);pointer-events:none"></div>
    <div style="position:absolute;top:-40px;right:20%;width:200px;height:100px;background:rgba(0,200,255,.04);border-radius:50%;filter:blur(40px);pointer-events:none"></div>

    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;position:relative">
      <div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <div style="width:38px;height:38px;background:#ff004428;border:1px solid #ff004455;border-radius:8px;
            display:flex;align-items:center;justify-content:center;color:#ff0044;font-size:1em">
            <i class="fas fa-spider"></i></div>
          <div>
            <div style="font-size:1em;font-weight:800;color:#00ff41;font-family:monospace;letter-spacing:.04em">
              DARK WEB INTELLIGENCE MONITOR
            </div>
            <div style="font-size:.72em;color:#666;font-family:monospace;margin-top:2px">
              <span style="color:#ff0044">●</span> LIVE · Tor Network Crawler · 
              <span style="color:#00ff41">${_DW_DATA.onion.filter(o=>o.status==='ONLINE').length} onions online</span> · 
              <span style="color:#888">Updated: ${new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </div>
      </div>
      <!-- Stats strip -->
      <div style="display:flex;gap:12px;flex-wrap:wrap">
        ${[
          {label:'Marketplace Listings',val:_DW_DATA.marketplace.length,c:'#ff4444'},
          {label:'Active RaaS Groups',val:_DW_DATA.ransomware.filter(r=>r.status==='ACTIVE').length,c:'#ff8800'},
          {label:'Credential Dumps',val:_DW_DATA.credentials.length,c:'#ffcc00'},
          {label:'Onion Sites Live',val:_DW_DATA.onion.filter(o=>o.status==='ONLINE').length,c:'#00ff41'},
        ].map(s=>`
        <div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:8px;padding:8px 12px;text-align:center">
          <div style="font-size:1.2em;font-weight:700;color:${s.c};font-family:monospace">${s.val}</div>
          <div style="font-size:.65em;color:#666;white-space:nowrap">${s.label}</div>
        </div>`).join('')}
      </div>
    </div>
  </div>

  <!-- Tab Bar -->
  <div style="display:flex;gap:0;border-bottom:1px solid #1a1a2e;background:#050810;padding:0 16px;overflow-x:auto;scrollbar-width:none">
    ${[
      {id:'marketplace',icon:'fa-store-alt',label:'Marketplace',count:_DW_DATA.marketplace.length,col:'#ff4444'},
      {id:'ransomware',icon:'fa-skull-crossbones',label:'Ransomware',count:_DW_DATA.ransomware.length,col:'#ff8800'},
      {id:'credentials',icon:'fa-key',label:'Credentials',count:_DW_DATA.credentials.length,col:'#ffcc00'},
      {id:'forums',icon:'fa-comments',label:'Forums',count:_DW_DATA.forums.length,col:'#8b5cf6'},
      {id:'onion',icon:'fa-globe',label:'Onion Monitor',count:_DW_DATA.onion.length,col:'#00ff41'},
    ].map(t=>`
    <button id="dwtab-${t.id}" onclick="_dwSetTab('${t.id}')"
      style="padding:10px 18px;background:${_dwTab===t.id?'rgba(255,255,255,.05)':'transparent'};
        border:none;border-bottom:2px solid ${_dwTab===t.id?t.col:'transparent'};
        color:${_dwTab===t.id?t.col:'#555'};font-size:.8em;cursor:pointer;white-space:nowrap;
        display:flex;align-items:center;gap:6px;transition:all .2s;font-family:inherit"
      onmouseover="if('${t.id}'!=='${_dwTab}')this.style.color='#999'"
      onmouseout="if('${t.id}'!=='${_dwTab}')this.style.color='#555'">
      <i class="fas ${t.icon}"></i>${t.label}
      <span style="background:${t.col}22;color:${t.col};border:1px solid ${t.col}44;
        padding:0 5px;border-radius:8px;font-size:.8em;font-weight:700">${t.count}</span>
    </button>`).join('')}
  </div>

  <!-- Tab Content -->
  <div id="dw-tab-content" style="padding:16px 0;min-height:400px"></div>
  `;

  _dwRenderTab(_dwTab);
};

window._dwSetTab = function(tab) {
  _dwTab = tab;
  // Update tab styles
  const tabColors = {marketplace:'#ff4444',ransomware:'#ff8800',credentials:'#ffcc00',forums:'#8b5cf6',onion:'#00ff41'};
  ['marketplace','ransomware','credentials','forums','onion'].forEach(t => {
    const btn = document.getElementById(`dwtab-${t}`);
    if (!btn) return;
    if (t === tab) {
      btn.style.borderBottomColor = tabColors[t];
      btn.style.color = tabColors[t];
      btn.style.background = 'rgba(255,255,255,.05)';
    } else {
      btn.style.borderBottomColor = 'transparent';
      btn.style.color = '#555';
      btn.style.background = 'transparent';
    }
  });
  _dwRenderTab(tab);
};

function _dwRenderTab(tab) {
  const c = document.getElementById('dw-tab-content');
  if (!c) return;
  switch(tab) {
    case 'marketplace':  c.innerHTML = _dwRenderMarketplace(); break;
    case 'ransomware':   c.innerHTML = _dwRenderRansomware(); break;
    case 'credentials':  c.innerHTML = _dwRenderCredentials(); break;
    case 'forums':       c.innerHTML = _dwRenderForums(); break;
    case 'onion':        c.innerHTML = _dwRenderOnion(); break;
  }
}

function _dwSevColor(sev) {
  return {CRITICAL:'#ff0044',HIGH:'#ff6600',MEDIUM:'#ffcc00',LOW:'#00cc44'}[sev] || '#666';
}
function _dwBadge(label, color) {
  return `<span style="background:${color}18;color:${color};border:1px solid ${color}33;padding:1px 8px;border-radius:10px;font-size:.68em;font-weight:700;font-family:monospace">${label}</span>`;
}
function _dwAgo(iso) {
  if (!iso) return 'Unknown';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function _dwRenderMarketplace() {
  const items = _DW_DATA.marketplace;
  return `
  <!-- Search Bar -->
  <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px">
    <div style="position:relative;flex:1;min-width:200px">
      <i class="fas fa-search" style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:#444;font-size:.8em"></i>
      <input placeholder="Search marketplace listings…" oninput="_dwSearchMarket(this.value)"
        style="width:100%;background:#080c14;border:1px solid #1a1a2e;color:#ccc;padding:7px 10px 7px 30px;
          border-radius:6px;font-size:.82em;font-family:monospace;box-sizing:border-box"/>
    </div>
    <select onchange="_dwFilterSev(this.value)" style="background:#080c14;border:1px solid #1a1a2e;color:#888;padding:7px 10px;border-radius:6px;font-size:.82em;font-family:monospace">
      <option value="">All Threat Levels</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
    </select>
    <select onchange="_dwFilterType(this.value)" style="background:#080c14;border:1px solid #1a1a2e;color:#888;padding:7px 10px;border-radius:6px;font-size:.82em;font-family:monospace">
      <option value="">All Types</option>
      <option value="Ransomware Listing">Ransomware</option>
      <option value="Exploit Sale">Exploit Sale</option>
      <option value="Credential Dump">Credentials</option>
      <option value="Data Breach">Data Breach</option>
      <option value="Initial Access">Access Broker</option>
    </select>
    <span style="font-size:.75em;color:#444;font-family:monospace">${items.length} listings</span>
  </div>

  <div id="dw-market-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:12px">
    ${items.map(item => `
    <div style="background:linear-gradient(135deg,#080c14,#0a0f1a);border:1px solid #1a1a2e;border-radius:10px;
      padding:16px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden"
      onmouseover="this.style.borderColor='${_dwSevColor(item.severity)}44';this.style.background='linear-gradient(135deg,#0d1117,#0f1420)'"
      onmouseout="this.style.borderColor='#1a1a2e';this.style.background='linear-gradient(135deg,#080c14,#0a0f1a)'"
      onclick="_dwOpenDetail('${item.id}')">
      <!-- Severity stripe -->
      <div style="position:absolute;top:0;left:0;right:0;height:2px;background:${_dwSevColor(item.severity)}"></div>
      <!-- Scanline overlay -->
      <div style="position:absolute;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(255,255,255,.006) 3px,rgba(255,255,255,.006) 6px);pointer-events:none"></div>

      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
        <div style="flex:1">
          <div style="font-size:.88em;font-weight:700;color:#ddd;line-height:1.3;margin-bottom:6px">${item.title}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">
            ${_dwBadge(item.type, _dwSevColor(item.severity))}
            ${_dwBadge(item.severity, _dwSevColor(item.severity))}
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div style="font-size:1em;font-weight:800;color:#00ff41;font-family:monospace">${item.price}</div>
          <div style="font-size:.65em;color:#444;font-family:monospace">★ ${item.rating}</div>
        </div>
      </div>

      <div style="font-size:.75em;color:#666;line-height:1.5;margin-bottom:10px;
        overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">
        ${item.description}
      </div>

      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${(item.tags||[]).map(t=>`<span style="background:#ffffff08;color:#555;border:1px solid #222;padding:1px 6px;border-radius:4px;font-size:.65em;font-family:monospace">#${t}</span>`).join('')}
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;font-size:.7em;color:#444;font-family:monospace;border-top:1px solid #111;padding-top:8px">
        <span><i class="fas fa-user" style="margin-right:3px;color:#333"></i>${item.seller}</span>
        <span><i class="fas fa-eye" style="margin-right:3px;color:#333"></i>${item.views.toLocaleString()}</span>
        <span>${_dwAgo(item.posted)}</span>
      </div>
    </div>`).join('')}
  </div>`;
}

function _dwRenderRansomware() {
  const groups = _DW_DATA.ransomware;
  const totalVictims = groups.reduce((a,g) => a + g.victims, 0);
  return `
  <!-- RaaS Header -->
  <div style="background:#ff000008;border:1px solid #ff000022;border-radius:10px;padding:14px;margin-bottom:16px;
    display:flex;align-items:center;gap:12px">
    <div style="width:36px;height:36px;background:#ff000018;border:1px solid #ff000044;border-radius:8px;
      display:flex;align-items:center;justify-content:center;color:#ff0044;font-size:1em;flex-shrink:0">
      <i class="fas fa-exclamation-triangle"></i></div>
    <div>
      <div style="font-size:.82em;font-weight:700;color:#ff4444">RANSOMWARE THREAT LANDSCAPE — ACTIVE MONITORING</div>
      <div style="font-size:.72em;color:#666;font-family:monospace">
        ${groups.filter(g=>g.status==='ACTIVE').length} active groups · ${totalVictims} total victims tracked · Data sourced from leak sites and threat intel feeds
      </div>
    </div>
  </div>

  <!-- KPI Strip -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px;margin-bottom:16px">
    ${[
      {label:'Active Groups',val:groups.filter(g=>g.status==='ACTIVE').length,c:'#ff0044'},
      {label:'Total Victims',val:totalVictims,c:'#ff8800'},
      {label:'Avg Ransom',val:'$2.1M',c:'#ffcc00'},
      {label:'Payment Rate',val:'35%',c:'#22c55e'},
    ].map(k=>`
    <div style="background:#080c14;border:1px solid #1a1a2e;border-radius:8px;padding:12px;text-align:center">
      <div style="font-size:1.3em;font-weight:800;color:${k.c};font-family:monospace">${k.val}</div>
      <div style="font-size:.65em;color:#555;margin-top:2px">${k.label}</div>
    </div>`).join('')}
  </div>

  <!-- Groups Table -->
  <div style="overflow-x:auto;background:#080c14;border:1px solid #1a1a2e;border-radius:10px">
    <table style="width:100%;border-collapse:collapse;font-size:.8em;font-family:monospace">
      <thead>
        <tr style="border-bottom:1px solid #1a1a2e;background:#050810">
          ${['GROUP','STATUS','VICTIMS','LATEST TARGET','NATION','SECTORS','AVG RANSOM','PAY RATE','ONION'].map(h=>
            `<th style="padding:10px 14px;color:#444;font-weight:600;text-align:left;white-space:nowrap">${h}</th>`
          ).join('')}
        </tr>
      </thead>
      <tbody>
        ${groups.map(g => `
        <tr style="border-bottom:1px solid #0d0d1a;cursor:pointer" 
          onmouseover="this.style.background='#0d1020'" onmouseout="this.style.background=''">
          <td style="padding:12px 14px">
            <div style="font-weight:700;color:#ff4444">${g.group}</div>
          </td>
          <td style="padding:12px 14px">
            <span style="background:${g.status==='ACTIVE'?'#ff000018':'#22222218'};color:${g.status==='ACTIVE'?'#ff0044':'#666'};
              border:1px solid ${g.status==='ACTIVE'?'#ff000044':'#333'};padding:2px 8px;border-radius:4px;font-size:.85em">
              ${g.status==='ACTIVE'?'⚡ ACTIVE':'DORMANT'}
            </span>
          </td>
          <td style="padding:12px 14px;color:#ff8800;font-weight:700">${g.victims}</td>
          <td style="padding:12px 14px;color:#ccc;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${g.latest_victim}">${g.latest_victim}</td>
          <td style="padding:12px 14px;color:#888">${g.country}</td>
          <td style="padding:12px 14px">
            <div style="display:flex;flex-wrap:wrap;gap:3px">
              ${g.sector_targets.slice(0,2).map(s=>`<span style="background:#ffffff08;color:#666;border:1px solid #222;padding:1px 5px;border-radius:3px;font-size:.8em">${s}</span>`).join('')}
            </div>
          </td>
          <td style="padding:12px 14px;color:#00ff41;font-weight:700">${g.negotiation_avg}</td>
          <td style="padding:12px 14px;color:#ffcc00">${g.payment_rate}</td>
          <td style="padding:12px 14px">
            <button onclick="if(window.showToast)showToast('Onion site monitored — access blocked for safety','warning')" 
              style="background:#ff000018;color:#ff4444;border:1px solid #ff000033;padding:2px 8px;border-radius:4px;font-size:.75em;cursor:pointer">
              <i class="fas fa-spider" style="margin-right:3px"></i>Monitor
            </button>
          </td>
        </tr>`).join('')}
      </tbody>
    </table>
  </div>`;
}

function _dwRenderCredentials() {
  return `
  <!-- Warning Banner -->
  <div style="background:#ffcc0008;border:1px solid #ffcc0022;border-radius:8px;padding:12px 14px;margin-bottom:14px;
    display:flex;align-items:center;gap:10px;font-size:.78em">
    <i class="fas fa-exclamation-triangle" style="color:#ffcc00;flex-shrink:0"></i>
    <span style="color:#888">This intelligence is collected for <strong style="color:#ccc">defensive monitoring purposes only</strong>. 
    Credential data is hashed and not stored. Use for breach notification and account protection.</span>
  </div>

  <!-- Credential Dumps Grid -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px">
    ${_DW_DATA.credentials.map(cr => `
    <div style="background:#080c14;border:1px solid ${cr.verified?'#ffcc0022':'#1a1a2e'};border-radius:10px;padding:16px;
      position:relative;overflow:hidden">
      ${cr.verified?`<div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#ffcc00,#ff8800)"></div>`:''}
      
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
        <div>
          <div style="font-size:.85em;font-weight:700;color:#ddd;margin-bottom:5px">${cr.source}</div>
          <span style="background:${cr.freshness.includes('VERY')?'#00ff4118':'#ffffff08'};
            color:${cr.freshness.includes('VERY')?'#00ff41':'#666'};
            border:1px solid ${cr.freshness.includes('VERY')?'#00ff4133':'#222'};
            padding:1px 7px;border-radius:4px;font-size:.68em;font-family:monospace">● ${cr.freshness}</span>
        </div>
        <div style="text-align:right">
          <div style="font-size:.95em;font-weight:800;color:#00ff41;font-family:monospace">${cr.price}</div>
          ${cr.verified?`<div style="font-size:.65em;color:#22c55e"><i class="fas fa-check-circle" style="margin-right:2px"></i>Verified</div>`:''}
        </div>
      </div>
      
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:.75em;font-family:monospace;margin-bottom:10px">
        <div style="background:#0a0f1a;border:1px solid #111;border-radius:5px;padding:7px">
          <div style="color:#444;font-size:.85em">COUNT</div>
          <div style="color:#ff8800;font-weight:700">${cr.count}</div>
        </div>
        <div style="background:#0a0f1a;border:1px solid #111;border-radius:5px;padding:7px">
          <div style="color:#444;font-size:.85em">FORMAT</div>
          <div style="color:#ccc;font-weight:600">${cr.format}</div>
        </div>
        <div style="background:#0a0f1a;border:1px solid #111;border-radius:5px;padding:7px">
          <div style="color:#444;font-size:.85em">TYPE</div>
          <div style="color:#8b5cf6;font-size:.9em">${cr.type.split('+')[0].trim()}</div>
        </div>
        <div style="background:#0a0f1a;border:1px solid #111;border-radius:5px;padding:7px">
          <div style="color:#444;font-size:.85em">DATE</div>
          <div style="color:#888">${cr.date}</div>
        </div>
      </div>
      
      <div style="font-size:.7em;color:#666;font-family:monospace;margin-bottom:10px">
        TYPE: ${cr.type}
      </div>
      
      <div style="display:flex;gap:6px">
        <button onclick="if(window.showToast)showToast('Monitoring active for this credential set','info')"
          style="flex:1;background:#ffffff08;color:#888;border:1px solid #222;padding:5px;border-radius:5px;font-size:.72em;cursor:pointer">
          <i class="fas fa-eye" style="margin-right:3px"></i>Monitor
        </button>
        <button onclick="if(window.showToast)showToast('Breach check initiated — checking against your domain','info')"
          style="flex:1;background:#ffcc0010;color:#ffcc00;border:1px solid #ffcc0033;padding:5px;border-radius:5px;font-size:.72em;cursor:pointer">
          <i class="fas fa-shield-alt" style="margin-right:3px"></i>Check Exposure
        </button>
      </div>
    </div>`).join('')}
  </div>`;
}

function _dwRenderForums() {
  return `
  <!-- Forum Activity -->
  <div style="margin-bottom:14px">
    <div style="font-size:.78em;color:#555;font-family:monospace;margin-bottom:10px">
      <i class="fas fa-comments" style="color:#8b5cf6;margin-right:6px"></i>
      MONITORED DARKNET FORUMS — ${_DW_DATA.forums.length} active threads · Sorted by threat level
    </div>
  </div>

  <div style="display:flex;flex-direction:column;gap:8px">
    ${_DW_DATA.forums.map(f => {
      const tc = {CRITICAL:'#ff0044',HIGH:'#ff6600',MEDIUM:'#ffcc00',LOW:'#22c55e'}[f.threat_level]||'#666';
      return `
    <div style="background:#080c14;border:1px solid #1a1a2e;border-radius:8px;padding:14px;cursor:pointer;
      transition:all .2s;position:relative;overflow:hidden"
      onmouseover="this.style.borderColor='${tc}33';this.style.background='#0d1020'"
      onmouseout="this.style.borderColor='#1a1a2e';this.style.background='#080c14'">
      <!-- Threat stripe -->
      <div style="position:absolute;left:0;top:0;bottom:0;width:3px;background:${tc}"></div>
      
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding-left:8px">
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;flex-wrap:wrap">
            <span style="background:#ffffff08;color:#666;border:1px solid #222;padding:1px 7px;border-radius:4px;font-size:.68em;font-family:monospace">
              <i class="fas fa-globe-americas" style="margin-right:3px;color:#555"></i>${f.forum}
            </span>
            <span style="background:#ffffff06;color:#555;padding:1px 7px;border-radius:4px;font-size:.68em;font-family:monospace">${f.category}</span>
            ${f.threat_level==='CRITICAL'?`<span style="background:#ff000018;color:#ff0044;border:1px solid #ff000033;padding:1px 7px;border-radius:4px;font-size:.68em;font-family:monospace;animation:dwPulse 2s infinite">⚡ CRITICAL</span>`:`<span style="background:${tc}18;color:${tc};border:1px solid ${tc}33;padding:1px 7px;border-radius:4px;font-size:.68em;font-family:monospace">${f.threat_level}</span>`}
          </div>
          <div style="font-size:.85em;font-weight:600;color:#ccc;margin-bottom:6px;line-height:1.4">${f.title}</div>
          <div style="display:flex;gap:14px;font-size:.72em;color:#444;font-family:monospace">
            <span><i class="fas fa-user" style="margin-right:3px;color:#333"></i>${f.author}</span>
            <span><i class="fas fa-reply" style="margin-right:3px;color:#333"></i>${f.replies} replies</span>
            <span><i class="fas fa-eye" style="margin-right:3px;color:#333"></i>${f.views} views</span>
            <span>${_dwAgo(f.posted)}</span>
          </div>
        </div>
        <div style="flex-shrink:0">
          <button onclick="if(window.showToast)showToast('Thread added to monitoring queue','info')"
            style="background:#ffffff08;color:#666;border:1px solid #222;padding:4px 10px;border-radius:5px;font-size:.72em;cursor:pointer">
            <i class="fas fa-bookmark" style="margin-right:3px"></i>Track
          </button>
        </div>
      </div>
    </div>`;
    }).join('')}
  </div>

  <style>
  @keyframes dwPulse {
    0%,100%{opacity:1} 50%{opacity:.6}
  }
  </style>`;
}

function _dwRenderOnion() {
  return `
  <!-- Onion Monitor Header -->
  <div style="background:#00ff4108;border:1px solid #00ff4122;border-radius:8px;padding:12px 14px;margin-bottom:14px;
    display:flex;align-items:center;gap:10px">
    <div style="width:32px;height:32px;background:#00ff4118;border:1px solid #00ff4144;border-radius:6px;
      display:flex;align-items:center;justify-content:center;color:#00ff41;font-size:.9em;flex-shrink:0">
      <i class="fas fa-satellite-dish"></i></div>
    <div>
      <div style="font-size:.82em;font-weight:700;color:#00ff41;font-family:monospace">TOR NETWORK MONITOR</div>
      <div style="font-size:.72em;color:#555;font-family:monospace">
        Passive monitoring only · No direct connections · 
        ${_DW_DATA.onion.filter(o=>o.status==='ONLINE').length}/${_DW_DATA.onion.length} sites online
      </div>
    </div>
    <div style="margin-left:auto;display:flex;gap:6px">
      <div style="background:#080c14;border:1px solid #1a1a2e;border-radius:6px;padding:6px 10px;font-family:monospace;font-size:.7em;color:#00ff41">
        <span style="animation:dwPulse 1s infinite">●</span> ${_DW_DATA.onion.filter(o=>o.status==='ONLINE').length} ONLINE
      </div>
      <div style="background:#080c14;border:1px solid #1a1a2e;border-radius:6px;padding:6px 10px;font-family:monospace;font-size:.7em;color:#ff4444">
        ● ${_DW_DATA.onion.filter(o=>o.status==='OFFLINE').length} OFFLINE
      </div>
    </div>
  </div>

  <!-- Onion Sites Grid -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px">
    ${_DW_DATA.onion.map(site => {
      const isOnline = site.status === 'ONLINE';
      const rc = {CRITICAL:'#ff0044',HIGH:'#ff6600',MEDIUM:'#ffcc00'}[site.risk]||'#22c55e';
      return `
    <div style="background:#080c14;border:1px solid ${isOnline?'#00ff4118':'#1a1a2e'};border-radius:9px;padding:14px;
      transition:all .2s"
      onmouseover="this.style.borderColor='${rc}33'" onmouseout="this.style.borderColor='${isOnline?'#00ff4118':'#1a1a2e'}'">
      <!-- Status indicator -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:8px;height:8px;border-radius:50%;background:${isOnline?'#00ff41':'#ff4444'};
            ${isOnline?'animation:dwPulse 2s infinite':''}"></div>
          <span style="font-size:.68em;color:${isOnline?'#00ff41':'#ff4444'};font-family:monospace;font-weight:700">${site.status}</span>
        </div>
        ${_dwBadge(site.risk, rc)}
      </div>

      <div style="font-size:.8em;font-weight:700;color:#ccc;margin-bottom:4px">${site.category}</div>
      <div style="font-size:.68em;color:#444;font-family:monospace;margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
        title="${site.url}">${site.url}</div>
      <div style="font-size:.72em;color:#777;font-style:italic;margin-bottom:8px">
        "${site.tor_title}"
      </div>
      <div style="font-size:.72em;color:#666;line-height:1.4;margin-bottom:10px">${site.description}</div>

      <div style="display:flex;justify-content:space-between;align-items:center;font-size:.68em;color:#444;font-family:monospace;
        border-top:1px solid #111;padding-top:8px">
        <span>Last check: ${_dwAgo(site.last_check)}</span>
        <button onclick="if(window.showToast)showToast('${site.category} added to monitoring','info')"
          style="background:#ffffff08;color:#666;border:1px solid #222;padding:2px 8px;border-radius:4px;font-size:.9em;cursor:pointer">
          <i class="fas fa-eye" style="margin-right:2px"></i>Watch
        </button>
      </div>
    </div>`;
    }).join('')}
  </div>

  <style>
  @keyframes dwPulse {
    0%,100%{opacity:1} 50%{opacity:.4}
  }
  </style>`;
}

window._dwSearchMarket = function(q) {
  const grid = document.getElementById('dw-market-grid');
  if (!grid) return;
  const items = _DW_DATA.marketplace.filter(i =>
    !q || i.title.toLowerCase().includes(q.toLowerCase()) ||
    i.description.toLowerCase().includes(q.toLowerCase()) ||
    i.type.toLowerCase().includes(q.toLowerCase())
  );
  grid.innerHTML = items.length ? items.map(item => `
    <div style="background:linear-gradient(135deg,#080c14,#0a0f1a);border:1px solid #1a1a2e;border-radius:10px;padding:16px;cursor:pointer;transition:all .2s;position:relative;overflow:hidden"
      onmouseover="this.style.borderColor='${_dwSevColor(item.severity)}44'"
      onmouseout="this.style.borderColor='#1a1a2e'"
      onclick="_dwOpenDetail('${item.id}')">
      <div style="position:absolute;top:0;left:0;right:0;height:2px;background:${_dwSevColor(item.severity)}"></div>
      <div style="font-size:.88em;font-weight:700;color:#ddd;margin-bottom:6px">${item.title}</div>
      <div style="display:flex;gap:4px;margin-bottom:8px">
        ${_dwBadge(item.type,_dwSevColor(item.severity))}${_dwBadge(item.severity,_dwSevColor(item.severity))}
      </div>
      <div style="font-size:.75em;color:#666;margin-bottom:8px">${item.description.slice(0,100)}…</div>
      <div style="font-size:.72em;color:#00ff41;font-family:monospace;font-weight:700">${item.price}</div>
    </div>`).join('') : `<div style="text-align:center;padding:40px;color:#444;font-family:monospace">No results for "${q}"</div>`;
};

window._dwFilterSev = function(sev) { _dwFilter.sev = sev; };
window._dwFilterType = function(type) { _dwFilter.type = type; };

window._dwOpenDetail = function(id) {
  const item = _DW_DATA.marketplace.find(i => i.id === id);
  if (!item) return;
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.92);z-index:9999;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px)';
  modal.innerHTML = `
  <div style="background:#080c14;border:1px solid #1a1a2e;border-radius:14px;padding:28px;max-width:560px;width:92%;position:relative;
    box-shadow:0 0 60px rgba(255,0,68,.08)">
    <div style="position:absolute;top:0;left:0;right:0;height:2px;background:${_dwSevColor(item.severity)};border-radius:14px 14px 0 0"></div>
    <button onclick="this.closest('div[style*=position]').remove()" style="position:absolute;top:12px;right:14px;background:none;border:none;color:#444;font-size:1.2em;cursor:pointer;color:#888">✕</button>
    <div style="margin-bottom:14px">
      ${_dwBadge(item.type, _dwSevColor(item.severity))}
      ${_dwBadge(item.severity, _dwSevColor(item.severity))}
    </div>
    <div style="font-size:1em;font-weight:800;color:#ddd;margin-bottom:10px;line-height:1.4">${item.title}</div>
    <div style="font-size:.82em;color:#888;line-height:1.7;margin-bottom:14px">${item.description}</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;font-size:.78em;font-family:monospace">
      <div style="background:#0a0f1a;border:1px solid #111;border-radius:6px;padding:10px">
        <div style="color:#444;margin-bottom:3px">PRICE</div>
        <div style="color:#00ff41;font-weight:700;font-size:1.1em">${item.price}</div>
      </div>
      <div style="background:#0a0f1a;border:1px solid #111;border-radius:6px;padding:10px">
        <div style="color:#444;margin-bottom:3px">SELLER</div>
        <div style="color:#888">${item.seller}</div>
      </div>
      <div style="background:#0a0f1a;border:1px solid #111;border-radius:6px;padding:10px">
        <div style="color:#444;margin-bottom:3px">VIEWS</div>
        <div style="color:#ffcc00">${item.views.toLocaleString()}</div>
      </div>
      <div style="background:#0a0f1a;border:1px solid #111;border-radius:6px;padding:10px">
        <div style="color:#444;margin-bottom:3px">RATING</div>
        <div style="color:#ff8800">★ ${item.rating}</div>
      </div>
    </div>
    <div style="background:#0a0f1a;border:1px solid #1a1a2e;border-radius:6px;padding:10px;margin-bottom:14px">
      <div style="font-size:.7em;color:#444;font-family:monospace;margin-bottom:4px">ONION URL (MONITORED)</div>
      <div style="font-size:.72em;color:#555;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${item.tor}</div>
    </div>
    <div style="display:flex;gap:8px">
      <button onclick="if(window.showToast)showToast('Intelligence added to case','success')" 
        style="flex:1;background:#ff000018;color:#ff4444;border:1px solid #ff000033;padding:8px;border-radius:7px;font-size:.78em;cursor:pointer">
        <i class="fas fa-file-alt" style="margin-right:5px"></i>Add to Case
      </button>
      <button onclick="if(window.showToast)showToast('IOC extraction queued','info')" 
        style="flex:1;background:#3b82f618;color:#3b82f6;border:1px solid #3b82f633;padding:8px;border-radius:7px;font-size:.78em;cursor:pointer">
        <i class="fas fa-fingerprint" style="margin-right:5px"></i>Extract IOCs
      </button>
      <button onclick="this.closest('div[style*=position]').remove()"
        style="background:#ffffff08;color:#666;border:1px solid #222;padding:8px 14px;border-radius:7px;font-size:.78em;cursor:pointer">Close</button>
    </div>
  </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
};

/* ── Legacy shims ── */
window.filterDarkWeb  = function() { if(window._dwSetTab) _dwSetTab(_dwTab); };
window.exportDarkWeb  = function() {
  const data = JSON.stringify(_DW_DATA.marketplace, null, 2);
  const blob = new Blob([data], {type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'darkweb-intel.json'; a.click();
  URL.revokeObjectURL(url);
  if (window.showToast) showToast('Dark web intel exported', 'success');
};

console.info('[DarkWeb] Module v4.0 loaded — hacker-style GUI ready');
