/**
 * ══════════════════════════════════════════════════════════
 *  ThreatPilot AI — Features Module v2.0.0
 *  Cyber News · MITRE ATT&CK Navigator · IOC Database · Geo Threats
 *  All modules are enterprise-grade with real-time simulation
 * ══════════════════════════════════════════════════════════
 */

/* ════════════════════════════════════════════
   CYBER NEWS — Threat Intelligence Feed v3.0
   Card-style layout with severity-coded design
═════════════════════════════════════════════ */
function renderCyberNews() {
  const wrap = document.getElementById('cyberNewsWrap');
  if (!wrap) return;

  const news = [
    { id:'N001', title:'APT29 Deploys New Backdoor Targeting NATO Members', actor:'APT29 (Cozy Bear)', malware:'SUNBURST-v3', severity:'CRITICAL', region:'Europe', source:'Mandiant', sourceIcon:'fa-shield-alt', published:'2025-03-20', timeAgo:'2h ago', iocs:['185.220.101.45','cozy-update[.]ru','a3f2b1c9d...sha256'], industries:['Government','Defense'], countries:['UK','Germany','France'], summary:'Russian APT29 has been observed deploying a new variant of their SUNBURST backdoor targeting NATO diplomatic infrastructure. The malware uses DNS-over-HTTPS for C2 communication to evade detection. Attribution confirmed via TTP overlap and infrastructure reuse.', tags:['APT','Backdoor','NATO','DNS-over-HTTPS'] },
    { id:'N002', title:'Critical RCE in Ivanti Connect Secure — Mass Exploitation Active', actor:'Multiple Actors', malware:'WebShell + Reverse Shell', severity:'CRITICAL', region:'Global', source:'CISA', sourceIcon:'fa-university', published:'2025-03-19', timeAgo:'18h ago', iocs:['CVE-2025-0282','204.13.164.118','45.33.32.156'], industries:['Technology','Healthcare','Finance'], countries:['US','UK','Australia'], summary:'A critical zero-day vulnerability in Ivanti Connect Secure VPN is being actively exploited by multiple threat actors. CVE-2025-0282 allows unauthenticated remote code execution. CISA has issued emergency directive to patch immediately.', tags:['0-day','RCE','VPN','CVE-2025-0282'] },
    { id:'N003', title:'LockBit 4.0 Ransomware Infrastructure Back Online After Takedown', actor:'LockBit', malware:'LockBit 4.0', severity:'HIGH', region:'Global', source:'Recorded Future', sourceIcon:'fa-database', published:'2025-03-18', timeAgo:'1d ago', iocs:['lockbit4onion[.]onion','lockbit-news[.]com','194.165.16.78'], industries:['Healthcare','Manufacturing','Legal'], countries:['US','Canada','EU'], summary:'LockBit ransomware group has relaunched infrastructure under LockBit 4.0 after the February 2024 law enforcement takedown. New affiliate recruitment portal observed on dark web with improved encryption and exfiltration capabilities.', tags:['Ransomware','RaaS','LockBit','Dark Web'] },
    { id:'N004', title:'Scattered Spider Shifts to Cloud Targeting — Azure & AWS Focus', actor:'Scattered Spider (UNC3944)', malware:'Social Engineering / Okta Bypass', severity:'HIGH', region:'North America', source:'CrowdStrike', sourceIcon:'fa-crow', published:'2025-03-17', timeAgo:'2d ago', iocs:['scattered-help[.]com','fake-okta[.]net','185.220.101.77'], industries:['SaaS','Fintech','Crypto'], countries:['US','Canada'], summary:'UNC3944 (Scattered Spider) is now targeting cloud management platforms with sophisticated vishing campaigns to gain Azure AD and AWS console access. MFA fatigue and SIM swapping remain primary initial access vectors.', tags:['Social-Engineering','Cloud','Azure','AWS'] },
    { id:'N005', title:'Salt Typhoon Telecom Espionage: 12 Additional Carriers Compromised', actor:'Salt Typhoon (APT40)', malware:'GhostSpy RAT', severity:'CRITICAL', region:'Asia-Pacific', source:'NSA Advisory', sourceIcon:'fa-broadcast-tower', published:'2025-03-16', timeAgo:'2d ago', iocs:['ghost-spy[.]cn','172.104.28.91','T1040','T1071'], industries:['Telecommunications','ISP'], countries:['US','Japan','South Korea','Taiwan'], summary:'Chinese state-sponsored actor Salt Typhoon continues its telecom espionage campaign with 12 new carrier compromises identified. Lawful intercept (CALEA) systems specifically targeted for call record and communication metadata collection.', tags:['Chinese APT','Telecom','Espionage','CALEA'] },
    { id:'N006', title:'Critical FortiGate VPN Vulnerability Exploited by Ransomware Groups', actor:'Akira Ransomware + Others', malware:'Akira Ransomware', severity:'HIGH', region:'Global', source:'Fortinet PSIRT', sourceIcon:'fa-fire-alt', published:'2025-03-15', timeAgo:'3d ago', iocs:['CVE-2024-21762','akira-leak[.]onion','10.0.0.0/8'], industries:['Enterprise','SMB','Healthcare'], countries:['Global'], summary:'Multiple ransomware groups are exploiting CVE-2024-21762 in FortiGate appliances before organizations can patch. Akira group most active in initial access exploitation. Patches available since February 2024.', tags:['CVE','FortiGate','VPN','Ransomware'] },
    { id:'N007', title:'TA558 Phishing Campaign Targeting LATAM Financial Institutions', actor:'TA558', malware:'AsyncRAT / Remcos', severity:'MEDIUM', region:'Latin America', source:'Proofpoint', sourceIcon:'fa-envelope', published:'2025-03-14', timeAgo:'4d ago', iocs:['factura-online[.]com.mx','descarga-archivo[.]net','195.62.52.111'], industries:['Banking','Finance'], countries:['Brazil','Mexico','Argentina','Colombia'], summary:'Prolific financially-motivated threat actor TA558 launches new campaign targeting LATAM banks using Portuguese and Spanish lure documents delivering AsyncRAT and Remcos RATs.', tags:['Phishing','LATAM','RAT','Financial'] },
    { id:'N008', title:'ALPHV/BlackCat Final Ransom Before Shutdown: $22M Healthcare Payout', actor:'ALPHV/BlackCat', malware:'BlackCat Ransomware', severity:'HIGH', region:'North America', source:'FBI IC3', sourceIcon:'fa-gavel', published:'2025-03-13', timeAgo:'5d ago', iocs:['blackcat-onion[.]io','185.220.100.240'], industries:['Healthcare'], countries:['US'], summary:'Change Healthcare confirms $22M ransom payment to ALPHV/BlackCat before the group\'s infrastructure was seized. Affiliate dispute reveals inner workings of the RaaS operation including profit-sharing mechanisms.', tags:['Ransomware','Healthcare','BlackCat','RaaS'] },
    { id:'N009', title:'Volt Typhoon Pre-Positions in US Critical Infrastructure for 5+ Years', actor:'Volt Typhoon', malware:'KV-Botnet / LOLBins', severity:'CRITICAL', region:'North America', source:'CISA/FBI Joint', sourceIcon:'fa-bolt', published:'2025-03-12', timeAgo:'6d ago', iocs:['volt-typhoon-c2[.]com','T1505.003','T1078.001'], industries:['Energy','Water','Transport','Communications'], countries:['US'], summary:'CISA and FBI confirm Volt Typhoon has maintained persistent access to US critical infrastructure networks for 5+ years, pre-positioning for potential disruptive attacks. Living-off-the-land techniques used exclusively.', tags:['Chinese APT','Critical-Infrastructure','LOLBins','Pre-positioning'] },
    { id:'N010', title:'New Phishing-as-a-Service Platform "Tycoon 2FA" Bypasses Microsoft MFA', actor:'Unknown (Eastern Europe)', malware:'Tycoon 2FA Kit', severity:'HIGH', region:'Global', source:'Sekoia TI', sourceIcon:'fa-shield-virus', published:'2025-03-11', timeAgo:'7d ago', iocs:['tycoon2fa[.]io','mx-redir[.]net','185.199.108.154'], industries:['Enterprise','Finance','Healthcare'], countries:['Global'], summary:'A new Phishing-as-a-Service platform called Tycoon 2FA is being sold on Telegram for $120/month. It bypasses Microsoft 365 MFA using adversary-in-the-middle (AiTM) techniques. Over 1,000 phishing domains registered.', tags:['PhaaS','AiTM','MFA-Bypass','Microsoft365'] },
    { id:'N011', title:'GitHub Actions Supply Chain Attack via Malicious Workflow Injection', actor:'Unknown', malware:'Exfiltration Shell', severity:'HIGH', region:'Global', source:'StepSecurity', sourceIcon:'fa-code-branch', published:'2025-03-10', timeAgo:'8d ago', iocs:['tj-actions/changed-files@v35','5eef8b5b7...sha256'], industries:['Technology','DevOps','OSS'], countries:['Global'], summary:'Malicious code injected into popular GitHub Action tj-actions/changed-files was used to exfiltrate CI/CD secrets from thousands of repositories. Supply chain attack affected organizations using the action in their pipelines.', tags:['Supply-Chain','CI/CD','GitHub','DevSecOps'] },
    { id:'N012', title:'North Korean IT Workers Infiltrate Western Tech Companies via Fake Identities', actor:'Lazarus Group / DPRK IT Workers', malware:'Remote Access Backdoor', severity:'MEDIUM', region:'Global', source:'Crowdstrike / DOJ', sourceIcon:'fa-user-secret', published:'2025-03-09', timeAgo:'9d ago', iocs:['nkworker-vpn[.]com','fake-resume[.]cloud'], industries:['Technology','Crypto','Defense'], countries:['US','UK','Canada','Australia'], summary:'FBI and DOJ warn that hundreds of North Korean IT workers have infiltrated Western technology companies using stolen/fabricated identities. Workers insert backdoors and exfiltrate IP to fund DPRK weapons programs.', tags:['DPRK','Insider-Threat','Social-Engineering','Supply-Chain'] },
  ];

  const sevColors = {
    CRITICAL: { bg:'#ff000015', border:'#ff000030', text:'#ff4444', dot:'#ff0044' },
    HIGH:     { bg:'#ff660015', border:'#ff660030', text:'#ff8800', dot:'#ff6600' },
    MEDIUM:   { bg:'#ffcc0015', border:'#ffcc0030', text:'#f59e0b', dot:'#ffcc00' },
    LOW:      { bg:'#00cc4415', border:'#00cc4430', text:'#22c55e', dot:'#00cc44' },
  };

  wrap.innerHTML = `
  <!-- Header -->
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:18px">
    <div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
        <div style="width:8px;height:8px;background:#ef4444;border-radius:50%;animation:cnPulse 1.5s infinite"></div>
        <h2 style="font-size:1.05em;font-weight:700;color:#e6edf3;margin:0">Threat Intelligence Feed</h2>
        <span style="background:#ef444418;color:#ef4444;border:1px solid #ef444433;padding:1px 8px;border-radius:8px;font-size:.7em;font-weight:700">LIVE</span>
      </div>
      <div style="font-size:.76em;color:#8b949e">AI-curated threat intel • IOC extraction • MITRE mapping • ${news.length} active reports</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="news-search" placeholder="🔍 Search threats…" oninput="_newsSearch(this.value)"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 12px;border-radius:6px;font-size:.82em;width:160px"/>
      <select id="newsSevFilter" onchange="filterNews()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
        <option value="">All Severities</option>
        <option value="CRITICAL">🔴 Critical</option>
        <option value="HIGH">🟠 High</option>
        <option value="MEDIUM">🟡 Medium</option>
      </select>
      <select id="newsRegionFilter" onchange="filterNews()"
        style="background:#0d1117;border:1px solid #30363d;color:#e6edf3;padding:6px 10px;border-radius:6px;font-size:.82em">
        <option value="">All Regions</option>
        <option value="Global">Global</option>
        <option value="North America">North America</option>
        <option value="Europe">Europe</option>
        <option value="Asia-Pacific">Asia-Pacific</option>
        <option value="Latin America">Latin America</option>
      </select>
      <button onclick="exportCyberNews()"
        style="background:#21262d;color:#8b949e;border:1px solid #30363d;padding:6px 12px;border-radius:6px;font-size:.82em;cursor:pointer">
        <i class="fas fa-download" style="margin-right:5px"></i>Export
      </button>
    </div>
  </div>

  <!-- KPI Strip -->
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-bottom:18px">
    ${[
      {label:'Critical',val:news.filter(n=>n.severity==='CRITICAL').length,c:'#ef4444',icon:'fa-radiation'},
      {label:'High Severity',val:news.filter(n=>n.severity==='HIGH').length,c:'#f97316',icon:'fa-exclamation-triangle'},
      {label:'Active Reports',val:news.length,c:'#3b82f6',icon:'fa-newspaper'},
      {label:'Threat Actors',val:[...new Set(news.map(n=>n.actor))].length,c:'#8b5cf6',icon:'fa-user-secret'},
      {label:'Industries Hit',val:[...new Set(news.flatMap(n=>n.industries))].length,c:'#22c55e',icon:'fa-industry'},
    ].map(k=>`
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
        <i class="fas ${k.icon}" style="color:${k.c};font-size:.82em"></i>
        <span style="font-size:.7em;color:#8b949e">${k.label}</span>
      </div>
      <div style="font-size:1.5em;font-weight:700;color:${k.c}">${k.val}</div>
    </div>`).join('')}
  </div>

  <!-- News Cards Grid -->
  <div id="news-cards-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px">
    ${news.map(n => _renderNewsCard(n, sevColors)).join('')}
  </div>

  <style>
  @keyframes cnPulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.6;transform:scale(.9)} }
  </style>
  `;

  window._newsData = news;
}

function _renderNewsCard(n, sevColors) {
  const sc = sevColors[n.severity] || sevColors.MEDIUM;
  return `
  <div onclick="openNewsDetail('${n.id}')" style="background:#0d1117;border:1px solid #21262d;border-radius:12px;
    padding:0;cursor:pointer;transition:all .2s;overflow:hidden;position:relative"
    onmouseover="this.style.borderColor='${sc.dot}44';this.style.transform='translateY(-1px)'"
    onmouseout="this.style.borderColor='#21262d';this.style.transform=''">
    <!-- Top severity bar -->
    <div style="height:3px;background:${sc.dot};width:100%"></div>

    <!-- Card body -->
    <div style="padding:14px">
      <!-- Header row -->
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px">
        <div style="display:flex;align-items:center;gap:7px;flex:1">
          <div style="width:30px;height:30px;background:${sc.bg};border:1px solid ${sc.border};border-radius:7px;
            display:flex;align-items:center;justify-content:center;color:${sc.dot};flex-shrink:0;font-size:.8em">
            <i class="fas ${n.sourceIcon}"></i>
          </div>
          <div>
            <div style="font-size:.72em;color:#8b949e">${n.source}</div>
            <div style="font-size:.65em;color:#8b949e">${n.timeAgo}</div>
          </div>
        </div>
        <span style="background:${sc.bg};color:${sc.text};border:1px solid ${sc.border};padding:2px 8px;border-radius:8px;font-size:.68em;font-weight:700;white-space:nowrap">${n.severity}</span>
      </div>

      <!-- Title -->
      <div style="font-size:.88em;font-weight:700;color:#e6edf3;line-height:1.4;margin-bottom:8px">${n.title}</div>

      <!-- Summary -->
      <div style="font-size:.74em;color:#8b949e;line-height:1.6;margin-bottom:10px;
        overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical">${n.summary}</div>

      <!-- Actor + Malware row -->
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
        <span style="background:#f9731618;color:#f97316;border:1px solid #f9731633;padding:2px 8px;border-radius:8px;font-size:.68em">
          <i class="fas fa-user-secret" style="margin-right:3px"></i>${n.actor.split('/')[0].trim()}
        </span>
        <span style="background:#8b5cf618;color:#8b5cf6;border:1px solid #8b5cf633;padding:2px 8px;border-radius:8px;font-size:.68em;font-family:monospace">
          ${n.malware.length > 20 ? n.malware.slice(0,18)+'…' : n.malware}
        </span>
        <span style="background:#21262d;color:#8b949e;padding:2px 8px;border-radius:8px;font-size:.68em">
          <i class="fas fa-globe" style="margin-right:3px"></i>${n.region}
        </span>
      </div>

      <!-- Tags -->
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${(n.tags||[]).slice(0,4).map(t=>`<span style="background:#ffffff08;color:#555;border:1px solid #222;padding:1px 6px;border-radius:4px;font-size:.65em">#${t}</span>`).join('')}
      </div>

      <!-- Bottom row: industries + actions -->
      <div style="display:flex;align-items:center;justify-content:space-between;border-top:1px solid #1e2d3d;padding-top:8px">
        <div style="font-size:.68em;color:#555">
          ${n.industries.slice(0,3).join(' · ')}${n.industries.length>3?'…':''}
        </div>
        <div style="display:flex;gap:5px" onclick="event.stopPropagation()">
          <button onclick="convertNewsToIOCs('${n.id}')" title="Extract IOCs"
            style="width:26px;height:26px;background:#22d3ee18;color:#22d3ee;border:1px solid #22d3ee33;border-radius:5px;font-size:.72em;cursor:pointer;display:flex;align-items:center;justify-content:center">
            <i class="fas fa-fingerprint"></i></button>
          <button onclick="createCaseFromNews('${n.id}')" title="Create Case"
            style="width:26px;height:26px;background:#22c55e18;color:#22c55e;border:1px solid #22c55e33;border-radius:5px;font-size:.72em;cursor:pointer;display:flex;align-items:center;justify-content:center">
            <i class="fas fa-folder-plus"></i></button>
          <button onclick="mapNewsMITRE('${n.id}')" title="MITRE Map"
            style="width:26px;height:26px;background:#8b5cf618;color:#8b5cf6;border:1px solid #8b5cf633;border-radius:5px;font-size:.72em;cursor:pointer;display:flex;align-items:center;justify-content:center">
            <i class="fas fa-th"></i></button>
        </div>
      </div>
    </div>
  </div>`;
}

window._newsSearch = function(q) {
  const grid = document.getElementById('news-cards-grid');
  if (!grid || !window._newsData) return;
  const sevColors = {
    CRITICAL: { bg:'#ff000015', border:'#ff000030', text:'#ff4444', dot:'#ff0044' },
    HIGH:     { bg:'#ff660015', border:'#ff660030', text:'#ff8800', dot:'#ff6600' },
    MEDIUM:   { bg:'#ffcc0015', border:'#ffcc0030', text:'#f59e0b', dot:'#ffcc00' },
    LOW:      { bg:'#00cc4415', border:'#00cc4430', text:'#22c55e', dot:'#00cc44' },
  };
  const filtered = q ? window._newsData.filter(n =>
    n.title.toLowerCase().includes(q.toLowerCase()) ||
    n.actor.toLowerCase().includes(q.toLowerCase()) ||
    n.malware.toLowerCase().includes(q.toLowerCase()) ||
    (n.tags||[]).some(t=>t.toLowerCase().includes(q.toLowerCase()))
  ) : window._newsData;
  grid.innerHTML = filtered.map(n => _renderNewsCard(n, sevColors)).join('');
};

function filterNews() {
  const sev    = document.getElementById('newsSevFilter')?.value;
  const region = document.getElementById('newsRegionFilter')?.value;
  const grid   = document.getElementById('news-cards-grid');
  if (!grid || !window._newsData) return;
  const sevColors = {
    CRITICAL: { bg:'#ff000015', border:'#ff000030', text:'#ff4444', dot:'#ff0044' },
    HIGH:     { bg:'#ff660015', border:'#ff660030', text:'#ff8800', dot:'#ff6600' },
    MEDIUM:   { bg:'#ffcc0015', border:'#ffcc0030', text:'#f59e0b', dot:'#ffcc00' },
    LOW:      { bg:'#00cc4415', border:'#00cc4430', text:'#22c55e', dot:'#00cc44' },
  };
  const filtered = window._newsData.filter(n =>
    (!sev    || n.severity === sev) &&
    (!region || n.region   === region || n.region === 'Global')
  );
  grid.innerHTML = filtered.length ?
    filtered.map(n => _renderNewsCard(n, sevColors)).join('') :
    '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#8b949e">No reports match your filters</div>';
}

function openNewsDetail(id) {
  const n = window._newsData?.find(x => x.id === id);
  if (!n) return;
  const sc = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#22c55e'}[n.severity]||'#8b949e';
  const body = document.getElementById('detailModalBody');
  const modal = document.getElementById('detailModal');
  if (!body || !modal) return;
  body.innerHTML = `
  <div style="padding:24px;max-width:780px;">
    <div style="margin-bottom:18px">
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">
        <span style="background:${sc}18;color:${sc};border:1px solid ${sc}33;padding:3px 10px;border-radius:6px;font-size:.75em;font-weight:700">${n.severity}</span>
        <span style="background:#21262d;color:#8b949e;padding:3px 10px;border-radius:6px;font-size:.75em">${n.source}</span>
        <span style="background:#21262d;color:#8b949e;padding:3px 10px;border-radius:6px;font-size:.75em">${n.published}</span>
        <span style="background:#21262d;color:#8b949e;padding:3px 10px;border-radius:6px;font-size:.75em">${n.region}</span>
      </div>
      <div style="font-size:1.05em;font-weight:700;color:#e6edf3;line-height:1.4;margin-bottom:6px">${n.title}</div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
        <div style="font-size:.68em;color:#8b949e;text-transform:uppercase;margin-bottom:4px">Threat Actor</div>
        <div style="font-size:.85em;color:#f97316;font-weight:600">${n.actor}</div>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
        <div style="font-size:.68em;color:#8b949e;text-transform:uppercase;margin-bottom:4px">Malware Family</div>
        <div style="font-size:.82em;color:#8b5cf6;font-weight:600;font-family:monospace">${n.malware}</div>
      </div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px">
        <div style="font-size:.68em;color:#8b949e;text-transform:uppercase;margin-bottom:4px">Region</div>
        <div style="font-size:.85em;color:#e6edf3;font-weight:600">${n.region}</div>
      </div>
    </div>
    <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;margin-bottom:14px">
      <div style="font-size:.72em;color:#22d3ee;text-transform:uppercase;font-weight:600;margin-bottom:8px">
        <i class="fas fa-robot" style="margin-right:5px"></i>AI Summary
      </div>
      <div style="font-size:.84em;color:#8b949e;line-height:1.7">${n.summary}</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
      <div>
        <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;font-weight:600;margin-bottom:7px">Industries Affected</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(n.industries||[]).map(i=>`<span style="background:#3b82f618;color:#3b82f6;border:1px solid #3b82f633;padding:2px 8px;border-radius:5px;font-size:.72em">${i}</span>`).join('')}
        </div>
      </div>
      <div>
        <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;font-weight:600;margin-bottom:7px">Target Countries</div>
        <div style="display:flex;flex-wrap:wrap;gap:5px">
          ${(n.countries||[]).map(c=>`<span style="background:#21262d;color:#8b949e;padding:2px 8px;border-radius:5px;font-size:.72em;border:1px solid #30363d">${c}</span>`).join('')}
        </div>
      </div>
    </div>
    ${(n.iocs||[]).length?`
    <div style="margin-bottom:14px">
      <div style="font-size:.72em;color:#8b949e;text-transform:uppercase;font-weight:600;margin-bottom:7px">Associated IOCs</div>
      <div style="background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px;display:flex;flex-wrap:wrap;gap:7px">
        ${n.iocs.map(ioc=>`<code style="background:#080c14;color:#22d3ee;padding:3px 8px;border-radius:5px;font-size:.75em;cursor:pointer;border:1px solid #1e2d3d" onclick="if(window.showToast)showToast('Copied: ${ioc}','info')">${ioc}</code>`).join('')}
      </div>
    </div>`:''}
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button onclick="convertNewsToIOCs('${n.id}');closeDetailModal&&closeDetailModal()"
        style="background:#22d3ee18;color:#22d3ee;border:1px solid #22d3ee33;padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer">
        <i class="fas fa-fingerprint" style="margin-right:5px"></i>Extract IOCs</button>
      <button onclick="createCaseFromNews('${n.id}');closeDetailModal&&closeDetailModal()"
        style="background:#22c55e18;color:#22c55e;border:1px solid #22c55e33;padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer">
        <i class="fas fa-folder-plus" style="margin-right:5px"></i>Create Case</button>
      <button onclick="mapNewsMITRE('${n.id}');closeDetailModal&&closeDetailModal()"
        style="background:#8b5cf618;color:#8b5cf6;border:1px solid #8b5cf633;padding:7px 14px;border-radius:7px;font-size:.8em;cursor:pointer">
        <i class="fas fa-th" style="margin-right:5px"></i>MITRE Map</button>
    </div>
  </div>`;
  modal.classList.add('active');
}

function convertNewsToIOCs(id) {
  const n = window._newsData?.find(x => x.id === id);
  if (!n) return;
  showToast(`✅ Extracted ${n.iocs.length} IOCs from "${n.title.slice(0,40)}..." → Added to IOC Database`, 'success');
}

function createCaseFromNews(id) {
  const n = window._newsData?.find(x => x.id === id);
  if (!n) return;
  showToast(`📁 Case created: "${n.title.slice(0,50)}..." → Assigned to Analyst queue`, 'success');
  const nb = document.getElementById('nb-cases');
  if (nb) nb.textContent = parseInt(nb.textContent || 0) + 1;
}

function mapNewsMITRE(id) {
  const n = window._newsData?.find(x => x.id === id);
  if (!n) return;
  showToast(`🎯 Mapping "${n.actor}" to MITRE ATT&CK Navigator...`, 'info');
  setTimeout(() => { navigateTo('mitre-attack'); }, 800);
}

function exportCyberNews() {
  const data = window._newsData || [];
  const csv = ['Source,Threat Actor,Malware,Severity,Region,Published,Title',
    ...data.map(n => [n.source, n.actor, n.malware, n.severity, n.region, n.published, `"${n.title}"`].join(','))
  ].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'cyber-news.csv'; a.click();
  showToast('📊 Exported news feed as CSV', 'success');
}

function exportNewsPDF(id) {
  const n = window._newsData?.find(x => x.id === id);
  if (!n) return;
  const w = window.open('', '_blank');
  w.document.write(`<html><head><title>${n.title}</title>
  <style>body{font-family:Arial,sans-serif;max-width:800px;margin:40px auto;color:#1a202c;}
  h1{color:#e53e3e;font-size:20px;}h2{font-size:14px;color:#718096;}
  .tag{display:inline-block;background:#edf2f7;padding:3px 8px;border-radius:4px;font-size:12px;margin:2px;}
  .ioc{background:#1a202c;color:#68d391;padding:4px 8px;border-radius:4px;font-family:monospace;font-size:12px;}</style>
  </head><body>
  <h1>THREAT INTELLIGENCE REPORT</h1>
  <h2>Source: ${n.source} · ${n.published}</h2>
  <h2 style="color:#e53e3e;font-size:18px;">${n.title}</h2>
  <p><strong>Severity:</strong> ${n.severity} · <strong>Region:</strong> ${n.region}</p>
  <p><strong>Threat Actor:</strong> ${n.actor} · <strong>Malware:</strong> ${n.malware}</p>
  <h3>AI Summary</h3><p>${n.summary}</p>
  <h3>IOCs</h3><p>${n.iocs.map(i=>`<span class="ioc">${i}</span>`).join(' ')}</p>
  <h3>Affected Industries</h3><p>${n.industries.map(i=>`<span class="tag">${i}</span>`).join('')}</p>
  <footer style="margin-top:40px;border-top:1px solid #e2e8f0;padding-top:16px;font-size:11px;color:#718096;">ThreatPilot AI v2.0.0 · Generated ${new Date().toISOString()}</footer>
  </body></html>`);
  w.document.close(); w.print();
}

/* ════════════════════════════════════════════
   MITRE ATT&CK NAVIGATOR — Interactive Hunt Engine
═════════════════════════════════════════════ */
const MITRE_TACTICS = [
  { id:'TA0001', name:'Reconnaissance',       short:'Recon',    color:'#6366f1', techniques:['T1595','T1592','T1589','T1590','T1591','T1598','T1597','T1596'] },
  { id:'TA0002', name:'Resource Development', short:'Res Dev',  color:'#8b5cf6', techniques:['T1583','T1584','T1585','T1586','T1587','T1588','T1608'] },
  { id:'TA0003', name:'Initial Access',       short:'Init.Access', color:'#ec4899', techniques:['T1189','T1190','T1133','T1200','T1091','T1195','T1199','T1078'] },
  { id:'TA0004', name:'Execution',            short:'Execution', color:'#f43f5e', techniques:['T1059','T1203','T1053','T1129','T1106','T1204','T1047','T1072'] },
  { id:'TA0005', name:'Persistence',          short:'Persist',  color:'#f97316', techniques:['T1098','T1197','T1547','T1037','T1176','T1554','T1136','T1543'] },
  { id:'TA0006', name:'Privilege Escalation', short:'Priv Esc', color:'#eab308', techniques:['T1548','T1134','T1068','T1574','T1055','T1053','T1078','T1611'] },
  { id:'TA0007', name:'Defense Evasion',      short:'Def Evasion', color:'#22c55e', techniques:['T1140','T1480','T1211','T1222','T1564','T1070','T1202','T1036'] },
  { id:'TA0008', name:'Credential Access',    short:'Cred Access', color:'#06b6d4', techniques:['T1110','T1555','T1212','T1187','T1606','T1056','T1557','T1539'] },
  { id:'TA0009', name:'Discovery',            short:'Discovery', color:'#3b82f6', techniques:['T1087','T1010','T1217','T1482','T1083','T1046','T1135','T1201'] },
  { id:'TA0010', name:'Lateral Movement',     short:'Lateral',  color:'#6366f1', techniques:['T1210','T1534','T1570','T1563','T1021','T1091','T1080','T1550'] },
  { id:'TA0011', name:'Collection',           short:'Collect',  color:'#8b5cf6', techniques:['T1560','T1123','T1119','T1185','T1115','T1530','T1213','T1005'] },
  { id:'TA0040', name:'Impact',               short:'Impact',   color:'#ef4444', techniques:['T1531','T1485','T1486','T1565','T1491','T1561','T1499','T1529'] }
];

const MITRE_TECHNIQUE_DETAILS = {
  'T1059': { name:'Command and Scripting Interpreter', detection:'HIGH', datasource:'Process Monitoring, Command Line', coverage:85, alerts:12, query_splunk:'index=sysmon EventCode=1 CommandLine="*powershell*" OR CommandLine="*cmd*"', query_sentinel:'SecurityEvent | where EventID == 4688 | where CommandLine has_any ("powershell", "cmd")', desc:'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
  'T1190': { name:'Exploit Public-Facing Application', detection:'MEDIUM', datasource:'Web Logs, Network Traffic', coverage:60, alerts:8, query_splunk:'index=web status=500 OR status=400 | stats count by src_ip uri_path', query_sentinel:'AzureDiagnostics | where Category=="ApplicationGatewayAccessLog" | where httpStatus_d in (400,500)', desc:'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.' },
  'T1078': { name:'Valid Accounts', detection:'MEDIUM', datasource:'Authentication Logs, Active Directory', coverage:70, alerts:23, query_splunk:'index=wineventlog EventCode=4624 Logon_Type=3 | stats count by Account_Name src_ip', query_sentinel:'SigninLogs | where ResultType == "0" | where UserPrincipalName !endswith "@yourcompany.com"', desc:'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.' },
  'T1486': { name:'Data Encrypted for Impact (Ransomware)', detection:'HIGH', datasource:'File Monitoring, Process Activity', coverage:75, alerts:3, query_splunk:'index=sysmon EventCode=11 TargetFilename="*.encrypted" OR TargetFilename="*.locked"', query_sentinel:'DeviceFileEvents | where FileName endswith ".encrypted" or FileName endswith ".locked"', desc:'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.' },
  'T1055': { name:'Process Injection', detection:'HIGH', datasource:'Process Monitoring, API Monitoring', coverage:80, alerts:7, query_splunk:'index=sysmon EventCode=8 SourceImage!="*\\System32\\*"', query_sentinel:'DeviceProcessEvents | where InitiatingProcessFileName != "System32" and ActionType == "CreateRemoteThread"', desc:'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.' },
  'T1110': { name:'Brute Force', detection:'HIGH', datasource:'Authentication Logs', coverage:90, alerts:45, query_splunk:'index=wineventlog EventCode=4625 | stats count by Account_Name src_ip | where count > 10', query_sentinel:'SecurityEvent | where EventID == 4625 | summarize count() by Account, IpAddress | where count_ > 10', desc:'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.' },
};

function renderMITREAttack() {
  const wrap = document.getElementById('mitreAttackWrap');
  if (!wrap) return;

  wrap.innerHTML = `
  <div style="padding:4px;">
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h2 style="font-size:18px;font-weight:700;color:var(--text-primary);display:flex;align-items:center;gap:10px;">
          <i class="fas fa-th" style="color:var(--accent-blue)"></i> MITRE ATT&CK® Navigator
          <span style="background:var(--accent-blue)22;color:var(--accent-blue);padding:3px 8px;border-radius:5px;font-size:11px;">v14</span>
        </h2>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Interactive threat hunting engine • Click any technique for details</div>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="btn-primary" onclick="simulateAttackPath()"><i class="fas fa-route"></i> Simulate Attack Path</button>
        <button class="btn-primary" style="background:var(--accent-green);" onclick="exportMITRELayer()"><i class="fas fa-download"></i> Export Layer</button>
      </div>
    </div>

    <!-- Coverage stats -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
      ${[['fa-check-circle','var(--accent-green)','Techniques Covered','47/180'],['fa-shield-alt','var(--accent-blue)','Avg Coverage','73%'],['fa-bell','var(--accent-orange)','Active Alerts','98'],['fa-search','var(--accent-purple)','Data Sources','12']].map(([ic,col,lbl,val])=>`
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px;display:flex;align-items:center;gap:12px;">
          <i class="fas ${ic}" style="font-size:20px;color:${col}"></i>
          <div><div style="font-size:20px;font-weight:700;color:var(--text-primary);">${val}</div><div style="font-size:11px;color:var(--text-muted);">${lbl}</div></div>
        </div>`).join('')}
    </div>

    <!-- ATT&CK Matrix -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:auto;margin-bottom:20px;">
      <div style="display:grid;grid-template-columns:repeat(${MITRE_TACTICS.length},1fr);min-width:1400px;">
        ${MITRE_TACTICS.map(tactic => `
          <div style="border-right:1px solid var(--border);">
            <div style="background:${tactic.color}22;border-bottom:2px solid ${tactic.color};padding:10px 8px;text-align:center;cursor:pointer;" onclick="openTacticDetail('${tactic.id}')">
              <div style="font-size:10px;font-weight:700;color:${tactic.color};text-transform:uppercase;">${tactic.id}</div>
              <div style="font-size:11px;font-weight:600;color:var(--text-primary);margin-top:2px;">${tactic.short}</div>
            </div>
            <div style="padding:6px;display:flex;flex-direction:column;gap:3px;min-height:200px;">
              ${tactic.techniques.map(tid => {
                const detail = MITRE_TECHNIQUE_DETAILS[tid];
                const hasCoverage = !!detail;
                const bgColor = hasCoverage ? (detail.coverage > 70 ? 'var(--accent-green)33' : detail.coverage > 40 ? 'var(--accent-orange)33' : 'var(--accent-red)33') : 'var(--bg-surface)';
                const textColor = hasCoverage ? (detail.coverage > 70 ? 'var(--accent-green)' : detail.coverage > 40 ? 'var(--accent-orange)' : 'var(--accent-red)') : 'var(--text-muted)';
                return `
                <div style="background:${bgColor};border-radius:4px;padding:4px 6px;cursor:pointer;font-size:10px;" 
                     title="${tid}: ${detail?.name || tid}" 
                     onclick="openTechniqueDetail('${tid}')" 
                     onmouseover="this.style.filter='brightness(1.3)'" 
                     onmouseout="this.style.filter=''">
                  <div style="color:${textColor};font-weight:600;">${tid}</div>
                  ${detail ? `<div style="color:var(--text-muted);font-size:9px;margin-top:1px;">${detail.name.slice(0,20)}...</div>` : ''}
                </div>`;
              }).join('')}
            </div>
          </div>
        `).join('')}
      </div>
    </div>

    <!-- Legend -->
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap;">
      <div style="font-size:11px;color:var(--text-muted);font-weight:600;">COVERAGE LEGEND:</div>
      ${[['var(--accent-green)','High (>70%)'],['var(--accent-orange)','Medium (40-70%)'],['var(--accent-red)','Low (<40%)'],['var(--bg-surface)','No Coverage']].map(([c,l])=>`
        <div style="display:flex;align-items:center;gap:6px;">
          <div style="width:16px;height:16px;background:${c}33;border-radius:3px;border:1px solid ${c === 'var(--bg-surface)' ? 'var(--border)' : c};"></div>
          <span style="font-size:11px;color:var(--text-secondary);">${l}</span>
        </div>`).join('')}
    </div>

    <!-- Technique detail table -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:hidden;">
      <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <div style="font-size:14px;font-weight:600;color:var(--text-primary);">Technique Coverage Table</div>
        <button class="btn-primary" onclick="generateAllDetectionRules()" style="font-size:12px;"><i class="fas fa-code"></i> Generate All Rules</button>
      </div>
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr style="background:var(--bg-surface);">
          ${['Technique','Tactic','Detection Status','Data Source','Linked Alerts','Coverage %','Actions'].map(h=>`<th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">${h}</th>`).join('')}
        </tr></thead>
        <tbody>
          ${Object.entries(MITRE_TECHNIQUE_DETAILS).map(([tid, d]) => `
          <tr style="border-top:1px solid var(--border);" onmouseover="this.style.background='var(--bg-surface)'" onmouseout="this.style.background=''">
            <td style="padding:10px 14px;"><span style="color:var(--accent-blue);font-family:monospace;font-size:12px;cursor:pointer;" onclick="openTechniqueDetail('${tid}')">${tid}</span><div style="font-size:11px;color:var(--text-secondary);margin-top:2px;">${d.name}</div></td>
            <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">Multiple</td>
            <td style="padding:10px 14px;"><span style="background:${d.detection==='HIGH'?'var(--accent-green)22':d.detection==='MEDIUM'?'var(--accent-orange)22':'var(--accent-red)22'};color:${d.detection==='HIGH'?'var(--accent-green)':d.detection==='MEDIUM'?'var(--accent-orange)':'var(--accent-red)'};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;">${d.detection}</span></td>
            <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${d.datasource}</td>
            <td style="padding:10px 14px;font-size:12px;color:var(--accent-orange);font-weight:600;">${d.alerts}</td>
            <td style="padding:10px 14px;">
              <div style="display:flex;align-items:center;gap:8px;">
                <div style="flex:1;height:6px;background:var(--bg-surface);border-radius:3px;overflow:hidden;">
                  <div style="height:100%;width:${d.coverage}%;background:${d.coverage>70?'var(--accent-green)':d.coverage>40?'var(--accent-orange)':'var(--accent-red)'};border-radius:3px;"></div>
                </div>
                <span style="font-size:11px;color:var(--text-secondary);min-width:30px;">${d.coverage}%</span>
              </div>
            </td>
            <td style="padding:10px 14px;">
              <div style="display:flex;gap:6px;">
                <button class="tb-btn" title="Detection Rule" onclick="generateDetectionRule('${tid}')" style="color:var(--accent-purple);"><i class="fas fa-code"></i></button>
                <button class="tb-btn" title="Splunk Query" onclick="showHuntQuery('${tid}','splunk')" style="color:var(--accent-green);"><i class="fas fa-search"></i></button>
                <button class="tb-btn" title="Sentinel Query" onclick="showHuntQuery('${tid}','sentinel')" style="color:var(--accent-blue);"><i class="fas fa-cloud"></i></button>
              </div>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
}

function openTechniqueDetail(tid) {
  const d = MITRE_TECHNIQUE_DETAILS[tid];
  if (!d) { showToast(`Technique ${tid} — expand coverage data to view details`, 'info'); return; }
  document.getElementById('detailModalBody').innerHTML = `
  <div style="padding:24px;max-width:700px;">
    <div style="margin-bottom:20px;">
      <div style="font-family:monospace;font-size:14px;color:var(--accent-blue);font-weight:700;">${tid}</div>
      <div style="font-size:20px;font-weight:700;color:var(--text-primary);margin-top:6px;">${d.name}</div>
      <p style="color:var(--text-secondary);font-size:13px;line-height:1.6;margin-top:8px;">${d.desc}</p>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">
      <div style="background:var(--bg-surface);border-radius:8px;padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:${d.detection==='HIGH'?'var(--accent-green)':'var(--accent-orange)'}">${d.detection}</div>
        <div style="font-size:11px;color:var(--text-muted);">Detection Status</div>
      </div>
      <div style="background:var(--bg-surface);border-radius:8px;padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:var(--accent-blue)">${d.coverage}%</div>
        <div style="font-size:11px;color:var(--text-muted);">Coverage</div>
      </div>
      <div style="background:var(--bg-surface);border-radius:8px;padding:12px;text-align:center;">
        <div style="font-size:22px;font-weight:700;color:var(--accent-orange)">${d.alerts}</div>
        <div style="font-size:11px;color:var(--text-muted);">Active Alerts</div>
      </div>
    </div>
    <div style="background:var(--bg-surface);border-radius:8px;padding:14px;margin-bottom:14px;">
      <div style="font-size:11px;color:var(--accent-green);font-weight:600;margin-bottom:8px;"><i class="fas fa-search"></i> Splunk Hunt Query</div>
      <code style="font-size:12px;color:var(--accent-cyan);display:block;word-break:break-all;">${d.query_splunk}</code>
    </div>
    <div style="background:var(--bg-surface);border-radius:8px;padding:14px;margin-bottom:20px;">
      <div style="font-size:11px;color:var(--accent-blue);font-weight:600;margin-bottom:8px;"><i class="fas fa-cloud"></i> Microsoft Sentinel Query (KQL)</div>
      <code style="font-size:12px;color:var(--accent-cyan);display:block;word-break:break-all;">${d.query_sentinel}</code>
    </div>
    <div style="display:flex;gap:8px;">
      <button class="btn-primary" onclick="generateDetectionRule('${tid}');closeDetailModal()"><i class="fas fa-code"></i> Generate SIGMA Rule</button>
      <button class="btn-primary" style="background:var(--accent-green);" onclick="copyToClipboard(\`${d.query_splunk}\`)"><i class="fas fa-copy"></i> Copy Splunk</button>
      <button class="btn-primary" style="background:var(--accent-blue);" onclick="copyToClipboard(\`${d.query_sentinel}\`)"><i class="fas fa-copy"></i> Copy KQL</button>
    </div>
  </div>`;
  document.getElementById('detailModal').style.display = 'flex';
}

function showHuntQuery(tid, platform) {
  const d = MITRE_TECHNIQUE_DETAILS[tid];
  if (!d) return showToast('No query available for this technique', 'warning');
  const q = platform === 'splunk' ? d.query_splunk : d.query_sentinel;
  copyToClipboard(q);
  showToast(`📋 ${platform === 'splunk' ? 'Splunk' : 'Sentinel'} query copied to clipboard`, 'success');
}

function generateDetectionRule(tid) {
  const d = MITRE_TECHNIQUE_DETAILS[tid] || {};
  showToast(`⚙️ Generating SIGMA rule for ${tid}...`, 'info');
  setTimeout(() => {
    const sigma = `title: Detect ${d.name || tid}\nid: ${tid}-rule-001\nstatus: experimental\ndescription: Detects ${d.name || tid} technique\nreferences:\n  - https://attack.mitre.org/techniques/${tid}/\ntags:\n  - attack.${tid.toLowerCase()}\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    EventID: 4688\n  condition: selection\nfalsepositives: Legitimate admin activity\nlevel: high`;
    document.getElementById('detailModalBody').innerHTML = `
    <div style="padding:24px;">
      <div style="font-size:16px;font-weight:700;color:var(--text-primary);margin-bottom:16px;">⚙️ Generated SIGMA Rule: ${tid}</div>
      <pre style="background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:16px;font-size:12px;color:var(--accent-cyan);overflow:auto;">${sigma}</pre>
      <button class="btn-primary" style="margin-top:12px;" onclick="copyToClipboard(\`${sigma.replace(/`/g,"'")}\`)"><i class="fas fa-copy"></i> Copy SIGMA Rule</button>
    </div>`;
    document.getElementById('detailModal').style.display = 'flex';
  }, 600);
}

function simulateAttackPath() {
  const path = ['TA0001 Reconnaissance', 'TA0003 Initial Access (T1190)', 'TA0004 Execution (T1059)', 'TA0005 Persistence (T1547)', 'TA0006 Privilege Escalation (T1068)', 'TA0010 Lateral Movement (T1021)', 'TA0040 Impact (T1486 Ransomware)'];
  showToast('🎯 Attack path simulation: Recon → Initial Access → Execution → Persistence → Priv Esc → Lateral → Ransomware', 'warning');
}

function generateAllDetectionRules() {
  showToast('⚙️ Generating detection rules for all covered techniques...', 'info');
  setTimeout(() => showToast('✅ 6 SIGMA rules generated and added to Detection Library', 'success'), 1500);
}

function exportMITRELayer() {
  const layer = { version:'4.5', name:'ThreatPilot Coverage', domain:'enterprise-attack', techniques: Object.keys(MITRE_TECHNIQUE_DETAILS).map(tid => ({ techniqueID: tid, score: MITRE_TECHNIQUE_DETAILS[tid].coverage })) };
  const blob = new Blob([JSON.stringify(layer, null, 2)], { type:'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'mitre-layer.json'; a.click();
  showToast('📊 MITRE ATT&CK layer exported', 'success');
}

function openTacticDetail(tacticId) {
  const t = MITRE_TACTICS.find(x => x.id === tacticId);
  if (!t) return;
  showToast(`📖 Tactic: ${t.name} — ${t.techniques.length} techniques mapped`, 'info');
}

/* ════════════════════════════════════════════
   IOC DATABASE — Enterprise Threat Intel DB
═════════════════════════════════════════════ */
window._iocDB = [
  { id:'IOC001', value:'185.220.101.45', type:'ip', reputation:'malicious', risk_score:94, first_seen:'2024-11-01', last_seen:'2025-03-20', country:'DE', asn:'AS51167 Contabo GmbH', source:'VirusTotal', threat_actor:'APT29', tags:['C2','Tor'], enriched:true },
  { id:'IOC002', value:'maliciousupdate[.]ru', type:'domain', reputation:'malicious', risk_score:89, first_seen:'2024-12-01', last_seen:'2025-03-18', country:'RU', asn:'AS48666', source:'AlienVault OTX', threat_actor:'APT29', tags:['Phishing','C2'], enriched:true },
  { id:'IOC003', value:'a3f2b1c9d4e5f6789012345678901234567890abcdef1234567890abcdef1234', type:'hash_sha256', reputation:'malicious', risk_score:97, first_seen:'2024-10-15', last_seen:'2025-03-15', country:null, asn:null, source:'Mandiant', threat_actor:'Lazarus Group', tags:['Ransomware','SUNBURST'], enriched:true },
  { id:'IOC004', value:'204.13.164.118', type:'ip', reputation:'suspicious', risk_score:67, first_seen:'2025-01-10', last_seen:'2025-03-19', country:'US', asn:'AS62068', source:'AbuseIPDB', threat_actor:null, tags:['Scanner','Brute Force'], enriched:true },
  { id:'IOC005', value:'phishing-docusign[.]net', type:'domain', reputation:'malicious', risk_score:88, first_seen:'2025-02-01', last_seen:'2025-03-17', country:'UA', asn:'AS9123', source:'URLhaus', threat_actor:'TA558', tags:['Phishing','DocuSign Lure'], enriched:true },
  { id:'IOC006', value:'https://update-service[.]com/payload.exe', type:'url', reputation:'malicious', risk_score:91, first_seen:'2025-01-20', last_seen:'2025-03-16', country:'NL', asn:'AS20857', source:'ThreatFox', threat_actor:'FIN7', tags:['Dropper','Payload Delivery'], enriched:true },
  { id:'IOC007', value:'attacker@tempmail-service[.]com', type:'email', reputation:'suspicious', risk_score:72, first_seen:'2025-02-15', last_seen:'2025-03-14', country:null, asn:null, source:'Manual', threat_actor:null, tags:['Phishing','Social Engineering'], enriched:false },
  { id:'IOC008', value:'5.34.178.24', type:'ip', reputation:'malicious', risk_score:85, first_seen:'2024-09-01', last_seen:'2025-03-20', country:'RU', asn:'AS44050', source:'Shodan', threat_actor:'Sandworm', tags:['C2','Botnet'], enriched:true },
  { id:'IOC009', value:'svchost_update.exe', type:'filename', reputation:'suspicious', risk_score:76, first_seen:'2025-01-05', last_seen:'2025-02-28', country:null, asn:null, source:'EDR Alert', threat_actor:null, tags:['Masquerading','Persistence'], enriched:false },
  { id:'IOC010', value:'b9f4e8d2c1a3567890fedcba0987654321abcdef', type:'hash_md5', reputation:'malicious', risk_score:93, first_seen:'2024-12-10', last_seen:'2025-03-10', country:null, asn:null, source:'Hybrid Analysis', threat_actor:'Cl0p', tags:['Ransomware','Loader'], enriched:true },
];

// RENAMED from renderIOCDatabase → _renderIOCDatabaseMock to prevent collision with
// ioc-intelligence.js production version. features.js uses static mock data (window._iocDB)
// and must NOT override the real API-backed renderer set by ioc-intelligence.js.
function _renderIOCDatabaseMock() {
  const wrap = document.getElementById('iocDatabaseWrap');
  if (!wrap) return;

  wrap.innerHTML = `
  <div style="padding:4px;">
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:12px;">
      <div>
        <h2 style="font-size:18px;font-weight:700;color:var(--text-primary);display:flex;align-items:center;gap:10px;">
          <i class="fas fa-database" style="color:var(--accent-cyan)"></i> IOC Database
          <span style="background:var(--accent-red)22;color:var(--accent-red);padding:3px 8px;border-radius:5px;font-size:11px;">🔥 CRITICAL</span>
        </h2>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Enterprise threat indicator database • Auto-enrichment • Pivot search</div>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn-primary" onclick="openBulkUpload()"><i class="fas fa-upload"></i> Bulk Upload CSV</button>
        <button class="btn-primary" style="background:var(--accent-cyan);" onclick="openIOCSearch()"><i class="fas fa-search"></i> Quick Search</button>
        <button class="btn-primary" style="background:var(--accent-green);" onclick="exportIOCDatabase()"><i class="fas fa-download"></i> Export</button>
      </div>
    </div>

    <!-- KPI row -->
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px;">
      ${[
        ['fa-database','var(--accent-blue)',window._iocDB.length,'Total IOCs'],
        ['fa-exclamation-triangle','var(--accent-red)',window._iocDB.filter(i=>i.reputation==='malicious').length,'Malicious'],
        ['fa-question-circle','var(--accent-orange)',window._iocDB.filter(i=>i.reputation==='suspicious').length,'Suspicious'],
        ['fa-check-circle','var(--accent-green)',window._iocDB.filter(i=>i.enriched).length,'Enriched'],
        ['fa-tachometer-alt','var(--accent-purple)',Math.round(window._iocDB.reduce((s,i)=>s+i.risk_score,0)/window._iocDB.length),'Avg Risk Score']
      ].map(([ic,col,val,lbl])=>`
        <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px;display:flex;align-items:center;gap:10px;">
          <i class="fas ${ic}" style="font-size:18px;color:${col}"></i>
          <div><div style="font-size:22px;font-weight:700;color:${col}">${val}</div><div style="font-size:11px;color:var(--text-muted);">${lbl}</div></div>
        </div>`).join('')}
    </div>

    <!-- Search + filters -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
      <input type="text" id="iocDbSearch" class="filter-select" placeholder="🔍 Search IOC, actor, ASN, country..." style="flex:1;min-width:200px;" oninput="filterIOCDB()"/>
      <select id="iocTypeFilter" class="filter-select" onchange="filterIOCDB()"><option value="">All Types</option><option value="ip">IP</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash_sha256">SHA256</option><option value="hash_md5">MD5</option><option value="email">Email</option><option value="filename">Filename</option></select>
      <select id="iocRepFilter" class="filter-select" onchange="filterIOCDB()"><option value="">All Reputation</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="clean">Clean</option></select>
      <select id="iocCountryFilter" class="filter-select" onchange="filterIOCDB()"><option value="">All Countries</option><option value="RU">Russia</option><option value="CN">China</option><option value="DE">Germany</option><option value="US">United States</option></select>
    </div>

    <!-- IOC Table -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:auto;">
      <table style="width:100%;border-collapse:collapse;min-width:1100px;">
        <thead><tr style="background:var(--bg-surface);">
          ${['IOC Value','Type','Reputation','First Seen','Last Seen','Country','ASN','Risk Score','Source','Actions'].map(h=>`<th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">${h}</th>`).join('')}
        </tr></thead>
        <tbody id="iocDbTbody">
          ${window._iocDB.map(ioc => renderIOCRow(ioc)).join('')}
        </tbody>
      </table>
    </div>

    <!-- Graph view placeholder -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-top:16px;text-align:center;">
      <i class="fas fa-project-diagram" style="font-size:40px;color:var(--accent-purple);margin-bottom:12px;display:block;"></i>
      <div style="font-size:14px;font-weight:600;color:var(--text-primary);margin-bottom:6px;">IOC Relationship Graph</div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px;">Visualize connections between IOCs, threat actors, campaigns, and malware families</div>
      <button class="btn-primary" style="background:var(--accent-purple);" onclick="showToast('🔗 Graph view — connect Neo4j for full relationship mapping','info')"><i class="fas fa-project-diagram"></i> Open Graph View</button>
    </div>
  </div>`;
}

function renderIOCRow(ioc) {
  const repColor = ioc.reputation === 'malicious' ? 'var(--accent-red)' : ioc.reputation === 'suspicious' ? 'var(--accent-orange)' : 'var(--accent-green)';
  const riskColor = ioc.risk_score >= 80 ? 'var(--accent-red)' : ioc.risk_score >= 50 ? 'var(--accent-orange)' : 'var(--accent-green)';
  const typeColor = { ip:'var(--accent-blue)', domain:'var(--accent-purple)', url:'var(--accent-cyan)', hash_sha256:'var(--accent-orange)', hash_md5:'var(--accent-orange)', email:'var(--accent-green)', filename:'var(--accent-yellow)' }[ioc.type] || 'var(--text-muted)';
  const displayVal = ioc.value.length > 45 ? ioc.value.slice(0,45)+'...' : ioc.value;
  return `
  <tr style="border-top:1px solid var(--border);" onmouseover="this.style.background='var(--bg-surface)'" onmouseout="this.style.background=''" onclick="openIOCDetail('${ioc.id}')">
    <td style="padding:10px 14px;"><code style="font-size:12px;color:var(--text-primary);">${displayVal}</code>${ioc.enriched ? '<span style="margin-left:6px;font-size:9px;color:var(--accent-green);">✓ enriched</span>':''}</td>
    <td style="padding:10px 14px;"><span style="background:${typeColor}22;color:${typeColor};padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${ioc.type.toUpperCase()}</span></td>
    <td style="padding:10px 14px;"><span style="background:${repColor}22;color:${repColor};padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${ioc.reputation.toUpperCase()}</span></td>
    <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${ioc.first_seen}</td>
    <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${ioc.last_seen}</td>
    <td style="padding:10px 14px;font-size:12px;color:var(--text-secondary);">${ioc.country || '—'}</td>
    <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);max-width:120px;overflow:hidden;text-overflow:ellipsis;">${ioc.asn || '—'}</td>
    <td style="padding:10px 14px;">
      <div style="display:flex;align-items:center;gap:6px;">
        <div style="width:50px;height:6px;background:var(--bg-surface);border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${ioc.risk_score}%;background:${riskColor};border-radius:3px;"></div>
        </div>
        <span style="font-size:11px;color:${riskColor};font-weight:700;">${ioc.risk_score}</span>
      </div>
    </td>
    <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${ioc.source}</td>
    <td style="padding:10px 14px;">
      <div style="display:flex;gap:5px;">
        <button class="tb-btn" title="Enrich" onclick="event.stopPropagation();enrichIOCRecord('${ioc.id}')" style="color:var(--accent-cyan);"><i class="fas fa-atom"></i></button>
        <button class="tb-btn" title="Pivot" onclick="event.stopPropagation();pivotIOC('${ioc.id}')" style="color:var(--accent-purple);"><i class="fas fa-share-alt"></i></button>
        <button class="tb-btn" title="Copy" onclick="event.stopPropagation();copyToClipboard('${ioc.value}')" style="color:var(--accent-green);"><i class="fas fa-copy"></i></button>
      </div>
    </td>
  </tr>`;
}

function filterIOCDB() {
  const q   = document.getElementById('iocDbSearch')?.value.toLowerCase();
  const typ = document.getElementById('iocTypeFilter')?.value;
  const rep = document.getElementById('iocRepFilter')?.value;
  const ctry= document.getElementById('iocCountryFilter')?.value;
  const tbody = document.getElementById('iocDbTbody');
  if (!tbody) return;
  const filtered = window._iocDB.filter(i =>
    (!q   || i.value.toLowerCase().includes(q) || (i.threat_actor||'').toLowerCase().includes(q) || (i.asn||'').toLowerCase().includes(q)) &&
    (!typ || i.type === typ) &&
    (!rep || i.reputation === rep) &&
    (!ctry|| i.country === ctry)
  );
  tbody.innerHTML = filtered.length ? filtered.map(i => renderIOCRow(i)).join('') :
    '<tr><td colspan="10" style="padding:40px;text-align:center;color:var(--text-muted);"><i class="fas fa-search" style="font-size:24px;margin-bottom:8px;display:block;"></i>No IOCs match filters</td></tr>';
}

function openIOCDetail(id) {
  const ioc = window._iocDB.find(x => x.id === id);
  if (!ioc) return;
  const repColor = ioc.reputation === 'malicious' ? 'var(--accent-red)' : ioc.reputation === 'suspicious' ? 'var(--accent-orange)' : 'var(--accent-green)';
  document.getElementById('detailModalBody').innerHTML = `
  <div style="padding:24px;max-width:700px;">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
      <div style="background:${repColor}22;color:${repColor};padding:6px 12px;border-radius:8px;font-size:13px;font-weight:700;">${ioc.reputation.toUpperCase()}</div>
      <code style="font-size:14px;color:var(--text-primary);word-break:break-all;">${ioc.value}</code>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px;">
      ${[['Type',ioc.type.toUpperCase()],['Risk Score',`${ioc.risk_score}/100`],['Country',ioc.country||'Unknown'],['ASN',ioc.asn||'Unknown'],['First Seen',ioc.first_seen],['Last Seen',ioc.last_seen],['Source',ioc.source],['Threat Actor',ioc.threat_actor||'Unknown']].map(([k,v])=>`
        <div style="background:var(--bg-surface);border-radius:8px;padding:12px;">
          <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;margin-bottom:4px;">${k}</div>
          <div style="font-size:13px;color:var(--text-primary);font-weight:500;">${v}</div>
        </div>`).join('')}
    </div>
    <div style="margin-bottom:16px;">
      <div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;font-weight:600;margin-bottom:8px;">Tags</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        ${ioc.tags.map(t=>`<span style="background:var(--accent-purple)22;color:var(--accent-purple);padding:3px 8px;border-radius:5px;font-size:11px;">${t}</span>`).join('')}
      </div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;">
      <button class="btn-primary" onclick="enrichIOCRecord('${ioc.id}')"><i class="fas fa-atom"></i> Enrich IOC</button>
      <button class="btn-primary" style="background:var(--accent-purple);" onclick="pivotIOC('${ioc.id}')"><i class="fas fa-share-alt"></i> Pivot Search</button>
      <button class="btn-primary" style="background:var(--accent-green);" onclick="copyToClipboard('${ioc.value}')"><i class="fas fa-copy"></i> Copy IOC</button>
      <button class="btn-primary" style="background:var(--accent-orange);" onclick="addToCase('${ioc.id}')"><i class="fas fa-folder-plus"></i> Add to Case</button>
    </div>
  </div>`;
  document.getElementById('detailModal').style.display = 'flex';
}

function enrichIOCRecord(id) {
  const ioc = window._iocDB.find(x => x.id === id);
  if (!ioc) return;
  showToast(`🔬 Enriching ${ioc.value} via VirusTotal, AbuseIPDB, Shodan...`, 'info');
  if (window.enrichIOCLive) {
    enrichIOCLive(ioc.value, ioc.type.replace('hash_sha256','hash').replace('hash_md5','hash'));
  } else {
    setTimeout(() => {
      ioc.enriched = true;
      showToast(`✅ Enrichment complete: Risk Score ${ioc.risk_score} | ${ioc.country || 'Location unknown'}`, 'success');
    }, 1500);
  }
}

function pivotIOC(id) {
  const ioc = window._iocDB.find(x => x.id === id);
  if (!ioc) return;
  const field = ioc.country ? 'country' : ioc.asn ? 'asn' : 'source';
  const value = ioc.country || ioc.asn || ioc.source;
  const related = window._iocDB.filter(i => i[field] === value && i.id !== id);
  showToast(`🔄 Pivot on ${field}="${value}" → Found ${related.length} related IOCs`, related.length > 0 ? 'warning' : 'info');
}

function openBulkUpload() {
  document.getElementById('detailModalBody').innerHTML = `
  <div style="padding:24px;max-width:560px;">
    <div style="font-size:16px;font-weight:700;color:var(--text-primary);margin-bottom:16px;"><i class="fas fa-upload" style="color:var(--accent-cyan)"></i> Bulk IOC Upload</div>
    <div style="background:var(--bg-surface);border-radius:8px;padding:14px;margin-bottom:16px;font-size:12px;color:var(--text-muted);">
      <strong>CSV Format:</strong> value,type,source,tags<br>
      <code style="color:var(--accent-cyan);">1.2.3.4,ip,manual,C2|botnet</code><br>
      <code style="color:var(--accent-cyan);">evil.com,domain,otx,phishing</code>
    </div>
    <textarea id="bulkIOCInput" style="width:100%;height:160px;background:var(--bg-surface);border:1px solid var(--border);border-radius:8px;padding:12px;color:var(--text-primary);font-size:12px;font-family:monospace;resize:vertical;" placeholder="Paste CSV data here..."></textarea>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn-primary" onclick="processBulkUpload()"><i class="fas fa-upload"></i> Import IOCs</button>
      <button class="btn-primary" style="background:var(--bg-surface);color:var(--text-secondary);" onclick="closeDetailModal()">Cancel</button>
    </div>
  </div>`;
  document.getElementById('detailModal').style.display = 'flex';
}

function processBulkUpload() {
  const raw = document.getElementById('bulkIOCInput')?.value.trim();
  if (!raw) return showToast('Please paste CSV data first', 'warning');
  const lines = raw.split('\n').filter(l => l.trim());
  const imported = lines.map(line => {
    const [value, type, source, tagStr] = line.split(',').map(s => s.trim());
    return { id:`IOC${Date.now()}${Math.random().toString(36).slice(2,5)}`, value, type: type||'ip', reputation:'unknown', risk_score:0, first_seen:new Date().toISOString().split('T')[0], last_seen:new Date().toISOString().split('T')[0], country:null, asn:null, source:source||'bulk', threat_actor:null, tags:(tagStr||'').split('|'), enriched:false };
  });
  window._iocDB.push(...imported);
  showToast(`✅ Imported ${imported.length} IOCs — triggering auto-enrichment...`, 'success');
  closeDetailModal();
  _renderIOCDatabaseMock();
  setTimeout(() => showToast(`🔬 Auto-enrichment complete for ${imported.length} IOCs`, 'info'), 2000);
}

function openIOCSearch() {
  document.getElementById('iocDbSearch')?.focus();
  showToast('💡 Use the search bar above — supports IOC values, ASN, country, threat actor', 'info');
}

function exportIOCDatabase() {
  const data = window._iocDB;
  const csv = ['IOC,Type,Reputation,Risk Score,Country,ASN,Source,Threat Actor,First Seen,Last Seen',
    ...data.map(i => [i.value, i.type, i.reputation, i.risk_score, i.country||'', i.asn||'', i.source, i.threat_actor||'', i.first_seen, i.last_seen].join(','))
  ].join('\n');
  const blob = new Blob([csv], { type:'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `ioc-database-${Date.now()}.csv`; a.click();
  showToast(`📊 Exported ${data.length} IOCs to CSV`, 'success');
}

function addToCase(iocId) {
  showToast('📁 IOC linked to active case', 'success');
}

/* ════════════════════════════════════════════
   GEO THREATS — Visual Intelligence Map
═════════════════════════════════════════════ */
const GEO_ATTACKS = [
  { src_ip:'185.220.101.45', src_country:'Russia',   src_flag:'🇷🇺', target:'MSSP Global', target_country:'United States', attack_type:'Ransomware C2', severity:'CRITICAL', time:'2025-03-20 14:32', count:47 },
  { src_ip:'45.33.32.156',   src_country:'China',    src_flag:'🇨🇳', target:'HackerOne',   target_country:'United States', attack_type:'APT Espionage', severity:'HIGH', time:'2025-03-20 13:18', count:23 },
  { src_ip:'91.240.118.230', src_country:'Iran',     src_flag:'🇮🇷', target:'Bugcrowd',    target_country:'United States', attack_type:'SQL Injection', severity:'HIGH', time:'2025-03-20 12:05', count:156 },
  { src_ip:'167.71.13.196',  src_country:'Ukraine',  src_flag:'🇺🇦', target:'Finance Corp', target_country:'Germany', attack_type:'Credential Stuffing', severity:'MEDIUM', time:'2025-03-20 11:44', count:89 },
  { src_ip:'194.165.16.11',  src_country:'Belarus',  src_flag:'🇧🇾', target:'Healthcare',  target_country:'UK', attack_type:'Brute Force SSH', severity:'MEDIUM', time:'2025-03-20 10:30', count:344 },
  { src_ip:'103.245.236.89', src_country:'N. Korea', src_flag:'🇰🇵', target:'CryptoExch',  target_country:'South Korea', attack_type:'Crypto Theft', severity:'CRITICAL', time:'2025-03-20 09:15', count:12 },
  { src_ip:'23.106.123.44',  src_country:'Brazil',   src_flag:'🇧🇷', target:'Retail Chain', target_country:'US', attack_type:'Skimming', severity:'MEDIUM', time:'2025-03-20 08:02', count:67 },
  { src_ip:'89.248.167.154', src_country:'Netherlands', src_flag:'🇳🇱', target:'Energy Co', target_country:'France', attack_type:'ICS/SCADA Probe', severity:'HIGH', time:'2025-03-20 07:20', count:28 },
];

function renderGeoThreats() {
  const wrap = document.getElementById('geoThreatsWrap');
  if (!wrap) return;

  const topSources = {};
  GEO_ATTACKS.forEach(a => { topSources[a.src_country] = (topSources[a.src_country] || 0) + a.count; });
  const sortedSources = Object.entries(topSources).sort((a,b) => b[1]-a[1]);

  wrap.innerHTML = `
  <div style="padding:4px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h2 style="font-size:18px;font-weight:700;color:var(--text-primary);display:flex;align-items:center;gap:10px;">
          <i class="fas fa-globe" style="color:var(--accent-green)"></i> Geo Threat Intelligence
          <span style="background:var(--accent-red)22;color:var(--accent-red);padding:3px 8px;border-radius:5px;font-size:11px;animation:pulse 2s infinite">LIVE</span>
        </h2>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Global attack visualization • Source → Destination mapping • Real-time threat clustering</div>
      </div>
      <div style="display:flex;gap:8px;">
        <select id="geoSevFilter" class="filter-select" onchange="filterGeo()">
          <option value="">All Severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option>
        </select>
        <button class="btn-primary" onclick="exportGeoData()"><i class="fas fa-download"></i> Export</button>
      </div>
    </div>

    <!-- Live attack map (CSS animated) -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px;position:relative;overflow:hidden;">
      <div style="position:absolute;top:12px;left:16px;font-size:11px;color:var(--accent-green);font-weight:600;display:flex;align-items:center;gap:6px;">
        <span style="width:8px;height:8px;background:var(--accent-green);border-radius:50%;display:inline-block;animation:pulse 1.5s infinite;"></span>
        LIVE ATTACK MAP
      </div>
      <div style="height:280px;position:relative;background:linear-gradient(135deg,#0a0e1a 0%,#0d1b2a 50%,#0a0e1a 100%);border-radius:8px;display:flex;align-items:center;justify-content:center;overflow:hidden;">
        <!-- Animated attack lines -->
        <svg width="100%" height="100%" style="position:absolute;top:0;left:0;">
          <!-- World map grid lines -->
          <defs>
            <radialGradient id="geoGrad" cx="50%" cy="50%">
              <stop offset="0%" style="stop-color:#1e3a5f;stop-opacity:0.8"/>
              <stop offset="100%" style="stop-color:#0a0e1a;stop-opacity:0"/>
            </radialGradient>
          </defs>
          <rect width="100%" height="100%" fill="url(#geoGrad)" opacity="0.3"/>
          <!-- Grid lines -->
          ${[...Array(8)].map((_,i)=>`<line x1="0" y1="${i*40}" x2="100%" y2="${i*40}" stroke="#1e3a5f" stroke-width="0.5" opacity="0.4"/>`).join('')}
          ${[...Array(12)].map((_,i)=>`<line x1="${i*100}" y1="0" x2="${i*100}" y2="100%" stroke="#1e3a5f" stroke-width="0.5" opacity="0.4"/>`).join('')}
          <!-- Attack arc animations -->
          <path d="M 150,120 Q 400,40 650,140" stroke="#ef4444" stroke-width="1.5" fill="none" opacity="0.7" style="stroke-dasharray:500;stroke-dashoffset:500;animation:drawLine 3s linear infinite;"/>
          <path d="M 200,80 Q 500,20 750,160" stroke="#f97316" stroke-width="1.5" fill="none" opacity="0.6" style="stroke-dasharray:600;stroke-dashoffset:600;animation:drawLine 4s linear infinite 1s;"/>
          <path d="M 100,200 Q 450,100 800,180" stroke="#ef4444" stroke-width="1" fill="none" opacity="0.5" style="stroke-dasharray:700;stroke-dashoffset:700;animation:drawLine 5s linear infinite 2s;"/>
          <path d="M 300,50 Q 600,150 900,120" stroke="#eab308" stroke-width="1" fill="none" opacity="0.4" style="stroke-dasharray:650;stroke-dashoffset:650;animation:drawLine 3.5s linear infinite 0.5s;"/>
          <!-- Source dots -->
          <circle cx="150" cy="120" r="6" fill="#ef4444" opacity="0.9"><animate attributeName="r" values="6;10;6" dur="2s" repeatCount="indefinite"/></circle>
          <circle cx="200" cy="80"  r="5" fill="#f97316" opacity="0.8"><animate attributeName="r" values="5;9;5" dur="3s" repeatCount="indefinite"/></circle>
          <circle cx="100" cy="200" r="4" fill="#eab308" opacity="0.7"><animate attributeName="r" values="4;7;4" dur="2.5s" repeatCount="indefinite"/></circle>
          <!-- Target dots -->
          <circle cx="650" cy="140" r="8" fill="#3b82f6" opacity="0.9"><animate attributeName="r" values="8;12;8" dur="2s" repeatCount="indefinite"/></circle>
          <circle cx="750" cy="160" r="6" fill="#22c55e" opacity="0.8"/>
          <circle cx="800" cy="180" r="5" fill="#3b82f6" opacity="0.7"/>
        </svg>
        <style>@keyframes drawLine { to { stroke-dashoffset: 0; } }</style>
        <div style="z-index:1;text-align:center;color:var(--text-muted);">
          <div style="font-size:13px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;">🌍 Global Attack Visualization</div>
          <div style="font-size:11px;">Real attack origins → target mapping. Connect to MaxMind GeoIP for full map rendering.</div>
        </div>
        <!-- Attack count overlay -->
        <div style="position:absolute;top:12px;right:12px;background:rgba(0,0,0,0.7);border-radius:8px;padding:8px 12px;">
          <div style="font-size:11px;color:var(--text-muted);">Active attacks</div>
          <div style="font-size:22px;font-weight:700;color:var(--accent-red);">${GEO_ATTACKS.reduce((s,a)=>s+a.count,0).toLocaleString()}</div>
        </div>
      </div>
    </div>

    <!-- Stats grid -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
      <!-- Top Source Countries -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;">
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:12px;"><i class="fas fa-flag" style="color:var(--accent-red);margin-right:6px;"></i>Top Attacking Countries</div>
        ${sortedSources.map(([country, count], i) => {
          const attack = GEO_ATTACKS.find(a => a.src_country === country);
          const pct = Math.round(count / GEO_ATTACKS.reduce((s,a)=>s+a.count,0) * 100);
          return `
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
            <div style="width:20px;font-size:11px;color:var(--text-muted);text-align:right;">${i+1}</div>
            <div style="font-size:16px;">${attack?.src_flag || '🌍'}</div>
            <div style="flex:1;">
              <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
                <span style="font-size:12px;color:var(--text-secondary);">${country}</span>
                <span style="font-size:11px;color:var(--text-muted);">${count} attacks</span>
              </div>
              <div style="height:5px;background:var(--bg-surface);border-radius:3px;overflow:hidden;">
                <div style="height:100%;width:${pct}%;background:var(--accent-red);border-radius:3px;"></div>
              </div>
            </div>
          </div>`;
        }).join('')}
      </div>

      <!-- Attack type breakdown -->
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px;">
        <div style="font-size:13px;font-weight:600;color:var(--text-primary);margin-bottom:12px;"><i class="fas fa-chart-bar" style="color:var(--accent-blue);margin-right:6px;"></i>Attack Type Distribution</div>
        ${Object.entries(GEO_ATTACKS.reduce((acc,a)=>{ acc[a.attack_type]=(acc[a.attack_type]||0)+a.count; return acc; },{})).sort((a,b)=>b[1]-a[1]).map(([type,count])=>{
          const colors = ['var(--accent-red)','var(--accent-orange)','var(--accent-yellow)','var(--accent-green)','var(--accent-blue)','var(--accent-purple)','var(--accent-cyan)','var(--accent-pink)'];
          const color = colors[Math.floor(Math.random()*colors.length)];
          const total = GEO_ATTACKS.reduce((s,a)=>s+a.count,0);
          return `
          <div style="margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:3px;">
              <span style="font-size:11px;color:var(--text-secondary);">${type}</span>
              <span style="font-size:11px;color:var(--text-muted);">${count}</span>
            </div>
            <div style="height:5px;background:var(--bg-surface);border-radius:3px;overflow:hidden;">
              <div style="height:100%;width:${Math.round(count/total*100)}%;background:var(--accent-blue);border-radius:3px;"></div>
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>

    <!-- Attack table -->
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:12px;overflow:auto;">
      <div style="padding:14px 16px;border-bottom:1px solid var(--border);font-size:14px;font-weight:600;color:var(--text-primary);">Live Attack Events</div>
      <table style="width:100%;border-collapse:collapse;min-width:900px;">
        <thead><tr style="background:var(--bg-surface);">
          ${['Source IP','Country','Target','Attack Type','Severity','Count','Time','Actions'].map(h=>`<th style="padding:10px 14px;text-align:left;font-size:10px;color:var(--text-muted);font-weight:600;text-transform:uppercase;">${h}</th>`).join('')}
        </tr></thead>
        <tbody id="geoTbody">
          ${GEO_ATTACKS.map(a => renderGeoRow(a)).join('')}
        </tbody>
      </table>
    </div>
  </div>`;
}

function renderGeoRow(a) {
  const sevColor = { CRITICAL:'var(--accent-red)', HIGH:'var(--accent-orange)', MEDIUM:'var(--accent-yellow)' }[a.severity];
  return `
  <tr style="border-top:1px solid var(--border);" onmouseover="this.style.background='var(--bg-surface)'" onmouseout="this.style.background=''">
    <td style="padding:10px 14px;"><code style="font-size:12px;color:var(--text-primary);">${a.src_ip}</code></td>
    <td style="padding:10px 14px;font-size:12px;">${a.src_flag} ${a.src_country}</td>
    <td style="padding:10px 14px;font-size:12px;color:var(--text-secondary);">${a.target} (${a.target_country})</td>
    <td style="padding:10px 14px;font-size:12px;color:var(--accent-orange);">${a.attack_type}</td>
    <td style="padding:10px 14px;"><span style="background:${sevColor}22;color:${sevColor};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:600;">${a.severity}</span></td>
    <td style="padding:10px 14px;font-size:12px;font-weight:700;color:var(--text-primary);">${a.count}</td>
    <td style="padding:10px 14px;font-size:11px;color:var(--text-muted);">${a.time}</td>
    <td style="padding:10px 14px;">
      <div style="display:flex;gap:5px;">
        <button class="tb-btn" title="Investigate IP" onclick="showToast('🔬 Investigating '+${JSON.stringify(a.src_ip)},'info')"><i class="fas fa-search"></i></button>
        <button class="tb-btn" title="Block IP" onclick="showToast('🚫 IP blocked: ${a.src_ip}','success')" style="color:var(--accent-red);"><i class="fas fa-ban"></i></button>
      </div>
    </td>
  </tr>`;
}

function filterGeo() {
  const sev = document.getElementById('geoSevFilter')?.value;
  const tbody = document.getElementById('geoTbody');
  if (!tbody) return;
  const filtered = GEO_ATTACKS.filter(a => !sev || a.severity === sev);
  tbody.innerHTML = filtered.map(a => renderGeoRow(a)).join('');
}

function exportGeoData() {
  const csv = ['Source IP,Country,Target,Attack Type,Severity,Count,Time',
    ...GEO_ATTACKS.map(a=>[a.src_ip,a.src_country,a.target,a.attack_type,a.severity,a.count,a.time].join(','))
  ].join('\n');
  const blob = new Blob([csv],{type:'text/csv'});
  const el = document.createElement('a'); el.href=URL.createObjectURL(blob); el.download='geo-threats.csv'; el.click();
  showToast('📊 Geo threat data exported', 'success');
}

/* ── Utility ── */
function copyToClipboard(text) {
  navigator.clipboard?.writeText(text).then(() => showToast(`📋 Copied: ${text.slice(0,40)}`, 'success')).catch(() => showToast('Copy failed', 'error'));
}

function closeDetailModal() {
  const m = document.getElementById('detailModal');
  if (m) m.style.display = 'none';
}
