/* ══════════════════════════════════════════════════════════
   EYEbot AI — Pages Module (Enhanced v2)
   All page renderers with full interactivity
   ══════════════════════════════════════════════════════════ */

/* ────────────── COMMAND CENTER ────────────── */
function renderCommandCenter() {
  renderLatestFindings();
  renderCollectorsMini();
  renderCampaignsMini();
  initAllCharts();
}

function renderLatestFindings() {
  const container = document.getElementById('latestFindings');
  if (!container) return;
  container.innerHTML = ARGUS_DATA.findings.slice(0, 8).map(f => `
    <div class="finding-row" onclick="openFindingModal('${f.id}')">
      <div class="finding-sev sev-${f.severity.toLowerCase()}"></div>
      <span class="finding-type">${f.type}</span>
      <span class="finding-value" title="${f.value}">${f.value.length>32?f.value.slice(0,32)+'...':f.value}</span>
      <span class="finding-time">${f.time}</span>
    </div>`).join('');
}

function renderCollectorsMini() {
  const container = document.getElementById('collectorsMiniList');
  if (!container) return;
  container.innerHTML = ARGUS_DATA.collectors.slice(0, 14).map(c => `
    <div class="collector-mini-row" onclick="navigateTo('collectors')">
      <div class="collector-status-dot c-${c.status}"></div>
      <span class="collector-name">${c.name}</span>
      <span class="collector-count">${c.iocs_today.toLocaleString()}</span>
    </div>`).join('');
}

function renderCampaignsMini() {
  const container = document.getElementById('campaignsMiniList');
  if (!container) return;
  container.innerHTML = ARGUS_DATA.campaigns.filter(c => c.status === 'Active').slice(0,4).map(c => `
    <div class="campaign-mini-card" onclick="openCampaignDetail('${c.id}')">
      <div class="camp-name">${c.name}</div>
      <div class="camp-actor">${c.actor}</div>
      <div class="camp-meta">
        <span class="camp-tag sev-${c.severity.toLowerCase()}" style="font-size:9px;">${c.severity}</span>
        <span class="camp-tag">${c.findings} findings</span>
      </div>
    </div>`).join('');
}

/* ────────────── FINDINGS TABLE ────────────── */
let findingsPage = 1;
let findingsFiltered = [...ARGUS_DATA.findings];
const FINDINGS_PER_PAGE = 10;

function renderFindings() {
  findingsFiltered = [...ARGUS_DATA.findings];
  renderFindingsTable();
}

function filterFindings() {
  const sev = document.getElementById('severityFilter')?.value || '';
  const type = document.getElementById('typeFilter')?.value || '';
  const cust = document.getElementById('customerFilter')?.value || '';
  findingsFiltered = ARGUS_DATA.findings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (type && !f.type.includes(type)) return false;
    if (cust && f.customer !== cust) return false;
    return true;
  });
  findingsPage = 1;
  renderFindingsTable();
}

function renderFindingsTable() {
  const tbody = document.getElementById('findingsTableBody');
  const countEl = document.getElementById('findingsCount');
  if (!tbody) return;
  countEl.textContent = `${findingsFiltered.length} findings`;
  const start = (findingsPage - 1) * FINDINGS_PER_PAGE;
  const pageData = findingsFiltered.slice(start, start + FINDINGS_PER_PAGE);
  tbody.innerHTML = pageData.map(f => {
    const sc = f.score >= 85 ? '#ef4444' : f.score >= 65 ? '#f97316' : f.score >= 45 ? '#f59e0b' : '#22c55e';
    return `<tr onclick="openFindingModal('${f.id}')">
      <td onclick="event.stopPropagation()"><input type="checkbox" /></td>
      <td><span class="sev-badge sev-${f.severity}">${f.severity}</span></td>
      <td>${f.type}</td>
      <td class="ioc-value-cell" title="${f.value}">${f.value.length>28?f.value.slice(0,28)+'...':f.value}</td>
      <td><span style="color:var(--text-muted);font-size:11px;">${f.source}</span></td>
      <td>${f.customer}</td>
      <td><div class="score-bar-wrap"><div class="score-bar"><div class="score-bar-fill" style="width:${f.score}%;background:${sc}"></div></div><span style="font-size:11px;font-weight:700;color:${sc}">${f.score}</span></div></td>
      <td><span class="mitre-tag">${f.mitre}</span></td>
      <td style="color:var(--text-muted);font-size:11px;">${f.time}</td>
      <td><div class="table-actions" onclick="event.stopPropagation()">
        <button class="tbl-btn" title="AI Investigate" onclick="investigateWithAI('${f.id}')"><i class="fas fa-robot"></i></button>
        <button class="tbl-btn" title="View Details" onclick="openFindingModal('${f.id}')"><i class="fas fa-eye"></i></button>
        <button class="tbl-btn" title="Mark FP" onclick="showToast('Marked as False Positive','info')"><i class="fas fa-ban"></i></button>
      </div></td>
    </tr>`;
  }).join('');
  renderPagination();
}

function renderPagination() {
  const pgEl = document.getElementById('findingsPagination');
  if (!pgEl) return;
  const totalPages = Math.ceil(findingsFiltered.length / FINDINGS_PER_PAGE);
  let html = `<button class="pg-btn" onclick="changePage(${findingsPage-1})" ${findingsPage===1?'disabled':''}>◀</button>`;
  for (let i = 1; i <= totalPages; i++) html += `<button class="pg-btn ${i===findingsPage?'active':''}" onclick="changePage(${i})">${i}</button>`;
  html += `<button class="pg-btn" onclick="changePage(${findingsPage+1})" ${findingsPage===totalPages?'disabled':''}>▶</button>`;
  pgEl.innerHTML = html;
}

function changePage(page) {
  const total = Math.ceil(findingsFiltered.length / FINDINGS_PER_PAGE);
  if (page < 1 || page > total) return;
  findingsPage = page;
  renderFindingsTable();
}

/* ────────────── CAMPAIGNS ────────────── */
let campaignsFiltered = [...ARGUS_DATA.campaigns];

function renderCampaigns() {
  campaignsFiltered = [...ARGUS_DATA.campaigns];
  renderCampaignsGrid();
}

function filterCampaigns() {
  const st = document.getElementById('campStatusFilter')?.value || '';
  const sv = document.getElementById('campSevFilter')?.value || '';
  campaignsFiltered = ARGUS_DATA.campaigns.filter(c => {
    if (st && c.status !== st) return false;
    if (sv && c.severity !== sv) return false;
    return true;
  });
  document.getElementById('campaignsCount').textContent = `${campaignsFiltered.length} campaigns`;
  renderCampaignsGrid();
}

function renderCampaignsGrid() {
  const container = document.getElementById('campaignsGrid');
  if (!container) return;
  const statusColor = { Active:'#ef4444', Monitoring:'#f59e0b', Contained:'#22d3ee', Resolved:'#22c55e' };
  container.innerHTML = campaignsFiltered.map(c => `
    <div class="campaign-card" onclick="openCampaignDetail('${c.id}')">
      <div class="camp-card-header">
        <div>
          <div class="camp-card-name">${c.name}</div>
          <div class="camp-card-actor">👤 ${c.actor}</div>
        </div>
        <span class="camp-card-severity sev-badge sev-${c.severity.toLowerCase()}">${c.severity}</span>
      </div>
      <p style="font-size:11px;color:var(--text-secondary);line-height:1.5;margin-bottom:10px;">${c.description}</p>
      <div class="camp-stats-row">
        <div class="camp-stat"><div class="camp-stat-val" style="color:${statusColor[c.status]}">${c.findings}</div><div class="camp-stat-lbl">Findings</div></div>
        <div class="camp-stat"><div class="camp-stat-val">${c.iocs}</div><div class="camp-stat-lbl">IOCs</div></div>
        <div class="camp-stat"><div class="camp-stat-val">${c.customers.length}</div><div class="camp-stat-lbl">Tenants</div></div>
        <div class="camp-stat"><div class="camp-stat-val" style="font-size:11px;padding:3px 7px;border-radius:4px;background:${statusColor[c.status]}22;color:${statusColor[c.status]};">${c.status}</div><div class="camp-stat-lbl">Status</div></div>
      </div>
      <div class="camp-tags">
        ${c.techniques.slice(0,4).map(t => `<span class="camp-tag-item">${t}</span>`).join('')}
        ${c.techniques.length > 4 ? `<span class="camp-tag-item">+${c.techniques.length-4}</span>` : ''}
      </div>
      <div class="camp-progress-bar" style="margin-top:8px;"><div class="camp-progress-fill" style="width:${c.progress}%;background:${c.color};"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:4px;font-size:10px;color:var(--text-muted);">
        <span>Progress: ${c.progress}%</span>
        <span style="color:var(--accent-blue);">Click for details →</span>
      </div>
    </div>`).join('');
  document.getElementById('campaignsCount').textContent = `${campaignsFiltered.length} campaigns`;
}

/* ────────────── LIVE DETECTIONS ────────────── */
let detectionInterval = null;
let detectionCount = 18432;
const detTypes = ['API Key','Credential','CVE','Malicious IP','Domain','Dark Web','Phishing','Ransomware','SSH Key'];
const detSources = ['GitHub Gist','URLhaus','AbuseIPDB','Feodo','ThreatFox','OpenPhish','MalwareBazaar','DarkSearch','HudsonRock','grep.app'];
const detValues = ['AKIA4HP***XYZ12','CVE-2024-8749','admin:hunter2@vpn.corp.com','malupdate[.]ru','sk-proj-***T3Bl','185.220.101.45','raccoon.bin (SHA256:a3f8...)','leaked_db_2024.sql','*.evil-corp[.]net','ghp_***ZKm9'];

function renderDetections() {
  const stream = document.getElementById('detectionsStream');
  if (!stream) return;
  stream.innerHTML = '';
  for (let i = 0; i < 25; i++) stream.appendChild(createDetectionItem());
  if (detectionInterval) clearInterval(detectionInterval);
  detectionInterval = setInterval(() => {
    const item = createDetectionItem();
    stream.insertBefore(item, stream.firstChild);
    detectionCount += Math.floor(Math.random() * 5);
    const el = document.getElementById('detTotal');
    if (el) el.textContent = detectionCount.toLocaleString() + ' total';
    while (stream.children.length > 80) stream.removeChild(stream.lastChild);
  }, 1800);
}

function createDetectionItem() {
  const type = detTypes[Math.floor(Math.random() * detTypes.length)];
  const source = detSources[Math.floor(Math.random() * detSources.length)];
  const value = detValues[Math.floor(Math.random() * detValues.length)];
  const score = Math.floor(Math.random() * 70) + 25;
  const sc = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#f59e0b' : '#22c55e';
  const now = new Date();
  const time = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
  const div = document.createElement('div');
  div.className = 'detection-item';
  div.innerHTML = `<span class="det-time">${time}</span><span class="det-source">${source}</span><span class="det-type">${type}</span><span class="det-value">${value}</span><span class="det-score" style="color:${sc}">${score}</span>`;
  div.onclick = () => showToast(`${type}: ${value} (score: ${score})`, score>=80?'error':score>=60?'warning':'info');
  return div;
}

function stopDetections() {
  if (detectionInterval) { clearInterval(detectionInterval); detectionInterval = null; }
}

/* ────────────── THREAT ACTORS ────────────── */
function renderThreatActors() {
  filterActors();
}

function filterActors() {
  const nation = document.getElementById('actorNationFilter')?.value || '';
  const motiv = document.getElementById('actorMotivFilter')?.value || '';
  const filtered = ARGUS_DATA.actors.filter(a => {
    if (nation && !a.nation.includes(nation)) return false;
    if (motiv && !a.motivation.includes(motiv)) return false;
    return true;
  });
  const container = document.getElementById('actorsGrid');
  if (!container) return;
  container.innerHTML = filtered.map(a => `
    <div class="actor-card" onclick="openActorDetail('${a.id}')">
      <div class="actor-header">
        <div class="actor-avatar">${a.emoji}</div>
        <div>
          <div class="actor-name">${a.name}</div>
          <div class="actor-alias">${a.aliases.slice(0,2).join(' · ')}</div>
        </div>
        <div class="actor-nation">${a.nation}</div>
      </div>
      <p class="actor-desc">${a.desc}</p>
      <div style="font-size:10px;color:var(--text-muted);margin-bottom:6px;">
        <span style="color:var(--accent-blue);">Motivation:</span> ${a.motivation} &nbsp;
        <span style="color:var(--accent-blue);">Active since:</span> ${a.active_since}
      </div>
      <div class="actor-techniques">
        ${a.techniques.map(t => `<span class="actor-ttp">${t}</span>`).join('')}
      </div>
      <div style="margin-top:8px;font-size:10px;color:var(--accent-blue);">Click for full profile & IOCs →</div>
    </div>`).join('');
}

/* ────────────── DARK WEB ────────────── */
function renderDarkWeb() {
  filterDarkWeb();
}

function filterDarkWeb() {
  const sev = document.getElementById('dwSevFilter')?.value || '';
  const type = document.getElementById('dwTypeFilter')?.value || '';
  const filtered = ARGUS_DATA.darkweb.filter(d => {
    if (sev && d.severity !== sev) return false;
    if (type && d.type !== type) return false;
    return true;
  });
  const container = document.getElementById('darkwebGrid');
  if (!container) return;
  container.innerHTML = filtered.map(d => {
    const sc = d.severity === 'CRITICAL' ? '#ef4444' : d.severity === 'HIGH' ? '#f97316' : '#f59e0b';
    return `
    <div class="darkweb-card" onclick="openDarkWebDetail('${d.id}')">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
        <span class="dw-source-badge">${d.source}</span>
        <span style="font-size:10px;font-weight:700;color:${sc}">${d.severity}</span>
      </div>
      <div class="dw-title">${d.title}</div>
      <div class="dw-preview">${d.preview}</div>
      <div class="dw-meta">
        <span>🕐 ${d.time}</span>
        <span style="padding:2px 6px;background:rgba(0,0,0,0.3);border-radius:4px;">${d.type}</span>
        <span style="color:var(--accent-blue);margin-left:auto;font-size:10px;">View Details →</span>
      </div>
    </div>`;
  }).join('');
}

/* ────────────── EXPOSURE ────────────── */
function renderExposure() {
  const container = document.getElementById('exposureWrap');
  if (!container) return;
  container.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-bottom:16px;">
      ${ARGUS_DATA.exposure.map(e => `
        <div class="exposure-card" onclick="showToast('${e.title}: ${e.desc}','info')">
          <div class="exp-title">${e.title}</div>
          <div class="exp-value" style="color:${e.color}">${e.value}</div>
          <div class="exp-desc">${e.desc}</div>
        </div>`).join('')}
    </div>
    <div class="chart-card">
      <div class="chart-header">
        <div class="chart-title"><i class="fas fa-map"></i> Asset Exposure Map</div>
        <button class="btn-primary" style="font-size:11px;padding:5px 10px;" onclick="exportExposure()"><i class="fas fa-download"></i> Export</button>
      </div>
      <div id="exposureChart" style="height:240px;"></div>
    </div>`;
  renderExposureMap();
}

function renderExposureMap() {
  const container = document.getElementById('exposureChart');
  if (!container) return;
  const assets = [
    {name:'API Endpoints',count:847,color:'rgba(239,68,68,0.7)'},
    {name:'Web Apps',count:234,color:'rgba(249,115,22,0.7)'},
    {name:'Cloud Storage',count:156,color:'rgba(168,85,247,0.7)'},
    {name:'Databases',count:89,color:'rgba(245,158,11,0.7)'},
    {name:'VPN Gateways',count:67,color:'rgba(59,130,246,0.7)'},
    {name:'Dev Envs',count:312,color:'rgba(236,72,153,0.7)'},
    {name:'CI/CD',count:123,color:'rgba(34,197,94,0.7)'},
  ];
  const total = assets.reduce((s,a) => s+a.count, 0);
  container.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;padding:4px;';
  assets.forEach(a => {
    const pct = (a.count/total*100).toFixed(1);
    const w = Math.max(80, (a.count/total)*100*8);
    const d = document.createElement('div');
    d.style.cssText = `background:${a.color};border-radius:8px;padding:12px;width:${w}px;min-width:80px;flex-shrink:0;cursor:pointer;transition:transform 0.15s ease;`;
    d.innerHTML = `<div style="font-size:14px;font-weight:800;color:white;">${a.count}</div><div style="font-size:10px;color:rgba(255,255,255,0.9);">${a.name}</div><div style="font-size:9px;color:rgba(255,255,255,0.7);">${pct}%</div>`;
    d.onmouseover = () => { d.style.transform='scale(1.05)'; d.style.zIndex='10'; };
    d.onmouseout = () => { d.style.transform='scale(1)'; d.style.zIndex='1'; };
    d.onclick = () => showToast(`${a.name}: ${a.count} assets (${pct}% of total exposure)`, 'info');
    container.appendChild(d);
  });
}

function exportExposure() {
  const csv = 'title,value,description\n' + ARGUS_DATA.exposure.map(e => `"${e.title}","${e.value}","${e.desc}"`).join('\n');
  downloadAsFile('threatpilot_exposure.csv', csv, 'text/csv');
  showToast('Exposure data exported', 'success');
}

/* ────────────── IOC REGISTRY ────────────── */
function renderIOCRegistry() {
  const container = document.getElementById('iocRegistryWrap');
  if (!container) return;
  const total = ARGUS_DATA.ioc_registry.reduce((s,c) => s+c.types.length, 0);
  const proven = ARGUS_DATA.ioc_registry.reduce((s,c) => s+c.types.filter(t=>t.status==='proven').length, 0);
  const working = ARGUS_DATA.ioc_registry.reduce((s,c) => s+c.types.filter(t=>t.status==='working').length, 0);
  const theoretical = ARGUS_DATA.ioc_registry.reduce((s,c) => s+c.types.filter(t=>t.status==='theoretical').length, 0);

  container.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;">
      <div class="metric-card info" style="padding:12px;"><div class="metric-icon"><i class="fas fa-fingerprint"></i></div><div class="metric-body"><div class="metric-value">${total}</div><div class="metric-label">Total IOC Types</div></div></div>
      <div class="metric-card green" style="padding:12px;"><div class="metric-icon"><i class="fas fa-check-circle"></i></div><div class="metric-body"><div class="metric-value">${proven}</div><div class="metric-label">Proven (Live DB)</div></div></div>
      <div class="metric-card cyan" style="padding:12px;"><div class="metric-icon"><i class="fas fa-cog"></i></div><div class="metric-body"><div class="metric-value">${working}</div><div class="metric-label">Working (Verified)</div></div></div>
      <div class="metric-card purple" style="padding:12px;"><div class="metric-icon"><i class="fas fa-flask"></i></div><div class="metric-body"><div class="metric-value">${theoretical}</div><div class="metric-label">Theoretical</div></div></div>
    </div>
    <div id="iocRegistryTableWrap">
      ${renderIOCTable(ARGUS_DATA.ioc_registry)}
    </div>`;
}

function filterIOCRegistry() {
  const search = document.getElementById('iocSearch')?.value.toLowerCase() || '';
  const status = document.getElementById('iocStatusFilter')?.value || '';
  const filtered = ARGUS_DATA.ioc_registry.map(cat => ({
    ...cat,
    types: cat.types.filter(t => {
      if (status && t.status !== status) return false;
      if (search && !t.name.toLowerCase().includes(search) && !cat.category.toLowerCase().includes(search)) return false;
      return true;
    })
  })).filter(cat => cat.types.length > 0);
  const wrap = document.getElementById('iocRegistryTableWrap');
  if (wrap) wrap.innerHTML = renderIOCTable(filtered);
}

function renderIOCTable(registry) {
  return registry.map(cat => `
    <div style="margin-bottom:14px;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <div style="width:14px;height:14px;border-radius:3px;background:${cat.color};flex-shrink:0;"></div>
        <span style="font-size:13px;font-weight:700;">${cat.category}</span>
        <span style="font-size:10px;padding:2px 7px;border-radius:10px;background:rgba(59,130,246,0.15);color:#60a5fa;">${cat.types.length} types</span>
      </div>
      <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);overflow:hidden;">
        <table class="ioc-registry-table">
          <thead><tr><th>IOC Type</th><th>Status</th><th>Detection Regex (preview)</th><th>Actions</th></tr></thead>
          <tbody>
            ${cat.types.map(t => {
              const sc = {proven:'#22c55e',working:'#3b82f6',theoretical:'#64748b'}[t.status];
              return `
              <tr onclick="openIOCDetail('${cat.category}','${t.name}')">
                <td><code style="font-size:12px;color:var(--accent-cyan);">${t.name}</code></td>
                <td><span style="padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;background:${sc}20;color:${sc};">${t.status.toUpperCase()}</span></td>
                <td><code style="font-size:10px;color:var(--text-muted);">${t.regex.slice(0,50)}${t.regex.length>50?'...':''}</code></td>
                <td onclick="event.stopPropagation()">
                  <div style="display:flex;gap:4px;">
                    <button class="tbl-btn" title="View Details" onclick="openIOCDetail('${cat.category}','${t.name}')"><i class="fas fa-eye"></i></button>
                    <button class="tbl-btn" title="Copy Regex" onclick="copyToClipboard('${t.regex.replace(/'/g,"\\'")}')"><i class="fas fa-copy"></i></button>
                    <button class="tbl-btn" title="Test Pattern" onclick="showToast('Testing ${t.name} against live IOC DB...','info')"><i class="fas fa-play"></i></button>
                  </div>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>`).join('');
}

/* ────────────── AI ORCHESTRATOR ────────────── */
function renderAIOrchestrator() {
  renderInvestigationList();
  renderToolLog();
}

function renderInvestigationList() {
  const container = document.getElementById('invList');
  if (!container) return;
  container.innerHTML = ARGUS_DATA.recent_investigations.map(inv => {
    const sc = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#22c55e'}[inv.severity];
    return `<div class="inv-item" onclick="loadInvestigation('${inv.query.replace(/'/g,"\\'")}')">
      <div class="inv-query">${inv.query.slice(0,50)}${inv.query.length>50?'...':''}</div>
      <div class="inv-meta"><span style="color:${sc}">${inv.severity}</span><span>${inv.time}</span></div>
      <div style="font-size:9px;color:var(--text-muted);margin-top:2px;">${inv.tools} tools · ${inv.iterations} iters</div>
    </div>`;
  }).join('');
}

function renderToolLog() {
  const container = document.getElementById('toolLog');
  if (!container) return;
  const tools = [
    {name:'whois_lookup',status:'✓ 200',time:'1.2s'},
    {name:'abuseipdb_check',status:'✓ 200',time:'0.8s'},
    {name:'virustotal_check',status:'✓ 200',time:'2.1s'},
    {name:'shodan_query',status:'✓ 200',time:'1.4s'},
    {name:'threatfox',status:'✓ 200',time:'0.6s'},
  ];
  container.innerHTML = tools.map(t => `
    <div class="tool-log-item">
      <span class="tool-name">${t.name}</span>
      <span class="tool-status">${t.status}</span>
      <span class="tool-time">${t.time}</span>
    </div>`).join('');
}

/* ────────────── COLLECTORS ────────────── */
function renderCollectors() {
  const container = document.getElementById('collectorsPageWrap');
  if (!container) return;
  const online = ARGUS_DATA.collectors.filter(c=>c.status==='online').length;
  const warning = ARGUS_DATA.collectors.filter(c=>c.status==='warning').length;
  const offline = ARGUS_DATA.collectors.filter(c=>c.status==='offline').length;
  const free = ARGUS_DATA.collectors.filter(c=>c.type==='free').length;
  const keyed = ARGUS_DATA.collectors.filter(c=>c.type==='keyed').length;

  container.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px;">
      <div class="metric-card green" style="padding:10px;"><div class="metric-icon"><i class="fas fa-check-circle"></i></div><div class="metric-body"><div class="metric-value">${online}</div><div class="metric-label">Online</div></div></div>
      <div class="metric-card high" style="padding:10px;"><div class="metric-icon"><i class="fas fa-exclamation-circle"></i></div><div class="metric-body"><div class="metric-value">${warning}</div><div class="metric-label">Warning</div></div></div>
      <div class="metric-card" style="padding:10px;border-left:3px solid var(--text-muted);"><div class="metric-icon" style="background:rgba(100,116,139,0.15);color:var(--text-muted);"><i class="fas fa-times-circle"></i></div><div class="metric-body"><div class="metric-value">${offline}</div><div class="metric-label">Offline</div></div></div>
      <div class="metric-card green" style="padding:10px;"><div class="metric-icon"><i class="fas fa-unlock"></i></div><div class="metric-body"><div class="metric-value">${free}</div><div class="metric-label">Free</div></div></div>
      <div class="metric-card cyan" style="padding:10px;"><div class="metric-icon"><i class="fas fa-key"></i></div><div class="metric-body"><div class="metric-value">${keyed}</div><div class="metric-label">API Key</div></div></div>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">
      <div class="collectors-tabs" id="collectorTabs">
        <button class="coll-tab active" onclick="filterCollectors(this,'all')">All (${ARGUS_DATA.collectors.length})</button>
        <button class="coll-tab" onclick="filterCollectors(this,'free')">Free (${free})</button>
        <button class="coll-tab" onclick="filterCollectors(this,'keyed')">Keyed (${keyed})</button>
        <button class="coll-tab" onclick="filterCollectors(this,'online')">Online (${online})</button>
        <button class="coll-tab" onclick="filterCollectors(this,'warning')">Warning (${warning})</button>
      </div>
      <div style="margin-left:auto;display:flex;gap:6px;">
        <button class="btn-export-csv" onclick="exportAllCollectorIOCs('csv')" style="font-size:11px;padding:6px 10px;"><i class="fas fa-file-csv"></i> Export All IOCs CSV</button>
        <button class="btn-export-json" onclick="exportAllCollectorIOCs('json')" style="font-size:11px;padding:6px 10px;"><i class="fas fa-code"></i> Export All IOCs JSON</button>
      </div>
    </div>
    <div class="collectors-grid-full" id="collectorsGridFull">
      ${renderCollectorCards(ARGUS_DATA.collectors)}
    </div>`;
}

function filterCollectors(btn, filter) {
  document.querySelectorAll('.coll-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const filtered = filter === 'all' ? ARGUS_DATA.collectors :
    ARGUS_DATA.collectors.filter(c => filter === 'free' ? c.type==='free' : filter === 'keyed' ? c.type==='keyed' : c.status===filter);
  document.getElementById('collectorsGridFull').innerHTML = renderCollectorCards(filtered);
}

function renderCollectorCards(list) {
  return list.map(c => `
    <div class="collector-card ${c.status}" onclick="openCollectorConfig('${c.id}')">
      <div class="coll-card-header">
        <div class="coll-card-name">${c.name}</div>
        <span class="coll-status-label status-${c.status}">${c.status.toUpperCase()}</span>
      </div>
      <div class="coll-card-desc">${c.desc}</div>
      <div class="coll-card-stats">
        <div class="coll-stat"><div class="coll-stat-val">${c.iocs_today.toLocaleString()}</div><div class="coll-stat-lbl">Today</div></div>
        <div class="coll-stat"><div class="coll-stat-val">${(c.iocs_total/1000).toFixed(0)}K</div><div class="coll-stat-lbl">Total</div></div>
        <div class="coll-stat" style="margin-left:auto;text-align:right;"><div class="coll-stat-val" style="font-size:11px;color:var(--text-muted);">${c.last_run}</div><div class="coll-stat-lbl">Last Run</div></div>
      </div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-top:6px;">
        <span class="coll-card-badge badge-${c.type}">${c.type==='free'?'🔓 Free':'🔑 API Key'}</span>
        <span style="font-size:10px;color:var(--accent-blue);">Configure →</span>
      </div>
    </div>`).join('');
}

function exportAllCollectorIOCs(format) {
  if (format === 'csv') {
    const rows = ['id,name,type,status,iocs_today,iocs_total,category'];
    ARGUS_DATA.collectors.forEach(c => rows.push(`${c.id},"${c.name}",${c.type},${c.status},${c.iocs_today},${c.iocs_total},"${c.category}"`));
    downloadAsFile('threatpilot_all_collector_iocs.csv', rows.join('\n'), 'text/csv');
    showToast('All collector feed IOCs exported as CSV', 'success');
  } else {
    downloadAsFile('threatpilot_all_collector_iocs.json', JSON.stringify({exported:new Date().toISOString(),collectors:ARGUS_DATA.collectors},null,2), 'application/json');
    showToast('All collector feed IOCs exported as JSON', 'success');
  }
}

/* ────────────── PLAYBOOKS ────────────── */
function renderPlaybooks() {
  const container = document.getElementById('playbooksWrap');
  if (!container) return;
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h3 style="font-size:15px;font-weight:700;">Automated Response Playbooks</h3>
        <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">96 playbooks · Click any to view steps, apply, or export</p>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn-primary" onclick="openNewPlaybookModal()"><i class="fas fa-plus"></i> New Playbook</button>
        <button class="btn-export-json" onclick="exportAllPlaybooks()" style="font-size:11px;padding:7px 12px;"><i class="fas fa-download"></i> Export All</button>
      </div>
    </div>
    <div class="playbooks-grid">
      ${ARGUS_DATA.playbooks.map(pb => `
        <div class="playbook-card" onclick="openPlaybookDetail('${pb.id}')">
          <div class="pb-header">
            <div class="pb-name">${pb.name}</div>
            <span class="pb-category">${pb.category}</span>
          </div>
          <div class="pb-desc">${pb.desc}</div>
          <div class="pb-meta">
            <span><i class="fas fa-list-ol"></i> ${pb.steps} steps</span>
            <span><i class="fas fa-th"></i> ${pb.mitre_coverage} TTPs</span>
          </div>
          <div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;">
            ${pb.triggers.map(t => `<span style="font-size:9px;padding:1px 5px;background:rgba(34,211,238,0.1);color:var(--accent-cyan);border-radius:3px;font-family:monospace;">${t}</span>`).join('')}
          </div>
          <div style="margin-top:8px;display:flex;gap:4px;" onclick="event.stopPropagation()">
            <button class="tbl-btn" title="Apply" onclick="applyPlaybook('${pb.id}')"><i class="fas fa-play"></i></button>
            <button class="tbl-btn" title="Export" onclick="exportPlaybookJSON('${pb.id}')"><i class="fas fa-download"></i></button>
            <span style="font-size:10px;color:var(--text-muted);margin-left:auto;align-self:center;">Click to view steps</span>
          </div>
        </div>`).join('')}
    </div>`;
}

function exportAllPlaybooks() {
  downloadAsFile('threatpilot_playbooks.json', JSON.stringify(ARGUS_DATA.playbooks, null, 2), 'application/json');
  showToast('All playbooks exported as JSON', 'success');
}

/* ────────────── CUSTOMERS/TENANTS ────────────── */
function renderCustomers() {
  const container = document.getElementById('customersGrid');
  if (!container) return;
  container.innerHTML = `
    <div style="grid-column:1/-1;display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
      <h3 style="font-size:15px;font-weight:700;">Tenant Management</h3>
      <button class="btn-primary" onclick="openTenantDetail('new')"><i class="fas fa-plus"></i> Add Tenant</button>
    </div>
    ${ARGUS_DATA.tenants.map(t => `
    <div class="customer-card" onclick="openTenantDetail('${t.id}')">
      <div class="cust-header">
        <div class="cust-logo" style="background:${t.color}22;color:${t.color};">${t.emoji}</div>
        <div>
          <div class="cust-name">${t.name}</div>
          <span class="cust-plan">${t.plan}</span>
        </div>
        <span class="sev-badge sev-${t.risk.toLowerCase()}" style="margin-left:auto;">${t.risk}</span>
      </div>
      <div class="cust-metrics">
        <div class="cust-metric"><div class="cust-metric-val" style="color:${t.color}">${ARGUS_DATA.findings.filter(f=>f.customer===t.short).length}</div><div class="cust-metric-lbl">Findings</div></div>
        <div class="cust-metric"><div class="cust-metric-val">${t.collectors}</div><div class="cust-metric-lbl">Collectors</div></div>
        <div class="cust-metric"><div class="cust-metric-val">${ARGUS_DATA.users.filter(u=>u.tenant===t.name).length}</div><div class="cust-metric-lbl">Users</div></div>
      </div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">
        <span style="font-size:10px;padding:2px 6px;background:rgba(34,211,238,0.1);color:var(--accent-cyan);border-radius:4px;">${t.siem}</span>
        <span style="font-size:10px;padding:2px 6px;background:rgba(168,85,247,0.1);color:#c084fc;border-radius:4px;">${t.edr}</span>
        <span style="font-size:10px;color:var(--text-muted);margin-left:auto;">Since ${t.created}</span>
      </div>
    </div>`).join('')}`;
}

/* ────────────── REPORTS ────────────── */
function renderReports() {
  const container = document.getElementById('reportsWrap');
  if (!container) return;
  const tenantOptions = ARGUS_DATA.tenants.map(t => `<option value="${t.short}">${t.name}</option>`).join('');
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
      <div>
        <h3 style="font-size:15px;font-weight:700;">Report Center</h3>
        <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">Generate and export intelligence reports in PDF, CSV, JSON, or STIX format</p>
      </div>
      <div style="display:flex;gap:8px;align-items:center;">
        <select class="filter-select" id="reportTenantFilter" style="width:180px;"><option value="">All Tenants</option>${tenantOptions}</select>
        <button class="btn-primary" onclick="quickGeneratePDF()" style="white-space:nowrap;"><i class="fas fa-file-pdf"></i> Quick PDF All</button>
      </div>
    </div>
    <div class="reports-grid">
      ${ARGUS_DATA.report_templates.map(rt => `
        <div class="report-card" onclick="openReportModal('${rt.id}')">
          <div class="rpt-icon">${rt.icon}</div>
          <div class="rpt-name">${rt.name}</div>
          <div class="rpt-desc">${rt.desc}</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px;">
            ${rt.formats.map(f => `<span class="fmt-badge fmt-${f.toLowerCase()}">${f}</span>`).join('')}
            <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:rgba(100,116,139,0.15);color:var(--text-muted);margin-left:auto;">${rt.type}</span>
          </div>
          <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px;">
            ${rt.formats.map(f => `<button class="rpt-fmt-btn" onclick="event.stopPropagation();doGenerateReport('${rt.id}','${f}')" title="Export as ${f}"><i class="fas fa-${f==='PDF'?'file-pdf':f==='CSV'?'file-csv':f==='STIX'?'shield-alt':'code'}"></i> ${f}</button>`).join('')}
          </div>
          <button class="rpt-btn" onclick="event.stopPropagation();openReportModal('${rt.id}')">
            <i class="fas fa-file-export"></i> Configure & Export
          </button>
        </div>`).join('')}
    </div>`;
}

function quickGeneratePDF() {
  const tenant = document.getElementById('reportTenantFilter')?.value || '';
  generateReport('RT001', 'PDF', tenant || null);
}

function doGenerateReport(rtId, fmt) {
  const tenant = document.getElementById('reportTenantFilter')?.value || '';
  generateReport(rtId, fmt, tenant || null);
}

/* ────────────── SETTINGS ────────────── */
function renderSettings() {
  const container = document.getElementById('settingsWrap');
  if (!container) return;
  const user = CURRENT_USER || ARGUS_DATA.users[0];
  const userName = CURRENT_USER ? CURRENT_USER.name : user.name;
  const userRole = CURRENT_USER ? CURRENT_USER.role : user.role;
  container.innerHTML = `
    <div style="margin-bottom:16px;">
      <h3 style="font-size:15px;font-weight:700;">Platform Settings</h3>
      <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">EYEbot AI v16.4.7 · Logged in as ${userName} (${userRole})</p>
    </div>`;
  // Only super_admin and admin can see full settings
  const isAdmin = userRole === 'SUPER_ADMIN' || userRole === 'ADMIN';
  if (!isAdmin) {
    container.innerHTML += `<div style="padding:24px;text-align:center;color:var(--text-muted);"><i class="fas fa-lock" style="font-size:32px;margin-bottom:12px;display:block;"></i><div style="font-size:13px;">Settings restricted to Admin and Super Admin roles</div></div>`;
    return;
  }
  container.innerHTML += `
    <div class="settings-section">
      <div class="settings-section-title">🤖 AI Configuration</div>
      <div class="settings-row"><div><div class="settings-label">Primary AI Provider</div><div class="settings-desc">Local Ollama with Qwen3:8B — GPU accelerated</div></div><div style="font-size:12px;color:var(--accent-cyan);font-weight:600;">Ollama / Qwen3:8B ✓</div></div>
      <div class="settings-row"><div><div class="settings-label">Ollama Endpoint</div><div class="settings-desc">Local Ollama server URL</div></div><input class="settings-input" value="http://localhost:11434" id="ollamaEndpointSetting" /></div>
      <div class="settings-row"><div><div class="settings-label">GPU Acceleration</div><div class="settings-desc">CUDA/ROCm for faster inference</div></div><div class="toggle-switch on" onclick="this.classList.toggle('on')"></div></div>
      <div class="settings-row"><div><div class="settings-label">Max Iterations</div><div class="settings-desc">Max autonomous investigation iterations</div></div><input class="settings-input" type="number" value="12" min="1" max="20" /></div>
      <div class="settings-row"><div><div class="settings-label">OpenAI API Key</div><div class="settings-desc">GPT-4o fallback</div></div><input class="settings-input" type="password" value="sk-proj-***" /></div>
      <div class="settings-row"><div><div class="settings-label">Anthropic API Key</div><div class="settings-desc">Claude 3.5 Sonnet</div></div><input class="settings-input" type="password" value="sk-ant-***" /></div>
      <div class="settings-row"><div><div class="settings-label">Google Gemini Key</div><div class="settings-desc">Gemini 2.0 Flash</div></div><input class="settings-input" type="password" value="AIza***" /></div>
    </div>
    <div class="settings-section">
      <div class="settings-section-title">📡 Collector Settings</div>
      <div class="settings-row"><div><div class="settings-label">Collection Interval</div><div class="settings-desc">Poll frequency for threat feeds</div></div><select class="filter-select"><option>Every 5 minutes</option><option selected>Every 15 minutes</option><option>Every hour</option></select></div>
      <div class="settings-row"><div><div class="settings-label">VirusTotal API Key</div><div class="settings-desc">Multi-AV scanning</div></div><input class="settings-input" type="password" placeholder="Enter VT key..." /></div>
      <div class="settings-row"><div><div class="settings-label">Shodan API Key</div><div class="settings-desc">Network scanning</div></div><input class="settings-input" type="password" placeholder="Enter Shodan key..." /></div>
      <div class="settings-row"><div><div class="settings-label">Auto-sync on boot</div><div class="settings-desc">Start pipeline automatically</div></div><div class="toggle-switch on" onclick="this.classList.toggle('on')"></div></div>
    </div>
    <div class="settings-section">
      <div class="settings-section-title">🔔 Alerts & Notifications</div>
      <div class="settings-row"><div><div class="settings-label">Critical Alert Webhook</div><div class="settings-desc">Slack/Teams integration</div></div><input class="settings-input" type="text" placeholder="https://hooks.slack.com/..." /></div>
      <div class="settings-row"><div><div class="settings-label">Email Notifications</div><div class="settings-desc">Critical findings via email</div></div><div class="toggle-switch on" onclick="this.classList.toggle('on')"></div></div>
      <div class="settings-row"><div><div class="settings-label">Cross-Tenant FP Learning</div><div class="settings-desc">Share false positive data to improve accuracy</div></div><div class="toggle-switch on" onclick="this.classList.toggle('on')"></div></div>
    </div>
    <div class="settings-section">
      <div class="settings-section-title">👤 My Account</div>
      <div class="settings-row">
        <div><div class="settings-label">Display Name</div><div class="settings-desc">Your name shown across the platform</div></div>
        <input class="settings-input" id="myDisplayName" value="${userName}" style="min-width:180px;" />
      </div>
      <div class="settings-row">
        <div><div class="settings-label">Email Address</div><div class="settings-desc">Login email</div></div>
        <input class="settings-input" id="myEmail" value="${CURRENT_USER?.email || ''}" style="min-width:220px;" />
      </div>
      <div class="settings-row">
        <div><div class="settings-label">Change Password</div><div class="settings-desc">Set a new password</div></div>
        <div style="display:flex;gap:6px;">
          <input class="settings-input" type="password" id="myOldPass" placeholder="Current password" />
          <input class="settings-input" type="password" id="myNewPass" placeholder="New password" />
          <button class="btn-primary" style="font-size:11px;white-space:nowrap;" onclick="changeMyPassword()"><i class="fas fa-key"></i> Change</button>
        </div>
      </div>
      <div class="settings-row">
        <div><div class="settings-label">Multi-Factor Auth (MFA)</div><div class="settings-desc">TOTP via Authenticator app</div></div>
        <div class="toggle-switch on" onclick="this.classList.toggle('on');showToast('MFA setting updated','success')"></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:4px;">
        <button class="btn-primary" onclick="saveMyProfile()"><i class="fas fa-save"></i> Save Profile</button>
      </div>
    </div>
    <div class="settings-section">
      <div class="settings-section-title" style="display:flex;align-items:center;justify-content:space-between;">
        <span>👥 User Management</span>
        <button class="btn-primary" style="font-size:11px;" onclick="openAddUserModal()"><i class="fas fa-user-plus"></i> Add User</button>
      </div>
      <div id="usersManagementTable">
        ${renderUsersTable()}
      </div>
    </div>
    <div style="display:flex;gap:8px;margin-top:8px;">
      <button class="btn-primary" onclick="showToast('Settings saved!','success')"><i class="fas fa-save"></i> Save Settings</button>
      <button style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);font-size:12px;cursor:pointer;" onclick="showToast('Reset to defaults','info')">Reset</button>
    </div>\n  `;
}

function renderUsersTable() {
  const users = ARGUS_DATA.users;
  return `<table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;">
    <thead><tr style="background:var(--bg-elevated);">
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">User</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">Email</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">Role</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">Tenant</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">MFA</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">Status</th>
      <th style="padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:var(--text-muted);">Actions</th>
    </tr></thead>
    <tbody>
      ${users.map(u => `
        <tr style="border-bottom:1px solid var(--border);" id="user-row-${u.id}">
          <td style="padding:8px 10px;">
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#3b82f6,#a855f7);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:white;flex-shrink:0;">${u.avatar}</div>
              <span style="font-weight:600;">${u.name}</span>
            </div>
          </td>
          <td style="padding:8px 10px;color:var(--text-muted);font-size:11px;">${u.email}</td>
          <td style="padding:8px 10px;">
            <span class="role-badge ${u.role.toLowerCase().includes('super')?'admin':u.role.toLowerCase().includes('admin')?'admin':u.role.toLowerCase().includes('analyst')?'analyst':'viewer'}">${u.role}</span>
          </td>
          <td style="padding:8px 10px;font-size:11px;color:var(--text-secondary);">${u.tenant}</td>
          <td style="padding:8px 10px;">${u.mfa ? '<span style="color:#22c55e;font-size:11px;font-weight:600;">✓ Active</span>' : '<span style="color:#ef4444;font-size:11px;">✗ Off</span>'}</td>
          <td style="padding:8px 10px;">
            <span style="font-size:10px;padding:2px 7px;border-radius:4px;background:${u.status==='active'?'rgba(34,197,94,0.15)':'rgba(100,116,139,0.15)'};color:${u.status==='active'?'#4ade80':'var(--text-muted)'};">${u.status}</span>
          </td>
          <td style="padding:8px 10px;">
            <div style="display:flex;gap:4px;">
              <button class="tbl-btn" title="Edit User" onclick="openEditUserModal('${u.id}')"><i class="fas fa-edit"></i></button>
              <button class="tbl-btn" title="Reset Password" onclick="showToast('Password reset email sent to ${u.email}','success')"><i class="fas fa-key"></i></button>
              <button class="tbl-btn" title="${u.status==='active'?'Deactivate':'Activate'} User" onclick="toggleUserStatus('${u.id}')"><i class="fas fa-${u.status==='active'?'user-slash':'user-check'}"></i></button>
            </div>
          </td>
        </tr>`).join('')}
    </tbody>
  </table>`;
}

function saveMyProfile() {
  const name  = document.getElementById('myDisplayName')?.value.trim();
  const email = document.getElementById('myEmail')?.value.trim();
  if (!name) { showToast('Display name cannot be empty','error'); return; }
  if (CURRENT_USER) {
    CURRENT_USER.name   = name;
    CURRENT_USER.email  = email;
    CURRENT_USER.avatar = name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase();
    // Update user in ARGUS_DATA
    const u = ARGUS_DATA.users.find(x => x.email === email || x.id === 'U001');
    if (u) { u.name = name; u.email = email; u.avatar = CURRENT_USER.avatar; }
    // Update sidebar display
    if (typeof updateUserUI === 'function') updateUserUI();
    const topAv = document.getElementById('topbarAvatar');
    const sidAv = document.getElementById('sidebarUserAv');
    if (topAv) topAv.textContent = CURRENT_USER.avatar;
    if (sidAv) sidAv.textContent = CURRENT_USER.avatar;
  }
  showToast('Profile updated successfully!', 'success');
}

function changeMyPassword() {
  const oldPass = document.getElementById('myOldPass')?.value;
  const newPass = document.getElementById('myNewPass')?.value;
  if (!oldPass || !newPass) { showToast('Both fields required','error'); return; }
  if (newPass.length < 8) { showToast('New password must be at least 8 characters','error'); return; }
  // Password change requires real API call in production
  // For now we just validate the new password meets policy
  document.getElementById('myOldPass').value = '';
  document.getElementById('myNewPass').value = '';
  showToast('Password changed successfully!', 'success');
}

function toggleUserStatus(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  u.status = u.status === 'active' ? 'inactive' : 'active';
  showToast(`User ${u.name} ${u.status === 'active' ? 'activated' : 'deactivated'}`, u.status === 'active' ? 'success' : 'warning');
  // Refresh the table
  const wrap = document.getElementById('usersManagementTable');
  if (wrap) wrap.innerHTML = renderUsersTable();
}

function openEditUserModal(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  const modal = document.createElement('div');
  modal.id = 'editUserOverlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;width:420px;max-width:90vw;">
      <div style="font-size:16px;font-weight:800;margin-bottom:16px;">✏️ Edit User: ${u.name}</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Full Name</label><input id="eu_name" value="${u.name}" class="settings-input" style="width:100%;" /></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Email</label><input id="eu_email" value="${u.email}" class="settings-input" style="width:100%;" /></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Role</label>
          <select id="eu_role" class="settings-input" style="width:100%;">
            <option ${u.role==='SUPER_ADMIN'?'selected':''} value="SUPER_ADMIN">SUPER ADMIN</option>
            <option ${u.role==='ADMIN'?'selected':''} value="ADMIN">ADMIN</option>
            <option ${u.role==='ANALYST'?'selected':''} value="ANALYST">ANALYST</option>
            <option ${u.role==='VIEWER'?'selected':''} value="VIEWER">VIEWER</option>
          </select></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Tenant</label>
          <select id="eu_tenant" class="settings-input" style="width:100%;">
            ${ARGUS_DATA.tenants.map(t=>`<option ${u.tenant===t.name?'selected':''}>${t.name}</option>`).join('')}
          </select></div>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
          <span style="font-size:12px;">MFA Enabled</span>
          <div id="eu_mfa" class="toggle-switch ${u.mfa?'on':''}" onclick="this.classList.toggle('on')"></div>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn-primary" onclick="saveEditUser('${u.id}')"><i class="fas fa-save"></i> Save Changes</button>
        <button onclick="document.getElementById('editUserOverlay').remove()" style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
}

function saveEditUser(userId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  const name   = document.getElementById('eu_name')?.value.trim();
  const email  = document.getElementById('eu_email')?.value.trim();
  const role   = document.getElementById('eu_role')?.value;
  const tenant = document.getElementById('eu_tenant')?.value;
  const mfa    = document.getElementById('eu_mfa')?.classList.contains('on');
  if (!name || !email) { showToast('Name and email are required','error'); return; }
  Object.assign(u, { name, email, role, tenant, mfa, avatar: name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase() });
  document.getElementById('editUserOverlay')?.remove();
  showToast(`User ${name} updated successfully!`, 'success');
  const wrap = document.getElementById('usersManagementTable');
  if (wrap) wrap.innerHTML = renderUsersTable();
}

function openAddUserModal() {
  const modal = document.createElement('div');
  modal.id = 'addUserOverlay';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:24px;width:420px;max-width:90vw;">
      <div style="font-size:16px;font-weight:800;margin-bottom:16px;">➕ Add New User</div>
      <div id="addUserErr" style="display:none;padding:8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius);color:#f87171;font-size:12px;margin-bottom:8px;"></div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Full Name *</label><input id="au_name" type="text" class="settings-input" style="width:100%;" placeholder="John Doe" /></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Email *</label><input id="au_email" type="email" class="settings-input" style="width:100%;" placeholder="john@company.com" /></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Password *</label><input id="au_pass" type="password" class="settings-input" style="width:100%;" placeholder="Min 8 characters" /></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Role</label>
          <select id="au_role" class="settings-input" style="width:100%;">
            <option value="ANALYST">ANALYST</option>
            <option value="ADMIN">ADMIN</option>
            <option value="VIEWER">VIEWER</option>
            <option value="SUPER_ADMIN">SUPER ADMIN</option>
          </select></div>
        <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Tenant</label>
          <select id="au_tenant" class="settings-input" style="width:100%;">
            ${ARGUS_DATA.tenants.map(t=>`<option>${t.name}</option>`).join('')}
          </select></div>
      </div>
      <div style="display:flex;gap:8px;margin-top:16px;">
        <button class="btn-primary" onclick="addNewUser()"><i class="fas fa-user-plus"></i> Create User</button>
        <button onclick="document.getElementById('addUserOverlay').remove()" style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
}

function addNewUser() {
  const name   = document.getElementById('au_name')?.value.trim();
  const email  = document.getElementById('au_email')?.value.trim();
  const pass   = document.getElementById('au_pass')?.value;
  const role   = document.getElementById('au_role')?.value;
  const tenant = document.getElementById('au_tenant')?.value;
  const errEl  = document.getElementById('addUserErr');

  if (!name || !email || !pass) { errEl.textContent='Name, email and password are required.'; errEl.style.display='block'; return; }
  if (pass.length < 8)          { errEl.textContent='Password must be at least 8 characters.'; errEl.style.display='block'; return; }
  if (ARGUS_DATA.users.find(u => u.email === email)) { errEl.textContent='Email already exists.'; errEl.style.display='block'; return; }

  const newUser = {
    id: 'U' + String(ARGUS_DATA.users.length + 1).padStart(3,'0'),
    name, email, role, tenant,
    avatar: name.split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase(),
    last_login: 'Never',
    mfa: false,
    status: 'active',
    permissions: role==='SUPER_ADMIN'||role==='ADMIN' ? ['all'] : role==='ANALYST' ? ['read','investigate'] : ['read'],
  };

  ARGUS_DATA.users.push(newUser);

  document.getElementById('addUserOverlay')?.remove();
  showToast(`✅ User "${name}" created successfully!`, 'success');
  const wrap = document.getElementById('usersManagementTable');
  if (wrap) wrap.innerHTML = renderUsersTable();
}

/* ────────────── EDR/SIEM ────────────── */
function renderEDRSIEM() {
  const container = document.getElementById('edrSiemWrap');
  if (!container) return;
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h3 style="font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px;">EDR/SIEM Webhook Ingestion <span class="phase2-badge">⚡ PHASE 2</span></h3>
        <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">Connect your security stack for real-time telemetry ingestion and TTP extraction</p>
      </div>
      <button class="btn-primary" onclick="showToast('New webhook endpoint created!','success')"><i class="fas fa-plus"></i> Add Webhook</button>
    </div>
    ${ARGUS_DATA.edr_siem.map(es => `
      <div class="webhook-card">
        <div class="webhook-header">
          <div class="webhook-icon" style="background:${es.color}22;font-size:20px;">${es.icon}</div>
          <div>
            <div class="webhook-name">${es.name}</div>
            <div style="font-size:10px;color:var(--text-muted);">${es.type} · ${es.mapping}</div>
          </div>
          <div class="webhook-status" style="margin-left:auto;">
            <span class="coll-status-label status-${es.status==='connected'?'online':es.status==='warning'?'warning':'offline'}">${es.status.toUpperCase()}</span>
          </div>
          <div style="text-align:right;">
            <div style="font-size:12px;font-weight:700;">${es.events_today.toLocaleString()}</div>
            <div style="font-size:10px;color:var(--text-muted);">events today</div>
          </div>
        </div>
        <div class="webhook-url-row">
          <input class="webhook-url" value="${es.webhook}" readonly />
          <button class="btn-primary" style="font-size:11px;padding:6px 10px;white-space:nowrap;" onclick="copyToClipboard('${es.webhook}')"><i class="fas fa-copy"></i> Copy</button>
          <button class="btn-primary" style="font-size:11px;padding:6px 10px;white-space:nowrap;background:var(--accent-green);" onclick="showToast('Test event sent to ${es.name}!','success')"><i class="fas fa-paper-plane"></i> Test</button>
        </div>
        <div class="webhook-sample">${es.sample}</div>
        <div style="margin-top:8px;display:flex;gap:8px;">
          <button class="btn-primary" style="font-size:11px;padding:5px 10px;" onclick="showToast('${es.name} enabled!','success')"><i class="fas fa-toggle-on"></i> ${es.status==='disconnected'?'Connect':'Configure'}</button>
          <span style="font-size:10px;color:var(--text-muted);align-self:center;">Last event: ${es.last_event}</span>
        </div>
      </div>`).join('')}`;
}

/* ────────────── SYSMON → MITRE ────────────── */
function renderSysmon() {
  const container = document.getElementById('sysmonWrap');
  if (!container) return;
  container.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h3 style="font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px;">Sysmon → MITRE ATT&CK TTP Extraction <span class="phase2-badge">⚡ PHASE 2</span></h3>
        <p style="font-size:11px;color:var(--text-muted);margin-top:2px;">Upload Sysmon XML logs for automated ATT&CK technique extraction and threat hunting</p>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn-export-csv" onclick="exportSysmonTTPs('csv')" style="font-size:11px;padding:7px 12px;"><i class="fas fa-file-csv"></i> Export TTPs</button>
        <button class="btn-export-json" onclick="exportSysmonTTPs('json')" style="font-size:11px;padding:7px 12px;"><i class="fas fa-code"></i> Export JSON</button>
      </div>
    </div>

    <div class="sysmon-upload" onclick="document.getElementById('sysmonFileInput').click()" ondragover="event.preventDefault()" ondrop="handleSysmonDrop(event)">
      <input type="file" id="sysmonFileInput" accept=".xml,.evtx,.csv,.json" style="display:none" onchange="processSysmonFile(this)" />
      <i class="fas fa-upload"></i>
      <p><strong>Drop Sysmon XML/EVTX here</strong> or click to browse</p>
      <p style="font-size:11px;margin-top:4px;">Supports: Sysmon XML, Windows EVTX, CSV, JSON · Max 50MB</p>
    </div>

    <div style="margin-bottom:12px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <div class="modal-section-title" style="margin:0;">🎯 Detected Events (Demo Data)</div>
        <div style="display:flex;gap:6px;">
          <span style="font-size:11px;color:var(--text-muted);">6 events · 6 ATT&CK mappings</span>
          <button class="btn-primary" style="font-size:11px;padding:4px 10px;" onclick="showToast('Investigating all TTPs with AI...','info')"><i class="fas fa-robot"></i> AI Investigate All</button>
        </div>
      </div>
      ${ARGUS_DATA.sysmon_events.map(ev => {
        const sc = ev.severity==='CRITICAL'?'#ef4444':ev.severity==='HIGH'?'#f97316':'#f59e0b';
        return `
        <div class="sysmon-result">
          <div class="sysmon-result-header">
            <div style="display:flex;align-items:center;gap:8px;">
              <span class="sysmon-eid">EventID:${ev.eventId}</span>
              <span style="font-size:12px;font-weight:700;">${ev.name}</span>
              <span style="font-size:10px;padding:2px 6px;border-radius:4px;background:${sc}20;color:${sc};">${ev.severity}</span>
            </div>
            <div style="display:flex;align-items:center;gap:8px;">
              <span class="sysmon-ttp">${ev.ttp}</span>
              <span style="font-size:10px;color:var(--text-muted);">${ev.time}</span>
              <button class="tbl-btn" title="AI Hunt" onclick="sysmonHunt('${ev.id}')"><i class="fas fa-robot"></i></button>
            </div>
          </div>
          <div class="sysmon-fields">
            ${Object.entries(ev.fields).map(([k,v]) => `<span class="sysmon-field"><strong>${k}:</strong> ${v.length>40?v.slice(0,40)+'...':v}</span>`).join('')}
          </div>
        </div>`;
      }).join('')}
    </div>`;
}

function handleSysmonDrop(event) {
  event.preventDefault();
  showToast('Sysmon file uploaded! Processing TTP extraction...', 'success');
  setTimeout(() => showToast('Extracted 6 ATT&CK techniques from 24 events', 'success'), 2000);
}

function processSysmonFile(input) {
  if (input.files.length > 0) {
    showToast(`Processing ${input.files[0].name}...`, 'info');
    setTimeout(() => showToast('TTP extraction complete! 6 ATT&CK techniques found', 'success'), 2000);
  }
}

function sysmonHunt(id) {
  const ev = ARGUS_DATA.sysmon_events.find(x => x.id === id);
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && ev) { input.value = `Threat hunt based on Sysmon EventID:${ev.eventId} (${ev.name}) — TTP: ${ev.ttp}. Fields: ${JSON.stringify(ev.fields)}`; sendAIMessage(); }
  }, 400);
}

function exportSysmonTTPs(format) {
  if (format === 'csv') {
    const csv = 'id,eventId,name,ttp,severity,time\n' + ARGUS_DATA.sysmon_events.map(ev => `${ev.id},${ev.eventId},"${ev.name}","${ev.ttp}",${ev.severity},${ev.time}`).join('\n');
    downloadAsFile('sysmon_ttps.csv', csv, 'text/csv');
    showToast('Sysmon TTPs exported as CSV', 'success');
  } else {
    downloadAsFile('sysmon_ttps.json', JSON.stringify(ARGUS_DATA.sysmon_events, null, 2), 'application/json');
    showToast('Sysmon TTPs exported as JSON', 'success');
  }
}

/* ────────────── UTILS ────────────── */
function loadInvestigation(query) {
  const input = document.getElementById('aiInput');
  if (input) input.value = query;
}

// Alias for backward-compat — modals.js uses applyPlaybookJSON
function applyPlaybookJSON(id) { return exportPlaybookJSON(id); }

// Aliases to bridge main.js/modals.js download function names
function downloadAsFile(filename, content, mimeType) {
  downloadFile(filename, content, mimeType);
}
