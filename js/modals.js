/* ══════════════════════════════════════════════════════════
   EYEbot AI — Modals & Detail Views Module
   All clickable detail modals, config panels, export handlers
   ══════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════
   UNIVERSAL DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openDetailModal(html) {
  document.getElementById('detailModalBody').innerHTML = html;
  document.getElementById('detailModal').classList.add('open');
}
function closeDetailModal(e) { if (e.target === e.currentTarget) closeDetailModalBtn(); }
function closeDetailModalBtn() { document.getElementById('detailModal').classList.remove('open'); }

/* ══════════════════════════════════════════════════════════
   CAMPAIGN DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openCampaignDetail(id) {
  const c = ARGUS_DATA.campaigns.find(x => x.id === id);
  if (!c) return;

  const sevClass = c.severity.toLowerCase();
  const statusColor = { Active:'#ef4444', Monitoring:'#f59e0b', Contained:'#22d3ee', Resolved:'#22c55e' }[c.status] || '#64748b';

  const relFindings = ARGUS_DATA.findings.filter(f => c.customers.some(cu => f.customer.includes(cu)));

  const html = `
  <div class="campaign-detail">
    <div class="modal-tabs">
      <button class="modal-tab active" onclick="switchModalTab(this,'ctab-overview')">Overview</button>
      <button class="modal-tab" onclick="switchModalTab(this,'ctab-findings')">Findings (${relFindings.length})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'ctab-ttps')">TTPs (${c.techniques.length})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'ctab-timeline')">Timeline</button>
    </div>

    <!-- Overview Tab -->
    <div id="ctab-overview" class="modal-tab-panel active">
      <div class="cd-hero">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
          <div>
            <div style="font-size:20px;font-weight:800;margin-bottom:4px;">${c.name}</div>
            <div style="font-size:13px;color:var(--text-muted);">👤 ${c.actor}</div>
          </div>
          <div style="text-align:right;flex-shrink:0;">
            <span class="sev-badge sev-${sevClass}">${c.severity}</span><br>
            <span style="font-size:12px;color:${statusColor};font-weight:700;margin-top:4px;display:block;">${c.status}</span>
          </div>
        </div>
        <p style="font-size:12px;color:var(--text-secondary);line-height:1.6;margin-top:10px;">${c.description}</p>
        <div style="margin-top:10px;">
          <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px;">INVESTIGATION PROGRESS</div>
          <div style="height:6px;background:var(--bg-elevated);border-radius:4px;overflow:hidden;">
            <div style="width:${c.progress}%;height:100%;background:${c.color};border-radius:4px;transition:width 1s ease;"></div>
          </div>
          <div style="font-size:10px;color:var(--text-muted);margin-top:3px;">${c.progress}% complete</div>
        </div>
      </div>

      <div class="cd-stats-row">
        <div class="cd-stat"><div class="cd-stat-val" style="color:${c.color}">${c.findings}</div><div class="cd-stat-lbl">Findings</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${c.iocs}</div><div class="cd-stat-lbl">IOCs</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${c.customers.length}</div><div class="cd-stat-lbl">Tenants</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${c.techniques.length}</div><div class="cd-stat-lbl">MITRE TTPs</div></div>
      </div>

      <div style="margin-top:12px;">
        <div class="modal-section-title">🏢 Affected Tenants</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;">
          ${c.customers.map(cu => `<span class="camp-tag-item" style="font-size:12px;padding:4px 10px;">${cu}</span>`).join('')}
        </div>
      </div>

      <div style="margin-top:12px;">
        <div class="modal-section-title">🔗 Related Campaigns</div>
        <p style="font-size:11px;color:var(--text-muted);">Part of a broader ${c.actor} operation targeting bug bounty and security platforms.</p>
      </div>

      <div class="export-btn-row" style="margin-top:16px;">
        <button class="btn-export-pdf" onclick="exportCampaignReport('${c.id}','pdf')"><i class="fas fa-file-pdf"></i> PDF Report</button>
        <button class="btn-export-csv" onclick="exportCampaignReport('${c.id}','csv')"><i class="fas fa-file-csv"></i> Export CSV</button>
        <button class="btn-export-json" onclick="exportCampaignReport('${c.id}','json')"><i class="fas fa-code"></i> STIX Bundle</button>
        <button class="btn-primary" onclick="investigateCampaign('${c.id}')"><i class="fas fa-robot"></i> AI Investigate</button>
      </div>
    </div>

    <!-- Findings Tab -->
    <div id="ctab-findings" class="modal-tab-panel">
      <div style="max-height:400px;overflow-y:auto;">
        ${relFindings.length === 0 ? '<p style="color:var(--text-muted);font-size:12px;padding:16px;">No findings directly linked to this campaign.</p>' :
          relFindings.map(f => `
          <div class="finding-row" onclick="closePeekAndOpen('${f.id}')" style="margin-bottom:6px;">
            <div class="finding-sev sev-${f.severity.toLowerCase()}"></div>
            <span class="sev-badge sev-${f.severity}" style="font-size:9px;">${f.severity}</span>
            <span class="finding-type">${f.type}</span>
            <span class="finding-value" style="max-width:200px;">${f.value}</span>
            <span style="margin-left:auto;font-size:10px;color:var(--text-muted);">${f.time}</span>
          </div>`).join('')}
      </div>
    </div>

    <!-- TTPs Tab -->
    <div id="ctab-ttps" class="modal-tab-panel">
      <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;">
        ${c.techniques.map(t => `
          <div style="padding:8px 12px;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);border-radius:var(--radius);cursor:pointer;"
               onclick="showToast('${t}: ${getMitreName(t)}','info')">
            <div style="font-size:12px;font-weight:700;color:#c084fc;font-family:monospace;">${t}</div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${getMitreName(t)}</div>
          </div>`).join('')}
      </div>
      <div style="padding:10px;background:var(--bg-surface);border-radius:var(--radius);border:1px solid var(--border);">
        <div style="font-size:11px;color:var(--text-muted);">Tactic coverage: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Collection, Exfiltration, Impact</div>
      </div>
    </div>

    <!-- Timeline Tab -->
    <div id="ctab-timeline" class="modal-tab-panel">
      <div class="cd-timeline">
        ${getCampaignTimeline(c).map(ev => `
          <div class="cd-tl-item">
            <div class="cd-tl-date">${ev.date}</div>
            <div class="cd-tl-event">
              <div style="font-size:12px;font-weight:600;">${ev.title}</div>
              <div style="font-size:11px;color:var(--text-muted);">${ev.desc}</div>
            </div>
          </div>`).join('')}
      </div>
    </div>
  </div>`;

  openDetailModal(html);
}

function getCampaignTimeline(c) {
  return [
    { date:'Dec 1', title:'Initial Detection', desc:`First IOCs linked to ${c.actor} detected across threat feeds.` },
    { date:'Dec 5', title:'Campaign Identified', desc:`EYEbot AI correlated ${c.iocs} IOCs into campaign cluster.` },
    { date:'Dec 8', title:'Tenant Impact Assessment', desc:`${c.customers.length} affected tenants notified. ${c.findings} findings created.` },
    { date:'Dec 10', title:'MITRE Mapping Complete', desc:`${c.techniques.length} ATT&CK techniques identified. Playbook triggered.` },
    { date:'Dec 12', title:'Ongoing Monitoring', desc:`Status: ${c.status}. Investigation ${c.progress}% complete.` },
    { date:'Present', title:'Active Intelligence Gathering', desc:`Continuous collection from 47 feeds. ${c.iocs} total IOCs tracked.` },
  ];
}

function getMitreName(id) {
  const map = {
    'T1566':'Phishing','T1566.001':'Spear-phishing Attachment','T1566.002':'Spear-phishing Link',
    'T1078':'Valid Accounts','T1078.002':'Domain Accounts','T1059':'Command Scripting',
    'T1059.001':'PowerShell','T1021':'Remote Services','T1021.002':'SMB/Windows Admin Shares',
    'T1055':'Process Injection','T1036':'Masquerading','T1027':'Obfuscated Files',
    'T1041':'Exfiltration over C2','T1547':'Boot Autostart','T1552':'Unsecured Credentials',
    'T1552.001':'Credentials In Files','T1552.004':'Private Keys','T1552.005':'Cloud Instance Metadata',
    'T1562':'Impair Defenses','T1070':'Indicator Removal','T1486':'Data Encrypted for Impact',
    'T1490':'Inhibit System Recovery','T1539':'Steal Web Session Cookie','T1550':'Use Alternate Auth Material',
    'T1590':'Gather Victim Network Info','T1589':'Gather Victim Identity Info','T1589.001':'Employee Names',
    'T1598.003':'Spear Phishing Voice','T1621':'MFA Request Generation','T1190':'Exploit Public-Facing App',
    'T1195':'Supply Chain Compromise','T1195.002':'Software Supply Chain','T1133':'External Remote Svcs',
    'T1530':'Cloud Storage Object','T1567':'Exfiltration to Cloud','T1567.002':'Exfiltration to Cloud Storage',
    'T1619':'Cloud Storage Enumeration','T1583.001':'Register Domains','T1553.004':'Install Root Certificate',
    'T1071':'Application Layer Protocol','T1071.001':'Web Protocols','T1090':'Proxy','T1090.003':'Multi-hop Proxy',
    'T1119':'Automated Collection','T1041':'Exfiltration Over C2 Channel',
  };
  return map[id] || id;
}

function closePeekAndOpen(fid) {
  closeDetailModalBtn();
  setTimeout(() => openFindingModal(fid), 200);
}

function investigateCampaign(id) {
  const c = ARGUS_DATA.campaigns.find(x => x.id === id);
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && c) { input.value = `Investigate campaign "${c.name}" by ${c.actor}. Analyze all ${c.findings} findings and ${c.iocs} IOCs.`; sendAIMessage(); }
  }, 400);
}

function exportCampaignReport(id, format) {
  const c = ARGUS_DATA.campaigns.find(x => x.id === id);
  showToast(`Exporting campaign "${c.name}" as ${format.toUpperCase()}...`, 'success');
  if (format === 'csv') downloadAsFile(`campaign_${id}.csv`, generateCampaignCSV(c), 'text/csv');
  else if (format === 'json') downloadAsFile(`campaign_${id}.json`, JSON.stringify(c, null, 2), 'application/json');
  else showToast(`PDF report for "${c.name}" queued for generation`, 'info');
}

function generateCampaignCSV(c) {
  return `Name,Actor,Severity,Status,Findings,IOCs,Progress\n${c.name},${c.actor},${c.severity},${c.status},${c.findings},${c.iocs},${c.progress}%`;
}

/* ══════════════════════════════════════════════════════════
   THREAT ACTOR DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openActorDetail(id) {
  const a = ARGUS_DATA.actors.find(x => x.id === id);
  if (!a) return;

  const relCampaigns = ARGUS_DATA.campaigns.filter(c => c.actor.includes(a.name.split(' ')[0]) || c.actor.includes(a.aliases[0]));

  const capabilities = [
    { label:'Sophistication', value:a.motivation.includes('Espionage') ? 95 : 80, color:'#ef4444' },
    { label:'Persistence', value:a.active_since < 2015 ? 92 : 75, color:'#f97316' },
    { label:'Stealth', value:a.motivation.includes('State') || a.nation.includes('Russia') ? 88 : 72, color:'#a855f7' },
    { label:'Impact', value:a.motivation.includes('Ransomware') ? 95 : 78, color:'#f59e0b' },
    { label:'Attribution Confidence', value:85, color:'#22d3ee' },
  ];

  const html = `
  <div>
    <div class="modal-tabs">
      <button class="modal-tab active" onclick="switchModalTab(this,'atab-profile')">Profile</button>
      <button class="modal-tab" onclick="switchModalTab(this,'atab-ttps')">TTPs (${a.techniques.length})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'atab-campaigns')">Campaigns (${relCampaigns.length})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'atab-iocs')">Known IOCs</button>
    </div>

    <div id="atab-profile" class="modal-tab-panel active">
      <div class="actor-detail-header">
        <div class="actor-detail-av">${a.emoji}</div>
        <div style="flex:1;">
          <div class="actor-detail-name">${a.name}</div>
          <div class="actor-detail-nation">${a.nation} · Active since ${a.active_since}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">
            ${a.aliases.map(al => `<span style="font-size:10px;padding:2px 6px;background:rgba(239,68,68,0.1);color:#f87171;border-radius:4px;">${al}</span>`).join('')}
          </div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);margin-bottom:4px;">MOTIVATION</div>
          <div style="font-size:12px;font-weight:700;color:var(--accent-orange);">${a.motivation}</div>
        </div>
      </div>

      <p style="font-size:12px;color:var(--text-secondary);line-height:1.7;margin-bottom:16px;">${a.desc}</p>

      <div style="margin-bottom:16px;">
        <div class="modal-section-title">⚡ Capability Assessment</div>
        <div style="margin-top:8px;">
          ${capabilities.map(cap => `
            <div class="actor-capability-bar">
              <span class="actor-cap-label">${cap.label}</span>
              <div class="actor-cap-bar"><div class="actor-cap-fill" style="width:${cap.value}%;background:${cap.color};"></div></div>
              <span class="actor-cap-val" style="color:${cap.color}">${cap.value}</span>
            </div>`).join('')}
        </div>
      </div>

      <div class="export-btn-row">
        <button class="btn-export-pdf" onclick="showToast('Generating ${a.name} threat report PDF...','info')"><i class="fas fa-file-pdf"></i> PDF Report</button>
        <button class="btn-export-stix" onclick="showToast('Exporting STIX 2.1 bundle for ${a.name}...','success')"><i class="fas fa-code"></i> STIX 2.1</button>
        <button class="btn-primary" onclick="investigateActor('${a.id}')"><i class="fas fa-robot"></i> AI Attribution</button>
      </div>
    </div>

    <div id="atab-ttps" class="modal-tab-panel">
      <div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);">MITRE ATT&CK techniques used by ${a.name}. Click any technique for details.</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;">
        ${a.techniques.map(t => `
          <div onclick="showTTPDetail('${t}')" style="padding:8px 12px;background:rgba(168,85,247,0.1);border:1px solid rgba(168,85,247,0.3);border-radius:var(--radius);cursor:pointer;transition:all 0.15s ease;" onmouseover="this.style.background='rgba(168,85,247,0.2)'" onmouseout="this.style.background='rgba(168,85,247,0.1)'">
            <div style="font-size:12px;font-weight:700;color:#c084fc;font-family:monospace;">${t}</div>
            <div style="font-size:10px;color:var(--text-muted);margin-top:2px;">${getMitreName(t)}</div>
          </div>`).join('')}
      </div>
    </div>

    <div id="atab-campaigns" class="modal-tab-panel">
      ${relCampaigns.length === 0 ? '<p style="color:var(--text-muted);font-size:12px;padding:16px;">No active campaigns attributed to this actor.</p>' :
        relCampaigns.map(c => `
          <div class="finding-row" style="margin-bottom:8px;cursor:pointer;" onclick="closeDetailModalBtn();setTimeout(()=>openCampaignDetail('${c.id}'),200)">
            <span class="sev-badge sev-${c.severity.toLowerCase()}">${c.severity}</span>
            <span style="font-size:13px;font-weight:700;flex:1;">${c.name}</span>
            <span style="font-size:10px;color:var(--text-muted);">${c.findings} findings · ${c.status}</span>
          </div>`).join('')}
    </div>

    <div id="atab-iocs" class="modal-tab-panel">
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:10px;">Known infrastructure and IOCs attributed to ${a.name}</div>
      <table class="ioc-export-table">
        <thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Last Seen</th></tr></thead>
        <tbody>
          ${getActorIOCs(a).map(ioc => `
            <tr>
              <td><span style="font-size:10px;padding:2px 6px;background:rgba(59,130,246,0.15);color:#60a5fa;border-radius:3px;white-space:nowrap;">${ioc.type}</span></td>
              <td style="max-width:280px;"><code style="font-size:10px;word-break:break-all;display:block;background:var(--bg-surface);padding:3px 6px;border-radius:3px;color:var(--accent-cyan);font-family:'JetBrains Mono',monospace;">${ioc.value}</code></td>
              <td style="color:${ioc.conf>=80?'#22c55e':'#f59e0b'};font-weight:700;">${ioc.conf}%</td>
              <td style="color:var(--text-muted);font-size:11px;white-space:nowrap;">${ioc.seen}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;

  openDetailModal(html);
}

function getActorIOCs(a) {
  const iocSets = {
    APT29: [
      {type:'IP',       value:'185.220.101.45',                                                              conf:92, seen:'2024-12-14'},
      {type:'Domain',   value:'maliciousupdate[.]ru',                                                        conf:87, seen:'2024-12-10'},
      {type:'SHA256',   value:'a3f8d2c1b4e5f6a709b231c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4',            conf:78, seen:'2024-12-08'},
      {type:'C2 Server',value:'cdn-update[.]net:443',                                                        conf:83, seen:'2024-12-12'},
      {type:'Email',    value:'no-reply@windows-update[.]ru',                                                conf:76, seen:'2024-12-11'},
      {type:'URL',      value:'https://maliciousupdate[.]ru/download/patch_kb5038386.exe',                   conf:91, seen:'2024-12-13'},
    ],
    APT41: [
      {type:'IP',       value:'203.0.113.100',                                                               conf:88, seen:'2024-12-13'},
      {type:'Domain',   value:'cloudsync[.]cc',                                                              conf:82, seen:'2024-12-09'},
      {type:'SHA256',   value:'d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5',            conf:75, seen:'2024-12-07'},
      {type:'Registry', value:'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHost32',         conf:70, seen:'2024-12-06'},
    ],
    FIN7: [
      {type:'IP',       value:'45.142.212.100',                                                              conf:85, seen:'2024-12-11'},
      {type:'Domain',   value:'payment-secure[.]biz',                                                        conf:79, seen:'2024-12-06'},
      {type:'Email',    value:'support@bank-alert[.]com',                                                    conf:72, seen:'2024-12-03'},
      {type:'SHA256',   value:'b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6',            conf:80, seen:'2024-12-09'},
    ],
    Lazarus: [
      {type:'IP',       value:'198.51.100.200',                                                              conf:90, seen:'2024-12-13'},
      {type:'SHA256',   value:'b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6',            conf:85, seen:'2024-12-10'},
      {type:'BTC Wallet',value:'bc1q9h8g7f6e5d4c3b2a1z0y9x8w7v6u5t4s3r2q1p0o9n8m7l6k5j4i3h2g1f0e',        conf:78, seen:'2024-12-08'},
      {type:'Domain',   value:'lazarus-cdn[.]net',                                                           conf:82, seen:'2024-12-11'},
    ],
  };
  const key = Object.keys(iocSets).find(k => a.name.includes(k));
  return iocSets[key] || [{type:'Domain',value:`${a.name.replace(/\s/g,'-').toLowerCase()}-c2[.]net`,conf:70,seen:'2024-12-10'}];
}

function investigateActor(id) {
  const a = ARGUS_DATA.actors.find(x => x.id === id);
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && a) { input.value = `Perform threat actor attribution analysis for ${a.name} (${a.aliases[0]}). Analyze TTPs, infrastructure, and recent campaigns.`; sendAIMessage(); }
  }, 400);
}

function showTTPDetail(ttp) {
  showToast(`${ttp}: ${getMitreName(ttp)} — Click ATT&CK for full details`, 'info');
}

/* ══════════════════════════════════════════════════════════
   DARK WEB DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openDarkWebDetail(id) {
  const d = ARGUS_DATA.darkweb.find(x => x.id === id);
  if (!d) return;

  const sevColor = d.severity === 'CRITICAL' ? '#ef4444' : d.severity === 'HIGH' ? '#f97316' : '#f59e0b';
  const riskIndicators = [
    { label:'Threat Level', value:d.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH', color:sevColor },
    { label:'Freshness', value:'New', color:'#22c55e' },
    { label:'Reliability', value:'HIGH', color:'#3b82f6' },
  ];

  const fullContent = getDarkWebFullContent(d);
  const mitigations = getDarkWebMitigations(d);

  const html = `
  <div class="dw-detail">
    <div class="dw-detail-source">📡 ${d.source} · 🕐 ${d.time} · <span style="padding:2px 6px;background:rgba(0,0,0,0.3);border-radius:4px;font-size:10px;">${d.type}</span></div>
    <div class="dw-detail-title">${d.title}</div>
    <span style="display:inline-block;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:700;background:rgba(239,68,68,0.15);color:${sevColor};margin-bottom:12px;">${d.severity}</span>

    <div class="dw-risk-indicators">
      <div class="dw-risk-item"><div class="dw-risk-val" style="color:${sevColor}">${d.severity}</div><div class="dw-risk-lbl">Threat Level</div></div>
      <div class="dw-risk-item"><div class="dw-risk-val" style="color:#22c55e">NEW</div><div class="dw-risk-lbl">Freshness</div></div>
      <div class="dw-risk-item"><div class="dw-risk-val" style="color:#3b82f6">HIGH</div><div class="dw-risk-lbl">Reliability</div></div>
    </div>

    <div class="modal-section-title">📄 Full Intelligence</div>
    <div class="dw-detail-content">${fullContent}</div>

    <div style="margin-top:14px;">
      <div class="modal-section-title">🛡️ Recommended Mitigations</div>
      <div style="display:flex;flex-direction:column;gap:6px;margin-top:6px;">
        ${mitigations.map((m,i) => `
          <div style="display:flex;gap:8px;padding:8px 10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
            <span style="color:var(--accent-blue);font-weight:800;width:18px;flex-shrink:0;">${i+1}</span>
            <span style="font-size:12px;">${m}</span>
          </div>`).join('')}
      </div>
    </div>

    <div class="export-btn-row" style="margin-top:14px;">
      <button class="btn-export-pdf" onclick="showToast('Generating dark web intel report...','info')"><i class="fas fa-file-pdf"></i> PDF Report</button>
      <button class="btn-export-json" onclick="exportDarkWebItem('${d.id}')"><i class="fas fa-code"></i> Export JSON</button>
      <button class="btn-primary" onclick="investigateDarkWeb('${d.id}')"><i class="fas fa-robot"></i> AI Investigate</button>
    </div>
  </div>`;

  openDetailModal(html);
}

function getDarkWebFullContent(d) {
  const extended = {
    DW001: 'ALPHV/BlackCat ransomware group has added TechCorp International as a new victim on their dark web leak site. The group claims to have exfiltrated 3.2TB of data including: employee payroll records (12,000+ employees), full customer database with PII (2.3M records), internal communications and strategic planning documents, financial records including bank account details, source code for proprietary software systems. The ransom demand is $4.5M USD in Bitcoin. The group has set a 72-hour deadline before beginning to publish the data. Sample files have been uploaded as proof including executive emails and partial customer data. Negotiation contact available via Tox messaging.',
    DW002: 'A threat actor using the handle "cyb3r_h4ck3r" posted what appears to be a significant database dump containing HackerOne researcher profiles. The dump includes: 1.2 million researcher accounts with real names and email addresses, bug bounty program participation history and earnings data, submitted vulnerability types and programs, associated GitHub/social media accounts, some physical addresses and phone numbers from profile data. The data appears to be from late 2024. The poster claims this was obtained through a third-party data processor breach. HIBP integration suggests 14% overlap with known prior breaches.',
  };
  return (extended[d.id] || d.preview + ' [Full intelligence report available from source. Automated extraction in progress. Cross-referencing with 47 threat feeds for additional context and attribution data. AI orchestrator has been notified and will begin autonomous investigation within 5 minutes.]').replace(/\n/g, '<br>');
}

function getDarkWebMitigations(d) {
  const mitigMap = {
    'Ransomware Listing': ['Immediately check if your organization matches the victim profile','Scan for vulnerable file transfer systems and patch immediately','Verify offline backup integrity and test restoration procedures','Enable enhanced EDR monitoring for lateral movement indicators','Prepare incident response team and legal counsel briefing'],
    'Data Breach': ['Run immediate password reset for all affected email accounts','Enable MFA for all users matching leaked credentials','Monitor for credential stuffing attacks against login systems','Issue internal advisory and conduct phishing awareness reminder','Engage data breach counsel for GDPR/regulatory notification assessment'],
    'Exploit Sale': ['Track the advertised vulnerability in your asset inventory','Apply emergency patches if vulnerability affects your stack','Implement virtual patching via WAF/IDS while permanent fix deployed','Monitor threat intelligence for PoC exploit code release','Brief executive team on potential zero-day exposure window'],
    'MaaS Offering': ['Deploy updated IOC blocklist from new stealer infrastructure','Enable behavioral detection rules for data exfiltration patterns','Audit all browser-saved credentials and password managers','Conduct user education campaign on stealer malware delivery vectors','Review and harden endpoint DLP controls'],
    'Credential Dump': ['Initiate emergency credential rotation for all leaked accounts','Check leaked IPs against VPN, RDP, and cloud access logs','Force MFA enrollment for accounts without it','Run OSINT on leaked data to assess true breach scope','Contact affected users with security advisory'],
  };
  return mitigMap[d.type] || ['Monitor for related indicators in threat feeds','Brief security team on this intelligence item','Update blocklists with any extracted IOCs','Consider proactive threat hunt for related TTPs'];
}

function exportDarkWebItem(id) {
  const d = ARGUS_DATA.darkweb.find(x => x.id === id);
  downloadAsFile(`darkweb_${id}.json`, JSON.stringify(d, null, 2), 'application/json');
  showToast('Dark web intelligence exported as JSON', 'success');
}

function investigateDarkWeb(id) {
  const d = ARGUS_DATA.darkweb.find(x => x.id === id);
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && d) { input.value = `Investigate dark web intelligence: "${d.title}" from ${d.source}. Assess threat severity and identify affected customers.`; sendAIMessage(); }
  }, 400);
}

/* ══════════════════════════════════════════════════════════
   IOC DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openIOCDetail(catName, typeName) {
  const cat = ARGUS_DATA.ioc_registry.find(c => c.category === catName);
  if (!cat) return;
  const ioc = cat.types.find(t => t.name === typeName);
  if (!ioc) return;

  const statusColors = { proven:'#22c55e', working:'#3b82f6', theoretical:'#64748b' };
  const color = statusColors[ioc.status];

  const matchExamples = getIOCExamples(ioc.name);

  const html = `
  <div class="ioc-detail-modal">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
      <div style="width:40px;height:40px;border-radius:var(--radius);background:${cat.color}22;display:flex;align-items:center;justify-content:center;font-size:18px;color:${cat.color};">🔑</div>
      <div>
        <div style="font-size:18px;font-weight:800;font-family:monospace;">${ioc.name}</div>
        <div style="font-size:11px;color:var(--text-muted);">Category: ${catName}</div>
      </div>
      <span style="margin-left:auto;padding:4px 10px;border-radius:10px;font-size:11px;font-weight:700;background:${color}20;color:${color};">${ioc.status.toUpperCase()}</span>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">🔤 Detection Regex</div>
      <div class="ioc-regex-box">${escapeHtmlModal(ioc.regex)}</div>
      <div style="display:flex;gap:6px;margin-top:6px;">
        <button class="btn-primary" style="font-size:11px;padding:5px 10px;" onclick="copyToClipboard('${ioc.regex.replace(/'/g, "\\'")}')"><i class="fas fa-copy"></i> Copy Regex</button>
        <button class="btn-primary" style="font-size:11px;padding:5px 10px;background:var(--accent-purple);" onclick="showToast('Testing regex against IOC database...','info')"><i class="fas fa-play"></i> Test Regex</button>
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">📋 Match Examples</div>
      <div style="display:flex;flex-direction:column;gap:4px;">
        ${matchExamples.map(ex => `
          <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
            <code style="flex:1;font-size:11px;">${ex.value}</code>
            <span style="font-size:10px;padding:1px 6px;border-radius:3px;background:${ex.valid?'rgba(34,197,94,0.15)':'rgba(239,68,68,0.15)'};color:${ex.valid?'#4ade80':'#f87171'};">${ex.valid?'✓ MATCH':'✗ NO MATCH'}</span>
          </div>`).join('')}
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">📡 Active Collectors Using This Pattern</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">
        ${getCollectorsForIOC(ioc.name).map(col => `<span style="font-size:11px;padding:3px 8px;background:rgba(34,211,238,0.1);color:var(--accent-cyan);border:1px solid rgba(34,211,238,0.2);border-radius:4px;">${col}</span>`).join('')}
      </div>
    </div>

    <div class="export-btn-row">
      <button class="btn-export-csv" onclick="exportSingleIOC('${ioc.name}','csv')"><i class="fas fa-file-csv"></i> Export CSV</button>
      <button class="btn-export-json" onclick="exportSingleIOC('${ioc.name}','json')"><i class="fas fa-code"></i> Export JSON</button>
    </div>
  </div>`;

  openDetailModal(html);
}

function getIOCExamples(name) {
  const examples = {
    google_api_key: [{value:'AIzaSyD-8xK9mN3pQ7vF2hJ4lR5tY6uW1eB0cA',valid:true},{value:'AIzaBadKey123',valid:false},{value:'AIzaSyB-correct-length-key-here-123456',valid:true}],
    openai_api_key: [{value:'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx',valid:true},{value:'sk-old-format-key',valid:false},{value:'sk-proj-' + 'A'.repeat(48),valid:true}],
    aws_access_key: [{value:'AKIAIOSFODNN7EXAMPLE',valid:true},{value:'AKID_WRONG_FORMAT',valid:false},{value:'AKIA4HPREDACTEDXYZ12',valid:true}],
    malicious_ip: [{value:'185.220.101.45',valid:true},{value:'10.0.0.1',valid:true},{value:'not-an-ip',valid:false}],
    cve_id: [{value:'CVE-2024-3400',valid:true},{value:'CVE-2024-12345678',valid:true},{value:'CVE-WRONG',valid:false}],
  };
  return examples[name] || [{value:`example_${name}_match`,valid:true},{value:`not_a_${name}`,valid:false}];
}

function getCollectorsForIOC(name) {
  if (name.includes('api_key') || name.includes('token')) return ['grep.app','GitHub Gist','Sourcegraph','GitHub Secrets'];
  if (name.includes('cve') || name.includes('cvss') || name.includes('epss')) return ['NVD','CISA KEV','EPSS','CIRCL CVE-Search'];
  if (name.includes('ip') || name.includes('domain') || name.includes('url')) return ['URLhaus','ThreatFox','AbuseIPDB','Feodo','Shodan','OTX'];
  if (name.includes('credential') || name.includes('ssh') || name.includes('password')) return ['HudsonRock','HIBP','Paste Sites','DarkSearch'];
  return ['ThreatFox','OTX','Pulsedive','CIRCL MISP'];
}

function exportSingleIOC(name, format) {
  const cat = ARGUS_DATA.ioc_registry.find(c => c.types.some(t => t.name === name));
  const ioc = cat?.types.find(t => t.name === name);
  if (!ioc) return;
  if (format === 'json') downloadAsFile(`ioc_${name}.json`, JSON.stringify({name:ioc.name,status:ioc.status,regex:ioc.regex,category:cat.category},null,2), 'application/json');
  else downloadAsFile(`ioc_${name}.csv`, `name,status,regex,category\n${ioc.name},${ioc.status},"${ioc.regex}",${cat.category}`, 'text/csv');
  showToast(`IOC "${name}" exported as ${format.toUpperCase()}`, 'success');
}

/* ══════════════════════════════════════════════════════════
   FINDING DETAIL MODAL
   ══════════════════════════════════════════════════════════ */
function openFindingModal(id) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  if (!f) return;
  const scoreColor = f.score >= 85 ? '#ef4444' : f.score >= 65 ? '#f97316' : '#f59e0b';
  const body = `
    <div>
      <div style="margin-bottom:16px;">
        <div style="font-size:16px;font-weight:800;margin-bottom:6px;display:flex;align-items:center;gap:8px;">
          <span class="sev-badge sev-${f.severity}">${f.severity}</span>${f.type} — ${f.id}
        </div>
        <code style="font-size:13px;display:block;margin:8px 0;padding:10px 14px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);word-break:break-all;">${f.value}</code>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:var(--text-muted);">📡 ${f.source}</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:var(--text-muted);">🏢 ${f.customer}</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:${scoreColor};">⚡ Score: ${f.score}/100</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:var(--text-muted);">🎯 ${f.mitre}</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:var(--text-muted);">🕐 ${f.time}</span>
          <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:var(--bg-elevated);color:var(--text-muted);">✓ ${f.confidence}% confidence</span>
        </div>
      </div>
      <p style="font-size:12px;color:var(--text-secondary);line-height:1.7;">${f.description}</p>
      <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-muted);margin-bottom:10px;">📋 Evidence Trail (${f.evidence.length} sources)</div>
        <div style="display:flex;flex-direction:column;gap:6px;">
          ${f.evidence.map((ev,i) => `
            <div style="display:flex;gap:10px;align-items:flex-start;">
              <div style="width:20px;height:20px;background:rgba(59,130,246,0.15);color:#60a5fa;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;">${i+1}</div>
              <div>
                <div style="font-size:11px;color:var(--accent-cyan);font-family:monospace;">${ev.src}</div>
                <div style="font-size:11px;color:var(--text-secondary);margin-top:2px;">${ev.detail}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>
      <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:var(--text-muted);margin-bottom:10px;">🎯 MITRE ATT&CK</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;">
          <span style="padding:4px 10px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.3);border-radius:5px;font-size:11px;color:#c084fc;font-family:monospace;">${f.mitre}</span>
          <span style="padding:4px 10px;background:rgba(168,85,247,0.15);border:1px solid rgba(168,85,247,0.3);border-radius:5px;font-size:11px;color:#c084fc;font-family:monospace;">T1589</span>
        </div>
      </div>
      <div class="export-btn-row" style="margin-top:14px;">
        <button class="btn-export-pdf" onclick="showToast('Generating finding PDF report...','info')"><i class="fas fa-file-pdf"></i> PDF</button>
        <button class="btn-export-csv" onclick="exportSingleFinding('${f.id}')"><i class="fas fa-file-csv"></i> CSV</button>
        <button class="btn-export-json" onclick="exportFindingJSON('${f.id}')"><i class="fas fa-code"></i> JSON</button>
        <button class="btn-primary" onclick="investigateWithAI('${f.id}')"><i class="fas fa-robot"></i> AI Investigate</button>
      </div>
    </div>`;
  document.getElementById('findingModalBody').innerHTML = body;
  document.getElementById('findingModal').classList.add('open');
}

function closeFindingModal(e) { if (e.target === e.currentTarget) closeFindingModalBtn(); }
function closeFindingModalBtn() { document.getElementById('findingModal').classList.remove('open'); }

function exportSingleFinding(id) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  downloadAsFile(`finding_${id}.csv`, `id,severity,type,value,source,customer,score,mitre,time\n${f.id},${f.severity},${f.type},"${f.value}",${f.source},${f.customer},${f.score},${f.mitre},${f.time}`, 'text/csv');
  showToast('Finding exported as CSV', 'success');
}
function exportFindingJSON(id) {
  const f = ARGUS_DATA.findings.find(x => x.id === id);
  downloadAsFile(`finding_${id}.json`, JSON.stringify(f, null, 2), 'application/json');
  showToast('Finding exported as JSON', 'success');
}

/* ══════════════════════════════════════════════════════════
   COLLECTOR CONFIG MODAL
   ══════════════════════════════════════════════════════════ */
function openCollectorConfig(id) {
  const c = ARGUS_DATA.collectors.find(x => x.id === id);
  if (!c) return;

  const iocSample = generateCollectorIOCs(c, 8);

  const html = `
  <div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
      <div style="width:44px;height:44px;border-radius:var(--radius);background:rgba(34,211,238,0.1);display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:800;color:var(--accent-cyan);">${c.name.slice(0,2)}</div>
      <div>
        <div style="font-size:18px;font-weight:800;">${c.name}</div>
        <div style="font-size:11px;color:var(--text-muted);">${c.desc}</div>
      </div>
      <span class="coll-status-label status-${c.status}" style="margin-left:auto;">${c.status.toUpperCase()}</span>
    </div>

    <div class="modal-tabs">
      <button class="modal-tab active" onclick="switchModalTab(this,'coltab-config')">Configuration</button>
      <button class="modal-tab" onclick="switchModalTab(this,'coltab-iocs')">Live IOCs (${c.iocs_today})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'coltab-stats')">Statistics</button>
    </div>

    <div id="coltab-config" class="modal-tab-panel active">
      <div class="collector-config-grid">
        <div class="config-field"><label>Collector Name</label><input type="text" value="${c.name}" /></div>
        <div class="config-field"><label>Category</label><input type="text" value="${c.category}" /></div>
        <div class="config-field"><label>Poll Interval</label><select><option>5 minutes</option><option selected>15 minutes</option><option>1 hour</option><option>6 hours</option></select></div>
        <div class="config-field"><label>Max IOCs/Run</label><input type="number" value="1000" /></div>
        ${c.type === 'keyed' ? `
        <div class="config-field" style="grid-column:span 2;"><label>API Key</label><input type="password" value="••••••••••••••••" placeholder="Enter API key..." /></div>` : ''}
        <div class="config-field"><label>Timeout (seconds)</label><input type="number" value="30" /></div>
        <div class="config-field"><label>Retry Attempts</label><input type="number" value="3" /></div>
        <div class="config-field" style="grid-column:span 2;display:flex;align-items:center;gap:10px;padding:8px;">
          <div class="toggle-switch on" onclick="this.classList.toggle('on')"></div>
          <span style="font-size:12px;">Enable collector</span>
          &nbsp;&nbsp;
          <div class="toggle-switch" onclick="this.classList.toggle('on')"></div>
          <span style="font-size:12px;">Deduplicate IOCs</span>
          &nbsp;&nbsp;
          <div class="toggle-switch on" onclick="this.classList.toggle('on')"></div>
          <span style="font-size:12px;">Auto-score</span>
        </div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;">
        <button class="btn-primary" onclick="showToast('${c.name} configuration saved!','success')"><i class="fas fa-save"></i> Save Config</button>
        <button class="btn-primary" style="background:var(--accent-green);" onclick="showToast('Running ${c.name} collector now...','info')"><i class="fas fa-play"></i> Run Now</button>
        <button class="btn-primary" style="background:var(--accent-red);" onclick="showToast('${c.name} collector stopped','warning')"><i class="fas fa-stop"></i> Stop</button>
      </div>
    </div>

    <div id="coltab-iocs" class="modal-tab-panel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <div style="font-size:12px;color:var(--text-muted);">Showing ${Math.min(8,c.iocs_today)} of ${c.iocs_today} IOCs collected today</div>
        <div style="display:flex;gap:6px;">
          <button class="btn-export-csv" onclick="exportCollectorIOCs('${c.id}','csv')" style="font-size:10px;padding:4px 8px;"><i class="fas fa-file-csv"></i> CSV</button>
          <button class="btn-export-json" onclick="exportCollectorIOCs('${c.id}','json')" style="font-size:10px;padding:4px 8px;"><i class="fas fa-code"></i> JSON</button>
          <button class="btn-export-stix" onclick="exportCollectorIOCs('${c.id}','stix')" style="font-size:10px;padding:4px 8px;"><i class="fas fa-shield-alt"></i> STIX</button>
        </div>
      </div>
      <table class="ioc-export-table">
        <thead><tr><th>Type</th><th>Value</th><th>Score</th><th>First Seen</th><th>Tags</th></tr></thead>
        <tbody>
          ${iocSample.map(ioc => `
            <tr>
              <td><span style="font-size:10px;padding:2px 5px;background:rgba(59,130,246,0.15);color:#60a5fa;border-radius:3px;">${ioc.type}</span></td>
              <td><code style="font-size:11px;color:var(--accent-cyan);">${ioc.value}</code></td>
              <td><span style="font-weight:700;color:${ioc.score>=80?'#ef4444':ioc.score>=60?'#f97316':'#f59e0b'}">${ioc.score}</span></td>
              <td style="font-size:10px;color:var(--text-muted);">${ioc.seen}</td>
              <td>${ioc.tags.map(t=>`<span style="font-size:9px;padding:1px 4px;background:var(--bg-elevated);border-radius:3px;margin-right:2px;">${t}</span>`).join('')}</td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>

    <div id="coltab-stats" class="modal-tab-panel">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px;">
        <div class="cd-stat"><div class="cd-stat-val" style="color:var(--accent-cyan)">${c.iocs_today.toLocaleString()}</div><div class="cd-stat-lbl">IOCs Today</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${(c.iocs_total/1000).toFixed(1)}K</div><div class="cd-stat-lbl">Total IOCs</div></div>
        <div class="cd-stat"><div class="cd-stat-val" style="color:${c.status==='online'?'#22c55e':'#f59e0b'}">${c.status}</div><div class="cd-stat-lbl">Status</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${c.last_run}</div><div class="cd-stat-lbl">Last Run</div></div>
        <div class="cd-stat"><div class="cd-stat-val">98.2%</div><div class="cd-stat-lbl">Uptime</div></div>
        <div class="cd-stat"><div class="cd-stat-val">${c.type==='free'?'Free':'Keyed'}</div><div class="cd-stat-lbl">Type</div></div>
      </div>
    </div>
  </div>`;

  document.getElementById('collectorModalBody').innerHTML = html;
  document.getElementById('collectorModal').classList.add('open');
}

function closeCollectorModal(e) { if (e.target === e.currentTarget) closeCollectorModalBtn(); }
function closeCollectorModalBtn() { document.getElementById('collectorModal').classList.remove('open'); }

function generateCollectorIOCs(c, count) {
  const typeMap = {
    'Vulnerability Intel': [{type:'CVE',val:'CVE-2024-',score:85,tags:['critical','rce']},{type:'CVE',val:'CVE-2023-',score:72,tags:['high','sqli']}],
    'Secret Exposure': [{type:'API Key',val:'AIzaSyD-REDACTED',score:91,tags:['google','active']},{type:'AWS Key',val:'AKIA4HPREDACTED',score:95,tags:['aws','admin']}],
    'Phishing': [{type:'URL',val:'http://phish-domain[.]ru/',score:88,tags:['phishing','active']},{type:'Domain',val:'fake-bank[.]com',score:82,tags:['phishing']}],
    'Botnet C2': [{type:'IP',val:'185.220.',score:90,tags:['c2','emotet']},{type:'IP',val:'45.142.',score:85,tags:['c2']}],
    'Malware Hashes': [{type:'SHA256',val:'a3f8d2c1...',score:87,tags:['malware','ransomware']},{type:'MD5',val:'b4e5f6a7...',score:78,tags:['trojan']}],
  };
  const templates = typeMap[c.category] || [{type:'IOC',val:'indicator-',score:70,tags:['threat']}];
  return Array.from({length:count}, (_,i) => {
    const t = templates[i % templates.length];
    return { type:t.type, value:`${t.val}${Math.random().toString(36).slice(2,8)}`, score:t.score - Math.floor(Math.random()*15), seen:`${Math.floor(Math.random()*12)+1}h ago`, tags:t.tags };
  });
}

function exportCollectorIOCs(id, format) {
  const c = ARGUS_DATA.collectors.find(x => x.id === id);
  const iocs = generateCollectorIOCs(c, 50);
  if (format === 'csv') {
    const csv = 'type,value,score,seen,tags\n' + iocs.map(i => `${i.type},"${i.value}",${i.score},${i.seen},"${i.tags.join(';')}"`).join('\n');
    downloadAsFile(`${c.name.replace(/\s/g,'_')}_iocs.csv`, csv, 'text/csv');
    showToast(`Exported ${iocs.length} IOCs from ${c.name} as CSV`, 'success');
  } else if (format === 'json') {
    downloadAsFile(`${c.name.replace(/\s/g,'_')}_iocs.json`, JSON.stringify({collector:c.name,exported:new Date().toISOString(),iocs}, null, 2), 'application/json');
    showToast(`Exported ${iocs.length} IOCs from ${c.name} as JSON`, 'success');
  } else {
    showToast(`STIX 2.1 bundle generation for ${c.name} started...`, 'info');
  }
}

/* ══════════════════════════════════════════════════════════
   PLAYBOOK DETAIL & CREATE MODAL
   ══════════════════════════════════════════════════════════ */
function openPlaybookDetail(id) {
  const pb = ARGUS_DATA.playbooks.find(x => x.id === id);
  if (!pb) return;

  const steps = getPlaybookSteps(pb);
  const html = `
  <div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px;">
      <div>
        <div style="font-size:18px;font-weight:800;">${pb.name}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${pb.desc}</div>
      </div>
      <span style="padding:4px 10px;background:rgba(34,211,238,0.1);color:var(--accent-cyan);border-radius:6px;font-size:11px;font-weight:700;flex-shrink:0;margin-left:12px;">${pb.category}</span>
    </div>

    <div style="display:flex;gap:10px;margin-bottom:14px;">
      <div class="cd-stat" style="flex:1;"><div class="cd-stat-val">${pb.steps}</div><div class="cd-stat-lbl">Steps</div></div>
      <div class="cd-stat" style="flex:1;"><div class="cd-stat-val">${pb.mitre_coverage}</div><div class="cd-stat-lbl">MITRE TTPs</div></div>
      <div class="cd-stat" style="flex:1;"><div class="cd-stat-val">${pb.triggers.length}</div><div class="cd-stat-lbl">Triggers</div></div>
      <div class="cd-stat" style="flex:1;"><div class="cd-stat-val" style="color:#22c55e">Active</div><div class="cd-stat-lbl">Status</div></div>
    </div>

    <div style="margin-bottom:12px;">
      <div class="modal-section-title">⚡ Triggers</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">
        ${pb.triggers.map(t => `<span style="font-size:11px;padding:3px 8px;background:rgba(34,211,238,0.1);color:var(--accent-cyan);border:1px solid rgba(34,211,238,0.2);border-radius:4px;font-family:monospace;">${t}</span>`).join('')}
      </div>
    </div>

    <div style="margin-bottom:12px;">
      <div class="modal-section-title">📋 Execution Steps</div>
      <div class="pb-step-list" style="margin-top:8px;">
        ${steps.map((s,i) => `
          <div class="pb-step">
            <div class="pb-step-num">${i+1}</div>
            <div class="pb-step-body">
              <div class="pb-step-title">${s.title}</div>
              <div class="pb-step-desc">${s.desc}</div>
              ${s.tool ? `<div class="pb-step-tool">🛠️ Tool: ${s.tool}</div>` : ''}
            </div>
            <span style="font-size:10px;padding:2px 6px;background:rgba(34,197,94,0.1);color:#4ade80;border-radius:4px;flex-shrink:0;">${s.duration}</span>
          </div>`).join('')}
      </div>
    </div>

    <div class="export-btn-row">
      <button class="btn-primary" onclick="applyPlaybook('${pb.id}')"><i class="fas fa-play"></i> Apply Now</button>
      <button class="btn-export-pdf" onclick="exportPlaybookPDF('${pb.id}')"><i class="fas fa-file-pdf"></i> Export PDF</button>
      <button class="btn-export-json" onclick="exportPlaybookJSON('${pb.id}')"><i class="fas fa-code"></i> Export JSON</button>
      <button class="btn-primary" style="background:var(--accent-purple);" onclick="closePlaybookModalBtn();openNewPlaybookModal()"><i class="fas fa-copy"></i> Duplicate</button>
    </div>
  </div>`;

  document.getElementById('playbookModalBody').innerHTML = html;
  document.getElementById('playbookModal').classList.add('open');
}

function getPlaybookSteps(pb) {
  const stepTemplates = {
    'Vulnerability Intel': [
      {title:'Check CVE in NVD and CISA KEV',desc:'Query National Vulnerability Database for full CVE details, CVSS vector, and KEV status.',tool:'cve_lookup',duration:'~5s'},
      {title:'Get EPSS exploitation probability',desc:'Fetch current EPSS score to quantify exploitation likelihood in next 30 days.',tool:'epss_query',duration:'~3s'},
      {title:'Scan customer asset inventory',desc:'Cross-reference affected software/versions against all tenant asset databases.',tool:'asset_scan',duration:'~15s'},
      {title:'Check for public exploit code',desc:'Search GitHub, ExploitDB, and Nuclei templates for working PoC code.',tool:'exploit_search',duration:'~8s'},
      {title:'Map to MITRE ATT&CK',desc:'Map vulnerability exploitation to relevant ATT&CK techniques.',tool:'mitre_map',duration:'~2s'},
      {title:'Generate patch priority matrix',desc:'Score each affected asset by exploitability × exposure × business criticality.',tool:'scoring_engine',duration:'~5s'},
      {title:'Create remediation tickets',desc:'Auto-generate remediation tickets with patch instructions and deadline.',tool:'ticket_create',duration:'~3s'},
    ],
    'Secret Exposure': [
      {title:'Validate exposed secret',desc:'Test the exposed credential/key to confirm it is active and determine access scope.',tool:'key_validator',duration:'~4s'},
      {title:'Determine access scope',desc:'Query the service to enumerate what resources and permissions the key grants.',tool:'scope_checker',duration:'~8s'},
      {title:'Check for misuse indicators',desc:'Review API logs and access patterns for signs of unauthorized usage.',tool:'log_analysis',duration:'~12s'},
      {title:'Notify customer',desc:'Send automated alert to affected tenant with key details and urgency classification.',tool:'notification',duration:'~1s'},
      {title:'Generate revocation guide',desc:'Create step-by-step revocation instructions specific to the exposed service.',tool:'doc_generator',duration:'~2s'},
    ],
    default: [
      {title:'Collect and normalize IOC',desc:'Gather the IOC from source feed and normalize to standard format.',tool:'collector',duration:'~3s'},
      {title:'Cross-reference threat databases',desc:'Check IOC against VirusTotal, OTX, ThreatFox, and AbuseIPDB.',tool:'virustotal_check',duration:'~5s'},
      {title:'Historical analysis',desc:'Review passive DNS, certificate history, and WHOIS for additional context.',tool:'passive_dns',duration:'~6s'},
      {title:'Threat attribution',desc:'Attempt to attribute IOC to known threat actors or campaigns.',tool:'mitre_map',duration:'~4s'},
      {title:'Generate threat report',desc:'Produce structured threat report with evidence trail and recommendations.',tool:'report_gen',duration:'~2s'},
    ],
  };
  const key = Object.keys(stepTemplates).find(k => pb.category.includes(k)) || 'default';
  return (stepTemplates[key] || stepTemplates.default).slice(0, pb.steps);
}

function applyPlaybook(id) {
  const pb = ARGUS_DATA.playbooks.find(x => x.id === id);
  showToast(`Executing playbook: ${pb.name}...`, 'success');
  closePlaybookModalBtn();
  addNotification({ type:'success', title:`Playbook Executed: ${pb.name}`, desc:`${pb.steps} steps completed automatically. Check findings for results.`, time:'Just now', page:'playbooks' });
}

function exportPlaybookJSON(id) {
  const pb = ARGUS_DATA.playbooks.find(x => x.id === id);
  downloadAsFile(`playbook_${id}.json`, JSON.stringify({...pb, steps: getPlaybookSteps(pb)}, null, 2), 'application/json');
  showToast('Playbook exported as JSON', 'success');
}

function exportPlaybookPDF(id) {
  const pb = ARGUS_DATA.playbooks.find(x => x.id === id);
  if (!pb) return;
  const steps = getPlaybookSteps(pb);
  showToast(`Generating PDF for "${pb.name}"...`, 'info');
  const win = window.open('', '_blank');
  if (!win) { showToast('Allow pop-ups to generate PDF', 'warning'); return; }
  win.document.write(`<!DOCTYPE html><html><head>
  <title>EYEbot AI — Playbook: ${pb.name}</title>
  <style>
    body { font-family: Arial, sans-serif; background: #fff; color: #1e293b; padding: 40px; max-width: 900px; margin: 0 auto; }
    h1 { color: #1e293b; border-bottom: 3px solid #3b82f6; padding-bottom: 12px; font-size: 24px; }
    .badge { display:inline-block; padding:3px 10px; border-radius:4px; font-weight:700; font-size:11px; background:#f1f5f9; color:#334155; }
    .meta-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:20px 0; }
    .meta-box { background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:12px; text-align:center; }
    .meta-val { font-size:22px; font-weight:800; color:#3b82f6; }
    .meta-lbl { font-size:11px; color:#64748b; margin-top:4px; }
    .triggers { display:flex; flex-wrap:wrap; gap:6px; margin:12px 0; }
    .trigger { background:#eff6ff; border:1px solid #bfdbfe; border-radius:4px; padding:3px 8px; font-size:11px; color:#2563eb; font-family:monospace; }
    .steps { margin-top:20px; }
    .step { display:flex; gap:16px; margin-bottom:16px; padding:14px; border:1px solid #e2e8f0; border-radius:8px; }
    .step-num { width:32px; height:32px; background:#3b82f6; color:#fff; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:800; font-size:14px; flex-shrink:0; }
    .step-title { font-weight:700; font-size:13px; margin-bottom:4px; }
    .step-desc { font-size:12px; color:#475569; }
    .step-tool { font-size:11px; color:#0891b2; font-family:monospace; margin-top:4px; }
    .step-dur { font-size:10px; color:#22c55e; background:#f0fdf4; padding:2px 6px; border-radius:4px; }
    .footer { margin-top:40px; font-size:10px; color:#94a3b8; border-top:1px solid #e2e8f0; padding-top:12px; text-align:center; }
    @media print { .footer { position: fixed; bottom: 0; width: 100%; } }
  </style></head><body>
  <h1>🛡️ EYEbot AI — Response Playbook</h1>
  <h2 style="font-size:20px;margin-bottom:4px;">${pb.name}</h2>
  <p style="color:#475569;margin-bottom:16px;">${pb.desc}</p>
  <span class="badge">${pb.category}</span>
  <div class="meta-grid">
    <div class="meta-box"><div class="meta-val">${pb.steps}</div><div class="meta-lbl">Execution Steps</div></div>
    <div class="meta-box"><div class="meta-val">${pb.mitre_coverage}</div><div class="meta-lbl">MITRE TTPs</div></div>
    <div class="meta-box"><div class="meta-val">${pb.triggers.length}</div><div class="meta-lbl">Triggers</div></div>
    <div class="meta-box"><div class="meta-val" style="color:#22c55e;">Active</div><div class="meta-lbl">Status</div></div>
  </div>
  <h3>⚡ Triggers</h3>
  <div class="triggers">${pb.triggers.map(t=>`<span class="trigger">${t}</span>`).join('')}</div>
  <h3>📋 Execution Steps</h3>
  <div class="steps">
    ${steps.map((s,i)=>`
    <div class="step">
      <div class="step-num">${i+1}</div>
      <div style="flex:1;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div class="step-title">${s.title}</div>
          <span class="step-dur">${s.duration}</span>
        </div>
        <div class="step-desc">${s.desc}</div>
        ${s.tool?`<div class="step-tool">🛠️ Tool: ${s.tool}</div>`:''}
      </div>
    </div>`).join('')}
  </div>
  <div class="footer">Generated by EYEbot AI v16.4.7 · ${new Date().toLocaleString()} · CONFIDENTIAL — DO NOT DISTRIBUTE</div>
  <script>setTimeout(()=>window.print(),400);<\/script>
  </body></html>`);
  win.document.close();
  setTimeout(() => showToast('Playbook PDF ready — use browser Print to save', 'success'), 600);
}

function closePlaybookModal(e) { if (e.target === e.currentTarget) closePlaybookModalBtn(); }
function closePlaybookModalBtn() { document.getElementById('playbookModal').classList.remove('open'); }

function openNewPlaybookModal() {
  const html = `
  <div>
    <div style="font-size:18px;font-weight:800;margin-bottom:16px;">➕ New Playbook</div>
    <div class="pb-form">
      <div class="pb-form-row">
        <div><label>Playbook Name</label><input type="text" placeholder="e.g., Critical CVE Response" /></div>
        <div><label>Category</label><select><option>Vulnerability Intel</option><option>Secret Exposure</option><option>Credentials</option><option>Network</option><option>Ransomware</option><option>Phishing</option><option>Dark Web</option><option>APT Intel</option><option>Supply Chain</option></select></div>
      </div>
      <div><label>Description</label><textarea rows="2" placeholder="Describe what this playbook does..."></textarea></div>
      <div class="pb-form-row">
        <div><label>Trigger Events</label><input type="text" placeholder="e.g., api_key_found, cve_critical" /></div>
        <div><label>MITRE Techniques Covered</label><input type="text" placeholder="e.g., T1552.001, T1190" /></div>
      </div>
      <div><label>Steps (one per line)</label><textarea rows="5" placeholder="1. Validate the IOC against VirusTotal&#10;2. Check customer asset inventory&#10;3. Notify affected tenant&#10;4. Generate remediation guide"></textarea></div>
      <div style="display:flex;gap:8px;">
        <button class="btn-primary" onclick="showToast('New playbook created and activated!','success');closePlaybookModalBtn()"><i class="fas fa-save"></i> Create Playbook</button>
        <button onclick="closePlaybookModalBtn()" style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
      </div>
    </div>
  </div>`;
  document.getElementById('playbookModalBody').innerHTML = html;
  document.getElementById('playbookModal').classList.add('open');
}

/* ══════════════════════════════════════════════════════════
   TENANT MODAL
   ══════════════════════════════════════════════════════════ */
function openTenantDetail(id) {
  const t = id === 'new' ? null : ARGUS_DATA.tenants.find(x => x.id === id);
  const isNew = !t;

  const colors = ['#3b82f6','#22d3ee','#a855f7','#22c55e','#f97316','#ec4899','#f59e0b','#10b981'];
  const emojis = ['🏢','🏦','🔐','🌐','🛡️','⚡','🔬','🚀'];

  const html = `
  <div id="tenantFormWrap">
    <div style="font-size:18px;font-weight:800;margin-bottom:16px;">${isNew ? '➕ Add New Tenant' : `🏢 ${t.name}`}</div>
    ${!isNew ? `
    <div class="modal-tabs">
      <button class="modal-tab active" onclick="switchModalTab(this,'ttab-info')">Details</button>
      <button class="modal-tab" onclick="switchModalTab(this,'ttab-users')">Users (${ARGUS_DATA.users.filter(u=>u.tenant===t.name).length})</button>
      <button class="modal-tab" onclick="switchModalTab(this,'ttab-config')">Configuration</button>
    </div>` : ''}

    <div id="ttab-info" class="modal-tab-panel active">
      <div class="tenant-form">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;">
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Tenant Name *</label><input id="tnName" type="text" value="${t?.name||''}" placeholder="Acme Security Corp" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;" /></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Short Name *</label><input id="tnShort" type="text" value="${t?.short||''}" placeholder="Acme" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;" /></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Domain</label><input id="tnDomain" type="text" value="${t?.domain||''}" placeholder="acme.com" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;" /></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Plan</label>
            <select id="tnPlan" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;">
              <option ${t?.plan==='Enterprise'?'selected':''}>Enterprise</option>
              <option ${t?.plan==='Professional'?'selected':''}>Professional</option>
              <option ${t?.plan==='Standard'?'selected':''}>Standard</option>
            </select></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">SIEM Integration</label>
            <select id="tnSiem" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;">
              <option ${t?.siem?.includes('Splunk')?'selected':''}>Splunk</option>
              <option ${t?.siem?.includes('Elastic')?'selected':''}>Elastic SIEM</option>
              <option ${t?.siem?.includes('Sentinel')?'selected':''}>Microsoft Sentinel</option>
              <option ${t?.siem?.includes('QRadar')?'selected':''}>QRadar</option>
              <option>Sumo Logic</option>
              <option ${!t?'selected':''}>None</option>
            </select></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">EDR Platform</label>
            <select id="tnEdr" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;">
              <option ${t?.edr?.includes('CrowdStrike')?'selected':''}>CrowdStrike</option>
              <option ${t?.edr?.includes('SentinelOne')?'selected':''}>SentinelOne</option>
              <option ${t?.edr?.includes('Defender')?'selected':''}>Microsoft Defender</option>
              <option ${t?.edr?.includes('CarbonBlack')?'selected':''}>CarbonBlack</option>
              <option>Sophos</option>
              <option ${!t?'selected':''}>None</option>
            </select></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Risk Level</label>
            <select id="tnRisk" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;">
              <option ${t?.risk==='HIGH'?'selected':''}>HIGH</option>
              <option ${t?.risk==='MEDIUM'?'selected':''}>MEDIUM</option>
              <option ${(!t||t?.risk==='LOW')?'selected':''}>LOW</option>
            </select></div>
          <div><label style="font-size:11px;color:var(--text-muted);font-weight:600;display:block;margin-bottom:4px;">Contact Email</label><input id="tnEmail" type="email" value="${t?.email||''}" placeholder="admin@acme.com" style="width:100%;padding:7px 10px;background:var(--bg-input);border:1px solid var(--border);border-radius:var(--radius);color:var(--text-primary);font-size:12px;" /></div>
        </div>
        ${!isNew ? `
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:8px 0;">
          <div class="cd-stat"><div class="cd-stat-val" style="color:${t.color}">${ARGUS_DATA.findings.filter(f=>f.customer===t.short).length}</div><div class="cd-stat-lbl">Findings</div></div>
          <div class="cd-stat"><div class="cd-stat-val">${t.collectors}</div><div class="cd-stat-lbl">Collectors</div></div>
          <div class="cd-stat"><div class="cd-stat-val" style="color:${t.risk==='HIGH'?'#ef4444':t.risk==='MEDIUM'?'#f59e0b':'#22c55e'}">${t.risk}</div><div class="cd-stat-lbl">Risk Level</div></div>
        </div>` : ''}
        <div id="tenantFormError" style="display:none;padding:8px 12px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius);color:#f87171;font-size:12px;margin-bottom:8px;"></div>
        <div style="display:flex;gap:8px;margin-top:4px;">
          <button class="btn-primary" onclick="${isNew ? 'createTenant()' : `saveTenant('${t.id}')`}">
            ${isNew?'<i class="fas fa-plus"></i> Create Tenant':'<i class="fas fa-save"></i> Save Changes'}
          </button>
          ${!isNew ? `<button class="btn-primary" style="background:var(--accent-red);" onclick="removeTenant('${t.id}')"><i class="fas fa-trash"></i> Remove Tenant</button>` : ''}
          <button onclick="closeTenantModalBtn()" style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
        </div>
      </div>
    </div>

    ${!isNew ? `
    <div id="ttab-users" class="modal-tab-panel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <span style="font-size:12px;color:var(--text-muted);">Users with access to ${t.name}</span>
        <button class="btn-primary" style="font-size:11px;padding:5px 10px;" onclick="openAddUserToTenant('${t.id}')"><i class="fas fa-user-plus"></i> Invite User</button>
      </div>
      <table class="rbac-table">
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Last Login</th><th>MFA</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          ${ARGUS_DATA.users.filter(u=>u.tenant===t.name).map(u => `
            <tr>
              <td><div style="display:flex;align-items:center;gap:8px;"><div style="width:26px;height:26px;border-radius:6px;background:linear-gradient(135deg,#3b82f6,#a855f7);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;">${u.avatar}</div>${u.name}</div></td>
              <td style="color:var(--text-muted);font-size:11px;">${u.email}</td>
              <td><span class="role-badge ${u.role.toLowerCase().includes('admin')?'admin':u.role.toLowerCase().includes('analyst')?'analyst':'viewer'}">${u.role}</span></td>
              <td style="font-size:11px;color:var(--text-muted);">${u.last_login}</td>
              <td>${u.mfa ? '<span style="color:#22c55e;font-size:11px;">✓ Active</span>' : '<span style="color:#ef4444;font-size:11px;">✗ Disabled</span>'}</td>
              <td><span style="font-size:10px;padding:2px 6px;border-radius:4px;background:${u.status==='active'?'rgba(34,197,94,0.15)':'rgba(100,116,139,0.15)'};color:${u.status==='active'?'#4ade80':'var(--text-muted)'};">${u.status}</span></td>
              <td>
                <div style="display:flex;gap:4px;">
                  <button class="tbl-btn" title="Reset Password" onclick="showToast('Password reset sent to ${u.email}','success')"><i class="fas fa-key"></i></button>
                  <button class="tbl-btn" title="Revoke Access" onclick="removeUserFromTenant('${u.id}','${t.id}')"><i class="fas fa-ban"></i></button>
                </div>
              </td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>

    <div id="ttab-config" class="modal-tab-panel">
      <div style="display:flex;flex-direction:column;gap:8px;">
        ${[
          {key:'alerts',    label:'Receive Critical Alerts', desc:'Email + webhook on CRITICAL findings',         val:true},
          {key:'autoplay',  label:'Auto-run Playbooks',      desc:'Trigger response playbooks automatically',     val:true},
          {key:'fp',        label:'Cross-tenant FP Learning', desc:'Contribute to shared false positive model',   val:false},
          {key:'darkweb',   label:'Dark Web Monitoring',      desc:'Monitor tenant domain on dark web',           val:true},
          {key:'aiinv',     label:'AI Auto-Investigation',    desc:'AI investigates HIGH+ findings automatically', val:true},
        ].map(s => `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);">
            <div><div style="font-size:12px;font-weight:600;">${s.label}</div><div style="font-size:10px;color:var(--text-muted);">${s.desc}</div></div>
            <div class="toggle-switch ${s.val?'on':''}" onclick="this.classList.toggle('on')"></div>
          </div>`).join('')}
      </div>
      <button class="btn-primary" style="margin-top:10px;" onclick="showToast('${t.name} configuration saved!','success')"><i class="fas fa-save"></i> Save Config</button>
    </div>` : ''}
  </div>`;

  document.getElementById('tenantModalBody').innerHTML = html;
  document.getElementById('tenantModal').classList.add('open');
}

function createTenant() {
  const name   = document.getElementById('tnName')?.value.trim();
  const short  = document.getElementById('tnShort')?.value.trim();
  const domain = document.getElementById('tnDomain')?.value.trim();
  const plan   = document.getElementById('tnPlan')?.value;
  const siem   = document.getElementById('tnSiem')?.value;
  const edr    = document.getElementById('tnEdr')?.value;
  const risk   = document.getElementById('tnRisk')?.value;
  const email  = document.getElementById('tnEmail')?.value.trim();
  const errEl  = document.getElementById('tenantFormError');

  if (!name || !short) {
    errEl.textContent = 'Tenant Name and Short Name are required.';
    errEl.style.display = 'block';
    return;
  }
  if (ARGUS_DATA.tenants.find(t => t.name.toLowerCase() === name.toLowerCase())) {
    errEl.textContent = 'A tenant with this name already exists.';
    errEl.style.display = 'block';
    return;
  }
  errEl.style.display = 'none';

  const colors = ['#3b82f6','#22d3ee','#a855f7','#22c55e','#f97316','#ec4899','#f59e0b','#10b981'];
  const emojis = ['🏢','🏦','🔐','🌐','🛡️','⚡','🔬','🚀'];
  const idx = ARGUS_DATA.tenants.length % colors.length;

  const newTenant = {
    id: 'T' + String(ARGUS_DATA.tenants.length + 1).padStart(3,'0'),
    name, short: short || name.slice(0,8),
    domain: domain || (short.toLowerCase().replace(/\s/g,'-') + '.com'),
    plan, siem, edr, risk,
    email: email || `admin@${domain||short.toLowerCase()}.com`,
    collectors: 15,
    findings: 0,
    color: colors[idx],
    emoji: emojis[idx],
    created: new Date().toISOString().slice(0,7),
    active: true,
  };

  ARGUS_DATA.tenants.push(newTenant);
  closeTenantModalBtn();
  showToast(`✅ Tenant "${name}" created successfully!`, 'success');
  addNotification({ type:'success', title:'New Tenant Added', desc:`${name} (${plan}) has been onboarded.`, time:'Just now', page:'customers' });

  // Refresh the tenants grid
  if (typeof renderCustomers === 'function') renderCustomers();
}

function saveTenant(id) {
  const t = ARGUS_DATA.tenants.find(x => x.id === id);
  if (!t) return;
  const name   = document.getElementById('tnName')?.value.trim();
  const short  = document.getElementById('tnShort')?.value.trim();
  const domain = document.getElementById('tnDomain')?.value.trim();
  const plan   = document.getElementById('tnPlan')?.value;
  const siem   = document.getElementById('tnSiem')?.value;
  const edr    = document.getElementById('tnEdr')?.value;
  const risk   = document.getElementById('tnRisk')?.value;
  const email  = document.getElementById('tnEmail')?.value.trim();
  const errEl  = document.getElementById('tenantFormError');

  if (!name || !short) {
    errEl.textContent = 'Tenant Name and Short Name are required.';
    errEl.style.display = 'block';
    return;
  }
  Object.assign(t, { name, short, domain, plan, siem, edr, risk, email });
  closeTenantModalBtn();
  showToast(`✅ Tenant "${name}" updated successfully!`, 'success');
  if (typeof renderCustomers === 'function') renderCustomers();
}

function removeTenant(id) {
  const t = ARGUS_DATA.tenants.find(x => x.id === id);
  if (!t) return;
  if (!confirm(`Remove tenant "${t.name}"? This cannot be undone.`)) return;
  ARGUS_DATA.tenants = ARGUS_DATA.tenants.filter(x => x.id !== id);
  closeTenantModalBtn();
  showToast(`Tenant "${t.name}" removed.`, 'warning');
  if (typeof renderCustomers === 'function') renderCustomers();
}

function removeUserFromTenant(userId, tenantId) {
  const u = ARGUS_DATA.users.find(x => x.id === userId);
  if (!u) return;
  u.status = 'inactive';
  showToast(`Access revoked for ${u.name}`, 'warning');
  // Refresh tenant modal
  const t = ARGUS_DATA.tenants.find(x => x.id === tenantId);
  if (t) openTenantDetail(tenantId);
}

function openAddUserToTenant(tenantId) {
  showToast('Invite functionality — enter email in Settings > User Management', 'info');
}

/* ══════════════════════════════════════════════════════════
   REPORT GENERATION MODAL
   ══════════════════════════════════════════════════════════ */
function openReportModal(id) {
  const rt = ARGUS_DATA.report_templates.find(x => x.id === id);
  if (!rt) return;

  const html = `
  <div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
      <div style="font-size:32px;">${rt.icon}</div>
      <div>
        <div style="font-size:18px;font-weight:800;">${rt.name}</div>
        <div style="font-size:11px;color:var(--text-muted);">${rt.desc}</div>
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">📁 Select Export Format</div>
      <div class="report-format-grid">
        ${rt.formats.map((f,i) => `
          <div class="report-format-btn ${i===0?'selected':''}" onclick="selectReportFormat(this)">
            <i class="fas fa-${f==='PDF'?'file-pdf':f==='CSV'?'file-csv':f==='JSON'?'code':f==='STIX'?'shield-alt':'file'}" style="color:${f==='PDF'?'#ef4444':f==='CSV'?'#22c55e':f==='JSON'?'#f59e0b':'#a855f7'}"></i>
            <span>${f}</span>
          </div>`).join('')}
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">🏢 Tenant Filter</div>
      <select class="filter-select" style="width:100%;margin-top:6px;">
        <option value="">All Tenants</option>
        ${ARGUS_DATA.tenants.map(t => `<option>${t.short}</option>`).join('')}
      </select>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">📋 Report Sections</div>
      <div style="display:flex;flex-direction:column;gap:4px;margin-top:6px;">
        ${rt.sections.map(s => `
          <label style="display:flex;align-items:center;gap:8px;padding:6px;cursor:pointer;border-radius:4px;transition:background 0.15s;" onmouseover="this.style.background='var(--bg-elevated)'" onmouseout="this.style.background='transparent'">
            <input type="checkbox" checked style="accent-color:var(--accent-blue);" />
            <span style="font-size:12px;">${s}</span>
          </label>`).join('')}
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <div class="modal-section-title">⏱️ Date Range</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px;">
        <div><label style="font-size:10px;color:var(--text-muted);">From</label><input type="date" class="settings-input" style="width:100%;" value="2024-12-07" /></div>
        <div><label style="font-size:10px;color:var(--text-muted);">To</label><input type="date" class="settings-input" style="width:100%;" value="2024-12-14" /></div>
      </div>
    </div>

    <div style="display:flex;gap:8px;">
      <button class="btn-primary" onclick="generateReport('${rt.id}')"><i class="fas fa-file-export"></i> Generate Report</button>
      <button onclick="closeTenantModalBtn()" style="padding:7px 14px;background:transparent;border:1px solid var(--border);border-radius:var(--radius);color:var(--text-secondary);cursor:pointer;font-size:12px;">Cancel</button>
    </div>
  </div>`;

  document.getElementById('tenantModalBody').innerHTML = html;
  document.getElementById('tenantModal').classList.add('open');
}

function selectReportFormat(btn) {
  btn.closest('.report-format-grid').querySelectorAll('.report-format-btn').forEach(b => b.classList.remove('selected'));
  btn.classList.add('selected');
}

function generateReport(rtId, formatOverride, tenantOverride) {
  const rt = ARGUS_DATA.report_templates.find(x => x.id === rtId);
  if (!rt) return;
  const selectedFmt = formatOverride || document.querySelector('.report-format-btn.selected span')?.textContent || rt.formats[0];
  const tenant = tenantOverride || null;
  closeTenantModalBtn();
  showToast(`Generating "${rt.name}" as ${selectedFmt}...`, 'info');
  setTimeout(() => {
    if (selectedFmt === 'CSV') {
      const csv = generateReportCSV(rt, tenant);
      downloadAsFile(`${rt.name.replace(/\s/g,'_')}_${Date.now()}.csv`, csv, 'text/csv');
      showToast(`Report "${rt.name}" exported as CSV!`, 'success');
    } else if (selectedFmt === 'JSON') {
      const json = generateReportJSON(rt, tenant);
      downloadAsFile(`${rt.name.replace(/\s/g,'_')}_${Date.now()}.json`, json, 'application/json');
      showToast(`Report "${rt.name}" exported as JSON!`, 'success');
    } else if (selectedFmt === 'STIX') {
      const stix = { type:'bundle', spec_version:'2.1', id:`bundle--${Date.now()}`, objects: ARGUS_DATA.campaigns.map(c => ({ type:'campaign', id:`campaign--${c.id}`, name:c.name, description:c.description })) };
      downloadAsFile(`${rt.name.replace(/\s/g,'_')}_stix_${Date.now()}.json`, JSON.stringify(stix, null, 2), 'application/json');
      showToast(`STIX bundle for "${rt.name}" exported!`, 'success');
    } else {
      // PDF — open in new window
      const findings = tenant ? ARGUS_DATA.findings.filter(f => f.customer === tenant) : ARGUS_DATA.findings;
      const win = window.open('', '_blank');
      if (win) {
        win.document.write(`<!DOCTYPE html><html><head><title>EYEbot — ${rt.name}</title>
        <style>body{font-family:Arial,sans-serif;padding:40px;}h1{border-bottom:3px solid #ef4444;padding-bottom:10px;}h2{color:#334155;margin-top:24px;}table{width:100%;border-collapse:collapse;}th,td{padding:8px;border:1px solid #ddd;text-align:left;}th{background:#f8fafc;}.footer{margin-top:40px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px;}.cover{background:#1e293b;color:#fff;padding:30px;border-radius:8px;margin-bottom:30px;}</style>
        </head><body>
        <div class="cover"><h1 style="color:#fff;border-bottom-color:#3b82f6;">🛡️ EYEbot AI</h1><h2 style="color:#94a3b8;">${rt.name}</h2>${tenant?`<p style="color:#64748b;">Tenant: ${tenant}</p>`:''}<p style="color:#64748b;">Generated: ${new Date().toLocaleString()}</p></div>
        <h2>Executive Summary</h2>
        <p>Total Findings: <strong>${findings.length}</strong> | Critical: <strong>${findings.filter(f=>f.severity==='CRITICAL').length}</strong> | High: <strong>${findings.filter(f=>f.severity==='HIGH').length}</strong></p>
        <h2>Findings (top 20)</h2>
        <table><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th><th>Score</th><th>Time</th></tr>
        ${findings.slice(0,20).map(f=>`<tr><td>${f.severity}</td><td>${f.type}</td><td>${f.value.slice(0,50)}</td><td>${f.source}</td><td>${f.score}</td><td>${f.time}</td></tr>`).join('')}
        </table>
        <div class="footer">EYEbot AI v16.4.7 · ${new Date().toISOString()} · CONFIDENTIAL</div>
        <script>window.print();<\/script></body></html>`);
        win.document.close();
      }
      showToast(`PDF report opened — use browser Print to save`, 'success');
    }
  }, 800);
}

function generateReportCSV(rt, tenant) {
  const findings = tenant ? ARGUS_DATA.findings.filter(f => f.customer === tenant) : ARGUS_DATA.findings;
  const rows = findings.map(f => `${f.id},${f.severity},${f.type},"${f.value}",${f.source},${f.customer},${f.score},${f.mitre},${f.time}`);
  return `EYEbot AI — ${rt.name}\nGenerated: ${new Date().toISOString()}${tenant?'\nTenant: '+tenant:''}\n\nid,severity,type,value,source,tenant,score,mitre,time\n${rows.join('\n')}`;
}

function generateReportJSON(rt, tenant) {
  const findings = tenant ? ARGUS_DATA.findings.filter(f => f.customer === tenant) : ARGUS_DATA.findings;
  return JSON.stringify({
    report_name: rt.name,
    generated: new Date().toISOString(),
    platform: 'EYEbot AI v16.4.7',
    tenant: tenant || 'all',
    summary: { total_findings: findings.length, critical: findings.filter(f=>f.severity==='CRITICAL').length, high: findings.filter(f=>f.severity==='HIGH').length },
    findings: findings,
    campaigns: ARGUS_DATA.campaigns.slice(0,5),
  }, null, 2);
}

function generatePDFText(rt) {
  return `=============================================================
EYEbot AI — ${rt.name}
Generated: ${new Date().toLocaleString()}
Platform: EYEbot AI v16.4.7
=============================================================

EXECUTIVE SUMMARY
-----------------
Total Findings: ${ARGUS_DATA.findings.length}
Critical: ${ARGUS_DATA.findings.filter(f=>f.severity==='CRITICAL').length}
High: ${ARGUS_DATA.findings.filter(f=>f.severity==='HIGH').length}
Active Campaigns: ${ARGUS_DATA.campaigns.filter(c=>c.status==='Active').length}
Threat Pressure Index: 74/100 (HIGH)

CRITICAL FINDINGS
-----------------
${ARGUS_DATA.findings.filter(f=>f.severity==='CRITICAL').map(f => `[${f.id}] ${f.type}: ${f.value}\n  Source: ${f.source} | Tenant: ${f.customer} | Score: ${f.score}/100\n  ${f.description}`).join('\n\n')}

ACTIVE CAMPAIGNS
----------------
${ARGUS_DATA.campaigns.filter(c=>c.status==='Active').map(c => `${c.name}\n  Actor: ${c.actor} | Severity: ${c.severity}\n  ${c.description}`).join('\n\n')}

=============================================================
END OF REPORT
=============================================================`;
}

/* ══════════════════════════════════════════════════════════
   NOTIFICATIONS HELPERS — addNotification only
   (toggleNotifications, markAllRead, updateNotifBadge are in main.js)
   ══════════════════════════════════════════════════════════ */
function addNotification(notif) {
  ARGUS_DATA.notifications.unshift({ id: 'N' + Date.now(), ...notif, read: false });
  if (typeof updateNotifBadge === 'function') updateNotifBadge();
  if (typeof renderNotificationList === 'function') renderNotificationList();
}

/* ══════════════════════════════════════════════════════════
   MODAL TAB SWITCHER
   ══════════════════════════════════════════════════════════ */
function switchModalTab(btn, panelId) {
  const tabsContainer = btn.closest('.modal-tabs');
  tabsContainer.querySelectorAll('.modal-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  const allPanels = tabsContainer.nextElementSibling?.parentElement?.querySelectorAll('.modal-tab-panel');
  if (allPanels) allPanels.forEach(p => p.classList.remove('active'));
  const panel = document.getElementById(panelId);
  if (panel) panel.classList.add('active');
}

/* ══════════════════════════════════════════════════════════
   UTILITIES
   ══════════════════════════════════════════════════════════ */
function downloadAsFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Also alias as downloadFile so main.js and modals.js share the same function
if (typeof downloadFile === 'undefined') {
  window.downloadFile = downloadAsFile;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard!', 'success')).catch(() => showToast('Copy failed', 'error'));
}

function escapeHtmlModal(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

/* Export functions delegate to main.js implementations */
function investigateWithAI(findingId) {
  const f = ARGUS_DATA.findings.find(x => x.id === findingId);
  closeFindingModalBtn();
  closeDetailModalBtn();
  navigateTo('ai-orchestrator');
  setTimeout(() => {
    const input = document.getElementById('aiInput');
    if (input && f) {
      input.value = `Investigate finding ${f.id}: ${f.type} "${f.value}" from ${f.source}. Customer: ${f.customer}. Score: ${f.score}/100`;
      input.dispatchEvent(new Event('input'));
      sendAIMessage();
    }
  }, 300);
}
