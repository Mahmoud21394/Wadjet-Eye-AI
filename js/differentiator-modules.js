/* ═══════════════════════════════════════════════════════════════════════
   EYEbot AI — Differentiator Modules v1.0
   ─────────────────────────────────────────────────────────────────────
   Module A: SOC Memory Engine         (institutional learning brain)
   Module B: Threat Intelligence Graph (entity relationship brain)
   Module C: Digital Risk Protection   (brand + external attack surface)
   Module D: Attack Storyline Generator (AI cinematic reconstruction)
   ═══════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ── Shared utilities ── */
  function _esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function _toast(m, t='info') { if (typeof window.showToast === 'function') window.showToast(m, t); }
  function _ago(iso) {
    if (!iso) return 'N/A';
    const d = Math.floor((Date.now() - new Date(iso)) / 1000);
    if (d < 60)   return d + 's ago';
    if (d < 3600) return Math.floor(d/60) + 'm ago';
    if (d < 86400) return Math.floor(d/3600) + 'h ago';
    return Math.floor(d/86400) + 'd ago';
  }
  function _rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

  /* ══════════════════════════════════════════════════════════════════
     MODULE A: SOC MEMORY ENGINE
     "Institutional Learning — The SOC Never Forgets"
     Stores analyst decisions, playbook outcomes, case resolutions,
     builds a living knowledge base that improves with every incident.
  ══════════════════════════════════════════════════════════════════ */
  window.renderSOCMemoryEngine = function () {
    const el = document.getElementById('page-soc-memory');
    if (!el) return;

    const MEMORIES = [
      {
        id: 'MEM-2025-0891',
        type: 'incident_resolution',
        title: 'APT29 Lateral Movement — WKSTN-045',
        category: 'Lateral Movement',
        resolution: 'Isolated host, rotated credentials for 47 users, deployed Cobalt Strike beacon hunter. Attack chain stopped before DC compromise.',
        analyst: 'Ahmed Hassan',
        date: new Date(Date.now() - 86400000 * 3).toISOString(),
        duration: '2h 14m',
        confidence_gain: 12,
        lessons: [
          'SMB beacon cadence exactly 4.3m = Cobalt Strike default — add to detection rule',
          'svchost.exe with parent explorer.exe is always suspicious — zero FP in 3 months',
          'Domain Controller subnet traffic from workstations requires immediate escalation',
        ],
        tags: ['apt29', 'cobalt-strike', 'lateral-movement', 'credential-rotation'],
        similar_cases: ['MEM-2024-0312', 'MEM-2023-1891'],
        playbook_used: 'PB-LATERAL-001',
        outcome: 'contained',
        mitre: ['T1021.002', 'T1055', 'T1078'],
        impact_score: 92,
      },
      {
        id: 'MEM-2025-0734',
        type: 'false_positive_learning',
        title: 'Legitimate IT Scan Misidentified as Recon',
        category: 'Network Scan',
        resolution: 'Verified with IT team — scheduled Nessus vulnerability scan from 10.0.50.10. Added to exclusion list with scheduled scan window.',
        analyst: 'Sara Williams',
        date: new Date(Date.now() - 86400000 * 7).toISOString(),
        duration: '18m',
        confidence_gain: -5,
        lessons: [
          'Nessus scan IP 10.0.50.10 must be whitelisted for SYN scan patterns',
          'Always check scheduled scan calendar before escalating network scan alerts',
          'IT change management window: Tuesdays 02:00-04:00 UTC',
        ],
        tags: ['false-positive', 'nessus', 'vulnerability-scan', 'exclusion'],
        similar_cases: ['MEM-2024-0891'],
        playbook_used: 'PB-VERIFY-001',
        outcome: 'false_positive',
        mitre: [],
        impact_score: 10,
      },
      {
        id: 'MEM-2025-0612',
        type: 'threat_hunt_success',
        title: 'Discovered Dormant Implant — Finance Server',
        category: 'Threat Hunt',
        resolution: 'Hunt based on LOLBAS pattern found WMI subscription persistence on FIN-SRV-03. Implant silent for 23 days. Full IR activated.',
        analyst: 'Omar Khalil',
        date: new Date(Date.now() - 86400000 * 14).toISOString(),
        duration: '4h 37m',
        confidence_gain: 18,
        lessons: [
          'WMI subscriptions on financial servers should be audited weekly',
          'Dormant implants often survive patch cycles — look for old LOLBin activity',
          'Process lineage from wmiprvse.exe to cmd.exe is 100% malicious in this env',
        ],
        tags: ['threat-hunt', 'wmi-persistence', 'lolbas', 'finance', 'dormant-implant'],
        similar_cases: ['MEM-2024-1203'],
        playbook_used: 'PB-HUNT-003',
        outcome: 'critical_finding',
        mitre: ['T1546.003', 'T1059.001', 'T1027'],
        impact_score: 97,
      },
      {
        id: 'MEM-2025-0445',
        type: 'playbook_optimization',
        title: 'Ransomware Response Playbook — Time Reduction',
        category: 'Ransomware',
        resolution: 'Added pre-built isolation scripts to playbook. Reduced mean time to contain from 47min to 8min across 3 incidents.',
        analyst: 'AI System',
        date: new Date(Date.now() - 86400000 * 21).toISOString(),
        duration: 'N/A',
        confidence_gain: 25,
        lessons: [
          'Pre-staged isolation scripts cut response time by 83%',
          'Automated SMB disabling on first C2 beacon detection prevents spread',
          'Shadow copy deletion check should be first step, not last',
        ],
        tags: ['playbook', 'ransomware', 'automation', 'mttc-improvement'],
        similar_cases: ['MEM-2025-0201', 'MEM-2024-0967'],
        playbook_used: 'PB-RANSOM-001',
        outcome: 'optimized',
        mitre: ['T1486', 'T1490', 'T1071'],
        impact_score: 78,
      }
    ];

    const KNOWLEDGE_GRAPH = [
      { pattern: 'SMB beacon 4.3m interval', confidence: 98, occurrences: 7, outcome: 'Cobalt Strike (100%)', tag: 'C2' },
      { pattern: 'mshta.exe → PowerShell → encoded', confidence: 97, occurrences: 12, outcome: 'Phishing dropper (97%)', tag: 'Initial Access' },
      { pattern: 'WMI subscription from non-admin', confidence: 94, occurrences: 4, outcome: 'Persistence implant (94%)', tag: 'Persistence' },
      { pattern: 'svchost.exe parent=explorer.exe', confidence: 99, occurrences: 23, outcome: 'Process injection (99%)', tag: 'Injection' },
      { pattern: 'DNS TXT query > 128 chars', confidence: 89, occurrences: 6, outcome: 'DNS tunneling (89%)', tag: 'C2' },
      { pattern: 'certutil.exe -decode download', confidence: 96, occurrences: 9, outcome: 'LOLBAS downloader (96%)', tag: 'Execution' },
    ];

    const STATS = [
      { label: 'Memories Stored', value: '4,891', color: '#a855f7', icon: 'fa-brain' },
      { label: 'Knowledge Patterns', value: '312', color: '#00d4ff', icon: 'fa-sitemap' },
      { label: 'FP Reduction', value: '73%', color: '#22c55e', icon: 'fa-filter' },
      { label: 'MTTC Improvement', value: '68%', color: '#f59e0b', icon: 'fa-bolt' },
    ];

    const outcomeColors = { contained:'#22c55e', false_positive:'#64748b', critical_finding:'#ef4444', optimized:'#00d4ff' };
    const typeIcons = { incident_resolution:'fa-shield-alt', false_positive_learning:'fa-filter', threat_hunt_success:'fa-crosshairs', playbook_optimization:'fa-cogs' };

    el.innerHTML = `
      <div class="cds-module cds-accent-memory">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(168,85,247,0.12);color:#a855f7;border:1px solid rgba(168,85,247,0.3);">
              <i class="fas fa-memory"></i>
            </div>
            <div>
              <div class="cds-module-name">SOC Memory Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Learning Active</div>
                <span>·</span><span>Institutional Intelligence</span><span>·</span><span>v1.0</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="window._socMemorySearch()"><i class="fas fa-search"></i> Search Memory</button>
            <button class="cds-btn cds-btn-sm cds-btn-primary" onclick="window._socMemoryAddLesson()"><i class="fas fa-plus"></i> Add Lesson</button>
          </div>
        </div>

        <div class="cds-module-body">
          <!-- Stats -->
          <div class="cds-metrics">
            ${STATS.map(s => `
              <div class="cds-card cds-stat-card" style="border-color:${s.color}22;">
                <div class="cds-stat-icon" style="background:${s.color}15;color:${s.color};border:1px solid ${s.color}33;"><i class="fas ${s.icon}"></i></div>
                <div><div class="cds-stat-num" style="color:${s.color};">${s.value}</div><div class="cds-stat-label">${s.label}</div></div>
              </div>`).join('')}
          </div>

          <!-- Tabs -->
          <div class="cds-tabs" style="margin-bottom:16px;">
            <button class="cds-tab cds-tab-active" onclick="window._socMemTab(this,'incidents')"><i class="fas fa-history"></i> Memory Log</button>
            <button class="cds-tab" onclick="window._socMemTab(this,'patterns')"><i class="fas fa-dna"></i> Knowledge Patterns</button>
            <button class="cds-tab" onclick="window._socMemTab(this,'lessons')"><i class="fas fa-graduation-cap"></i> Lessons Learned</button>
          </div>

          <!-- Memory Log Tab -->
          <div id="soc-mem-incidents" class="soc-mem-tab-panel" style="display:flex;flex-direction:column;gap:12px;">
            ${MEMORIES.map(m => `
              <div class="cds-card" style="border-left:3px solid ${outcomeColors[m.outcome]||'#64748b'};">
                <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
                  <div style="display:flex;align-items:center;gap:10px;">
                    <div style="width:36px;height:36px;border-radius:8px;background:${outcomeColors[m.outcome]||'#64748b'}22;color:${outcomeColors[m.outcome]||'#64748b'};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                      <i class="fas ${typeIcons[m.type]||'fa-bookmark'}"></i>
                    </div>
                    <div>
                      <div style="font-size:13px;font-weight:700;color:var(--cds-text-primary);">${_esc(m.title)}</div>
                      <div style="font-size:10px;color:var(--cds-text-muted);">${m.id} · ${_esc(m.category)} · ${_ago(m.date)} · Analyst: ${_esc(m.analyst)}</div>
                    </div>
                  </div>
                  <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;">
                    <span class="cds-badge" style="background:${outcomeColors[m.outcome]||'#64748b'}22;color:${outcomeColors[m.outcome]||'#64748b'};border:1px solid ${outcomeColors[m.outcome]||'#64748b'}44;">${m.outcome.replace('_',' ').toUpperCase()}</span>
                    ${m.confidence_gain > 0 ? `<span style="font-size:11px;color:#22c55e;font-weight:700;"><i class="fas fa-arrow-up"></i> +${m.confidence_gain}% confidence</span>` : `<span style="font-size:11px;color:#64748b;font-weight:700;"><i class="fas fa-arrow-down"></i> ${m.confidence_gain}% FP logged</span>`}
                  </div>
                </div>

                <div style="background:var(--cds-bg-tertiary);border-radius:6px;padding:10px;margin-bottom:10px;font-size:12px;color:var(--cds-text-secondary);line-height:1.5;">
                  ${_esc(m.resolution)}
                </div>

                <div style="margin-bottom:10px;">
                  <div class="cds-section-title" style="margin-bottom:6px;"><i class="fas fa-lightbulb"></i> Lessons Learned</div>
                  ${m.lessons.map(l => `
                    <div style="display:flex;align-items:flex-start;gap:6px;margin-bottom:4px;">
                      <i class="fas fa-check-circle" style="color:#22c55e;font-size:10px;margin-top:3px;flex-shrink:0;"></i>
                      <span style="font-size:11px;color:var(--cds-text-secondary);">${_esc(l)}</span>
                    </div>`).join('')}
                </div>

                <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                  ${m.tags.map(t => `<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(100,116,139,0.15);color:var(--cds-text-muted);">${_esc(t)}</span>`).join('')}
                  ${m.mitre.map(t => `<span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.2);">${t}</span>`).join('')}
                  <span style="margin-left:auto;font-size:10px;color:var(--cds-text-muted);">⏱ ${m.duration} · Impact: <strong style="color:#f59e0b;">${m.impact_score}</strong>/100</span>
                </div>
              </div>
            `).join('')}
          </div>

          <!-- Knowledge Patterns Tab -->
          <div id="soc-mem-patterns" class="soc-mem-tab-panel" style="display:none;">
            <div class="cds-card" style="margin-bottom:12px;">
              <div class="cds-section-title" style="margin-bottom:12px;"><i class="fas fa-dna"></i> Learned Detection Patterns (auto-generated from resolved cases)</div>
              <div class="cds-table-wrap">
                <table class="cds-table">
                  <thead><tr><th>Pattern</th><th>Occurrences</th><th>Confidence</th><th>Verdict</th><th>Category</th></tr></thead>
                  <tbody>
                    ${KNOWLEDGE_GRAPH.map(p => `
                      <tr>
                        <td><code style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#00d4ff;">${_esc(p.pattern)}</code></td>
                        <td style="text-align:center;font-weight:700;color:#f59e0b;">${p.occurrences}</td>
                        <td>
                          <div style="display:flex;align-items:center;gap:6px;">
                            <div class="cds-progress" style="width:80px;">
                              <div class="cds-progress-fill" style="width:${p.confidence}%;background:${p.confidence>=95?'linear-gradient(90deg,#22c55e,#16a34a)':'linear-gradient(90deg,#f59e0b,#ea580c)'};"></div>
                            </div>
                            <span style="font-size:11px;font-weight:700;color:${p.confidence>=95?'#22c55e':'#f59e0b'};">${p.confidence}%</span>
                          </div>
                        </td>
                        <td style="font-size:11px;color:var(--cds-text-secondary);">${_esc(p.outcome)}</td>
                        <td><span class="cds-badge cds-badge-info">${_esc(p.tag)}</span></td>
                      </tr>`).join('')}
                  </tbody>
                </table>
              </div>
            </div>
            <div class="cds-ai-explainer">
              <div class="cds-ai-explainer-header">
                <div class="cds-ai-badge"><i class="fas fa-robot"></i> AI MEMORY INSIGHT</div>
              </div>
              <div class="cds-ai-reasoning">
                SOC Memory Engine has identified <strong>6 high-confidence patterns</strong> from 312 resolved incidents. 
                The most reliable signal is <strong>svchost.exe with parent explorer.exe</strong> (99% malicious, 23 observations) — 
                this has never produced a false positive in this environment. Recommend adding this pattern as a Tier 1 auto-escalation rule 
                with automated host isolation. The SMB beacon pattern could save an average of 47 minutes of analyst time per incident.
              </div>
            </div>
          </div>

          <!-- Lessons Learned Tab -->
          <div id="soc-mem-lessons" class="soc-mem-tab-panel" style="display:none;">
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">
              ${[
                { title:'Never ignore beacon cadence', desc:'Tool-specific timing patterns (CS: 4.3m, Empire: 5m, Brute Ratel: variable) are the most reliable C2 identifiers. Always check interval regularity.', priority:'critical', author:'SOC Team' },
                { title:'Parent process is the truth', desc:'Legitimate processes have predictable parents. svchost→services.exe, powershell→cmd.exe (admin tasks). Any deviation is suspicious. Build ancestry rules.', priority:'high', author:'Ahmed Hassan' },
                { title:'Check scheduled scans first', desc:'30% of network scan alerts are IT vulnerability management. Always verify against the weekly scan schedule before escalating. Saved 12 analyst-hours last month.', priority:'medium', author:'Sara Williams' },
                { title:'Shadow copies = ransomware intent', desc:'Any process deleting VSS is either ransomware or preparing for ransomware. No legitimate software does this. Treat as confirmed incident immediately.', priority:'critical', author:'Omar Khalil' },
                { title:'DNS TXT > 128 chars = tunneling', desc:'All legitimate DNS TXT records in this env are under 60 chars. Any response over 128 chars with base64 patterns is DNS C2 tunneling with 89% confidence.', priority:'high', author:'AI Engine' },
                { title:'Finance servers need weekly WMI audit', desc:'WMI subscription persistence is silent and survives reboots. Finance servers are prime targets. Weekly automated audit catches dormant implants early.', priority:'high', author:'Omar Khalil' },
              ].map(l => `
                <div class="cds-card" style="border-left:3px solid ${l.priority==='critical'?'#ef4444':l.priority==='high'?'#f97316':'#f59e0b'};">
                  <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px;">
                    <span class="cds-badge cds-badge-${l.priority}">${l.priority.toUpperCase()}</span>
                    <span style="font-size:12px;font-weight:700;color:var(--cds-text-primary);">${_esc(l.title)}</span>
                  </div>
                  <div style="font-size:11px;color:var(--cds-text-secondary);line-height:1.5;margin-bottom:8px;">${_esc(l.desc)}</div>
                  <div style="font-size:10px;color:var(--cds-text-muted);"><i class="fas fa-user"></i> ${_esc(l.author)}</div>
                </div>`).join('')}
            </div>
          </div>
        </div>
      </div>
    `;

    /* Tab switcher */
    window._socMemTab = function(btn, tab) {
      document.querySelectorAll('.soc-mem-tab-panel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('#page-soc-memory .cds-tab').forEach(b => b.classList.remove('cds-tab-active'));
      const panel = document.getElementById('soc-mem-' + tab);
      if (panel) panel.style.display = tab === 'lessons' ? 'grid' : 'flex';
      btn.classList.add('cds-tab-active');
    };
    window._socMemorySearch = function() { _toast('🧠 Memory search: type any pattern, IOC, or case ID', 'info'); };
    window._socMemoryAddLesson = function() { _toast('📝 Lesson form would open — add institutional knowledge', 'info'); };
  };


  /* ══════════════════════════════════════════════════════════════════
     MODULE B: THREAT INTELLIGENCE GRAPH BRAIN
     "Visualize the web of threats — every entity, relationship, cluster"
  ══════════════════════════════════════════════════════════════════ */
  window.renderThreatGraphBrain = function () {
    const el = document.getElementById('page-threat-graph');
    if (!el) return;

    const NODES = [
      { id: 'n1', label: 'APT29 / Cozy Bear', type: 'actor', risk: 'critical', x: 50, y: 30, connections: 8 },
      { id: 'n2', label: '185.220.101.45', type: 'ip', risk: 'critical', x: 20, y: 55, connections: 5 },
      { id: 'n3', label: 'maliciousupdate.ru', type: 'domain', risk: 'critical', x: 75, y: 55, connections: 6 },
      { id: 'n4', label: 'LockBit 4.0 Loader', type: 'malware', risk: 'critical', x: 50, y: 65, connections: 4 },
      { id: 'n5', label: 'CVE-2024-3400', type: 'cve', risk: 'critical', x: 30, y: 80, connections: 3 },
      { id: 'n6', label: 'Campaign: WINTER STORM', type: 'campaign', risk: 'high', x: 70, y: 20, connections: 7 },
      { id: 'n7', label: '45.33.91.200', type: 'ip', risk: 'high', x: 15, y: 35, connections: 3 },
      { id: 'n8', label: 'finance-corp.onion', type: 'domain', risk: 'high', x: 85, y: 40, connections: 2 },
      { id: 'n9', label: 'AsyncRAT Payload', type: 'malware', risk: 'high', x: 60, y: 80, connections: 4 },
      { id: 'n10', label: 'Telecom VPN Access', type: 'credential', risk: 'critical', x: 40, y: 15, connections: 2 },
    ];

    const EDGES = [
      { from: 'n1', to: 'n2', label: 'uses C2', strength: 95 },
      { from: 'n1', to: 'n3', label: 'deploys', strength: 90 },
      { from: 'n1', to: 'n6', label: 'attributed to', strength: 87 },
      { from: 'n1', to: 'n10', label: 'leverages', strength: 82 },
      { from: 'n3', to: 'n4', label: 'delivers', strength: 94 },
      { from: 'n4', to: 'n5', label: 'exploits', strength: 88 },
      { from: 'n2', to: 'n7', label: 'related IP', strength: 73 },
      { from: 'n6', to: 'n9', label: 'includes', strength: 85 },
      { from: 'n9', to: 'n8', label: 'calls home to', strength: 91 },
    ];

    const typeColors = { actor:'#ef4444', ip:'#00d4ff', domain:'#a855f7', malware:'#f97316', cve:'#f59e0b', campaign:'#22c55e', credential:'#ec4899' };
    const typeIcons = { actor:'fa-user-secret', ip:'fa-server', domain:'fa-globe', malware:'fa-bug', cve:'fa-exclamation-triangle', campaign:'fa-chess-knight', credential:'fa-key' };

    const INTEL_CLUSTERS = [
      { id: 'C1', name: 'Eastern European APT Cluster', entities: 47, threat_level: 'CRITICAL', primary_actor: 'APT29/APT28', targets: 'Government, Finance, Energy', last_activity: new Date(Date.now()-3600000).toISOString(), tlp: 'RED', confidence: 94 },
      { id: 'C2', name: 'RaaS Ecosystem — LockBit 4.0', entities: 23, threat_level: 'CRITICAL', primary_actor: 'LockBit Group', targets: 'Healthcare, Manufacturing', last_activity: new Date(Date.now()-7200000).toISOString(), tlp: 'AMBER', confidence: 91 },
      { id: 'C3', name: 'MaaS Network — AsyncRAT Operators', entities: 31, threat_level: 'HIGH', primary_actor: 'Unknown (tracked)', targets: 'SMB, Education', last_activity: new Date(Date.now()-14400000).toISOString(), tlp: 'AMBER', confidence: 87 },
      { id: 'C4', name: 'Access Broker Marketplace', entities: 18, threat_level: 'HIGH', primary_actor: 'Multiple actors', targets: 'Telecom, Critical Infrastructure', last_activity: new Date(Date.now()-86400000).toISOString(), tlp: 'GREEN', confidence: 79 },
    ];

    const clusterColors = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#f59e0b', LOW:'#22c55e' };
    const tlpColors = { RED:'#ef4444', AMBER:'#f59e0b', GREEN:'#22c55e', WHITE:'#64748b' };

    el.innerHTML = `
      <div class="cds-module cds-accent-graph">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.3);">
              <i class="fas fa-project-diagram"></i>
            </div>
            <div>
              <div class="cds-module-name">Threat Intelligence Graph Brain</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Graph Live</div>
                <span>·</span><span>${NODES.length} Entities</span><span>·</span><span>${EDGES.length} Relationships</span><span>·</span><span>v1.0</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('🔍 Deep graph search across all entities','info')"><i class="fas fa-search"></i> Search Graph</button>
            <button class="cds-btn cds-btn-sm cds-btn-primary" onclick="_toast('📤 Graph exported as STIX 2.1 bundle','success')"><i class="fas fa-share-alt"></i> Export STIX</button>
          </div>
        </div>

        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Total Entities','10,241','#00d4ff','fa-cube'],['Active Clusters','47','#ef4444','fa-layer-group'],['Relationships','28,934','#a855f7','fa-project-diagram'],['TLP:RED Items','312','#ef4444','fa-shield-alt']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div style="display:grid;grid-template-columns:1fr 340px;gap:16px;">
            <!-- Graph Canvas -->
            <div class="cds-card" style="padding:0;overflow:hidden;">
              <div style="padding:12px 16px;border-bottom:1px solid var(--cds-border);display:flex;align-items:center;justify-content:space-between;">
                <div class="cds-section-title" style="margin:0;"><i class="fas fa-project-diagram"></i> Entity Relationship Graph</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                  ${Object.entries(typeColors).map(([type,color]) => `
                    <span style="display:flex;align-items:center;gap:4px;font-size:10px;color:var(--cds-text-muted);">
                      <span style="width:8px;height:8px;border-radius:50%;background:${color};display:inline-block;"></span>${type}
                    </span>`).join('')}
                </div>
              </div>
              <!-- SVG Graph Visualization -->
              <div style="position:relative;height:400px;background:radial-gradient(ellipse at center,rgba(0,212,255,0.03) 0%,transparent 70%);overflow:hidden;" id="graphCanvas">
                <svg width="100%" height="100%" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid meet" style="position:absolute;top:0;left:0;">
                  <!-- Grid lines -->
                  <defs>
                    <pattern id="graph-grid" width="10" height="10" patternUnits="userSpaceOnUse">
                      <path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(0,212,255,0.05)" stroke-width="0.2"/>
                    </pattern>
                  </defs>
                  <rect width="100" height="100" fill="url(#graph-grid)"/>
                  <!-- Edges -->
                  ${EDGES.map(e => {
                    const from = NODES.find(n => n.id === e.from);
                    const to = NODES.find(n => n.id === e.to);
                    if (!from || !to) return '';
                    const opacity = e.strength / 100;
                    return `
                      <line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" 
                        stroke="rgba(0,212,255,${opacity * 0.4})" stroke-width="0.4" stroke-dasharray="${e.strength > 85 ? '' : '1,1'}"/>
                      <text x="${(from.x+to.x)/2}" y="${(from.y+to.y)/2 - 1}" text-anchor="middle" fill="rgba(148,163,184,0.6)" font-size="1.8">${_esc(e.label)}</text>
                    `;
                  }).join('')}
                  <!-- Nodes -->
                  ${NODES.map(n => `
                    <g transform="translate(${n.x},${n.y})" style="cursor:pointer;" onclick="window._graphNodeClick('${n.id}')">
                      <circle r="${3 + n.connections * 0.4}" fill="${typeColors[n.type]||'#64748b'}33" stroke="${typeColors[n.type]||'#64748b'}" stroke-width="0.5"/>
                      <circle r="${1.2 + n.connections * 0.1}" fill="${typeColors[n.type]||'#64748b'}"/>
                      ${n.risk === 'critical' ? `<circle r="${3.5 + n.connections * 0.4}" fill="none" stroke="${typeColors[n.type]||'#64748b'}" stroke-width="0.2" opacity="0.4"><animate attributeName="r" values="${3+n.connections*0.4};${5+n.connections*0.4};${3+n.connections*0.4}" dur="2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite"/></circle>` : ''}
                      <text y="${4 + n.connections * 0.4 + 2}" text-anchor="middle" fill="rgba(226,232,240,0.9)" font-size="1.8">${_esc(n.label.length > 18 ? n.label.slice(0,16)+'…' : n.label)}</text>
                    </g>
                  `).join('')}
                </svg>
              </div>
            </div>

            <!-- Intel Clusters Panel -->
            <div style="display:flex;flex-direction:column;gap:10px;">
              <div class="cds-section-title"><i class="fas fa-layer-group"></i> Intelligence Clusters</div>
              ${INTEL_CLUSTERS.map(c => `
                <div class="cds-card" style="border-left:3px solid ${clusterColors[c.threat_level]};cursor:pointer;" onclick="window._graphClusterDetail('${c.id}')">
                  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                    <span style="font-size:11px;font-weight:700;color:var(--cds-text-primary);">${_esc(c.name)}</span>
                    <span style="font-size:9px;padding:1px 5px;border-radius:3px;background:${tlpColors[c.tlp]}22;color:${tlpColors[c.tlp]};border:1px solid ${tlpColors[c.tlp]}44;">TLP:${c.tlp}</span>
                  </div>
                  <div style="display:flex;gap:12px;margin-bottom:6px;flex-wrap:wrap;">
                    <span style="font-size:10px;color:var(--cds-text-muted);">Primary: <strong style="color:var(--cds-text-secondary);">${_esc(c.primary_actor)}</strong></span>
                    <span style="font-size:10px;color:var(--cds-text-muted);">${c.entities} entities</span>
                  </div>
                  <div style="font-size:10px;color:var(--cds-text-muted);margin-bottom:6px;">Targets: ${_esc(c.targets)}</div>
                  <div style="display:flex;align-items:center;justify-content:space-between;">
                    <div class="cds-progress" style="flex:1;margin-right:8px;">
                      <div class="cds-progress-fill" style="width:${c.confidence}%;background:${clusterColors[c.threat_level]};"></div>
                    </div>
                    <span style="font-size:10px;font-weight:700;color:${clusterColors[c.threat_level]};">${c.confidence}%</span>
                  </div>
                  <div style="font-size:9px;color:var(--cds-text-muted);margin-top:4px;">Last activity: ${_ago(c.last_activity)}</div>
                </div>
              `).join('')}
            </div>
          </div>

          <!-- Node Detail Panel -->
          <div id="graph-node-detail" style="display:none;margin-top:12px;">
            <div class="cds-ai-explainer">
              <div class="cds-ai-explainer-header">
                <div class="cds-ai-badge"><i class="fas fa-cube"></i> ENTITY PROFILE</div>
                <button onclick="document.getElementById('graph-node-detail').style.display='none'" style="background:none;border:none;color:var(--cds-text-muted);cursor:pointer;"><i class="fas fa-times"></i></button>
              </div>
              <div class="cds-ai-reasoning" id="graph-node-detail-content">Select a node in the graph to see its full intelligence profile.</div>
            </div>
          </div>
        </div>
      </div>
    `;

    window._graphNodeClick = function(id) {
      const node = NODES.find(n => n.id === id);
      if (!node) return;
      const detail = document.getElementById('graph-node-detail');
      const content = document.getElementById('graph-node-detail-content');
      if (!detail || !content) return;
      content.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
          <div style="width:32px;height:32px;border-radius:8px;background:${typeColors[node.type]||'#64748b'}22;color:${typeColors[node.type]||'#64748b'};display:flex;align-items:center;justify-content:center;">
            <i class="fas ${typeIcons[node.type]||'fa-cube'}"></i>
          </div>
          <div>
            <div style="font-size:14px;font-weight:700;color:var(--cds-text-primary);">${_esc(node.label)}</div>
            <div style="font-size:11px;color:var(--cds-text-muted);">Type: ${node.type} · Risk: ${node.risk} · ${node.connections} connections</div>
          </div>
          <span class="cds-badge cds-badge-${node.risk}" style="margin-left:auto;">${node.risk.toUpperCase()}</span>
        </div>
        <div style="font-size:12px;color:var(--cds-text-secondary);line-height:1.5;">
          This entity has <strong>${node.connections}</strong> confirmed relationships in the graph. It appears in 
          <strong>${_rand(2,8)}</strong> active threat clusters and has been observed in 
          <strong>${_rand(3,15)}</strong> incident investigations. 
          Last seen: <strong>${_rand(1,24)}h ago</strong>. 
          Confidence score: <strong style="color:#22c55e;">${_rand(80,98)}%</strong>.
        </div>
        <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">
          <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('🔍 Full entity profile opened','info')"><i class="fas fa-external-link-alt"></i> Full Profile</button>
          <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('🕷️ Pivot analysis started','info')"><i class="fas fa-project-diagram"></i> Pivot Analysis</button>
          <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('📤 Entity exported as STIX object','success')"><i class="fas fa-download"></i> Export STIX</button>
        </div>
      `;
      detail.style.display = 'block';
    };
    window._graphClusterDetail = function(id) {
      const c = INTEL_CLUSTERS.find(x => x.id === id);
      if (!c) return;
      _toast(`🔍 Loading cluster profile: ${c.name}`, 'info');
    };
  };


  /* ══════════════════════════════════════════════════════════════════
     MODULE C: DIGITAL RISK PROTECTION (DRP)
     "Monitor your brand, domains, employees across the entire internet"
  ══════════════════════════════════════════════════════════════════ */
  window.renderDigitalRiskProtection = function () {
    const el = document.getElementById('page-digital-risk');
    if (!el) return;

    const DRP_ALERTS = [
      { id: 'DRP-001', type: 'domain_squatting', severity: 'critical', title: 'Typosquat domain registered', detail: 'wadjet-eye-ai.com registered 6h ago — near-perfect clone of wadjet-eye.ai, used for phishing kit delivery', source: 'Domain Monitor', action_required: true, first_seen: new Date(Date.now()-21600000).toISOString(), risk_score: 97 },
      { id: 'DRP-002', type: 'credential_leak', severity: 'critical', title: 'Executive credentials on dark web', detail: 'CEO mahmoud.osman@wadjet.ai password hash found in COMBOLISTS-2025 dataset on BreachForums. Hash type: bcrypt.', source: 'Dark Web Monitor', action_required: true, first_seen: new Date(Date.now()-86400000).toISOString(), risk_score: 95 },
      { id: 'DRP-003', type: 'brand_impersonation', severity: 'high', title: 'LinkedIn fake company page', detail: '"EYEbot AI Security" fake LinkedIn page with 147 followers attempting spearphishing campaigns against clients.', source: 'Social Monitor', action_required: true, first_seen: new Date(Date.now()-172800000).toISOString(), risk_score: 82 },
      { id: 'DRP-004', type: 'data_exposure', severity: 'high', title: 'GitHub repository secret leak', detail: 'API key WEY_SK_LIVE_xxxx found in public GitHub repo "wadjet-integration-examples" — key potentially valid.', source: 'Code Monitor', action_required: true, first_seen: new Date(Date.now()-43200000).toISOString(), risk_score: 91 },
      { id: 'DRP-005', type: 'mobile_app_clone', severity: 'medium', title: 'Cloned mobile app on 3rd party store', detail: 'WadjetEye_v2.1.apk uploaded to APKPure — repackaged with banking trojan (AsyncRAT payload detected).', source: 'App Store Monitor', action_required: false, first_seen: new Date(Date.now()-259200000).toISOString(), risk_score: 74 },
      { id: 'DRP-006', type: 'employee_pii', severity: 'medium', title: 'Employee PII in data broker databases', detail: '23 employees found in data broker databases (Spokeo, BeenVerified) with home addresses and phone numbers.', source: 'PII Monitor', action_required: false, first_seen: new Date(Date.now()-345600000).toISOString(), risk_score: 62 },
    ];

    const ATTACK_SURFACE = [
      { category: 'External IPs', total: 47, exposed: 12, critical: 3, color: '#ef4444' },
      { category: 'Web Applications', total: 23, exposed: 5, critical: 1, color: '#f97316' },
      { category: 'SSL Certificates', total: 31, exposed: 2, critical: 0, color: '#22c55e' },
      { category: 'Email Security', total: 1, exposed: 0, critical: 0, color: '#22c55e' },
      { category: 'Cloud Storage', total: 18, exposed: 4, critical: 1, color: '#f59e0b' },
      { category: 'Third-party APIs', total: 34, exposed: 7, critical: 2, color: '#f97316' },
    ];

    const typeIcons = { domain_squatting:'fa-globe', credential_leak:'fa-key', brand_impersonation:'fa-user-secret', data_exposure:'fa-database', mobile_app_clone:'fa-mobile-alt', employee_pii:'fa-user-shield' };

    el.innerHTML = `
      <div class="cds-module cds-accent-drp">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(236,72,153,0.1);color:#ec4899;border:1px solid rgba(236,72,153,0.3);">
              <i class="fas fa-shield-virus"></i>
            </div>
            <div>
              <div class="cds-module-name">Digital Risk Protection</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot" style="background:#ec4899;box-shadow:0 0 4px #ec4899;"></div>Monitoring Active</div>
                <span>·</span><span>Brand + External Surface</span><span>·</span><span>v1.0</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <span class="cds-badge" style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;animation:pulse 2s infinite;">${DRP_ALERTS.filter(a=>a.action_required).length} ACTION REQUIRED</span>
            <button class="cds-btn cds-btn-sm cds-btn-primary" onclick="_toast('📊 DRP report generated','success')"><i class="fas fa-file-pdf"></i> Full Report</button>
          </div>
        </div>

        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Digital Risks','6','#ef4444','fa-exclamation-circle'],['Attack Surface','47','#f97316','fa-crosshairs'],['Monitored Assets','312','#00d4ff','fa-eye'],['Remediated (30d)','23','#22c55e','fa-check-circle']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div style="display:grid;grid-template-columns:1fr 300px;gap:16px;">
            <!-- DRP Alert Feed -->
            <div>
              <div class="cds-section-title" style="margin-bottom:12px;"><i class="fas fa-bell"></i> Digital Risk Alerts</div>
              <div style="display:flex;flex-direction:column;gap:10px;">
                ${DRP_ALERTS.map(a => `
                  <div class="cds-card${a.severity==='critical'?' cds-card--glow-red':''}" style="border-left:3px solid ${a.severity==='critical'?'#ef4444':a.severity==='high'?'#f97316':'#f59e0b'};">
                    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:8px;flex-wrap:wrap;">
                      <div style="display:flex;align-items:center;gap:8px;">
                        <div style="width:32px;height:32px;border-radius:8px;background:${a.severity==='critical'?'rgba(239,68,68,0.15)':'rgba(249,115,22,0.1)'};color:${a.severity==='critical'?'#ef4444':'#f97316'};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                          <i class="fas ${typeIcons[a.type]||'fa-shield-alt'}"></i>
                        </div>
                        <div>
                          <div style="font-size:12px;font-weight:700;color:var(--cds-text-primary);">${_esc(a.title)}</div>
                          <div style="font-size:10px;color:var(--cds-text-muted);">${a.id} · ${_esc(a.source)} · ${_ago(a.first_seen)}</div>
                        </div>
                      </div>
                      <div style="display:flex;align-items:center;gap:6px;flex-shrink:0;">
                        <span class="cds-badge cds-badge-${a.severity}">${a.severity.toUpperCase()}</span>
                        ${a.action_required ? '<span class="cds-badge" style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;animation:pulse 2s infinite;">ACT NOW</span>' : ''}
                        <span style="font-size:12px;font-weight:800;font-family:\'JetBrains Mono\',monospace;color:${a.risk_score>=90?'#ef4444':a.risk_score>=70?'#f97316':'#f59e0b'};">${a.risk_score}</span>
                      </div>
                    </div>
                    <div style="font-size:11px;color:var(--cds-text-secondary);line-height:1.5;margin-bottom:8px;">${_esc(a.detail)}</div>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;">
                      <button class="cds-btn cds-btn-sm cds-btn-primary" onclick="_toast('🛡️ Takedown request initiated for ${_esc(a.id)}','success')"><i class="fas fa-gavel"></i> Takedown</button>
                      <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('🔍 Full investigation for ${_esc(a.id)}','info')"><i class="fas fa-search"></i> Investigate</button>
                      <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('✅ ${_esc(a.id)} marked as remediated','success')"><i class="fas fa-check"></i> Remediated</button>
                    </div>
                  </div>
                `).join('')}
              </div>
            </div>

            <!-- Attack Surface Panel -->
            <div>
              <div class="cds-section-title" style="margin-bottom:12px;"><i class="fas fa-crosshairs"></i> External Attack Surface</div>
              <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px;">
                ${ATTACK_SURFACE.map(a => `
                  <div class="cds-card" style="padding:10px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                      <span style="font-size:11px;font-weight:600;color:var(--cds-text-secondary);">${_esc(a.category)}</span>
                      <div style="display:flex;gap:6px;align-items:center;">
                        ${a.critical>0?`<span style="font-size:10px;font-weight:700;color:#ef4444;">${a.critical} critical</span>`:''}
                        <span style="font-size:10px;color:${a.exposed>0?a.color:'#22c55e'};">${a.exposed}/${a.total} exposed</span>
                      </div>
                    </div>
                    <div class="cds-progress">
                      <div class="cds-progress-fill" style="width:${(a.exposed/a.total)*100}%;background:${a.color};"></div>
                    </div>
                  </div>
                `).join('')}
              </div>

              <!-- Quick Stats -->
              <div class="cds-ai-explainer">
                <div class="cds-ai-explainer-header">
                  <div class="cds-ai-badge"><i class="fas fa-robot"></i> AI RISK ASSESSMENT</div>
                </div>
                <div class="cds-ai-reasoning" style="font-size:11px;">
                  <strong>Critical:</strong> Typosquat domain + executive credential leak creates a perfect spearphishing scenario. 
                  The attacker can send convincing emails from <em>wadjet-eye-ai.com</em> while the CEO's password is compromised. 
                  <strong>Recommend:</strong> Immediate domain takedown + forced password reset within 2 hours.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;
  };


  /* ══════════════════════════════════════════════════════════════════
     MODULE D: ATTACK STORYLINE GENERATOR
     NEVER-SEEN-BEFORE INNOVATION #1:
     "AI reconstructs attacks as cinematic, human-readable narratives"
     Full kill-chain reconstruction with timeline, actors, decisions
  ══════════════════════════════════════════════════════════════════ */
  window.renderAttackStorylineGenerator = function () {
    const el = document.getElementById('page-attack-storyline');
    if (!el) return;

    const STORYLINES = [
      {
        id: 'STR-2025-0047',
        title: 'Operation: WINTER STORM — The 72-Hour Infiltration',
        threat_actor: 'APT29 / Cozy Bear',
        campaign: 'WINTER STORM',
        severity: 'critical',
        status: 'contained',
        duration: '72h 14m',
        start_time: new Date(Date.now() - 86400000 * 4).toISOString(),
        end_time: new Date(Date.now() - 86400000 * 1).toISOString(),
        summary: 'A sophisticated nation-state actor conducted a 72-hour campaign targeting the company\'s financial data. The attack began with a spearphishing email to the CFO, progressed through credential theft, lateral movement, and domain controller compromise, before being detected and contained by the SOC.',
        chapters: [
          {
            phase: 'INITIAL ACCESS',
            time: 'Day 1 — 09:23 UTC',
            icon: 'fa-envelope-open-text',
            color: '#f59e0b',
            mitre: 'T1566.002',
            title: 'The Spear Falls',
            narrative: 'The campaign began not with a bang, but with a carefully crafted email. Sent to CFO Sarah Chen at 09:23 UTC, the message appeared to be from PwC auditors — complete with correct logos, sender display names, and references to the ongoing Q4 audit. The attachment: a macro-enabled Excel file titled "Q4_Audit_Preliminary_Findings.xlsm". Sarah opened it during her morning review.',
            iocs: ['hash:4a8b2c1d9f3e6a7b', 'domain:pwc-audit-portal.com', 'email:audit@pwc-services.net'],
          },
          {
            phase: 'EXECUTION',
            time: 'Day 1 — 09:24 UTC',
            icon: 'fa-code',
            color: '#f97316',
            mitre: 'T1059.001',
            title: 'The Payload Wakes',
            narrative: 'Within 60 seconds of the file opening, Excel spawned mshta.exe, which in turn launched a heavily obfuscated PowerShell script. The script performed an AMSI bypass using the "amsiInitFailed" technique, then downloaded a 47KB stager from a CDN domain registered just 3 days prior. The stager — a Cobalt Strike beacon — established its first callback at 09:24:37 UTC, 74 seconds after the email was opened.',
            iocs: ['ip:185.220.101.45', 'domain:cdn-static-assets-01.com', 'hash:b9c3e8f1a2d4e7f0'],
          },
          {
            phase: 'PERSISTENCE',
            time: 'Day 1 — 11:47 UTC',
            icon: 'fa-anchor',
            color: '#a855f7',
            mitre: 'T1546.003',
            title: 'Digging In',
            narrative: 'Two hours after initial access, the attacker established persistence via a WMI event subscription. A permanent consumer was created that would execute the beacon loader whenever any user logged in. This technique survives reboots, standard antivirus scans, and is invisible to casual inspection of running processes. The attacker was now guaranteed a foothold even if the original Excel file was quarantined.',
            iocs: ['registry:HKLM\\SOFTWARE\\Microsoft\\WBEM\\ESS', 'wmi:__FilterToConsumerBinding'],
          },
          {
            phase: 'LATERAL MOVEMENT',
            time: 'Day 2 — 03:18 UTC',
            icon: 'fa-network-wired',
            color: '#ef4444',
            mitre: 'T1021.002',
            title: 'The Quiet Expansion',
            narrative: 'At 03:18 UTC on Day 2 — when the SOC was understaffed and alert volumes were lowest — the attacker began moving laterally. Using harvested credentials from the CFO\'s cached tokens, they connected via SMB to the Finance server (FIN-SRV-01), then to the HR system (HR-SRV-03), and finally toward the Domain Controller (DC-01). The beacon\'s heartbeat every 4.3 minutes created a distinctive pattern that our AI later identified as the Cobalt Strike default jitter setting.',
            iocs: ['host:WKSTN-045→FIN-SRV-01', 'host:FIN-SRV-01→HR-SRV-03', 'credential:sarah.chen@corp'],
          },
          {
            phase: 'DETECTION',
            time: 'Day 2 — 07:41 UTC',
            icon: 'fa-eye',
            color: '#00d4ff',
            mitre: null,
            title: 'The Eye Opens',
            narrative: 'At 07:41 UTC, EYEbot AI\'s Cognitive Layer flagged WKSTN-045 for anomalous SMB traffic — specifically the 4.3-minute beacon cadence identified from SOC Memory Engine\'s learned pattern database. The alert was classified as CRITICAL with 94% AI confidence. Analyst Ahmed Hassan was paged at 07:43. He reviewed the AI reasoning chain, confirmed the Cobalt Strike signature in under 4 minutes, and immediately escalated to incident response.',
            iocs: [],
          },
          {
            phase: 'CONTAINMENT',
            time: 'Day 2 — 08:02 UTC',
            icon: 'fa-shield-alt',
            color: '#22c55e',
            mitre: null,
            title: 'The Walls Go Up',
            narrative: 'At 08:02 UTC — just 21 minutes after AI detection — WKSTN-045 was isolated via automated playbook execution. All active sessions for sarah.chen were terminated. Network ACLs blocked the C2 IP 185.220.101.45. The WMI persistence mechanism was identified and removed by 09:15. Forensic acquisition of WKSTN-045 began immediately. By Day 3, the full attack chain had been reconstructed, all 7 affected hosts cleaned, and a post-incident report delivered to the board.',
            iocs: ['remediation:host-isolation', 'remediation:credential-rotation-47-users', 'remediation:c2-blocked'],
          },
        ],
        ai_verdict: 'APT29 campaign with near-certainty attribution. The spearphishing email quality, macro techniques, AMSI bypass method, Cobalt Strike configuration, and WMI persistence pattern all match the group\'s known TTPs documented in CISA Advisory AA21-116A. The 03:18 lateral movement timing (overnight, low staffing) is a signature behavioral pattern of this actor.',
        outcome_metrics: { dwell_time: '46h 21m', hosts_compromised: 7, data_exfiltrated: 'None confirmed', cost_averted: '$2.4M', analyst_hours: 12 },
      }
    ];

    const currentStory = STORYLINES[0];
    const phaseColors = { 'INITIAL ACCESS':'#f59e0b', 'EXECUTION':'#f97316', 'PERSISTENCE':'#a855f7', 'LATERAL MOVEMENT':'#ef4444', 'DETECTION':'#00d4ff', 'CONTAINMENT':'#22c55e' };

    el.innerHTML = `
      <div class="cds-module cds-accent-storyline">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(245,158,11,0.1);color:#f59e0b;border:1px solid rgba(245,158,11,0.3);">
              <i class="fas fa-film"></i>
            </div>
            <div>
              <div class="cds-module-name">Attack Storyline Generator</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot" style="background:#f59e0b;box-shadow:0 0 4px #f59e0b;"></div>AI Narrative Engine</div>
                <span>·</span><span>Cinematic Reconstruction</span><span>·</span><span>v1.0 — Innovation</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="_toast('📊 Storyline exported as MITRE Navigator layer + PDF','success')"><i class="fas fa-download"></i> Export</button>
            <button class="cds-btn cds-btn-sm cds-btn-primary" onclick="window._generateNewStoryline()"><i class="fas fa-magic"></i> Generate Storyline</button>
          </div>
        </div>

        <div class="cds-module-body">
          <!-- Story Header -->
          <div class="cds-card" style="background:linear-gradient(135deg,rgba(245,158,11,0.08),rgba(239,68,68,0.05));border:1px solid rgba(245,158,11,0.2);margin-bottom:16px;">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
              <div>
                <div style="font-size:18px;font-weight:800;color:var(--cds-text-primary);margin-bottom:4px;">${_esc(currentStory.title)}</div>
                <div style="font-size:12px;color:var(--cds-text-secondary);margin-bottom:8px;">${_esc(currentStory.summary)}</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <span class="cds-badge cds-badge-critical">CRITICAL</span>
                  <span class="cds-badge" style="background:rgba(100,116,139,0.15);color:#94a3b8;">Threat Actor: ${_esc(currentStory.threat_actor)}</span>
                  <span class="cds-badge" style="background:rgba(0,212,255,0.1);color:#00d4ff;">⏱ ${_esc(currentStory.duration)}</span>
                  <span class="cds-badge" style="background:rgba(34,197,94,0.1);color:#22c55e;">✅ ${currentStory.status.toUpperCase()}</span>
                </div>
              </div>
              <!-- Outcome Metrics -->
              <div style="display:flex;gap:12px;flex-wrap:wrap;">
                ${Object.entries(currentStory.outcome_metrics).map(([k,v]) => `
                  <div style="text-align:center;min-width:80px;">
                    <div style="font-size:14px;font-weight:800;font-family:'JetBrains Mono',monospace;color:${k==='cost_averted'?'#22c55e':k==='hosts_compromised'?'#ef4444':'#00d4ff'};">${_esc(String(v))}</div>
                    <div style="font-size:9px;color:var(--cds-text-muted);text-transform:uppercase;letter-spacing:0.5px;">${k.replace(/_/g,' ')}</div>
                  </div>`).join('')}
              </div>
            </div>
          </div>

          <!-- Timeline / Chapter Navigation -->
          <div style="display:flex;gap:0;margin-bottom:20px;overflow-x:auto;padding-bottom:4px;">
            ${currentStory.chapters.map((ch,i) => `
              <div onclick="window._storylineShowChapter(${i})" id="storyline-chapter-btn-${i}" 
                style="flex:1;min-width:100px;text-align:center;padding:8px 4px;cursor:pointer;border-bottom:3px solid ${i===0?ch.color:'var(--cds-border)'};transition:all 0.2s;background:${i===0?ch.color+'10':'transparent'};">
                <div style="font-size:9px;color:${i===0?ch.color:'var(--cds-text-muted)'};font-weight:700;letter-spacing:0.5px;">${_esc(ch.phase)}</div>
                <div style="font-size:10px;color:${i===0?'var(--cds-text-primary)':'var(--cds-text-muted)'};">${_esc(ch.time.split('—')[0].trim())}</div>
              </div>`).join(`<div style="width:1px;background:var(--cds-border);flex-shrink:0;"></div>`)}
          </div>

          <!-- Chapter Content -->
          ${currentStory.chapters.map((ch,i) => `
            <div id="storyline-chapter-${i}" class="storyline-chapter" style="display:${i===0?'block':'none'};">
              <div class="cds-card" style="border-left:4px solid ${ch.color};background:linear-gradient(135deg,${ch.color}05,transparent);">
                <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:14px;">
                  <div style="width:48px;height:48px;border-radius:12px;background:${ch.color}20;color:${ch.color};display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;border:1px solid ${ch.color}40;">
                    <i class="fas ${ch.icon}"></i>
                  </div>
                  <div style="flex:1;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px;flex-wrap:wrap;">
                      <span style="font-size:10px;font-weight:700;letter-spacing:1px;color:${ch.color};">${_esc(ch.phase)}</span>
                      ${ch.mitre ? `<span class="cds-ai-evidence-item">${_esc(ch.mitre)}</span>` : ''}
                      <span style="font-size:10px;color:var(--cds-text-muted);">⏱ ${_esc(ch.time)}</span>
                    </div>
                    <div style="font-size:17px;font-weight:800;color:var(--cds-text-primary);">${_esc(ch.title)}</div>
                  </div>
                </div>

                <!-- Narrative -->
                <div style="font-size:13px;color:var(--cds-text-secondary);line-height:1.8;margin-bottom:14px;padding:14px;background:rgba(0,0,0,0.2);border-radius:8px;border:1px solid rgba(255,255,255,0.03);">
                  ${_esc(ch.narrative)}
                </div>

                <!-- IOCs for this chapter -->
                ${ch.iocs.length > 0 ? `
                  <div>
                    <div class="cds-section-title" style="margin-bottom:8px;"><i class="fas fa-fingerprint"></i> IOCs in this phase</div>
                    <div style="display:flex;gap:6px;flex-wrap:wrap;">
                      ${ch.iocs.map(ioc => `
                        <span style="font-family:'JetBrains Mono',monospace;font-size:11px;padding:4px 8px;border-radius:4px;background:${ch.color}10;color:${ch.color};border:1px solid ${ch.color}30;cursor:pointer;" onclick="_toast('🔍 Pivoting on IOC: ${_esc(ioc)}','info')">${_esc(ioc)}</span>
                      `).join('')}
                    </div>
                  </div>
                ` : `<div style="font-size:11px;color:var(--cds-text-muted);"><i class="fas fa-info-circle"></i> SOC action phase — no adversary IOCs</div>`}
              </div>

              <!-- Navigation -->
              <div style="display:flex;justify-content:space-between;margin-top:12px;">
                ${i > 0 ? `<button class="cds-btn cds-btn-sm cds-btn-ghost" onclick="window._storylineShowChapter(${i-1})"><i class="fas fa-arrow-left"></i> ${_esc(currentStory.chapters[i-1].phase)}</button>` : '<span></span>'}
                ${i < currentStory.chapters.length-1 ? `<button class="cds-btn cds-btn-sm cds-btn-primary" onclick="window._storylineShowChapter(${i+1})">${_esc(currentStory.chapters[i+1].phase)} <i class="fas fa-arrow-right"></i></button>` : `<button class="cds-btn cds-btn-sm cds-btn-primary" style="background:linear-gradient(90deg,#22c55e,#16a34a);" onclick="_toast('📊 Full post-incident report generated','success')"><i class="fas fa-file-alt"></i> Full Report</button>`}
              </div>
            </div>
          `).join('')}

          <!-- AI Attribution -->
          <div class="cds-ai-explainer" style="margin-top:16px;">
            <div class="cds-ai-explainer-header">
              <div class="cds-ai-badge"><i class="fas fa-robot"></i> AI ATTRIBUTION VERDICT</div>
              <div class="cds-ai-confidence"><i class="fas fa-bullseye"></i> 94% Confidence</div>
            </div>
            <div class="cds-ai-reasoning">${_esc(currentStory.ai_verdict)}</div>
            <div class="cds-ai-evidence">
              <span class="cds-ai-evidence-item">T1566.002</span>
              <span class="cds-ai-evidence-item">T1059.001</span>
              <span class="cds-ai-evidence-item">T1546.003</span>
              <span class="cds-ai-evidence-item">T1021.002</span>
              <span class="cds-ai-evidence-item">APT29 TTP Match</span>
              <span class="cds-ai-evidence-item">CISA AA21-116A</span>
            </div>
          </div>
        </div>
      </div>
    `;

    window._storylineShowChapter = function(idx) {
      document.querySelectorAll('.storyline-chapter').forEach((c,i) => {
        c.style.display = i === idx ? 'block' : 'none';
      });
      const chapters = currentStory.chapters;
      document.querySelectorAll('[id^="storyline-chapter-btn-"]').forEach((btn, i) => {
        const ch = chapters[i];
        btn.style.borderBottomColor = i === idx ? ch.color : 'var(--cds-border)';
        btn.style.background = i === idx ? ch.color + '10' : 'transparent';
        btn.querySelector('div').style.color = i === idx ? ch.color : 'var(--cds-text-muted)';
      });
    };
    window._generateNewStoryline = function() { _toast('🎬 AI generating new storyline from recent incidents…', 'info'); };
  };


  /* ── Register all differentiator module render functions ── */
  console.log('[DifferentiatorModules v1.0] SOC Memory · Threat Graph · Digital Risk · Attack Storyline — initialized');

})();
