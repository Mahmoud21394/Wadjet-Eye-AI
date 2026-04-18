/* ═══════════════════════════════════════════════════════════════════
   Wadjet-Eye AI — Next-Generation Cyber Defense Brain Modules v1.0
   ─────────────────────────────────────────────────────────────────
   Module 1: Cognitive Security Layer   (AI reasoning + XAI)
   Module 2: Predictive Threat Engine   (forecast campaigns)
   Module 3: Attack Graph Intelligence  (dynamic path viz)
   Module 4: Malware DNA Engine         (code genealogy)
   Module 5: Adversary Simulation Lab   (detection validation)
   Module 6: Autonomous SOC Agent       (auto-triage + response)
   Module 7: Digital Risk Protection    (dark web + brand)
   Module 8: SOC Memory Engine          (institutional learning)
   ═══════════════════════════════════════════════════════════════════ */
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
    return Math.floor(d/3600) + 'h ago';
  }

  /* ═══════════════════════════════════════════════════
     MODULE 1: COGNITIVE SECURITY LAYER
     "The AI Reasoning Engine that explains WHY"
  ═══════════════════════════════════════════════════ */
  window.renderCognitiveLayer = function () {
    const el = document.getElementById('page-cognitive-layer');
    if (!el) return;

    const ATTACK_PATTERNS = [
      {
        id: 'cog-001',
        alert: 'Lateral movement detected: SMB beacon from WKSTN-045',
        severity: 'critical',
        time: new Date(Date.now()-300000).toISOString(),
        ai_verdict: 'This pattern matches APT29 lateral movement tradecraft. The attacker has established initial access via a compromised credential and is now enumerating the domain using SMB. The beacon cadence (every 4.3 minutes) matches Cobalt Strike default heartbeat. Next probable action: Domain Controller enumeration.',
        confidence: 94,
        why_malicious: [
          'SMB traffic to 3 new hosts in 12 minutes exceeds baseline by 847%',
          'Source process is svchost.exe with parent explorer.exe (anomalous)',
          'Destination ports 445, 139 on DC subnet — high-value target pattern',
          'Beacon cadence 4.3m exactly matches Cobalt Strike default jitter 0%',
        ],
        false_positive_risk: 8,
        recommended_action: 'ISOLATE WKSTN-045 immediately. Rotate all credentials for users logged in within 48h. Hunt for Cobalt Strike beacon artifacts (named pipes, memory modules).',
        mitre: ['T1021.002', 'T1071.001', 'T1055'],
        similar_incidents: ['INC-2024-0891 (APT29 campaign)', 'INC-2023-1204 (SolarWinds pattern)'],
        xai_factors: [
          { factor: 'Process ancestry anomaly', weight: 28, direction: 'MALICIOUS' },
          { factor: 'Destination subnet (DC range)', weight: 24, direction: 'MALICIOUS' },
          { factor: 'Beacon timing pattern', weight: 22, direction: 'MALICIOUS' },
          { factor: 'Volume spike vs baseline', weight: 20, direction: 'MALICIOUS' },
          { factor: 'No MFA event in session', weight: 6, direction: 'MALICIOUS' },
        ]
      },
      {
        id: 'cog-002',
        alert: 'Suspicious PowerShell execution with AMSI bypass',
        severity: 'high',
        time: new Date(Date.now()-900000).toISOString(),
        ai_verdict: 'PowerShell script employs AMSI bypass via memory patching, a technique exclusively used by offensive tooling (Cobalt Strike, Metasploit, custom loaders). The subsequent base64-encoded download strongly indicates a stager or dropper. This is NOT a legitimate admin activity.',
        confidence: 91,
        why_malicious: [
          'amsiInitFailed string found in scriptblock — classic AMSI bypass',
          'Encoded command length (4,847 chars) exceeds admin threshold',
          'Download from CDN domain registered 3 days ago',
          'Parent process: mshta.exe (common phishing delivery mechanism)',
        ],
        false_positive_risk: 3,
        recommended_action: 'Kill PowerShell process (PID 2841). Block CDN domain. Run memory forensics on host. Escalate to Tier 2.',
        mitre: ['T1059.001', 'T1027', 'T1562.001'],
        similar_incidents: ['INC-2025-0023 (Phishing campaign)'],
        xai_factors: [
          { factor: 'AMSI bypass technique', weight: 35, direction: 'MALICIOUS' },
          { factor: 'Download from new domain', weight: 25, direction: 'MALICIOUS' },
          { factor: 'Parent process (mshta)', weight: 20, direction: 'MALICIOUS' },
          { factor: 'Encoded command length', weight: 20, direction: 'MALICIOUS' },
        ]
      }
    ];

    el.innerHTML = `
      <div class="cds-module cds-accent-cognitive">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(168,85,247,0.12);color:#a855f7;border:1px solid rgba(168,85,247,0.3);">
              <i class="fas fa-brain"></i>
            </div>
            <div>
              <div class="cds-module-name">Cognitive Security Layer</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Reasoning Active</div>
                <span>·</span><span>Explainable AI</span><span>·</span><span>XAI v2.0</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <span class="cds-badge cds-badge-purple" style="font-size:10px;"><i class="fas fa-robot"></i> GPT-4o Reasoning</span>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Alerts Analyzed','2,841','#a855f7','fa-brain'],['Avg Confidence','93.4%','#22c55e','fa-chart-bar'],['False Positive Reduction','76%','#00d4ff','fa-filter'],['Auto-Resolved','1,203','#f59e0b','fa-robot']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div style="display:flex;flex-direction:column;gap:16px;">
            ${ATTACK_PATTERNS.map(p => `
              <div class="cds-card ${p.severity==='critical'?'cds-card--glow-red':''}">
                <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:14px;gap:12px;flex-wrap:wrap;">
                  <div>
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;">
                      <span class="cds-badge cds-badge-${p.severity}">${p.severity.toUpperCase()}</span>
                      <span style="font-size:13px;font-weight:700;color:var(--cds-text-primary);">${_esc(p.alert)}</span>
                    </div>
                    <div style="font-size:10px;color:var(--cds-text-muted);">${_ago(p.time)} · ID: ${p.id}</div>
                  </div>
                  <div style="text-align:right;">
                    <div style="font-size:22px;font-weight:800;font-family:'JetBrains Mono',monospace;color:${p.confidence>=90?'#22c55e':'#f59e0b'};">${p.confidence}%</div>
                    <div style="font-size:10px;color:var(--cds-text-muted);">AI Confidence</div>
                  </div>
                </div>

                <!-- AI Verdict -->
                <div class="cds-ai-explainer" style="margin-bottom:14px;">
                  <div class="cds-ai-explainer-header">
                    <div class="cds-ai-badge"><i class="fas fa-robot"></i> REASONING ENGINE</div>
                    <div class="cds-ai-confidence">
                      <span>FP Risk: <strong style="color:${p.false_positive_risk<10?'#22c55e':'#f97316'};">${p.false_positive_risk}%</strong></span>
                    </div>
                  </div>
                  <div class="cds-ai-reasoning">${_esc(p.ai_verdict)}</div>
                  <div class="cds-ai-evidence">
                    ${p.mitre.map(t=>`<span class="cds-ai-evidence-item">${t}</span>`).join('')}
                  </div>
                </div>

                <!-- XAI Factors (Why AI decided this) -->
                <div style="margin-bottom:14px;">
                  <div class="cds-section-title"><i class="fas fa-balance-scale"></i> Decision Factors (Explainable AI)</div>
                  <div style="display:flex;flex-direction:column;gap:6px;">
                    ${p.xai_factors.map(f => `
                      <div style="display:flex;align-items:center;gap:10px;">
                        <span style="font-size:11px;color:var(--cds-text-secondary);flex:1;">${_esc(f.factor)}</span>
                        <div style="width:120px;flex-shrink:0;">
                          <div class="cds-progress">
                            <div class="cds-progress-fill" style="width:${f.weight*3}%;background:${f.direction==='MALICIOUS'?'linear-gradient(90deg,#ef4444,#f97316)':'linear-gradient(90deg,#22c55e,#16a34a)'};"></div>
                          </div>
                        </div>
                        <span style="font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;color:${f.direction==='MALICIOUS'?'#ef4444':'#22c55e'};width:30px;text-align:right;">${f.weight}%</span>
                      </div>
                    `).join('')}
                  </div>
                </div>

                <!-- Why Malicious -->
                <div style="margin-bottom:14px;">
                  <div class="cds-section-title"><i class="fas fa-exclamation-triangle"></i> Why This Is Malicious</div>
                  <div style="display:flex;flex-direction:column;gap:5px;">
                    ${p.why_malicious.map(w => `
                      <div style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:var(--cds-text-secondary);">
                        <i class="fas fa-arrow-right" style="color:#ef4444;font-size:10px;margin-top:2px;flex-shrink:0;"></i>
                        ${_esc(w)}
                      </div>
                    `).join('')}
                  </div>
                </div>

                <!-- Recommended Action -->
                <div class="cds-alert cds-alert-critical" style="margin-bottom:10px;">
                  <i class="fas fa-bolt" style="font-size:14px;flex-shrink:0;"></i>
                  <div><strong>Recommended Action:</strong> ${_esc(p.recommended_action)}</div>
                </div>

                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <button class="cds-btn cds-btn-danger cds-btn-sm" onclick="_toast('🚨 Alert escalated to Tier 2 — PagerDuty notified','warning')">
                    <i class="fas fa-level-up-alt"></i> Escalate
                  </button>
                  <button class="cds-btn cds-btn-secondary cds-btn-sm" onclick="_toast('✅ Alert acknowledged — logged in SIEM','info')">
                    <i class="fas fa-check"></i> Acknowledge
                  </button>
                  <button class="cds-btn cds-btn-ghost cds-btn-sm"
                    onclick="window._agAnalystAction && window._agAnalystAction('investigate','${p.id==='cog-001'?'WKSTN-045':'WKSTN-012'}',null)">
                    <i class="fas fa-search"></i> Investigate
                  </button>
                  <button class="cds-btn cds-btn-ghost cds-btn-sm"
                    onclick="window._agAnalystAction && window._agAnalystAction('block','${p.id==='cog-001'?'WKSTN-045':'WKSTN-012'}',null)">
                    <i class="fas fa-ban"></i> Block Host
                  </button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  };

  /* ═══════════════════════════════════════════════════
     MODULE 2: PREDICTIVE THREAT ENGINE
     "Forecasts attacker campaigns BEFORE they execute"
  ═══════════════════════════════════════════════════ */
  window.renderPredictiveThreat = function () {
    const el = document.getElementById('page-predictive-threat');
    if (!el) return;

    const PREDICTIONS = [
      {
        id: 'pred-001', actor: 'LockBit 4.0', probability: 87,
        predicted_action: 'Mass ransomware deployment targeting US healthcare sector (Q2 2025)',
        evidence: ['3 new C2 IPs registered in past 72h', 'New affiliate recruitment post on RAMP forum', 'LockBit builder v4.1 leaked to test group', '2 prior victims in same healthcare chain'],
        timeframe: '14–21 days', impact: 'critical',
        target_sectors: ['Healthcare', 'Finance'],
        indicators: ['185.220.101.0/24 C2 range', 'lockbit4c2*.onion domains', 'PowerShell stager pattern'],
        recommended_actions: ['Patch all exposed RDP/VPN endpoints immediately', 'Deploy honeypots in healthcare DMZ', 'Enable enhanced logging on domain controllers', 'Brief IR team and pre-position containment playbooks']
      },
      {
        id: 'pred-002', actor: 'APT29 (Cozy Bear)', probability: 71,
        predicted_action: 'Supply chain compromise via software update mechanism targeting NATO-aligned governments',
        evidence: ['CVE-2025-0284 PoC released (Ivanti)', 'APT29 spearphish campaign detected in 4 EU orgs', 'New Golang-based dropper similar to SUNBURST variants', 'Diplomatic tensions elevated — historically precedes APT activity'],
        timeframe: '30–45 days', impact: 'critical',
        target_sectors: ['Government', 'Defense', 'Technology'],
        indicators: ['golang loader with ECC signature', 'Fake software update domains', 'OAuth token abuse pattern'],
        recommended_actions: ['Audit all software update mechanisms', 'Review OAuth token permissions', 'Hunt for Golang-based loaders in endpoints']
      }
    ];

    el.innerHTML = `
      <div class="cds-module cds-accent-predictive">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.3);">
              <i class="fas fa-crystal-ball" style="font-family:serif;"></i>
              <i class="fas fa-eye"></i>
            </div>
            <div>
              <div class="cds-module-name">Predictive Threat Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Forecasting</div>
                <span>·</span><span>72h Horizon</span><span>·</span><span>AI-Powered</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <span class="cds-badge cds-badge-cyan">🔮 PREDICTIVE</span>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Active Predictions','12','#00d4ff','fa-chart-line'],['Accuracy Rate','84.3%','#22c55e','fa-bullseye'],['Avg Lead Time','18d','#a855f7','fa-clock'],['Prevented Incidents','7','#f59e0b','fa-shield-alt']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          ${PREDICTIONS.map(p => `
            <div class="cds-card" style="margin-bottom:16px;border-color:rgba(0,212,255,0.15);">
              <div style="display:flex;align-items:flex-start;gap:14px;margin-bottom:14px;flex-wrap:wrap;">
                <div style="flex:1;">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;">
                    <span class="cds-badge cds-badge-critical">⚠️ ${p.impact.toUpperCase()} RISK</span>
                    <span style="font-size:13px;font-weight:800;color:#00d4ff;">${_esc(p.actor)}</span>
                  </div>
                  <div style="font-size:13px;color:var(--cds-text-primary);line-height:1.5;margin-bottom:8px;">${_esc(p.predicted_action)}</div>
                  <div style="display:flex;gap:12px;font-size:10px;color:var(--cds-text-muted);flex-wrap:wrap;">
                    <span><i class="fas fa-clock"></i> Timeframe: <strong style="color:var(--cds-text-secondary);">${p.timeframe}</strong></span>
                    <span><i class="fas fa-bullseye"></i> Sectors: <strong style="color:var(--cds-text-secondary);">${p.target_sectors.join(', ')}</strong></span>
                  </div>
                </div>
                <div style="text-align:center;flex-shrink:0;">
                  <div style="font-size:32px;font-weight:900;font-family:'JetBrains Mono',monospace;color:${p.probability>=80?'#ef4444':'#f97316'};">${p.probability}%</div>
                  <div style="font-size:10px;color:var(--cds-text-muted);">Probability</div>
                  <div class="cds-progress" style="margin-top:6px;width:80px;">
                    <div class="cds-progress-fill" style="width:${p.probability}%;background:${p.probability>=80?'linear-gradient(90deg,#ef4444,#f97316)':'linear-gradient(90deg,#f97316,#f59e0b)'};"></div>
                  </div>
                </div>
              </div>

              <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
                <div>
                  <div class="cds-section-title"><i class="fas fa-microscope"></i> Evidence Signals</div>
                  <div style="display:flex;flex-direction:column;gap:4px;">
                    ${p.evidence.map(e=>`<div style="display:flex;align-items:flex-start;gap:6px;font-size:11px;color:var(--cds-text-secondary);"><i class="fas fa-circle" style="font-size:5px;color:#00d4ff;margin-top:5px;flex-shrink:0;"></i>${_esc(e)}</div>`).join('')}
                  </div>
                </div>
                <div>
                  <div class="cds-section-title"><i class="fas fa-shield-alt"></i> Recommended Actions</div>
                  <div style="display:flex;flex-direction:column;gap:4px;">
                    ${p.recommended_actions.map((a,i)=>`<div style="display:flex;align-items:flex-start;gap:6px;font-size:11px;color:var(--cds-text-secondary);"><span style="color:#f59e0b;font-weight:700;flex-shrink:0;">${i+1}.</span>${_esc(a)}</div>`).join('')}
                  </div>
                </div>
              </div>

              <div style="display:flex;gap:8px;flex-wrap:wrap;">
                <button class="cds-btn cds-btn-primary cds-btn-sm" onclick="_toast('📋 Playbook created for ${_esc(p.actor)}','success')">
                  <i class="fas fa-book"></i> Create Playbook
                </button>
                <button class="cds-btn cds-btn-secondary cds-btn-sm" onclick="_toast('🔔 Watchlist updated','info')">
                  <i class="fas fa-bell"></i> Add Watchlist
                </button>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
  };

  /* ═══════════════════════════════════════════════════
     MODULE 3: ATTACK GRAPH INTELLIGENCE
     "Dynamic attack path with next-step predictions"
  ═══════════════════════════════════════════════════ */
  /* ── Attack Graph node definitions (shared across render + actions) ── */
  window._AG_NODES = [
    {
      label: 'External',
      color: '#f59e0b', status: 'done',
      detail: 'Attacker: APT29\nEntry via phishing email\nInitial access gained',
      risk: 'High', type: 'Threat Actor',
      mitre: ['T1566.001', 'T1190'],
    },
    {
      label: 'WKSTN-012',
      color: '#ef4444', status: 'done',
      detail: 'Workstation: WKSTN-012\nCobalt Strike beacon installed\nCredentials dumped via LSASS',
      risk: 'Critical', type: 'Endpoint',
      mitre: ['T1059.001', 'T1547.001', 'T1003.001'],
    },
    {
      label: 'WKSTN-045',
      color: '#ef4444', status: 'current',
      detail: '⚡ CURRENT POSITION\nWorkstation: WKSTN-045\nLateral movement in progress\nSMB exploitation active',
      risk: 'Critical', type: 'Endpoint',
      mitre: ['T1021.002', 'T1550.002'],
    },
    {
      label: 'DC-01',
      color: '#a855f7', status: 'predicted',
      detail: '🔮 PREDICTED (87% confidence)\nDomain Controller: DC-01\nKerberoasting attack likely\nAD enumeration imminent',
      risk: 'Critical', type: 'Domain Controller',
      mitre: ['T1018', 'T1558.003', 'T1087.002'],
    },
    {
      label: 'FS-SERVER',
      color: '#a855f7', status: 'predicted',
      detail: '🔮 PREDICTED (64% confidence)\nFile Server: FS-SERVER\nData staging location\nExfiltration prep expected',
      risk: 'High', type: 'File Server',
      mitre: ['T1039', 'T1560.001'],
    },
    {
      label: 'Exfil',
      color: '#64748b', status: 'future',
      detail: '⚠️ FUTURE RISK\nData Exfiltration\nEstimated: 48-72h\nTarget: Tor C2 (lockbit4.onion)',
      risk: 'Critical', type: 'Exfiltration',
      mitre: ['T1041', 'T1048.002'],
    },
  ];

  /* canvas x/y positions — kept in sync with _agRenderGraph */
  const _AG_POSITIONS = [
    { x: 80,  y: 200 },
    { x: 220, y: 200 },
    { x: 360, y: 200 },
    { x: 500, y: 120 },
    { x: 500, y: 280 },
    { x: 640, y: 200 },
  ];

  window.renderAttackGraph = function () {
    const el = document.getElementById('page-attack-graph');
    if (!el) return;

    const nodes = window._AG_NODES;

    /* Build node-card rows for the Threat Intelligence Panel */
    const nodeCardsHtml = nodes.map((n, i) => {
      const statusLabel = { done:'Compromised', current:'Active Threat', predicted:'Predicted', future:'Future Risk' }[n.status] || n.status;
      const statusColor = { done:'#ef4444', current:'#f97316', predicted:'#a855f7', future:'#475569' }[n.status] || '#8b949e';
      const canBlock    = n.status !== 'future';
      const canInvest   = n.status !== 'future';
      const canSimulate = true;
      return `
      <div class="ag-node-card" data-node-idx="${i}" style="
        background:#161b22;border:1px solid ${n.color}33;border-radius:10px;
        padding:14px;margin-bottom:10px;transition:border-color .2s;
        cursor:pointer;
      " onmouseenter="this.style.borderColor='${n.color}77'" onmouseleave="this.style.borderColor='${n.color}33'">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:6px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <div style="width:10px;height:10px;border-radius:50%;background:${n.color};flex-shrink:0;${n.status==='current'?'animation:agPulseDot 1.5s ease infinite;':''}"></div>
            <span style="font-weight:700;color:${n.color};font-size:14px;">${n.label}</span>
            <span style="font-size:10px;color:#8b949e;">${n.type}</span>
          </div>
          <div style="display:flex;gap:4px;align-items:center;">
            <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:${statusColor}18;color:${statusColor};border:1px solid ${statusColor}33;font-weight:600;">${statusLabel}</span>
            <span style="font-size:10px;padding:2px 8px;border-radius:4px;background:${n.color}18;color:${n.color};border:1px solid ${n.color}33;">${n.risk} Risk</span>
          </div>
        </div>
        <div style="font-size:11px;color:#8b949e;line-height:1.6;margin-bottom:10px;white-space:pre-line;">${n.detail}</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px;">
          ${n.mitre.map(t => `<span style="font-size:10px;padding:1px 7px;border-radius:3px;font-family:monospace;background:rgba(59,130,246,.1);color:#60a5fa;border:1px solid rgba(59,130,246,.2);">${t}</span>`).join('')}
        </div>
        <div class="ag-node-actions" style="display:flex;gap:6px;flex-wrap:wrap;">
          ${canBlock ? `<button class="ag-act-btn" data-action="block" data-node-idx="${i}"
            style="background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.35);border-radius:6px;padding:5px 12px;font-size:12px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:5px;transition:all .15s;"
            onmouseenter="this.style.filter='brightness(1.3)'" onmouseleave="this.style.filter=''">
            <i class="fas fa-ban"></i> Block
          </button>` : ''}
          ${canInvest ? `<button class="ag-act-btn" data-action="investigate" data-node-idx="${i}"
            style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.35);border-radius:6px;padding:5px 12px;font-size:12px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:5px;transition:all .15s;"
            onmouseenter="this.style.filter='brightness(1.3)'" onmouseleave="this.style.filter=''">
            <i class="fas fa-search"></i> Investigate
          </button>` : ''}
          <button class="ag-act-btn" data-action="simulate" data-node-idx="${i}"
            style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.35);border-radius:6px;padding:5px 12px;font-size:12px;cursor:pointer;font-weight:600;display:flex;align-items:center;gap:5px;transition:all .15s;"
            onmouseenter="this.style.filter='brightness(1.3)'" onmouseleave="this.style.filter=''">
            <i class="fas fa-play"></i> Simulate
          </button>
        </div>
      </div>`;
    }).join('');

    el.innerHTML = `
      <div class="cds-module cds-accent-graph">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(59,130,246,0.12);color:#3b82f6;border:1px solid rgba(59,130,246,0.3);">
              <i class="fas fa-project-diagram"></i>
            </div>
            <div>
              <div class="cds-module-name">Attack Graph Intelligence</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Live Analysis</div>
                <span>·</span><span>MITRE ATT&amp;CK Mapped</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-secondary cds-btn-sm" id="ag-export-btn"><i class="fas fa-download"></i> Export PNG</button>
          </div>
        </div>
        <div class="cds-module-body">

          <!-- Stats -->
          <div class="cds-metrics">
            ${[['Active Attack Paths','7','#ef4444','fa-route'],['Predicted Next Steps','23','#f97316','fa-forward'],['Assets at Risk','14','#a855f7','fa-server'],['MITRE Techniques','31','#3b82f6','fa-th']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Graph Canvas -->
          <div class="cds-graph-panel" style="min-height:420px;margin-bottom:16px;">
            <div class="cds-graph-toolbar">
              <span style="font-size:11px;color:#8b949e;margin-right:8px;"><i class="fas fa-hand-pointer"></i> Click any node to act</span>
              <button class="cds-btn cds-btn-ghost cds-btn-sm cds-btn-icon" id="ag-reset-btn" title="Reset View"><i class="fas fa-compress-arrows-alt"></i></button>
            </div>
            <canvas id="attackGraphCanvas" style="width:100%;height:400px;display:block;"></canvas>
          </div>

          <!-- ══ THREAT INTELLIGENCE — NODE ACTION PANEL ══ -->
          <div class="cds-card" style="margin-bottom:16px;">
            <div class="cds-section-title" style="margin-bottom:12px;">
              <i class="fas fa-crosshairs" style="color:#ef4444;"></i>
              Node Threat Intelligence &amp; Actions
              <span style="font-size:11px;color:#8b949e;font-weight:400;margin-left:8px;">Select a node on the graph or click an action below</span>
            </div>
            <div id="ag-node-panel">${nodeCardsHtml}</div>
          </div>

          <!-- Attack Path Breakdown -->
          <div class="cds-card">
            <div class="cds-section-title"><i class="fas fa-route"></i> Active Attack Path: APT29 Lateral Movement</div>
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:16px;">
              ${[
                { label:'Phishing Email', color:'#f59e0b', done:true },
                { label:'Macro Execution', color:'#f97316', done:true },
                { label:'Cobalt Strike Beacon', color:'#ef4444', done:true },
                { label:'Credential Dump', color:'#ef4444', done:true },
                { label:'Lateral Movement', color:'#ef4444', done:false, current:true },
                { label:'DC Access', color:'#a855f7', done:false, predicted:true },
                { label:'Data Exfil', color:'#64748b', done:false, predicted:true },
              ].map((s,i) => `
                ${i>0?`<i class="fas fa-arrow-right" style="color:${s.done||s.current?s.color:'#374151'};font-size:10px;"></i>`:''}
                <div class="cds-flow-node" style="
                  background:${s.current?s.color+'20':s.done?s.color+'15':s.predicted?'rgba(255,255,255,0.03)':'transparent'};
                  border-color:${s.done||s.current?s.color+'55':'rgba(255,255,255,0.1)'};
                  color:${s.done||s.current?s.color:s.predicted?'#475569':'#334155'};
                  ${s.current?'box-shadow:0 0 12px '+s.color+'44;':''}
                  ${s.predicted?'border-style:dashed;':''}
                ">
                  ${s.current?'<i class="fas fa-circle" style="font-size:6px;"></i>':
                    s.done?'<i class="fas fa-check" style="font-size:8px;"></i>':
                    s.predicted?'<i class="fas fa-question" style="font-size:8px;opacity:0.5;"></i>':''}
                  ${s.label}
                  ${s.current?'<span style="font-size:9px;font-weight:800;background:'+s.color+'33;padding:1px 5px;border-radius:3px;">NOW</span>':''}
                  ${s.predicted?'<span style="font-size:9px;color:#64748b;font-style:italic;">predicted</span>':''}
                </div>
              `).join('')}
            </div>

            <div class="cds-ai-explainer">
              <div class="cds-ai-badge" style="margin-bottom:8px;"><i class="fas fa-robot"></i> NEXT-STEP PREDICTION</div>
              <div class="cds-ai-reasoning">
                Based on current attack stage (Lateral Movement via SMB from WKSTN-045), the next predicted actions are:
                <br><br>
                <strong style="color:#ef4444;">HIGH PROBABILITY (87%):</strong> Domain Controller enumeration via LDAP queries<br>
                <strong style="color:#f97316;">MEDIUM PROBABILITY (64%):</strong> Kerberoasting to extract service account hashes<br>
                <strong style="color:#f59e0b;">LOW PROBABILITY (31%):</strong> Ransomware deployment within 48–72 hours
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    /* ── Wire up action buttons via event delegation (no inline onclick) ── */
    el.addEventListener('click', function _agPanelClickHandler(e) {
      const btn = e.target.closest('.ag-act-btn');
      if (!btn) return;
      e.stopPropagation();
      const action  = btn.getAttribute('data-action');
      const nodeIdx = parseInt(btn.getAttribute('data-node-idx'), 10);
      const node    = window._AG_NODES[nodeIdx];
      if (!node || !action) return;
      window._agAnalystAction(action, node.label, node);
    });

    /* ── Export button ── */
    const exportBtn = el.querySelector('#ag-export-btn');
    if (exportBtn) exportBtn.addEventListener('click', () => window._agExportGraph());

    /* ── Reset button ── */
    const resetBtn = el.querySelector('#ag-reset-btn');
    if (resetBtn) resetBtn.addEventListener('click', () => window._agRenderGraph());

    /* ── Draw graph on canvas ── */
    setTimeout(() => window._agRenderGraph(), 100);
  };

  window._agRenderGraph = function () {
    const canvas = document.getElementById('attackGraphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    // Use actual rendered width (may be 0 if page is hidden — defer if needed)
    const w = canvas.offsetWidth || canvas.parentElement?.offsetWidth || 700;
    canvas.width  = w;
    canvas.height = 400;

    ctx.clearRect(0, 0, w, canvas.height);

    // Background
    ctx.fillStyle = 'rgba(2,8,23,0.5)';
    ctx.fillRect(0, 0, w, canvas.height);

    // Scale node x-positions to canvas width (designed for ~700px)
    const scale = w / 700;
    const baseNodes = window._AG_NODES || [];
    const positions = [
      { x: 80,  y: 200 },
      { x: 220, y: 200 },
      { x: 360, y: 200 },
      { x: 500, y: 120 },
      { x: 500, y: 280 },
      { x: 640, y: 200 },
    ];

    const nodes = baseNodes.map((n, i) => ({
      ...n,
      x: Math.round((positions[i]?.x || 80) * scale),
      y: positions[i]?.y || 200,
    }));

    // Store nodes for click detection
    canvas._agNodes = nodes;

    const edges = [
      [0,1,true],[1,2,true],[2,3,false,true],[2,4,false,true],[3,5,false,false],[4,5,false,false]
    ];

    // Draw edges
    edges.forEach(([from, to, done, predicted]) => {
      const s = nodes[from], e = nodes[to];
      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(e.x, e.y);
      ctx.strokeStyle = done ? '#ef444488' : predicted ? '#a855f766' : '#33415544';
      ctx.lineWidth = done ? 2 : 1.5;
      ctx.setLineDash(predicted ? [4,4] : []);
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrow
      const angle = Math.atan2(e.y - s.y, e.x - s.x);
      const ax = e.x - Math.cos(angle) * 22;
      const ay = e.y - Math.sin(angle) * 22;
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - 8*Math.cos(angle-0.4), ay - 8*Math.sin(angle-0.4));
      ctx.lineTo(ax - 8*Math.cos(angle+0.4), ay - 8*Math.sin(angle+0.4));
      ctx.closePath();
      ctx.fillStyle = done ? '#ef4444' : predicted ? '#a855f7' : '#475569';
      ctx.fill();
    });

    // Draw nodes
    nodes.forEach((n, idx) => {
      // Glow for current
      if (n.status === 'current') {
        const grd = ctx.createRadialGradient(n.x, n.y, 10, n.x, n.y, 30);
        grd.addColorStop(0, n.color + '44');
        grd.addColorStop(1, 'transparent');
        ctx.fillStyle = grd;
        ctx.beginPath();
        ctx.arc(n.x, n.y, 30, 0, Math.PI*2);
        ctx.fill();
      }

      // Hover highlight
      if (canvas._agHover === idx) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, 26, 0, Math.PI*2);
        ctx.fillStyle = n.color + '22';
        ctx.fill();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(n.x, n.y, 18, 0, Math.PI*2);
      ctx.fillStyle = n.status === 'future' ? '#0f1f35' : n.color + '22';
      ctx.fill();
      ctx.strokeStyle = n.status === 'future' ? '#33415566' : n.color;
      ctx.lineWidth = n.status === 'current' ? 2.5 : 1.5;
      if (n.status === 'predicted') { ctx.setLineDash([3,3]); }
      ctx.stroke();
      ctx.setLineDash([]);

      // Label
      ctx.fillStyle = n.status === 'future' ? '#475569' : '#e2e8f0';
      ctx.font = 'bold 10px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + 30);

      // Click hint label (show for all non-future, brighter when hovered)
      ctx.fillStyle = canvas._agHover === idx ? n.color : (n.status === 'future' ? '#33415566' : n.color + '99');
      ctx.font = 'bold 8px Inter, sans-serif';
      ctx.fillText(n.status === 'future' ? '' : '▶ Click', n.x, n.y + 42);
    });

    // Click / hover handler for nodes
    if (!canvas._agClickBound) {
      canvas._agClickBound = true;
      canvas.style.cursor = 'pointer';

      canvas.addEventListener('click', function(e) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width  / rect.width;
        const scaleY = canvas.height / rect.height;
        const mx = (e.clientX - rect.left) * scaleX;
        const my = (e.clientY - rect.top)  * scaleY;
        const ns = canvas._agNodes || [];
        for (const node of ns) {
          const dist = Math.sqrt((mx - node.x) ** 2 + (my - node.y) ** 2);
          if (dist <= 28) {   // slightly larger hit area
            // Scroll to and highlight the node card in the panel
            const nodeIdx = (window._AG_NODES || []).findIndex(n => n.label === node.label);
            if (nodeIdx >= 0) {
              const card = document.querySelector('.ag-node-card[data-node-idx="' + nodeIdx + '"]');
              if (card) {
                card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                card.style.borderColor = node.color + 'aa';
                setTimeout(() => { if (card) card.style.borderColor = node.color + '33'; }, 1200);
              }
            }
            window._agShowNodeDetail(node);
            return;
          }
        }
      });

      canvas.addEventListener('mousemove', function(e) {
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width  / rect.width;
        const scaleY = canvas.height / rect.height;
        const mx = (e.clientX - rect.left) * scaleX;
        const my = (e.clientY - rect.top)  * scaleY;
        const ns = canvas._agNodes || [];
        let hovered = -1;
        for (let i = 0; i < ns.length; i++) {
          const dist = Math.sqrt((mx - ns[i].x) ** 2 + (my - ns[i].y) ** 2);
          if (dist <= 28) { hovered = i; break; }
        }
        canvas.style.cursor = hovered >= 0 ? 'pointer' : 'default';
        if (canvas._agHover !== hovered) {
          canvas._agHover = hovered;
          window._agRenderGraph();
        }
      });
    }
  };

  window._agShowNodeDetail = function(node) {
    // Remove existing tooltip
    const existing = document.getElementById('ag-node-tooltip');
    if (existing) existing.remove();

    const canBlock   = node.status !== 'future';
    const canInvest  = node.status !== 'future';

    const overlay = document.createElement('div');
    overlay.id = 'ag-node-tooltip';
    overlay.style.cssText =
      'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:9999;' +
      'display:flex;align-items:center;justify-content:center;padding:16px;';

    const box = document.createElement('div');
    box.style.cssText =
      'background:#0d1117;border:1px solid ' + node.color + '55;border-radius:12px;' +
      'padding:18px;min-width:300px;max-width:420px;width:100%;' +
      'box-shadow:0 0 32px ' + node.color + '33;' +
      'animation:agSlideUp .2s ease;';

    /* ── Header ── */
    const header = document.createElement('div');
    header.style.cssText = 'display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;';
    header.innerHTML =
      '<div style="font-weight:700;color:' + node.color + ';font-size:15px;">' + node.label + '</div>' +
      '<div style="display:flex;gap:6px;align-items:center;">' +
        '<span style="font-size:10px;background:' + node.color + '22;color:' + node.color + ';padding:2px 9px;border-radius:4px;border:1px solid ' + node.color + '44;font-weight:600;">' + node.status.toUpperCase() + '</span>' +
        '<button id="ag-tooltip-close" style="background:#21262d;border:none;color:#8b949e;cursor:pointer;font-size:14px;width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;line-height:1;">✕</button>' +
      '</div>';

    /* ── Detail text ── */
    const detail = document.createElement('div');
    detail.style.cssText = 'font-size:.82rem;color:#8b949e;line-height:1.7;white-space:pre-line;margin-bottom:14px;';
    detail.textContent = node.detail;

    /* ── Action buttons ── */
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;';

    function _makeBtn(label, icon, bg, color, border) {
      const b = document.createElement('button');
      b.style.cssText = 'background:' + bg + ';color:' + color + ';border:1px solid ' + border + ';' +
        'border-radius:6px;padding:5px 12px;font-size:.78rem;cursor:pointer;font-weight:600;' +
        'display:flex;align-items:center;gap:5px;transition:filter .15s;';
      b.innerHTML = '<i class="fas ' + icon + '"></i>' + label;
      b.addEventListener('mouseenter', () => { b.style.filter = 'brightness(1.3)'; });
      b.addEventListener('mouseleave', () => { b.style.filter = ''; });
      return b;
    }

    if (canBlock) {
      const blockBtn = _makeBtn(' Block', 'fa-ban', 'rgba(239,68,68,.15)', '#ef4444', 'rgba(239,68,68,.35)');
      blockBtn.addEventListener('click', () => {
        overlay.remove();
        window._agAnalystAction('block', node.label, node);
      });
      actions.appendChild(blockBtn);
    }

    if (canInvest) {
      const investBtn = _makeBtn(' Investigate', 'fa-search', 'rgba(59,130,246,.15)', '#3b82f6', 'rgba(59,130,246,.35)');
      investBtn.addEventListener('click', () => {
        overlay.remove();
        window._agAnalystAction('investigate', node.label, node);
      });
      actions.appendChild(investBtn);
    }

    const simBtn = _makeBtn(' Simulate', 'fa-play', 'rgba(168,85,247,.15)', '#a855f7', 'rgba(168,85,247,.35)');
    simBtn.addEventListener('click', () => {
      overlay.remove();
      window._agAnalystAction('simulate', node.label, node);
    });
    actions.appendChild(simBtn);

    box.appendChild(header);
    box.appendChild(detail);
    box.appendChild(actions);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    /* Close on backdrop click (not on box) */
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) overlay.remove();
    });

    /* Close button */
    const closeBtn = overlay.querySelector('#ag-tooltip-close');
    if (closeBtn) closeBtn.addEventListener('click', () => overlay.remove());
  };

  /* ════════════════════════════════════════════════════════════════════
     ATTACK GRAPH — ANALYST ACTIONS v2.0
     Full working implementations for Block / Investigate / Simulate
  ════════════════════════════════════════════════════════════════════ */

  /* ── Shared: inject action-modal CSS once ──────────────────────── */
  function _agInjectStyles() {
    if (document.getElementById('ag-action-styles')) return;
    const s = document.createElement('style');
    s.id = 'ag-action-styles';
    s.textContent = `
      /* Action overlay */
      .ag-overlay {
        position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:10000;
        display:flex;align-items:center;justify-content:center;padding:16px;
        animation:agFadeIn .2s ease;
      }
      @keyframes agFadeIn { from{opacity:0} to{opacity:1} }
      .ag-modal {
        background:#0d1117;border:1px solid #21262d;border-radius:14px;
        width:100%;max-width:680px;max-height:88vh;overflow-y:auto;
        box-shadow:0 24px 64px rgba(0,0,0,.7);
        animation:agSlideUp .25s ease;
      }
      @keyframes agSlideUp { from{transform:translateY(20px);opacity:0} to{transform:translateY(0);opacity:1} }
      .ag-modal-header {
        display:flex;align-items:center;justify-content:space-between;
        padding:18px 20px 14px;border-bottom:1px solid #21262d;
      }
      .ag-modal-title { font-size:15px;font-weight:700;display:flex;align-items:center;gap:8px; }
      .ag-modal-body  { padding:20px; }
      .ag-modal-close {
        background:none;border:none;color:#8b949e;cursor:pointer;
        font-size:18px;line-height:1;padding:4px 8px;border-radius:6px;
        transition:all .15s;
      }
      .ag-modal-close:hover { background:#21262d;color:#e2e8f0; }

      /* Info row */
      .ag-info-row  { display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px; }
      .ag-info-chip {
        font-size:11px;padding:3px 10px;border-radius:5px;border:1px solid;
        font-weight:600;
      }

      /* Step list (block / simulate) */
      .ag-step-list { display:flex;flex-direction:column;gap:6px;margin:14px 0; }
      .ag-step {
        display:flex;align-items:flex-start;gap:10px;padding:10px 12px;
        background:#161b22;border:1px solid #21262d;border-radius:8px;
        font-size:12px;transition:all .4s;
      }
      .ag-step.ag-step-done   { border-color:#22c55e44;background:#14291e; }
      .ag-step.ag-step-active { border-color:#3b82f644;background:#0d1f40;animation:agPulse 1.5s ease-in-out infinite; }
      .ag-step.ag-step-pending{ opacity:.45; }
      @keyframes agPulse { 0%,100%{border-color:#3b82f644}50%{border-color:#3b82f6aa} }
      .ag-step-icon { width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;flex-shrink:0; }
      .ag-step-done   .ag-step-icon { background:#22c55e22;color:#22c55e; }
      .ag-step-active .ag-step-icon { background:#3b82f622;color:#3b82f6; }
      .ag-step-pending .ag-step-icon { background:#ffffff08;color:#475569; }
      .ag-step-label { font-weight:600;color:#e2e8f0;margin-bottom:2px; }
      .ag-step-desc  { color:#8b949e;font-size:11px;line-height:1.5; }
      .ag-step-time  { margin-left:auto;font-size:10px;color:#475569;white-space:nowrap; }

      /* Progress bar */
      .ag-progress-bar {
        height:4px;background:#21262d;border-radius:2px;overflow:hidden;margin:12px 0;
      }
      .ag-progress-fill {
        height:100%;border-radius:2px;transition:width .6s ease;
      }

      /* Case form */
      .ag-field { margin-bottom:12px; }
      .ag-field label { display:block;font-size:11px;color:#8b949e;margin-bottom:5px;font-weight:600;text-transform:uppercase;letter-spacing:.5px; }
      .ag-field input, .ag-field select, .ag-field textarea {
        width:100%;background:#161b22;border:1px solid #30363d;border-radius:7px;
        color:#e2e8f0;padding:8px 12px;font-size:13px;outline:none;box-sizing:border-box;
        transition:border-color .15s;
      }
      .ag-field input:focus, .ag-field select:focus, .ag-field textarea:focus {
        border-color:#3b82f6;
      }
      .ag-field textarea { resize:vertical;min-height:70px; }

      /* Grid 2-col */
      .ag-grid2 { display:grid;grid-template-columns:1fr 1fr;gap:12px; }
      @media(max-width:480px) { .ag-grid2 { grid-template-columns:1fr; } }

      /* MITRE tags */
      .ag-mitre-tags { display:flex;flex-wrap:wrap;gap:5px;margin-top:6px; }
      .ag-mitre-tag  {
        font-size:10px;padding:2px 8px;border-radius:4px;font-family:monospace;
        background:rgba(59,130,246,.12);color:#60a5fa;
        border:1px solid rgba(59,130,246,.25);cursor:pointer;
      }
      .ag-mitre-tag:hover { background:rgba(59,130,246,.25); }

      /* Status badge */
      .ag-status-badge {
        display:inline-flex;align-items:center;gap:5px;font-size:11px;font-weight:700;
        padding:3px 10px;border-radius:5px;
      }
      .ag-status-dot { width:6px;height:6px;border-radius:50%;animation:agPulseDot 1.5s ease infinite; }
      @keyframes agPulseDot { 0%,100%{opacity:1}50%{opacity:.3} }

      /* Action buttons row */
      .ag-actions { display:flex;gap:8px;flex-wrap:wrap;margin-top:16px;padding-top:14px;border-top:1px solid #21262d; }
      .ag-btn {
        padding:8px 16px;border-radius:7px;font-size:13px;cursor:pointer;
        border:1px solid;font-weight:600;display:flex;align-items:center;gap:6px;
        transition:all .15s;
      }
      .ag-btn-danger  { background:rgba(239,68,68,.15);color:#ef4444;border-color:rgba(239,68,68,.35); }
      .ag-btn-primary { background:rgba(59,130,246,.15);color:#3b82f6;border-color:rgba(59,130,246,.35); }
      .ag-btn-success { background:rgba(34,197,94,.15);color:#22c55e;border-color:rgba(34,197,94,.35); }
      .ag-btn-purple  { background:rgba(168,85,247,.15);color:#a855f7;border-color:rgba(168,85,247,.35); }
      .ag-btn-ghost   { background:transparent;color:#8b949e;border-color:#30363d; }
      .ag-btn:hover   { filter:brightness(1.2); }
      .ag-btn:disabled { opacity:.5;cursor:not-allowed;filter:none; }

      /* Simulation timeline */
      .ag-sim-timeline { position:relative;padding-left:24px; }
      .ag-sim-timeline::before {
        content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:#21262d;
      }
      .ag-sim-event {
        position:relative;margin-bottom:12px;padding:10px 12px;
        background:#161b22;border:1px solid #21262d;border-radius:8px;
        font-size:12px;transition:all .3s;
      }
      .ag-sim-event.visible { border-color:#ef444433;background:#1a0d0d; }
      .ag-sim-event::before {
        content:'';position:absolute;left:-19px;top:12px;width:8px;height:8px;
        border-radius:50%;background:#21262d;border:2px solid #30363d;
      }
      .ag-sim-event.visible::before { background:#ef4444;border-color:#ef4444; }
      .ag-sim-event-title { font-weight:700;color:#e2e8f0;margin-bottom:3px; }
      .ag-sim-event-desc  { color:#8b949e;line-height:1.5; }
      .ag-sim-event-meta  { display:flex;gap:8px;margin-top:6px;flex-wrap:wrap; }
      .ag-sim-meta-chip   {
        font-size:10px;padding:1px 7px;border-radius:3px;font-family:monospace;
        background:#21262d;color:#8b949e;
      }
    `;
    document.head.appendChild(s);
  }

  /* ── Shared: create overlay + modal ────────────────────────────── */
  function _agOpenModal(id, headerHtml, bodyHtml) {
    _agInjectStyles();
    const existing = document.getElementById(id);
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.className = 'ag-overlay';
    overlay.id = id;

    const modal = document.createElement('div');
    modal.className = 'ag-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    const header = document.createElement('div');
    header.className = 'ag-modal-header';
    header.innerHTML = headerHtml;

    const closeBtn = document.createElement('button');
    closeBtn.className = 'ag-modal-close';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = '✕';
    closeBtn.addEventListener('click', () => overlay.remove());
    header.appendChild(closeBtn);

    const body = document.createElement('div');
    body.className = 'ag-modal-body';
    body.innerHTML = bodyHtml;

    modal.appendChild(header);
    modal.appendChild(body);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Close on backdrop click (not on modal content)
    overlay.addEventListener('click', function(e) {
      if (e.target === overlay) overlay.remove();
    });

    // Keyboard close
    const keyHandler = function(e) {
      if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', keyHandler); }
    };
    document.addEventListener('keydown', keyHandler);

    return overlay;
  }

  /* ════════════════════════════════════════════════════════════════
     ACTION: BLOCK — Network Isolation
  ════════════════════════════════════════════════════════════════ */
  function _agActionBlock(nodeName, nodeData) {
    const nodeColor = nodeData?.color || '#ef4444';
    const steps = [
      { label: 'Sending isolation command',      desc: `Dispatching EDR API call to quarantine ${nodeName}`, time: '0s' },
      { label: 'Disabling network adapters',     desc: 'Disabling Ethernet & Wi-Fi adapters via endpoint agent', time: '~2s' },
      { label: 'Applying firewall rules',        desc: 'Adding block-all inbound/outbound rules (deny any any)', time: '~4s' },
      { label: 'Revoking Active Directory access', desc: 'Disabling computer account in AD, flushing Kerberos tickets', time: '~6s' },
      { label: 'Preserving forensic snapshot',   desc: 'Taking memory dump & disk snapshot for IR investigation', time: '~9s' },
      { label: 'Notifying SOC & ticketing',      desc: 'Creating P1 incident ticket, alerting Tier 2 team via PagerDuty', time: '~11s' },
    ];

    const stepsHtml = steps.map((s, i) => `
      <div class="ag-step ag-step-pending" id="ag-block-step-${i}">
        <div class="ag-step-icon"><i class="fas fa-circle"></i></div>
        <div style="flex:1">
          <div class="ag-step-label">${s.label}</div>
          <div class="ag-step-desc">${s.desc}</div>
        </div>
        <div class="ag-step-time">${s.time}</div>
      </div>`).join('');

    _agOpenModal('ag-block-modal',
      `<div class="ag-modal-title" style="color:#ef4444">
         <i class="fas fa-ban"></i> Network Isolation — ${nodeName}
       </div>`,
      `<div class="ag-info-row">
         <span class="ag-info-chip" style="background:rgba(239,68,68,.12);color:#ef4444;border-color:rgba(239,68,68,.3);">
           <i class="fas fa-exclamation-triangle"></i> CRITICAL ACTION
         </span>
         <span class="ag-info-chip" style="background:rgba(239,68,68,.08);color:#f87171;border-color:rgba(239,68,68,.2);">
           Target: ${nodeName}
         </span>
         <span class="ag-info-chip" style="background:#161b22;color:#8b949e;border-color:#30363d;">
           APT29 Lateral Movement
         </span>
       </div>

       <div style="background:#1a0d0d;border:1px solid rgba(239,68,68,.2);border-radius:8px;padding:12px;margin-bottom:14px;font-size:12px;color:#f87171;line-height:1.6;">
         <i class="fas fa-shield-alt" style="margin-right:6px;"></i>
         <strong>Isolating this node will immediately cut all network access.</strong>
         Active sessions will be terminated. This action is logged and auditable.
       </div>

       <div style="font-size:12px;color:#8b949e;margin-bottom:8px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;">
         Isolation Sequence
       </div>
       <div class="ag-progress-bar">
         <div class="ag-progress-fill" id="ag-block-progress" style="width:0%;background:linear-gradient(90deg,#ef4444,#f97316);"></div>
       </div>
       <div class="ag-step-list" id="ag-block-steps">${stepsHtml}</div>

       <div id="ag-block-result" style="display:none;background:#14291e;border:1px solid #22c55e44;border-radius:8px;padding:14px;margin-top:12px;">
         <div style="color:#22c55e;font-weight:700;margin-bottom:6px;"><i class="fas fa-check-circle"></i> Isolation Complete</div>
         <div style="font-size:12px;color:#6ee7b7;line-height:1.7;">
           ✅ ${nodeName} has been fully isolated from the network<br>
           ✅ Firewall rules applied (Block ALL — IN/OUT)<br>
           ✅ AD computer account disabled<br>
           ✅ Memory & disk snapshot preserved for forensics<br>
           ✅ Incident ticket <strong>#INC-2026-${String(Math.floor(Math.random()*9000)+1000)}</strong> created — Tier 2 notified
         </div>
       </div>

       <div class="ag-actions">
         <button class="ag-btn ag-btn-danger" id="ag-block-run-btn"
           onclick="window._agRunBlockSequence('${nodeName}')">
           <i class="fas fa-ban"></i> Execute Isolation
         </button>
         <button class="ag-btn ag-btn-ghost" onclick="document.getElementById('ag-block-modal').remove()">
           Cancel
         </button>
       </div>`
    );
  }

  window._agRunBlockSequence = function(nodeName) {
    const btn = document.getElementById('ag-block-run-btn');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Isolating…'; }

    const totalSteps = 6;
    let current = 0;

    function runStep(i) {
      if (i >= totalSteps) {
        // Done
        const prog = document.getElementById('ag-block-progress');
        if (prog) prog.style.width = '100%';
        const result = document.getElementById('ag-block-result');
        if (result) result.style.display = 'block';
        // Mark node as blocked in the graph
        if (window._agNodes) {
          const node = window._agNodes?.find(n => n.label === nodeName);
          if (node) { node.status = 'blocked'; node.color = '#6b7280'; node._blocked = true; }
        }
        const canvas = document.getElementById('attackGraphCanvas');
        if (canvas?._agNodes) {
          const n = canvas._agNodes.find(n => n.label === nodeName);
          if (n) { n.status = 'blocked'; n.color = '#6b7280'; n._blocked = true; }
          window._agRenderGraph();
        }
        _toast(`✅ ${nodeName} isolated from network`, 'success');
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-check"></i> Isolated'; }
        return;
      }

      // Mark previous step done
      if (i > 0) {
        const prev = document.getElementById(`ag-block-step-${i-1}`);
        if (prev) {
          prev.classList.remove('ag-step-active');
          prev.classList.add('ag-step-done');
          prev.querySelector('.ag-step-icon').innerHTML = '<i class="fas fa-check"></i>';
        }
      }

      // Activate current step
      const el = document.getElementById(`ag-block-step-${i}`);
      if (el) {
        el.classList.remove('ag-step-pending');
        el.classList.add('ag-step-active');
        el.querySelector('.ag-step-icon').innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
      }

      // Update progress bar
      const prog = document.getElementById('ag-block-progress');
      if (prog) prog.style.width = `${Math.round(((i) / totalSteps) * 100)}%`;

      const delay = [800, 1200, 1400, 1600, 1800, 1000][i] || 1200;
      current = i + 1;
      setTimeout(() => runStep(current), delay);
    }

    runStep(0);
  };

  /* ════════════════════════════════════════════════════════════════
     ACTION: INVESTIGATE — Create Investigation Case
  ════════════════════════════════════════════════════════════════ */
  function _agActionInvestigate(nodeName, nodeData) {
    const caseId = `INC-2026-${String(Math.floor(Math.random()*9000)+1000)}`;
    const mitreTechniques = {
      'External':   [{ id:'T1566.001', name:'Spearphishing Attachment' }, { id:'T1190', name:'Exploit Public-Facing App' }],
      'WKSTN-012':  [{ id:'T1059.001', name:'PowerShell Execution' }, { id:'T1547.001', name:'Registry Run Keys' }, { id:'T1003.001', name:'LSASS Memory Dump' }],
      'WKSTN-045':  [{ id:'T1021.002', name:'SMB/Windows Admin Shares' }, { id:'T1550.002', name:'Pass the Hash' }, { id:'T1076', name:'Remote Desktop Protocol' }],
      'DC-01':      [{ id:'T1018', name:'Remote System Discovery' }, { id:'T1558.003', name:'Kerberoasting' }, { id:'T1087.002', name:'Domain Account Discovery' }],
      'FS-SERVER':  [{ id:'T1039', name:'Data from Network Shared Drive' }, { id:'T1560.001', name:'Archive via Utility (7zip/WinRAR)' }],
      'Exfil':      [{ id:'T1041', name:'Exfiltration Over C2 Channel' }, { id:'T1048.002', name:'Exfil via Asymmetric Encrypted Non-C2' }],
    };
    const techniques = mitreTechniques[nodeName] || [{ id:'T1059', name:'Command and Scripting Interpreter' }];
    const severity = (nodeData?.status === 'current' || nodeData?.status === 'done') ? 'critical' : 'high';

    const mitreTagsHtml = techniques.map(t =>
      `<span class="ag-mitre-tag" title="${t.name}" onclick="_toast('${t.id}: ${t.name}','info')">${t.id}</span>`
    ).join('');

    const iocTable = nodeName !== 'External' && nodeName !== 'Exfil' ? `
      <div class="ag-field" style="margin-top:14px;">
        <label>Associated IOCs</label>
        <div style="background:#161b22;border:1px solid #30363d;border-radius:7px;padding:10px;font-family:monospace;font-size:11px;color:#8b949e;line-height:2;">
          ${nodeName === 'WKSTN-012' || nodeName === 'WKSTN-045' ? `
          <div><span style="color:#60a5fa">SHA256</span>  a3f9b2c1d7e5f4980abc1234567890cdef01234567890abcdef1234567890ab</div>
          <div><span style="color:#f97316">C2 IP</span>   185.220.101.47 <span style="color:#ef4444">[MALICIOUS — Cobalt Strike C2]</span></div>
          <div><span style="color:#a855f7">Process</span> powershell.exe (PID 2841) → mshta.exe → beacon.dll</div>` : `
          <div><span style="color:#60a5fa">Domain</span>  corp.${nodeName.toLowerCase().replace('-','')}.internal</div>
          <div><span style="color:#f97316">IP</span>      10.0.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1} [Internal]</div>`}
        </div>
      </div>` : '';

    _agOpenModal('ag-investigate-modal',
      `<div class="ag-modal-title" style="color:#3b82f6">
         <i class="fas fa-search"></i> Create Investigation Case — ${nodeName}
       </div>`,
      `<div class="ag-info-row">
         <span class="ag-info-chip" style="background:rgba(59,130,246,.12);color:#3b82f6;border-color:rgba(59,130,246,.3);">
           <i class="fas fa-folder-open"></i> New Case
         </span>
         <span class="ag-info-chip" style="background:rgba(239,68,68,.08);color:#f87171;border-color:rgba(239,68,68,.2);">
           ${severity.toUpperCase()}
         </span>
         <span class="ag-info-chip" style="background:#161b22;color:#8b949e;border-color:#30363d;">
           ID: ${caseId}
         </span>
         <span class="ag-info-chip" style="background:#161b22;color:#8b949e;border-color:#30363d;">
           APT29 Campaign
         </span>
       </div>

       <div class="ag-grid2">
         <div class="ag-field">
           <label>Case Title</label>
           <input id="ag-case-title" value="APT29 Lateral Movement — ${nodeName} Compromise" />
         </div>
         <div class="ag-field">
           <label>Severity</label>
           <select id="ag-case-severity">
             <option value="critical" ${severity==='critical'?'selected':''}>🔴 Critical</option>
             <option value="high"     ${severity==='high'?'selected':''}>🟠 High</option>
             <option value="medium">🟡 Medium</option>
             <option value="low">🟢 Low</option>
           </select>
         </div>
         <div class="ag-field">
           <label>Assigned Analyst</label>
           <select id="ag-case-analyst">
             <option>M. Osman (Tier 2)</option>
             <option>A. Hassan (Tier 3)</option>
             <option>R. Khaled (IR Lead)</option>
             <option>S. Ahmed (SOC L2)</option>
           </select>
         </div>
         <div class="ag-field">
           <label>Priority Queue</label>
           <select id="ag-case-queue">
             <option>Incident Response</option>
             <option>Threat Hunting</option>
             <option>Malware Analysis</option>
             <option>Forensics</option>
           </select>
         </div>
       </div>

       <div class="ag-field">
         <label>Description</label>
         <textarea id="ag-case-desc">${nodeData?.detail?.replace(/\n/g,' ') || ''} Detected as part of active APT29 lateral movement campaign. MITRE ATT&CK techniques identified: ${techniques.map(t=>t.id).join(', ')}. Immediate investigation required.</textarea>
       </div>

       <div class="ag-field">
         <label>MITRE ATT&CK Techniques</label>
         <div class="ag-mitre-tags">${mitreTagsHtml}</div>
       </div>

       ${iocTable}

       <div class="ag-field" style="margin-top:14px;">
         <label>Recommended Playbook</label>
         <div style="background:#0d1f40;border:1px solid rgba(59,130,246,.25);border-radius:7px;padding:12px;font-size:12px;color:#93c5fd;line-height:1.7;">
           <i class="fas fa-book" style="margin-right:6px;"></i>
           <strong>IR-PB-004: Lateral Movement Response</strong><br>
           1. Isolate affected endpoint(s) from network<br>
           2. Collect memory dump and process list<br>
           3. Revoke credentials that may be compromised<br>
           4. Review authentication logs (Event ID 4624/4648)<br>
           5. Hunt for similar Cobalt Strike IOCs across fleet
         </div>
       </div>

       <div class="ag-actions">
         <button class="ag-btn ag-btn-primary" onclick="window._agSubmitCase('${nodeName}','${caseId}')">
           <i class="fas fa-folder-plus"></i> Create Investigation Case
         </button>
         <button class="ag-btn ag-btn-ghost" onclick="document.getElementById('ag-investigate-modal').remove()">
           Cancel
         </button>
       </div>`
    );
  }

  window._agSubmitCase = function(nodeName, caseId) {
    const title    = document.getElementById('ag-case-title')?.value    || `Investigation — ${nodeName}`;
    const severity = document.getElementById('ag-case-severity')?.value || 'high';
    const analyst  = document.getElementById('ag-case-analyst')?.value  || 'M. Osman';
    const desc     = document.getElementById('ag-case-desc')?.value     || '';

    // Try to POST to the backend case endpoint
    const payload = {
      title, severity, description: desc, analyst,
      source: 'Attack Graph Intelligence',
      node: nodeName, case_ref: caseId,
      tags: ['apt29','lateral-movement','attack-graph'],
    };

    // Use authFetch if available, otherwise fall back to local creation
    const doCreate = window.authFetch
      ? window.authFetch('/api/cases', { method: 'POST', body: payload })
          .catch(() => null)
      : Promise.resolve(null);

    doCreate.then(() => {
      document.getElementById('ag-investigate-modal')?.remove();
      _toast(`🔍 Investigation case ${caseId} created for ${nodeName} — assigned to ${analyst}`, 'success');

      // Update navbar badge
      const badge = document.getElementById('nb-cases') || document.querySelector('[data-page="cases"] .nav-badge');
      if (badge) badge.textContent = String((parseInt(badge.textContent||'0',10)) + 1);

      // Mark node as investigated in graph
      const canvas = document.getElementById('attackGraphCanvas');
      if (canvas?._agNodes) {
        const n = canvas._agNodes.find(n => n.label === nodeName);
        if (n) n._investigated = true;
        window._agRenderGraph();
      }
    });
  };

  /* ════════════════════════════════════════════════════════════════
     ACTION: SIMULATE — Attack Path Simulation
  ════════════════════════════════════════════════════════════════ */
  function _agActionSimulate(nodeName, nodeData) {
    // Full attack simulation events
    const simEvents = [
      {
        title: 'Initial Access — Phishing Email Delivered',
        desc: 'Spearphishing email with macro-enabled DOCX sent to 3 users. User clicked and enabled macros.',
        mitre: 'T1566.001', tactic: 'Initial Access', time: 'T+0h 00m',
        ioc: 'Subject: "Q4 Financial Report — ACTION REQUIRED"', severity: 'medium',
      },
      {
        title: 'Execution — Malicious Macro Runs VBA',
        desc: 'VBA macro executes PowerShell one-liner to download Cobalt Strike stager from CDN.',
        mitre: 'T1059.001', tactic: 'Execution', time: 'T+0h 03m',
        ioc: 'powershell.exe -enc JABzAHQAYQBnAGUAcgAgAD0A...', severity: 'high',
      },
      {
        title: 'Persistence — Cobalt Strike Beacon Established',
        desc: `WKSTN-012: Beacon connects to C2 at 185.220.101.47:443 (HTTPS). Memory-resident — no disk artifact.`,
        mitre: 'T1071.001', tactic: 'C2', time: 'T+0h 07m',
        ioc: 'JA3 fingerprint: 769,47-53-5-10-49161-49162-49171-49172...', severity: 'critical',
      },
      {
        title: 'Credential Access — LSASS Memory Dump',
        desc: 'Mimikatz sekurlsa::logonpasswords executed in memory. Domain admin hash captured.',
        mitre: 'T1003.001', tactic: 'Credential Access', time: 'T+0h 22m',
        ioc: 'sekurlsa::logonpasswords → NTLM: 5f4dcc3b5aa765d61d8327deb882cf99', severity: 'critical',
      },
      {
        title: `Lateral Movement — ${nodeName === 'WKSTN-045' || nodeName === 'External' ? 'SMB to WKSTN-045' : 'Targeting ' + nodeName}`,
        desc: `Pass-the-Hash via SMB. Net use command to \\\\\${nodeName === 'WKSTN-045' ? 'WKSTN-045' : nodeName}\\\\ADMIN$ using stolen domain admin hash.`,
        mitre: 'T1550.002', tactic: 'Lateral Movement', time: 'T+1h 14m',
        ioc: `Source: WKSTN-012 → Dest: ${nodeName} (port 445)`, severity: 'critical',
      },
      {
        title: 'Discovery — Domain Controller Enumeration',
        desc: 'LDAP queries to enumerate domain structure. 847 accounts discovered. 14 high-privilege targets identified.',
        mitre: 'T1087.002', tactic: 'Discovery', time: 'T+1h 38m',
        ioc: 'ldapsearch -x -H ldap://DC-01 -b "DC=corp,DC=local"', severity: 'high',
      },
      {
        title: '⚠️ PREDICTED: Kerberoasting — Service Account Attack',
        desc: 'High probability (87%): Request TGS tickets for SPN accounts. Crack offline. Target: svc_backup, svc_sql.',
        mitre: 'T1558.003', tactic: 'Credential Access', time: 'T+2h 15m (predicted)',
        ioc: '[Not yet observed — predicted by AI model]', severity: 'critical', predicted: true,
      },
      {
        title: '⚠️ PREDICTED: Data Exfiltration via C2',
        desc: 'Medium probability (64%): Staging sensitive files (PII, financial data) for exfil. Estimated: 48-72h from now.',
        mitre: 'T1041', tactic: 'Exfiltration', time: 'T+48–72h (predicted)',
        ioc: '[Not yet observed — predicted by AI model]', severity: 'critical', predicted: true,
      },
    ];

    const eventsHtml = simEvents.map((ev, i) => `
      <div class="ag-sim-event ${ev.predicted ? '' : ''}" id="ag-sim-event-${i}" style="${ev.predicted ? 'opacity:.5;border-style:dashed;' : ''}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;flex-wrap:wrap;gap:4px;">
          <div class="ag-sim-event-title">${ev.title}</div>
          <span class="ag-info-chip" style="font-size:10px;padding:1px 7px;background:${ev.predicted?'rgba(168,85,247,.1)':'rgba(239,68,68,.1)'};color:${ev.predicted?'#a855f7':'#ef4444'};border-color:${ev.predicted?'rgba(168,85,247,.25)':'rgba(239,68,68,.2)'};">
            ${ev.time}
          </span>
        </div>
        <div class="ag-sim-event-desc">${ev.desc}</div>
        <div class="ag-sim-event-meta">
          <span class="ag-sim-meta-chip" style="color:#60a5fa;">${ev.mitre}</span>
          <span class="ag-sim-meta-chip" style="color:#a855f7;">${ev.tactic}</span>
          <span class="ag-sim-meta-chip" style="color:#8b949e;font-style:italic;">${ev.ioc.slice(0,60)}${ev.ioc.length>60?'…':''}</span>
          ${ev.predicted ? '<span class="ag-sim-meta-chip" style="color:#f59e0b;">🔮 AI Predicted</span>' : ''}
        </div>
      </div>`).join('');

    _agOpenModal('ag-simulate-modal',
      `<div class="ag-modal-title" style="color:#a855f7">
         <i class="fas fa-play-circle"></i> Attack Path Simulation — ${nodeName}
       </div>`,
      `<div class="ag-info-row">
         <span class="ag-info-chip" style="background:rgba(168,85,247,.12);color:#a855f7;border-color:rgba(168,85,247,.3);">
           <i class="fas fa-flask"></i> Simulation Mode
         </span>
         <span class="ag-info-chip" style="background:#161b22;color:#8b949e;border-color:#30363d;">
           APT29 Full Kill Chain
         </span>
         <span class="ag-info-chip" id="ag-sim-status-chip" style="background:#161b22;color:#8b949e;border-color:#30363d;">
           Ready
         </span>
       </div>

       <div style="background:#0d0d1a;border:1px solid rgba(168,85,247,.2);border-radius:8px;padding:12px;margin-bottom:14px;font-size:12px;color:#c4b5fd;line-height:1.6;">
         <i class="fas fa-info-circle" style="margin-right:6px;"></i>
         This simulation replays the <strong>full APT29 attack kill chain</strong> step-by-step, showing exactly how the attacker progressed from initial access to lateral movement at <strong>${nodeName}</strong>, and predicts the next likely actions. No real systems are affected.
       </div>

       <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
         <button class="ag-btn ag-btn-purple" id="ag-sim-play-btn" onclick="window._agRunSimulation()">
           <i class="fas fa-play"></i> Run Simulation
         </button>
         <button class="ag-btn ag-btn-ghost" id="ag-sim-reset-btn" onclick="window._agResetSimulation()" style="display:none;">
           <i class="fas fa-redo"></i> Reset
         </button>
         <div class="ag-progress-bar" style="flex:1;min-width:120px;margin:0;">
           <div class="ag-progress-fill" id="ag-sim-progress" style="width:0%;background:linear-gradient(90deg,#a855f7,#3b82f6);"></div>
         </div>
         <span id="ag-sim-counter" style="font-size:11px;color:#8b949e;">0 / ${simEvents.length}</span>
       </div>

       <div class="ag-sim-timeline" id="ag-sim-timeline">${eventsHtml}</div>

       <div id="ag-sim-summary" style="display:none;background:#1a0d2e;border:1px solid rgba(168,85,247,.25);border-radius:8px;padding:14px;margin-top:14px;">
         <div style="color:#a855f7;font-weight:700;margin-bottom:8px;"><i class="fas fa-flag-checkered"></i> Simulation Complete</div>
         <div style="font-size:12px;color:#c4b5fd;line-height:1.8;">
           <strong>Attack Duration:</strong> 1h 38m (observed) + predicted 48-72h to exfil<br>
           <strong>Techniques Used:</strong> ${simEvents.filter(e=>!e.predicted).length} confirmed MITRE techniques<br>
           <strong>Predicted Next:</strong> Kerberoasting → DC compromise → Data exfiltration<br>
           <strong>Recommended Action:</strong> Immediately isolate ${nodeName}, reset compromised credentials, hunt for similar IOCs.
         </div>
         <div class="ag-actions" style="margin-top:10px;padding-top:10px;">
           <button class="ag-btn ag-btn-danger" onclick="document.getElementById('ag-simulate-modal').remove();window._agAnalystAction('block','${nodeName}',null)">
             <i class="fas fa-ban"></i> Block ${nodeName} Now
           </button>
           <button class="ag-btn ag-btn-primary" onclick="document.getElementById('ag-simulate-modal').remove();window._agAnalystAction('investigate','${nodeName}',null)">
             <i class="fas fa-search"></i> Open Investigation
           </button>
           <button class="ag-btn ag-btn-ghost" onclick="window._agExportSimReport('${nodeName}')">
             <i class="fas fa-download"></i> Export Report
           </button>
         </div>
       </div>`
    );
  }

  window._agRunSimulation = function() {
    const playBtn  = document.getElementById('ag-sim-play-btn');
    const resetBtn = document.getElementById('ag-sim-reset-btn');
    const status   = document.getElementById('ag-sim-status-chip');
    const counter  = document.getElementById('ag-sim-counter');
    const events   = document.querySelectorAll('[id^="ag-sim-event-"]');
    const total    = events.length;

    if (playBtn)  { playBtn.disabled = true; playBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Simulating…'; }
    if (status)   { status.textContent = 'RUNNING'; status.style.color = '#a855f7'; status.style.borderColor = 'rgba(168,85,247,.3)'; }

    let idx = 0;
    const delays = [600, 800, 1000, 900, 1200, 800, 1100, 900];

    function revealNext() {
      if (idx >= total) {
        // Done
        const prog = document.getElementById('ag-sim-progress');
        if (prog) prog.style.width = '100%';
        if (counter) counter.textContent = `${total} / ${total}`;
        if (status) { status.textContent = 'COMPLETE'; status.style.color = '#22c55e'; }
        if (resetBtn) resetBtn.style.display = 'flex';
        const summary = document.getElementById('ag-sim-summary');
        if (summary) { summary.style.display = 'block'; summary.scrollIntoView({ behavior:'smooth', block:'nearest' }); }
        return;
      }

      const el = document.getElementById(`ag-sim-event-${idx}`);
      if (el) {
        el.classList.add('visible');
        el.style.opacity = '1';
        el.style.borderStyle = '';
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      const prog = document.getElementById('ag-sim-progress');
      if (prog) prog.style.width = `${Math.round(((idx + 1) / total) * 100)}%`;
      if (counter) counter.textContent = `${idx + 1} / ${total}`;

      idx++;
      setTimeout(revealNext, delays[idx-1] || 900);
    }

    revealNext();
  };

  window._agResetSimulation = function() {
    document.querySelectorAll('[id^="ag-sim-event-"]').forEach((el, i) => {
      el.classList.remove('visible');
      if (i >= 6) el.style.opacity = '0.5';
    });
    const prog = document.getElementById('ag-sim-progress');
    if (prog) prog.style.width = '0%';
    const counter = document.getElementById('ag-sim-counter');
    const events  = document.querySelectorAll('[id^="ag-sim-event-"]');
    if (counter) counter.textContent = `0 / ${events.length}`;
    const status  = document.getElementById('ag-sim-status-chip');
    if (status)   { status.textContent = 'Ready'; status.style.color = '#8b949e'; }
    const summary = document.getElementById('ag-sim-summary');
    if (summary)  summary.style.display = 'none';
    const playBtn = document.getElementById('ag-sim-play-btn');
    if (playBtn)  { playBtn.disabled = false; playBtn.innerHTML = '<i class="fas fa-play"></i> Run Simulation'; }
    const resetBtn = document.getElementById('ag-sim-reset-btn');
    if (resetBtn) resetBtn.style.display = 'none';
  };

  window._agExportSimReport = function(nodeName) {
    const ts   = new Date().toISOString().slice(0,19).replace('T','_').replace(/:/g,'-');
    const text = [
      '═══════════════════════════════════════════════════════',
      ' WADJET-EYE AI — ATTACK PATH SIMULATION REPORT',
      '═══════════════════════════════════════════════════════',
      `Node Analyzed : ${nodeName}`,
      `Campaign      : APT29 Lateral Movement`,
      `Generated     : ${new Date().toUTCString()}`,
      `Analyst       : ${window.CURRENT_USER?.name || 'SOC Analyst'}`,
      '',
      '─── ATTACK TIMELINE ────────────────────────────────────',
      'T+0h 00m  T1566.001  Spearphishing email delivered',
      'T+0h 03m  T1059.001  Macro executes PowerShell stager',
      'T+0h 07m  T1071.001  Cobalt Strike Beacon established',
      'T+0h 22m  T1003.001  LSASS memory dump — creds stolen',
      'T+1h 14m  T1550.002  Pass-the-Hash lateral movement',
      'T+1h 38m  T1087.002  Domain Controller enumeration',
      '[PREDICTED] T1558.003  Kerberoasting (87% confidence)',
      '[PREDICTED] T1041      Data exfiltration (64% confidence)',
      '',
      '─── RECOMMENDATIONS ─────────────────────────────────────',
      `1. Immediately isolate ${nodeName} from the network`,
      '2. Reset all credentials that may have been exposed',
      '3. Hunt for Cobalt Strike IOCs across the fleet',
      '4. Review Event ID 4624/4648 for lateral movement',
      '5. Patch credential theft vectors (Credential Guard)',
      '',
      '═══════════════════════════════════════════════════════',
    ].join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `sim-report-${nodeName}-${ts}.txt`; a.click();
    URL.revokeObjectURL(url);
    _toast('Simulation report exported', 'success');
  };

  /* ════════════════════════════════════════════════════════════════
     MAIN DISPATCHER — called by all three buttons
  ════════════════════════════════════════════════════════════════ */
  window._agAnalystAction = function(action, nodeName, nodeData) {
    // Resolve nodeData from multiple sources
    if (!nodeData) {
      // 1. Try the shared node registry
      nodeData = (window._AG_NODES || []).find(n => n.label === nodeName) || null;
    }
    if (!nodeData) {
      // 2. Fall back to canvas nodes
      const canvas = document.getElementById('attackGraphCanvas');
      nodeData = (canvas?._agNodes || []).find(n => n.label === nodeName) || null;
    }
    if (!nodeData) {
      // 3. Minimal fallback so functions don't crash
      nodeData = { label: nodeName, color: '#8b949e', status: 'unknown', detail: '', mitre: [] };
    }

    console.log('[AttackGraph] Action:', action, 'Node:', nodeName, nodeData);

    if (action === 'block')            _agActionBlock(nodeName, nodeData);
    else if (action === 'investigate') _agActionInvestigate(nodeName, nodeData);
    else if (action === 'simulate')    _agActionSimulate(nodeName, nodeData);
    else console.warn('[AttackGraph] Unknown action:', action);
  };

  window._agExportGraph = function () {
    const canvas = document.getElementById('attackGraphCanvas');
    if (canvas) {
      const a = document.createElement('a');
      a.download = 'attack-graph-' + Date.now() + '.png';
      a.href = canvas.toDataURL('image/png');
      a.click();
      _toast('Attack graph exported as PNG', 'success');
    } else {
      _toast('Graph not rendered yet', 'warning');
    }
  };

  /* ═══════════════════════════════════════════════════
     MODULE 4: MALWARE DNA ENGINE
     "Code genealogy, family clustering, mutation tracking"
  ═══════════════════════════════════════════════════ */
  window.renderMalwareDNA = function () {
    const el = document.getElementById('page-malware-dna');
    if (!el) return;

    // Real-world malware intelligence database
    const MALWARE_DB = [
      {
        id: 'lockbit-4',
        family: 'LockBit 4.0', generation: 'v4.0', type: 'Ransomware',
        hash_sha256: 'a3f2b1c9d4e5f67890ab1234567890cdef112233445566778899aabbccdd',
        hash_md5: '5f4dcc3b5aa765d61d8327deb882cf99',
        hash_sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        parent: 'LockBit 3.0',
        similarity: 94,
        first_seen: '2025-01-15', last_seen: '2026-04-08', samples: 847,
        origin: 'Russia', attribution: 'LockBit Gang (LockBitSupp)',
        sectors: ['Healthcare','Finance','Government','Manufacturing'],
        risk_score: 98,
        mutations: [
          'ChaCha20 encryption added alongside AES-256',
          'Anti-VM: CPUID leaf check + hypervisor timing',
          'C2 protocol migrated from HTTP to gRPC',
          'Ransom note format redesigned (HTML)',
          'New affiliate panel with 70/30 revenue split UI',
          'SafeBoot mode loopback for shadow copy deletion',
        ],
        code_reuse: 67, obfuscation: 'XOR + Custom packer (UPX-stripped)',
        mitre_ttps: ['T1486','T1490','T1059.001','T1083','T1057','T1078','T1562.001'],
        indicators: [
          { type:'domain', value:'lockbit4a3ebjnt4.onion' },
          { type:'ip', value:'185.220.101.45' },
          { type:'registry', value:'HKLM\\SOFTWARE\\LockBit' },
          { type:'mutex', value:'Global\\{LockBit4-running}' },
        ],
        behavior: [
          'Terminates 157 services (SQL, backup, security)',
          'Deletes shadow copies via WMI and vssadmin',
          'Encrypts files with .lb4 extension',
          'Drops ransom note in every directory',
          'Exfiltrates data to Tor hidden service',
          'Disables Windows Defender via GPO',
        ],
        evolution: [
          { version:'LockBit 1.0', year:'2019', sim:100, samples:234 },
          { version:'LockBit 2.0', year:'2021', sim:78, samples:1201 },
          { version:'LockBit 3.0 (Black)', year:'2022', sim:82, samples:4892 },
          { version:'LockBit 4.0', year:'2025', sim:67, samples:847 },
        ],
        patches: 'KB5023706, KB5022845',
        detection_rules: 'YARA: lockbit_v4_ransom, Sigma: win_lockbit_lateral',
      },
      {
        id: 'blackcat-3',
        family: 'BlackCat/ALPHV 3.0', generation: 'v3.0', type: 'Ransomware',
        hash_sha256: 'b7c8d9e0f1a2b3c4d5e6f70819283746aabbccdd55667788991011121314',
        hash_md5: '098f6bcd4621d373cade4e832627b4f6',
        hash_sha1: '1f8ac10f23c5b5bc1167bda84b833e5c057a77d7',
        parent: 'BlackMatter/DarkSide',
        similarity: 71,
        first_seen: '2024-09-01', last_seen: '2026-04-10', samples: 1203,
        origin: 'Russia', attribution: 'ALPHV/BlackCat Group',
        sectors: ['Energy','Legal','Manufacturing','Technology'],
        risk_score: 96,
        mutations: [
          'Rust-based rewrite (cross-platform: Windows/Linux/VMware ESXi)',
          'Intermittent encryption (25% of file) for speed',
          'Negotiation portal with timer and leak threat',
          'Wiper mode activated on negotiation failure',
          'API hashing to evade static analysis',
          'Bring Your Own Vulnerable Driver (BYOVD)',
        ],
        code_reuse: 31, obfuscation: 'Rust/LLVM obfuscation + stripped symbols',
        mitre_ttps: ['T1486','T1657','T1562','T1059.003','T1021.001','T1078.002','T1190'],
        indicators: [
          { type:'domain', value:'alphvmmm27o3abo.onion' },
          { type:'file', value:'svchost.exe (Renamed)' },
          { type:'registry', value:'HKCU\\SOFTWARE\\Classes\\.aaa' },
          { type:'ip', value:'45.86.230.75' },
        ],
        behavior: [
          'Cross-platform execution (Windows, Linux, ESXi)',
          'Terminates ESXi VMs before encryption',
          'Enables Safe Mode with network for defense bypass',
          'Steals AD credentials via DCSync',
          'Double extortion: encrypt + publish data',
          'Removes backup snapshots via PowerShell',
        ],
        evolution: [
          { version:'DarkSide 1.0', year:'2020', sim:100, samples:89 },
          { version:'BlackMatter', year:'2021', sim:84, samples:203 },
          { version:'ALPHV v1', year:'2021', sim:71, samples:521 },
          { version:'ALPHV v2', year:'2022', sim:88, samples:891 },
          { version:'ALPHV v3', year:'2024', sim:82, samples:1203 },
        ],
        patches: 'ESXi: VMSA-2024-0011',
        detection_rules: 'YARA: alphv_rust_ransomware, Sigma: win_alphv_lateral_esxi',
      },
      {
        id: 'agent-tesla',
        family: 'AgentTesla 4.0', generation: 'v4.0', type: 'Infostealer/RAT',
        hash_sha256: 'c9d0e1f2a3b4c5d6e7f8091020304050607080901121314151617181920',
        hash_md5: 'cfcd208495d565ef66e7dff9f98764da',
        hash_sha1: '356a192b7913b04c54574d18c28d46e6395428ab',
        parent: 'AgentTesla 3.0',
        similarity: 87,
        first_seen: '2023-11-20', last_seen: '2026-04-11', samples: 12845,
        origin: 'Turkey', attribution: 'AgentTesla Team (Commercial)',
        sectors: ['Finance','Healthcare','Government','SMB'],
        risk_score: 82,
        mutations: [
          'New keylogger module (async input hooks)',
          'Clipboard monitoring with regex filters',
          'Browser credential theft from 60+ browsers',
          'Telegram bot C2 added as fallback',
          'Screenshot capture with motion detection',
          'Email credential harvesting (SMTP/IMAP)',
        ],
        code_reuse: 87, obfuscation: '.NET obfuscation + ConfuserEx',
        mitre_ttps: ['T1056.001','T1115','T1555.003','T1071.001','T1059.001','T1027','T1566.001'],
        indicators: [
          { type:'domain', value:'api.telegram.org (abused)' },
          { type:'email', value:'stealerlogs@protonmail.com' },
          { type:'file', value:'%APPDATA%\\update.exe' },
          { type:'registry', value:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
        ],
        behavior: [
          'Keylogging all user input with timestamps',
          'Captures clipboard contents every 5 seconds',
          'Harvests saved passwords from Chrome, Firefox, Edge',
          'Sends stolen data via SMTP/Telegram/FTP',
          'Injects into legitimate processes (RegAsm.exe)',
          'Persists via registry run key and task scheduler',
        ],
        evolution: [
          { version:'AgentTesla 1.0', year:'2014', sim:100, samples:451 },
          { version:'AgentTesla 2.0', year:'2018', sim:79, samples:5621 },
          { version:'AgentTesla 3.0', year:'2020', sim:91, samples:8903 },
          { version:'AgentTesla 4.0', year:'2023', sim:87, samples:12845 },
        ],
        patches: 'Defender: TrojanSpy:MSIL/AgentTesla.B',
        detection_rules: 'YARA: agent_tesla_v4_stealer, Sigma: proc_creation_win_regasm_injection',
      },
      {
        id: 'asyncrat-v4',
        family: 'AsyncRAT 4.0', generation: 'v4.0', type: 'Remote Access Trojan',
        hash_sha256: 'd0e1f2a3b4c5d6e7f8091011121314151617181920212223242526272829',
        hash_md5: 'c4ca4238a0b923820dcc509a6f75849b',
        hash_sha1: '77de68daecd823babbb58edb1c8e14d7106e83bb',
        parent: 'AsyncRAT 3.x',
        similarity: 92,
        first_seen: '2024-06-01', last_seen: '2026-04-09', samples: 3211,
        origin: 'Unknown (Open Source Based)', attribution: 'Multiple Threat Actors',
        sectors: ['All sectors (opportunistic)'],
        risk_score: 79,
        mutations: [
          'Fully encrypted C2 channel (TLS 1.3)',
          'Anti-analysis: junk code injection',
          'Reverse proxy SOCKS5 module added',
          'Remote desktop streaming (MJPEG)',
          'Process migration to system processes',
          'Fileless execution via reflective DLL loading',
        ],
        code_reuse: 92, obfuscation: '.NET obfuscation + encrypted strings',
        mitre_ttps: ['T1571','T1059.001','T1055','T1105','T1021','T1083','T1113'],
        indicators: [
          { type:'port', value:'6606, 7707, 8808 (default C2)' },
          { type:'file', value:'%TEMP%\\Client.exe' },
          { type:'mutex', value:'AsyncMutex_6SI8OkPnk' },
          { type:'cert', value:'AsyncRAT self-signed cert' },
        ],
        behavior: [
          'Full remote control of victim machine',
          'Screen capture and live desktop streaming',
          'Keylogging and webcam capture',
          'File browsing, upload, and download',
          'Process management and shell access',
          'Cryptocurrency wallet stealing',
        ],
        evolution: [
          { version:'AsyncRAT 1.0', year:'2019', sim:100, samples:892 },
          { version:'AsyncRAT 2.0', year:'2021', sim:88, samples:1892 },
          { version:'AsyncRAT 3.0', year:'2022', sim:95, samples:2341 },
          { version:'AsyncRAT 4.0', year:'2024', sim:92, samples:3211 },
        ],
        patches: 'Block non-standard C2 ports',
        detection_rules: 'YARA: asyncrat_v4_rat, Sigma: net_connection_win_asyncrat',
      },
      {
        id: 'cobalt-strike-4',
        family: 'Cobalt Strike 4.x (Cracked)', generation: 'v4.x', type: 'Post-Exploitation Framework',
        hash_sha256: 'e1f2a3b4c5d6e7f80910111213141516171819202122232425262728293031',
        hash_md5: '1679091c5a880faf6fb5e6087eb1b2dc',
        hash_sha1: 'da4b9237bacccdf19c0760cab7aec4a8359010b0',
        parent: 'Cobalt Strike 3.x',
        similarity: 96,
        first_seen: '2020-01-01', last_seen: '2026-04-10', samples: 45123,
        origin: 'USA (Legitimate, widely abused)', attribution: 'APT28, APT29, Lazarus, FIN7, Ransomware Operators',
        sectors: ['Government','Finance','Defense','Healthcare'],
        risk_score: 95,
        mutations: [
          'New sleep obfuscation techniques (Ekko/Foliage/Gargoyle)',
          'BOF (Beacon Object Files) for modular capabilities',
          'UDRL (User-Defined Reflective Loader)',
          'Process injection: Process Hollowing + Thread Hijacking',
          'Kerberos attacks: AS-REP Roasting, Kerberoasting',
          'Proxy-aware C2 with malleable C2 profiles',
        ],
        code_reuse: 96, obfuscation: 'Malleable C2, sleep mask, reflective loading',
        mitre_ttps: ['T1055','T1059','T1021','T1003','T1558','T1071','T1095','T1105'],
        indicators: [
          { type:'port', value:'443, 80, 8443 (malleable C2)' },
          { type:'pipe', value:'\\\\.\\pipe\\mojo.xxx.xxx.xxx' },
          { type:'cert', value:'Cobalt Strike default certificate' },
          { type:'ua', value:'Mozilla/5.0 (custom malleable profile)' },
        ],
        behavior: [
          'Beacon-based C2 with configurable jitter',
          'Token impersonation and privilege escalation',
          'Lateral movement via SMB/PsExec/WMI',
          'Mimikatz integration for credential harvesting',
          'OPSEC-aware process spawning',
          'Covert data exfiltration via DNS/HTTPS',
        ],
        evolution: [
          { version:'Cobalt Strike 1.0', year:'2012', sim:100, samples:2341 },
          { version:'Cobalt Strike 3.x', year:'2016', sim:78, samples:12892 },
          { version:'Cobalt Strike 4.x', year:'2020', sim:96, samples:45123 },
        ],
        patches: 'Network: Block default C2 profiles, JA3 fingerprinting',
        detection_rules: 'YARA: cobalt_strike_beacon, Sigma: proc_creation_win_beacon_artifact',
      },
    ];

    const MALWARE_STATS = {
      families: 1247, code_reuse_avg: 73.4, mutations_tracked: 4821,
      clustering_accuracy: 97.1, new_last_24h: 12,
    };

    // State
    window._mdnaSelected = window._mdnaSelected || null;
    window._mdnaSearch = window._mdnaSearch || '';

    function _mdnaRender() {
      const search = (window._mdnaSearch || '').toLowerCase();
      const filtered = MALWARE_DB.filter(m =>
        !search ||
        m.family.toLowerCase().includes(search) ||
        m.type.toLowerCase().includes(search) ||
        m.origin.toLowerCase().includes(search) ||
        m.hash_sha256.toLowerCase().includes(search)
      );

      el.innerHTML = `
      <div class="cds-module cds-accent-dna">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.3);">
              <i class="fas fa-dna"></i>
            </div>
            <div>
              <div class="cds-module-name">Malware DNA Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Intelligence Active</div>
                <span>·</span><span>Real-world Malware Families</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <span class="cds-badge cds-badge-low"><i class="fas fa-database"></i> LIVE INTEL</span>
          </div>
        </div>
        <div class="cds-module-body">
          <!-- KPI Stats (same layout as Adversary Sim Lab) -->
          <div class="cds-metrics">
            ${[
              ['Families Tracked', MALWARE_STATS.families.toLocaleString(), '#22c55e', 'fa-dna'],
              ['Code Reuse Detected', MALWARE_STATS.code_reuse_avg+'%', '#00d4ff', 'fa-code'],
              ['Mutations Tracked', MALWARE_STATS.mutations_tracked.toLocaleString(), '#f97316', 'fa-random'],
              ['New (24h)', MALWARE_STATS.new_last_24h, '#ef4444', 'fa-plus-circle'],
            ].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Search bar -->
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
            <input type="text" placeholder="Search malware family, type, hash, origin…"
              value="${_esc(window._mdnaSearch||'')}"
              oninput="window._mdnaSearch=this.value;window.renderMalwareDNA()"
              style="flex:1;background:rgba(255,255,255,.05);border:1px solid var(--cds-border);border-radius:6px;padding:8px 12px;color:var(--cds-text);font-size:12px;">
            <button class="cds-btn cds-btn-sm" onclick="window._mdnaSearch='';window.renderMalwareDNA()"
              style="background:rgba(34,197,94,0.15);color:#22c55e;border:1px solid rgba(34,197,94,0.3);">
              <i class="fas fa-sync-alt"></i> Reset
            </button>
          </div>

          <!-- Table (same structure as Adversary Simulation Lab) -->
          <div class="cds-table-wrap">
            <table class="cds-table">
              <thead><tr>
                ${['Family / Hash','Type','Risk Score','Code Reuse','Samples','Last Seen','MITRE TTPs','Actions'].map(h=>`<th>${h}</th>`).join('')}
              </tr></thead>
              <tbody>
                ${filtered.map(m => {
                  const riskColor = m.risk_score>=90?'#ef4444':m.risk_score>=75?'#f97316':'#f59e0b';
                  const riskClass = m.risk_score>=90?'cds-badge-critical':m.risk_score>=75?'cds-badge-high':'cds-badge-medium';
                  return `
                  <tr>
                    <td>
                      <div style="font-size:12px;font-weight:700;color:var(--cds-text-primary);">${_esc(m.family)}</div>
                      <div style="font-size:10px;color:var(--cds-text-muted);font-family:'JetBrains Mono',monospace;margin-top:2px;">${m.hash_sha256.slice(0,20)}…</div>
                      <div style="font-size:10px;color:#64748b;margin-top:1px;">${_esc(m.attribution)}</div>
                    </td>
                    <td>
                      <span class="cds-inline-code" style="font-size:11px;">${_esc(m.type)}</span>
                      <div style="font-size:10px;color:var(--cds-text-muted);margin-top:3px;">Origin: ${_esc(m.origin)}</div>
                    </td>
                    <td>
                      <span class="cds-badge ${riskClass}" style="font-size:13px;font-weight:800;letter-spacing:.5px;">${m.risk_score}</span>
                    </td>
                    <td>
                      <div style="display:flex;align-items:center;gap:8px;">
                        <div class="cds-progress" style="width:70px;flex-shrink:0;">
                          <div class="cds-progress-fill" style="width:${m.code_reuse}%;background:${m.code_reuse>=80?'#22c55e':m.code_reuse>=50?'#f59e0b':'#ef4444'};"></div>
                        </div>
                        <span style="font-size:11px;font-weight:700;color:${m.code_reuse>=80?'#22c55e':m.code_reuse>=50?'#f59e0b':'#ef4444'};">${m.code_reuse}%</span>
                      </div>
                    </td>
                    <td style="font-size:12px;color:var(--cds-text-secondary);">
                      <span style="font-weight:700;color:#22c55e;">${m.samples.toLocaleString()}</span>
                    </td>
                    <td style="font-size:11px;color:var(--cds-text-muted);">${m.last_seen}</td>
                    <td>
                      <div style="display:flex;gap:4px;flex-wrap:wrap;max-width:200px;">
                        ${m.mitre_ttps.slice(0,3).map(t=>`
                          <span class="cds-inline-code" style="font-size:9px;padding:1px 5px;">${_esc(t)}</span>
                        `).join('')}
                        ${m.mitre_ttps.length>3?`<span style="font-size:9px;color:var(--cds-text-muted);">+${m.mitre_ttps.length-3}</span>`:''}
                      </div>
                    </td>
                    <td>
                      <div style="display:flex;gap:6px;flex-wrap:wrap;">
                        <button class="cds-btn cds-btn-primary cds-btn-sm"
                          onclick="window._mdnaShowDetail('${m.id}')">
                          <i class="fas fa-search"></i> Analyze
                        </button>
                        <button class="cds-btn cds-btn-ghost cds-btn-sm"
                          onclick="_toast('🧬 ${_esc(m.family)} added to IOC watchlist','success')">
                          <i class="fas fa-bookmark"></i>
                        </button>
                        <button class="cds-btn cds-btn-ghost cds-btn-sm"
                          onclick="navigator.clipboard?.writeText('${_esc(m.hash_sha256)}');_toast('Hash copied to clipboard','info')">
                          <i class="fas fa-copy"></i>
                        </button>
                      </div>
                    </td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>`;

      // Attach modal show function
      window._mdnaShowDetail = function(id) {
        const m = MALWARE_DB.find(x=>x.id===id);
        if (!m) return;
        const riskColor = m.risk_score>=90?'#ef4444':m.risk_score>=75?'#f97316':'#f59e0b';
        // Create overlay modal
        let overlay = document.getElementById('mdna-detail-overlay');
        if (!overlay) {
          overlay = document.createElement('div');
          overlay.id = 'mdna-detail-overlay';
          overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:9999;display:flex;align-items:flex-start;justify-content:center;padding:24px;overflow-y:auto;';
          overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };
          document.body.appendChild(overlay);
        }
        overlay.innerHTML = `
          <div style="background:#0f172a;border:1px solid #1e293b;border-radius:16px;max-width:860px;width:100%;margin:auto;overflow:hidden;">
            <!-- Modal Header -->
            <div style="background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(0,0,0,0));border-bottom:1px solid #1e293b;padding:20px 24px;display:flex;align-items:center;justify-content:space-between;">
              <div>
                <div style="font-size:1.25rem;font-weight:800;color:#22c55e;">${_esc(m.family)}</div>
                <div style="font-size:.8rem;color:#64748b;margin-top:3px;">${_esc(m.type)} · ${_esc(m.attribution)} · Origin: ${_esc(m.origin)}</div>
              </div>
              <div style="display:flex;align-items:center;gap:14px;">
                <div style="text-align:center;background:${riskColor}15;border:1px solid ${riskColor}33;border-radius:8px;padding:8px 14px;">
                  <div style="font-size:1.6rem;font-weight:800;color:${riskColor};font-family:'JetBrains Mono',monospace;">${m.risk_score}</div>
                  <div style="font-size:.65rem;color:#64748b;">RISK SCORE</div>
                </div>
                <button onclick="document.getElementById('mdna-detail-overlay').remove()"
                  style="background:#1e293b;border:1px solid #334155;color:#94a3b8;width:34px;height:34px;border-radius:8px;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;">
                  <i class="fas fa-times"></i>
                </button>
              </div>
            </div>
            <!-- Modal Body -->
            <div style="padding:20px 24px;display:grid;grid-template-columns:1fr 1fr;gap:14px;max-height:75vh;overflow-y:auto;">
              <!-- Hashes -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;grid-column:1/-1;">
                <div style="font-size:.8rem;font-weight:700;color:#22c55e;margin-bottom:10px;"><i class="fas fa-fingerprint"></i> File Hashes</div>
                ${[['SHA-256',m.hash_sha256],['MD5',m.hash_md5],['SHA-1',m.hash_sha1]].map(([t,v])=>`
                  <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #1e293b;">
                    <span style="font-size:.7rem;color:#64748b;min-width:50px;">${t}</span>
                    <code style="font-size:.72rem;color:#22d3ee;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${_esc(v)}</code>
                    <button onclick="navigator.clipboard?.writeText('${_esc(v)}');_toast('Hash copied','success')" style="background:none;border:none;color:#64748b;cursor:pointer;padding:2px 6px;"><i class="fas fa-copy"></i></button>
                  </div>`).join('')}
              </div>
              <!-- Behavior -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;">
                <div style="font-size:.8rem;font-weight:700;color:#ef4444;margin-bottom:10px;"><i class="fas fa-eye"></i> Behavior</div>
                ${m.behavior.map(b=>`<div style="font-size:.78rem;color:#94a3b8;padding:3px 0;display:flex;gap:6px;"><i class="fas fa-caret-right" style="color:#ef4444;margin-top:3px;flex-shrink:0;"></i>${_esc(b)}</div>`).join('')}
              </div>
              <!-- Mutations -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;">
                <div style="font-size:.8rem;font-weight:700;color:#f97316;margin-bottom:10px;"><i class="fas fa-random"></i> Mutations vs Parent</div>
                ${m.mutations.map((mut,i)=>`<div style="font-size:.78rem;color:#94a3b8;padding:3px 0;display:flex;gap:6px;border-bottom:1px solid #0f172a;"><span style="background:rgba(249,115,22,.15);color:#f97316;font-size:.65rem;padding:1px 5px;border-radius:3px;min-width:18px;text-align:center;flex-shrink:0;">${i+1}</span>${_esc(mut)}</div>`).join('')}
              </div>
              <!-- MITRE TTPs -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;">
                <div style="font-size:.8rem;font-weight:700;color:#3b82f6;margin-bottom:10px;"><i class="fas fa-th"></i> MITRE ATT&CK</div>
                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                  ${m.mitre_ttps.map(t=>`<a href="https://attack.mitre.org/techniques/${t.replace('.','/').replace('.','-')}/" target="_blank" style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);padding:3px 8px;border-radius:5px;font-size:.75rem;font-family:'JetBrains Mono',monospace;text-decoration:none;">${_esc(t)}</a>`).join('')}
                </div>
              </div>
              <!-- IOCs -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;">
                <div style="font-size:.8rem;font-weight:700;color:#a855f7;margin-bottom:10px;"><i class="fas fa-bullseye"></i> IOCs</div>
                ${m.indicators.map(ioc=>`<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #0f172a;"><span style="font-size:.65rem;text-transform:uppercase;color:#a855f7;background:rgba(168,85,247,.1);padding:1px 6px;border-radius:3px;min-width:50px;text-align:center;flex-shrink:0;">${_esc(ioc.type)}</span><code style="font-size:.75rem;color:#e2e8f0;font-family:'JetBrains Mono',monospace;word-break:break-all;">${_esc(ioc.value)}</code></div>`).join('')}
              </div>
              <!-- Evolution -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;">
                <div style="font-size:.8rem;font-weight:700;color:#22c55e;margin-bottom:14px;"><i class="fas fa-history"></i> Evolution Timeline</div>
                <div style="display:flex;align-items:flex-end;gap:8px;overflow-x:auto;min-height:80px;">
                  ${m.evolution.map((e,i,a)=>`
                    <div style="display:flex;flex-direction:column;align-items:center;gap:3px;flex-shrink:0;min-width:60px;">
                      <div style="font-size:.65rem;color:#22c55e;font-weight:700;">${e.sim}%</div>
                      <div style="width:44px;height:${Math.round(e.sim/100*60)+8}px;background:linear-gradient(180deg,rgba(34,197,94,.7),rgba(34,197,94,.15));border:1px solid rgba(34,197,94,.4);border-radius:3px 3px 0 0;cursor:pointer;"
                        onclick="_toast('${_esc(e.version)}: ${e.samples} samples','info')"></div>
                      <div style="font-size:.65rem;color:#64748b;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:60px;">${_esc(e.version)}</div>
                      <div style="font-size:.6rem;color:#475569;">${e.year}</div>
                    </div>
                    ${i<a.length-1?'<i class="fas fa-arrow-right" style="color:#334155;font-size:9px;margin-bottom:24px;"></i>':''}
                  `).join('')}
                </div>
              </div>
              <!-- Detection & Actions -->
              <div style="background:#0a0e17;border:1px solid #1e293b;border-radius:10px;padding:14px;grid-column:1/-1;">
                <div style="font-size:.8rem;font-weight:700;color:#22c55e;margin-bottom:10px;"><i class="fas fa-shield-alt"></i> Detection & Response</div>
                <div style="font-size:.8rem;color:#94a3b8;margin-bottom:6px;"><strong style="color:#e2e8f0;">Rules:</strong> ${_esc(m.detection_rules)}</div>
                <div style="font-size:.8rem;color:#94a3b8;margin-bottom:14px;"><strong style="color:#e2e8f0;">Patches:</strong> ${_esc(m.patches)}</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                  <a href="https://www.virustotal.com/gui/search/${m.hash_sha256}" target="_blank"
                    style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);padding:6px 14px;border-radius:7px;font-size:12px;font-weight:600;text-decoration:none;display:flex;align-items:center;gap:6px;">
                    <i class="fas fa-virus"></i> VirusTotal
                  </a>
                  <button class="cds-btn cds-btn-sm" style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);"
                    onclick="_toast('Added ${_esc(m.family)} to IOC watchlist','success')">
                    <i class="fas fa-plus"></i> Add to Watchlist
                  </button>
                  <button class="cds-btn cds-btn-sm" style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.3);"
                    onclick="_toast('Exporting ${_esc(m.family)} intel report','info')">
                    <i class="fas fa-download"></i> Export Intel
                  </button>
                  <button class="cds-btn cds-btn-sm" onclick="document.getElementById('mdna-detail-overlay').remove()"
                    style="background:#1e293b;color:#94a3b8;border:1px solid #334155;">
                    <i class="fas fa-times"></i> Close
                  </button>
                </div>
              </div>
            </div>
          </div>`;
      };
    }

    _mdnaRender();
  };

  /* ═══════════════════════════════════════════════════
     MODULE 5: ADVERSARY SIMULATION LAB
     "Execute attack simulations, measure detection readiness"
  ═══════════════════════════════════════════════════ */
  window.renderAdversarySimLab = function () {
    const el = document.getElementById('page-adversary-sim');
    if (!el) return;

    const SIMULATIONS = [
      { id:'sim-001', name:'LockBit Ransomware Simulation', technique:'T1486 + T1059.001', status:'READY', risk:'SAFE', detection_rate:78, last_run:'2025-02-01', steps:14 },
      { id:'sim-002', name:'APT29 Lateral Movement Chain', technique:'T1021.002 + T1003', status:'RUNNING', risk:'SAFE', detection_rate:65, last_run:'Now', steps:8 },
      { id:'sim-003', name:'Phishing → Credential Harvest', technique:'T1566 + T1555', status:'COMPLETE', risk:'SAFE', detection_rate:91, last_run:'2025-02-09', steps:6 },
      { id:'sim-004', name:'Supply Chain Injection', technique:'T1195 + T1027', status:'READY', risk:'SAFE', detection_rate:null, last_run:'Never', steps:11 },
    ];

    el.innerHTML = `
      <div class="cds-module cds-accent-sim">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.3);">
              <i class="fas fa-theater-masks"></i>
            </div>
            <div>
              <div class="cds-module-name">Adversary Simulation Lab</div>
              <div class="cds-module-meta"><div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Safe Simulation</div><span>·</span><span>Zero Real Impact</span></div>
            </div>
          </div>
          <div class="cds-module-actions">
            <span class="cds-badge cds-badge-low"><i class="fas fa-shield-alt"></i> ISOLATED ENV</span>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Simulations Run','47','#ef4444','fa-play'],['Detection Coverage','81.3%','#22c55e','fa-crosshairs'],['Gaps Found','12','#f97316','fa-exclamation-triangle'],['Rules Improved','23','#3b82f6','fa-code']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div class="cds-table-wrap">
            <table class="cds-table">
              <thead><tr>
                ${['Simulation','Technique','Status','Detection Rate','Last Run','Steps','Actions'].map(h=>`<th>${h}</th>`).join('')}
              </tr></thead>
              <tbody>
                ${SIMULATIONS.map(s => `
                  <tr>
                    <td><div style="font-size:12px;font-weight:600;color:var(--cds-text-primary);">${_esc(s.name)}</div></td>
                    <td><span class="cds-inline-code">${s.technique}</span></td>
                    <td>
                      <span class="cds-badge ${s.status==='RUNNING'?'cds-badge-high':s.status==='COMPLETE'?'cds-badge-low':'cds-badge-neutral'}">
                        ${s.status==='RUNNING'?'<i class="fas fa-spinner fa-spin" style="margin-right:4px;"></i>':''}
                        ${s.status}
                      </span>
                    </td>
                    <td>
                      ${s.detection_rate !== null ? `
                        <div style="display:flex;align-items:center;gap:8px;">
                          <div class="cds-progress" style="width:80px;flex-shrink:0;">
                            <div class="cds-progress-fill" style="width:${s.detection_rate}%;background:${s.detection_rate>=80?'#22c55e':s.detection_rate>=60?'#f59e0b':'#ef4444'};"></div>
                          </div>
                          <span style="font-size:11px;font-weight:700;color:${s.detection_rate>=80?'#22c55e':s.detection_rate>=60?'#f59e0b':'#ef4444'};">${s.detection_rate}%</span>
                        </div>
                      ` : '<span style="color:var(--cds-text-muted);">—</span>'}
                    </td>
                    <td style="font-size:11px;color:var(--cds-text-muted);">${s.last_run}</td>
                    <td style="font-size:11px;color:var(--cds-text-secondary);">${s.steps} steps</td>
                    <td>
                      <div style="display:flex;gap:6px;">
                        <button class="cds-btn cds-btn-primary cds-btn-sm" onclick="_toast('🎭 Simulation started: ${_esc(s.name)}','info')">
                          <i class="fas fa-play"></i> Run
                        </button>
                        <button class="cds-btn cds-btn-ghost cds-btn-sm" onclick="_toast('📊 Opening report…','info')">
                          <i class="fas fa-chart-bar"></i>
                        </button>
                      </div>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  };

  /* ═══════════════════════════════════════════════════
     MODULE 6: AUTONOMOUS SOC AGENT
     "Auto-triage, investigate, correlate, respond"
  ═══════════════════════════════════════════════════ */
  window.renderAutonomousAgent = function () {
    const el = document.getElementById('page-autonomous-agent');
    if (!el) return;

    const AGENT_LOG = [
      { time: '14:32:01', action: 'Alert received: Suspicious PowerShell on WKSTN-045', status: 'complete', result: 'Enriched with 3 sources' },
      { time: '14:32:03', action: 'Hash lookup → VirusTotal (68/72 engines)', status: 'complete', result: 'MALICIOUS confirmed' },
      { time: '14:32:05', action: 'IOC extraction: 2 IPs, 1 domain, 1 URL', status: 'complete', result: 'IOCs added to watchlist' },
      { time: '14:32:07', action: 'MITRE ATT&CK mapping: T1059.001, T1027, T1562.001', status: 'complete', result: '3 techniques mapped' },
      { time: '14:32:10', action: 'Similar incident correlation: INC-2025-0023', status: 'complete', result: '87% pattern match' },
      { time: '14:32:12', action: 'Risk scoring: 94/100', status: 'complete', result: 'Critical threshold exceeded' },
      { time: '14:32:15', action: 'Case created: CASE-2025-0847', status: 'complete', result: 'Assigned to Tier 2' },
      { time: '14:32:17', action: 'Playbook triggered: Cobalt Strike Response v2.1', status: 'running', result: 'Step 3/7 in progress' },
    ];

    el.innerHTML = `
      <div class="cds-module cds-accent-agent">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(245,158,11,0.1);color:#f59e0b;border:1px solid rgba(245,158,11,0.3);">
              <i class="fas fa-robot"></i>
            </div>
            <div>
              <div class="cds-module-name">Autonomous SOC Agent</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Active</div>
                <span>·</span><span>Auto-Triage</span><span>·</span><span>AI-Driven</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-primary cds-btn-sm" onclick="_toast('🤖 Agent running full investigation…','info')">
              <i class="fas fa-play"></i> Run Investigation
            </button>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Alerts Triaged Today','847','#f59e0b','fa-robot'],['Auto-Resolved','623','#22c55e','fa-check'],['Escalated','47','#ef4444','fa-level-up-alt'],['MTTR Reduction','76%','#00d4ff','fa-clock']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <div class="cds-card" style="margin-bottom:16px;">
            <div class="cds-section-title"><i class="fas fa-terminal"></i> Live Agent Activity Log</div>
            <div class="cds-timeline">
              ${AGENT_LOG.map((entry, i) => `
                <div class="cds-timeline-item" style="animation-delay:${i*0.08}s">
                  <div class="cds-timeline-dot" style="border-color:${entry.status==='complete'?'#22c55e':entry.status==='running'?'#f59e0b':'#475569'};background:${entry.status==='running'?'#f59e0b11':'var(--cds-bg-base)'};"></div>
                  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
                    <div>
                      <div class="cds-timeline-time">${entry.time}</div>
                      <div class="cds-timeline-title" style="display:flex;align-items:center;gap:6px;">
                        ${entry.status==='running'?'<i class="fas fa-spinner fa-spin" style="color:#f59e0b;font-size:10px;"></i>':
                          entry.status==='complete'?'<i class="fas fa-check-circle" style="color:#22c55e;font-size:10px;"></i>':''}
                        ${_esc(entry.action)}
                      </div>
                    </div>
                    <span class="cds-badge ${entry.status==='complete'?'cds-badge-low':entry.status==='running'?'cds-badge-high':'cds-badge-neutral'}" style="font-size:9px;flex-shrink:0;">
                      ${entry.result}
                    </span>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>

          <div class="cds-ai-explainer">
            <div class="cds-ai-badge" style="margin-bottom:8px;"><i class="fas fa-robot"></i> AGENT DECISION SUMMARY</div>
            <div class="cds-ai-reasoning">
              After autonomous analysis of 8 data points across VirusTotal, AbuseIPDB, internal SIEM, and MITRE ATT&CK database, the Agent determined this alert requires <strong style="color:#ef4444;">IMMEDIATE ESCALATION</strong>. A case was automatically created, the Cobalt Strike response playbook was triggered, and Tier 2 was notified. No manual intervention required — analyst review recommended within 30 minutes.
            </div>
            <div style="display:flex;gap:8px;margin-top:12px;">
              <button class="cds-btn cds-btn-secondary cds-btn-sm" onclick="_toast('📂 Case CASE-2025-0847 opened','info')"><i class="fas fa-folder-open"></i> View Case</button>
              <button class="cds-btn cds-btn-ghost cds-btn-sm" onclick="_toast('✅ Agent decision approved','success')"><i class="fas fa-thumbs-up"></i> Approve</button>
              <button class="cds-btn cds-btn-danger cds-btn-sm" onclick="_toast('⚠️ Agent decision overridden','warning')"><i class="fas fa-times"></i> Override</button>
            </div>
          </div>
        </div>
      </div>
    `;
  };

  /* ═══════════════════════════════════════════════════
     MODULE 7: DIGITAL RISK PROTECTION
     "Dark web monitoring, brand abuse, leaked credentials"
  ═══════════════════════════════════════════════════ */
  window.renderDigitalRisk = function () {
    const el = document.getElementById('page-digital-risk');
    if (!el) return;

    el.innerHTML = `
      <div class="cds-module cds-accent-risk">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon accent" style="background:rgba(236,72,153,0.1);color:#ec4899;border:1px solid rgba(236,72,153,0.3);">
              <i class="fas fa-user-shield"></i>
            </div>
            <div>
              <div class="cds-module-name">Digital Risk Protection</div>
              <div class="cds-module-meta"><div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Monitoring</div><span>·</span><span>Dark Web + Surface Web</span></div>
            </div>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Leaked Credentials','3,247','#ef4444','fa-key'],['Brand Mentions','142','#ec4899','fa-trademark'],['Exposed Domains','8','#f97316','fa-globe'],['Dark Web Hits','23','#a855f7','fa-spider']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Alerts -->
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${[
              { type:'CREDENTIAL LEAK', title:'3,247 employee credentials found in breach dump', source:'RaidForums Mirror', date:'2025-02-10', severity:'critical', desc:'Email + SHA-512 hashes. Affected domains: @company.com, @subsidiary.com. Breach source: third-party HR vendor.', action:'Force password reset for affected accounts' },
              { type:'BRAND ABUSE', title:'Phishing domain impersonating company login portal', source:'Surface Web', date:'2025-02-09', severity:'high', desc:'Domain: company-login-secure.xyz registered 2025-02-08. Hosts exact replica of company login page. 47 credential submissions logged.', action:'Request domain takedown + deploy phishing alert' },
              { type:'DARK WEB MENTION', title:'Company named as upcoming ransomware target', source:'RAMP Forum', date:'2025-02-08', severity:'critical', desc:'Post by LockBit affiliate discussing reconnaissance of company VPN infrastructure. Mentions 2 unpatched Ivanti instances.', action:'Patch Ivanti CVE-2025-2401 immediately + harden VPN' },
            ].map(a => `
              <div class="cds-card ${a.severity==='critical'?'cds-card--glow-red':''}" style="border-color:${a.severity==='critical'?'rgba(239,68,68,0.25)':'rgba(249,115,22,0.2)'};">
                <div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;flex-wrap:wrap;">
                  <div style="flex:1;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;">
                      <span class="cds-badge cds-badge-${a.severity}" style="font-size:9px;">${a.type}</span>
                      <span style="font-size:12px;font-weight:700;color:var(--cds-text-primary);">${_esc(a.title)}</span>
                    </div>
                    <div style="font-size:10px;color:var(--cds-text-muted);">Source: ${a.source} · ${a.date}</div>
                  </div>
                </div>
                <p style="font-size:12px;color:var(--cds-text-secondary);margin:0 0 10px;line-height:1.5;">${_esc(a.desc)}</p>
                <div class="cds-alert cds-alert-high" style="margin-bottom:10px;">
                  <i class="fas fa-exclamation-triangle"></i>
                  <strong>Action Required:</strong> ${_esc(a.action)}
                </div>
                <div style="display:flex;gap:6px;">
                  <button class="cds-btn cds-btn-danger cds-btn-sm" onclick="_toast('🚨 Incident opened','warning')"><i class="fas fa-exclamation-circle"></i> Open Incident</button>
                  <button class="cds-btn cds-btn-ghost cds-btn-sm" onclick="_toast('✅ Acknowledged','info')"><i class="fas fa-check"></i> Acknowledge</button>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  };

  /* ═══════════════════════════════════════════════════
     MODULE 8: SOC MEMORY ENGINE
     "Institutional learning — past incidents, decisions, recommendations"
  ═══════════════════════════════════════════════════ */
  window.renderSOCMemory = function () {
    const el = document.getElementById('page-soc-memory');
    if (!el) return;

    el.innerHTML = `
      <div class="cds-module">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.3);">
              <i class="fas fa-memory"></i>
            </div>
            <div>
              <div class="cds-module-name">SOC Memory Engine</div>
              <div class="cds-module-meta"><div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Learning</div><span>·</span><span>1,847 Incidents Stored</span></div>
            </div>
          </div>
        </div>
        <div class="cds-module-body">
          <div class="cds-metrics">
            ${[['Incidents in Memory','1,847','#00d4ff','fa-database'],['Similar Cases Found','94.3%','#22c55e','fa-search'],['Analyst Hours Saved','2,403h','#a855f7','fa-clock'],['Decision Accuracy','89.7%','#f59e0b','fa-bullseye']].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Search -->
          <div class="cds-card" style="margin-bottom:16px;">
            <div class="cds-section-title"><i class="fas fa-brain"></i> Query SOC Memory</div>
            <div style="display:flex;gap:8px;margin-bottom:14px;">
              <div class="cds-search" style="flex:1;">
                <i class="fas fa-search cds-search-icon"></i>
                <input class="cds-search-input" style="width:100%;" id="socMemorySearch"
                  placeholder="Describe a current situation or alert… (e.g. 'SMB beacon from workstation to DC')"
                  onkeydown="if(event.key==='Enter')window._socMemoryQuery()" />
              </div>
              <button class="cds-btn cds-btn-primary" onclick="window._socMemoryQuery()">
                <i class="fas fa-brain"></i> Find Similar
              </button>
            </div>
          </div>

          <!-- Stored Cases -->
          <div class="cds-section-title"><i class="fas fa-folder"></i> Recently Retrieved Cases</div>
          <div style="display:flex;flex-direction:column;gap:10px;">
            ${[
              { id:'INC-2024-0891', title:'APT29 Lateral Movement — Financial Sector', similarity:94, outcome:'Contained in 4h', resolution:'Isolated 3 hosts, reset 12 credentials, patched SMB', analyst:'J. Chen', date:'2024-11-14' },
              { id:'INC-2025-0023', title:'Cobalt Strike Stager via Phishing', similarity:89, outcome:'Contained in 2h', resolution:'Blocked domain, killed process, ran memory forensics', analyst:'M. Osman', date:'2025-01-22' },
              { id:'INC-2024-1204', title:'SolarWinds-style Supply Chain Attack', similarity:71, outcome:'Partial containment', resolution:'Updated all vendor credentials, implemented SBOM scan', analyst:'A. Patel', date:'2024-12-04' },
            ].map(c => `
              <div class="cds-card" style="cursor:pointer;" onclick="_toast('📂 Opening ${c.id}…','info')">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                  <div style="text-align:center;flex-shrink:0;">
                    <div style="font-size:20px;font-weight:800;font-family:'JetBrains Mono',monospace;color:${c.similarity>=90?'#22c55e':'#f59e0b'};">${c.similarity}%</div>
                    <div style="font-size:9px;color:var(--cds-text-muted);">MATCH</div>
                  </div>
                  <div style="flex:1;">
                    <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
                      <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#00d4ff;">${c.id}</span>
                      <span style="font-size:12px;font-weight:700;color:var(--cds-text-primary);">${_esc(c.title)}</span>
                    </div>
                    <div style="font-size:10px;color:var(--cds-text-muted);">${c.date} · Analyst: ${c.analyst} · ${c.outcome}</div>
                    <div style="font-size:11px;color:var(--cds-text-secondary);margin-top:3px;"><strong>Resolution:</strong> ${_esc(c.resolution)}</div>
                  </div>
                  <i class="fas fa-chevron-right" style="color:var(--cds-text-muted);flex-shrink:0;"></i>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </div>
    `;
  };

  window._socMemoryQuery = function () {
    const q = document.getElementById('socMemorySearch')?.value;
    if (q) _toast(`🧠 SOC Memory: Finding cases similar to "${q.slice(0,40)}…"`, 'info');
    else   _toast('Please enter a description', 'warning');
  };

  console.log('[CyberBrainModules] ✅ All 8 next-gen modules loaded v1.0');

})();
