/* ═══════════════════════════════════════════════════════════════════
   EYEbot AI — Next-Generation Cyber Defense Brain Modules v1.0
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
                  <button class="cds-btn cds-btn-danger cds-btn-sm" onclick="_toast('🚨 Alert escalated to Tier 2','warning')">
                    <i class="fas fa-level-up-alt"></i> Escalate
                  </button>
                  <button class="cds-btn cds-btn-secondary cds-btn-sm" onclick="_toast('✅ Alert acknowledged','info')">
                    <i class="fas fa-check"></i> Acknowledge
                  </button>
                  <button class="cds-btn cds-btn-ghost cds-btn-sm" onclick="_toast('🔍 Opening investigation…','info')">
                    <i class="fas fa-search"></i> Investigate
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
  window.renderAttackGraph = function () {
    const el = document.getElementById('page-attack-graph');
    if (!el) return;

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
                <span>·</span><span>MITRE ATT&CK Mapped</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <button class="cds-btn cds-btn-secondary cds-btn-sm" onclick="window._agExportGraph()"><i class="fas fa-download"></i> Export</button>
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
          <div class="cds-graph-panel" style="min-height:400px;margin-bottom:16px;">
            <div class="cds-graph-toolbar">
              <button class="cds-btn cds-btn-ghost cds-btn-sm cds-btn-icon" onclick="_toast('Zoom in','info')" title="Zoom In"><i class="fas fa-search-plus"></i></button>
              <button class="cds-btn cds-btn-ghost cds-btn-sm cds-btn-icon" onclick="_toast('Zoom out','info')" title="Zoom Out"><i class="fas fa-search-minus"></i></button>
              <button class="cds-btn cds-btn-ghost cds-btn-sm cds-btn-icon" onclick="window._agRenderGraph()" title="Reset"><i class="fas fa-compress-arrows-alt"></i></button>
            </div>
            <canvas id="attackGraphCanvas" style="width:100%;height:400px;"></canvas>
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
                  ${s.current?'box-shadow:0 0 12px '+s.color+'44;animation:cds-pulse-dot 1.5s ease-in-out infinite;':''}
                  ${s.predicted?'border-style:dashed;':''}
                ">
                  ${s.current?'<i class="fas fa-circle" style="font-size:6px;animation:cds-pulse-dot 1s ease-in-out infinite;"></i>':
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

    // Draw simple attack graph on canvas
    setTimeout(() => window._agRenderGraph(), 100);
  };

  window._agRenderGraph = function () {
    const canvas = document.getElementById('attackGraphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.offsetWidth;
    canvas.height = 400;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Background
    ctx.fillStyle = 'rgba(2,8,23,0.5)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const nodes = [
      { x: 80,  y: 200, label: 'External', color: '#f59e0b', status: 'done', detail: 'Attacker: APT29\nEntry via phishing email\nInitial access gained' },
      { x: 220, y: 200, label: 'WKSTN-012', color: '#ef4444', status: 'done', detail: 'Workstation: WKSTN-012\nCobalt Strike beacon installed\nCredentials dumped via LSASS' },
      { x: 360, y: 200, label: 'WKSTN-045', color: '#ef4444', status: 'current', detail: '⚡ CURRENT POSITION\nWorkstation: WKSTN-045\nLateral movement in progress\nSMB exploitation active' },
      { x: 500, y: 120, label: 'DC-01', color: '#a855f7', status: 'predicted', detail: '🔮 PREDICTED (87% confidence)\nDomain Controller: DC-01\nKerberoasting attack likely\nAD enumeration imminent' },
      { x: 500, y: 280, label: 'FS-SERVER', color: '#a855f7', status: 'predicted', detail: '🔮 PREDICTED (64% confidence)\nFile Server: FS-SERVER\nData staging location\nExfiltration prep expected' },
      { x: 640, y: 200, label: 'Exfil', color: '#64748b', status: 'future', detail: '⚠️ FUTURE RISK\nData Exfiltration\nEstimated: 48-72h\nTarget: Tor C2 (lockbit4.onion)' },
    ];

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

      // Index label for click hint
      if (n.status !== 'future') {
        ctx.fillStyle = n.color;
        ctx.font = 'bold 9px Inter, sans-serif';
        ctx.fillText('↓', n.x, n.y + 41);
      }
    });

    // Click handler for nodes
    if (!canvas._agClickBound) {
      canvas._agClickBound = true;
      canvas.style.cursor = 'pointer';
      canvas.addEventListener('click', function(e) {
        const rect = canvas.getBoundingClientRect();
        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
        const nodes = canvas._agNodes || [];
        for (const node of nodes) {
          const dist = Math.sqrt((mx-node.x)**2 + (my-node.y)**2);
          if (dist <= 22) {
            window._agShowNodeDetail(node);
            return;
          }
        }
      });
      canvas.addEventListener('mousemove', function(e) {
        const rect = canvas.getBoundingClientRect();
        const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
        const my = (e.clientY - rect.top) * (canvas.height / rect.height);
        const nodes = canvas._agNodes || [];
        let hovered = -1;
        for (let i = 0; i < nodes.length; i++) {
          const dist = Math.sqrt((mx-nodes[i].x)**2 + (my-nodes[i].y)**2);
          if (dist <= 22) { hovered = i; break; }
        }
        if (canvas._agHover !== hovered) {
          canvas._agHover = hovered;
          window._agRenderGraph();
        }
      });
    }
  };

  window._agShowNodeDetail = function(node) {
    // Remove existing tooltip
    document.getElementById('ag-node-tooltip')?.remove();

    const tooltip = document.createElement('div');
    tooltip.id = 'ag-node-tooltip';
    tooltip.style.cssText = `
      position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
      background:#0d1117;border:1px solid ${node.color}44;border-radius:10px;
      padding:16px;z-index:9999;min-width:300px;max-width:400px;
      box-shadow:0 0 24px ${node.color}33;`;
    tooltip.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
        <div style="font-weight:700;color:${node.color};">${node.label}</div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span style="font-size:10px;background:${node.color}22;color:${node.color};padding:2px 8px;border-radius:4px;border:1px solid ${node.color}44;">${node.status.toUpperCase()}</span>
          <button onclick="document.getElementById('ag-node-tooltip').remove()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:14px;">✕</button>
        </div>
      </div>
      <div style="font-size:.82rem;color:#8b949e;line-height:1.7;white-space:pre-line;">${node.detail}</div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap;">
        <button onclick="window._agAnalystAction('block','${node.label}');document.getElementById('ag-node-tooltip').remove()"
          style="background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3);border-radius:6px;padding:4px 10px;font-size:.75rem;cursor:pointer;">
          <i class="fas fa-ban"></i> Block
        </button>
        <button onclick="window._agAnalystAction('investigate','${node.label}');document.getElementById('ag-node-tooltip').remove()"
          style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);border-radius:6px;padding:4px 10px;font-size:.75rem;cursor:pointer;">
          <i class="fas fa-search"></i> Investigate
        </button>
        <button onclick="window._agAnalystAction('simulate','${node.label}');document.getElementById('ag-node-tooltip').remove()"
          style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.3);border-radius:6px;padding:4px 10px;font-size:.75rem;cursor:pointer;">
          <i class="fas fa-play"></i> Simulate
        </button>
      </div>`;
    document.body.appendChild(tooltip);
    // Auto-close on backdrop click
    setTimeout(() => {
      document.addEventListener('click', function closer(e) {
        if (!tooltip.contains(e.target)) { tooltip.remove(); document.removeEventListener('click', closer); }
      });
    }, 100);
  };

  window._agAnalystAction = function(action, node) {
    const msgs = {
      block: `🚫 Isolation command sent — ${node} blocked from network`,
      investigate: `🔍 Investigation case created for ${node}`,
      simulate: `▶️ Simulation started: attack path through ${node}`,
    };
    _toast(msgs[action] || 'Action taken', action==='block'?'error':action==='investigate'?'info':'success');
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
      const selected = window._mdnaSelected;
      const search = window._mdnaSearch.toLowerCase();
      const filtered = MALWARE_DB.filter(m =>
        !search ||
        m.family.toLowerCase().includes(search) ||
        m.type.toLowerCase().includes(search) ||
        m.origin.toLowerCase().includes(search) ||
        m.hash_sha256.toLowerCase().includes(search)
      );

      el.innerHTML = `
      <div class="cds-module cds-accent-dna" style="min-height:100%;">
        <div class="cds-module-header">
          <div class="cds-module-title-group">
            <div class="cds-module-icon" style="background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.3);">
              <i class="fas fa-dna"></i>
            </div>
            <div>
              <div class="cds-module-name">Malware DNA Engine</div>
              <div class="cds-module-meta">
                <div class="cds-status cds-status-online"><div class="cds-status-dot"></div>Intelligence Active</div>
                <span>·</span><span>Real-world Malware Intel</span><span>·</span>
                <span style="color:#22c55e;font-weight:700;font-size:10px;">CONTINUOUS UPDATES</span>
              </div>
            </div>
          </div>
          <div class="cds-module-actions">
            <input type="text" id="mdna-search" placeholder="Search malware family, type, hash…"
              value="${_esc(window._mdnaSearch)}"
              oninput="window._mdnaSearch=this.value;window.renderMalwareDNA()"
              style="background:rgba(255,255,255,.05);border:1px solid var(--cds-border);border-radius:6px;padding:6px 10px;color:var(--cds-text);font-size:12px;width:220px;">
            <button class="cds-btn cds-btn-sm" onclick="window.renderMalwareDNA()"
              style="background:rgba(34,197,94,0.15);color:#22c55e;border:1px solid rgba(34,197,94,0.3);">
              <i class="fas fa-sync-alt"></i> Refresh
            </button>
          </div>
        </div>
        <div class="cds-module-body">

          <!-- KPIs -->
          <div class="cds-metrics" style="margin-bottom:20px;">
            ${[
              ['Families Tracked', MALWARE_STATS.families.toLocaleString(), '#22c55e', 'fa-dna'],
              ['Avg Code Reuse', MALWARE_STATS.code_reuse_avg+'%', '#00d4ff', 'fa-code'],
              ['Mutations Tracked', MALWARE_STATS.mutations_tracked.toLocaleString(), '#f97316', 'fa-random'],
              ['New (24h)', MALWARE_STATS.new_last_24h, '#ef4444', 'fa-plus-circle'],
              ['Clustering Accuracy', MALWARE_STATS.clustering_accuracy+'%', '#a855f7', 'fa-bullseye'],
            ].map(([l,v,c,i])=>`
              <div class="cds-card cds-stat-card" style="border-color:${c}22;">
                <div class="cds-stat-icon" style="background:${c}15;color:${c};border:1px solid ${c}33;"><i class="fas ${i}"></i></div>
                <div><div class="cds-stat-num" style="color:${c};">${v}</div><div class="cds-stat-label">${l}</div></div>
              </div>`).join('')}
          </div>

          <!-- Two-panel: list + detail -->
          <div style="display:grid;grid-template-columns:320px 1fr;gap:16px;min-height:600px;">

            <!-- Left: Malware List -->
            <div style="display:flex;flex-direction:column;gap:8px;overflow-y:auto;">
              ${filtered.map(m => `
              <div onclick="window._mdnaSelected='${m.id}';window.renderMalwareDNA()"
                style="background:var(--cds-card);border:1px solid ${selected===m.id?'#22c55e':'var(--cds-border)'};border-radius:10px;padding:12px 14px;cursor:pointer;transition:all .2s;${selected===m.id?'box-shadow:0 0 12px rgba(34,197,94,.2);':''}"
                onmouseover="this.style.borderColor='#22c55e44'"
                onmouseout="this.style.borderColor='${selected===m.id?'#22c55e':'var(--cds-border)'}'">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                  <div style="width:36px;height:36px;border-radius:8px;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <i class="fas fa-dna" style="color:#22c55e;"></i>
                  </div>
                  <div style="min-width:0;">
                    <div style="font-weight:700;font-size:.9rem;color:var(--cds-text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${_esc(m.family)}</div>
                    <div style="font-size:.75rem;color:var(--cds-text-muted);">${_esc(m.type)} · ${_esc(m.origin)}</div>
                  </div>
                  <div style="margin-left:auto;flex-shrink:0;">
                    <div style="font-size:1.1rem;font-weight:800;color:${m.risk_score>=90?'#ef4444':m.risk_score>=75?'#f97316':'#f59e0b'};font-family:'JetBrains Mono',monospace;">${m.risk_score}</div>
                    <div style="font-size:.65rem;color:var(--cds-text-muted);text-align:center;">Risk</div>
                  </div>
                </div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                  <span style="font-size:.7rem;padding:1px 6px;border-radius:4px;background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2);">${m.samples.toLocaleString()} samples</span>
                  <span style="font-size:.7rem;padding:1px 6px;border-radius:4px;background:rgba(0,0,0,.2);color:var(--cds-text-muted);">Last: ${m.last_seen}</span>
                </div>
              </div>`).join('')}
            </div>

            <!-- Right: Detail Panel -->
            ${selected ? (() => {
              const m = MALWARE_DB.find(x=>x.id===selected);
              if (!m) return '<div style="padding:40px;text-align:center;color:var(--cds-text-muted);">Not found</div>';
              const riskColor = m.risk_score>=90?'#ef4444':m.risk_score>=75?'#f97316':'#f59e0b';
              return `
              <div style="overflow-y:auto;display:flex;flex-direction:column;gap:14px;">

                <!-- Header -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:16px;">
                  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px;">
                    <div>
                      <div style="font-size:1.25rem;font-weight:800;color:#22c55e;">${_esc(m.family)}</div>
                      <div style="font-size:.8rem;color:var(--cds-text-muted);margin-top:2px;">${_esc(m.type)} · ${_esc(m.attribution)}</div>
                    </div>
                    <div style="text-align:center;background:${riskColor}15;border:1px solid ${riskColor}33;border-radius:8px;padding:8px 14px;">
                      <div style="font-size:1.8rem;font-weight:800;color:${riskColor};font-family:'JetBrains Mono',monospace;">${m.risk_score}</div>
                      <div style="font-size:.7rem;color:var(--cds-text-muted);">RISK SCORE</div>
                    </div>
                  </div>
                  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">First Seen</div><div style="color:var(--cds-text);">${m.first_seen}</div></div>
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">Last Active</div><div style="color:var(--cds-text);">${m.last_seen}</div></div>
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">Samples</div><div style="color:#22c55e;font-weight:700;">${m.samples.toLocaleString()}</div></div>
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">Origin</div><div style="color:var(--cds-text);">${m.origin}</div></div>
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">Code Reuse</div><div style="color:#00d4ff;">${m.code_reuse}%</div></div>
                    <div style="font-size:.78rem;"><div style="color:var(--cds-text-muted);margin-bottom:2px;">Obfuscation</div><div style="color:#f97316;">${_esc(m.obfuscation)}</div></div>
                  </div>
                </div>

                <!-- Hashes -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-fingerprint"></i> File Hashes</div>
                  ${[['SHA-256',m.hash_sha256],['MD5',m.hash_md5],['SHA-1',m.hash_sha1]].map(([t,v])=>`
                    <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--cds-border);">
                      <span style="font-size:.7rem;color:var(--cds-text-muted);min-width:50px;">${t}</span>
                      <code style="font-size:.7rem;color:#00d4ff;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${_esc(v)}</code>
                      <button onclick="navigator.clipboard?.writeText('${_esc(v)}');_toast('Hash copied','success')"
                        style="background:none;border:none;color:var(--cds-text-muted);cursor:pointer;font-size:.75rem;padding:2px 6px;border-radius:4px;">
                        <i class="fas fa-copy"></i>
                      </button>
                    </div>`).join('')}
                </div>

                <!-- Behavior -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-eye" style="color:#ef4444;"></i> Behavior Analysis</div>
                  ${m.behavior.map(b=>`
                    <div style="display:flex;align-items:flex-start;gap:8px;padding:4px 0;font-size:.8rem;color:var(--cds-text-secondary);">
                      <i class="fas fa-caret-right" style="color:#ef4444;margin-top:3px;flex-shrink:0;"></i>${_esc(b)}
                    </div>`).join('')}
                </div>

                <!-- Mutations -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-random" style="color:#f97316;"></i> New Mutations (vs Parent)</div>
                  ${m.mutations.map((mut,i)=>`
                    <div style="display:flex;align-items:flex-start;gap:8px;padding:4px 0;font-size:.8rem;color:var(--cds-text-secondary);border-bottom:1px solid var(--cds-border);">
                      <span style="background:rgba(249,115,22,.15);color:#f97316;font-size:.65rem;padding:1px 5px;border-radius:3px;min-width:16px;text-align:center;flex-shrink:0;">${i+1}</span>
                      ${_esc(mut)}
                    </div>`).join('')}
                </div>

                <!-- MITRE TTPs -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-th" style="color:#3b82f6;"></i> MITRE ATT&CK Techniques</div>
                  <div style="display:flex;flex-wrap:wrap;gap:6px;">
                    ${m.mitre_ttps.map(ttp=>`
                      <a href="https://attack.mitre.org/techniques/${ttp.replace('.','/')}/" target="_blank"
                        style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);padding:3px 8px;border-radius:5px;font-size:.75rem;font-family:'JetBrains Mono',monospace;text-decoration:none;">
                        ${_esc(ttp)}
                      </a>`).join('')}
                  </div>
                </div>

                <!-- Indicators -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-bullseye" style="color:#a855f7;"></i> Indicators of Compromise (IOCs)</div>
                  ${m.indicators.map(ioc=>`
                    <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--cds-border);">
                      <span style="font-size:.65rem;text-transform:uppercase;color:#a855f7;background:rgba(168,85,247,.1);padding:1px 6px;border-radius:3px;min-width:55px;text-align:center;flex-shrink:0;">${_esc(ioc.type)}</span>
                      <code style="font-size:.78rem;color:var(--cds-text);font-family:'JetBrains Mono',monospace;flex:1;word-break:break-all;">${_esc(ioc.value)}</code>
                    </div>`).join('')}
                </div>

                <!-- Evolution Timeline -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:14px;"><i class="fas fa-history" style="color:#22c55e;"></i> Evolution Timeline</div>
                  <div style="display:flex;align-items:flex-end;gap:8px;padding:12px 0;overflow-x:auto;min-height:120px;">
                    ${m.evolution.map((e,i,arr) => `
                      <div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex-shrink:0;min-width:72px;">
                        <div style="font-size:.7rem;color:#22c55e;font-weight:700;">${e.sim}%</div>
                        <div title="${_esc(e.version)}: ${e.samples} samples"
                          style="width:56px;height:${Math.round(e.sim/100*80)+10}px;background:linear-gradient(180deg,rgba(34,197,94,.7),rgba(34,197,94,.2));border:1px solid rgba(34,197,94,.4);border-radius:4px 4px 0 0;cursor:pointer;"
                          onclick="_toast('${_esc(e.version)}: ${e.samples} samples · ${e.year}','info')">
                        </div>
                        <div style="font-size:.7rem;color:var(--cds-text-muted);text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:72px;">${_esc(e.version)}</div>
                        <div style="font-size:.65rem;color:#475569;">${e.year}</div>
                      </div>
                      ${i < arr.length-1 ? '<i class="fas fa-arrow-right" style="color:#334155;font-size:10px;margin-bottom:34px;flex-shrink:0;"></i>' : ''}
                    `).join('')}
                  </div>
                </div>

                <!-- Detection Rules -->
                <div style="background:var(--cds-card);border:1px solid var(--cds-border);border-radius:10px;padding:14px;">
                  <div class="cds-section-title" style="margin-bottom:10px;"><i class="fas fa-shield-alt" style="color:#22c55e;"></i> Detection & Mitigation</div>
                  <div style="font-size:.8rem;color:var(--cds-text-secondary);">
                    <div style="margin-bottom:6px;"><strong style="color:var(--cds-text);">Detection Rules:</strong> ${_esc(m.detection_rules)}</div>
                    <div><strong style="color:var(--cds-text);">Relevant Patches:</strong> ${_esc(m.patches)}</div>
                  </div>
                  <div style="display:flex;gap:8px;margin-top:12px;">
                    <button class="cds-btn cds-btn-sm" style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);"
                      onclick="_toast('Searching VirusTotal for ${_esc(m.hash_sha256.slice(0,16))}…','info')">
                      <i class="fas fa-virus"></i> VirusTotal
                    </button>
                    <button class="cds-btn cds-btn-sm" style="background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.3);"
                      onclick="_toast('Creating IOC watchlist entry for ${_esc(m.family)}','success')">
                      <i class="fas fa-plus"></i> Add to Watchlist
                    </button>
                    <button class="cds-btn cds-btn-sm" style="background:rgba(168,85,247,.15);color:#a855f7;border:1px solid rgba(168,85,247,.3);"
                      onclick="_toast('Exporting ${_esc(m.family)} intelligence report','info')">
                      <i class="fas fa-download"></i> Export Intel
                    </button>
                  </div>
                </div>

              </div>`;
            })() : `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;padding:60px;text-align:center;">
              <i class="fas fa-dna" style="font-size:3rem;color:#22c55e;opacity:.3;margin-bottom:16px;"></i>
              <div style="font-size:1rem;font-weight:600;color:var(--cds-text);margin-bottom:8px;">Select a Malware Sample</div>
              <div style="font-size:.85rem;color:var(--cds-text-muted);">Click any malware family on the left to view full intelligence report including hashes, behavior, MITRE TTPs, IOCs, and evolution timeline.</div>
            </div>`}

          </div>
        </div>
      </div>`;
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
