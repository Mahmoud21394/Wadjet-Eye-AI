/**
 * ETI-AARE Email Threat Intelligence Frontend Module v1.0
 * Premium SOC interface for email threat analysis
 * Features: Investigation workspace, attack graph, behavioral fingerprinting,
 * AI explainability panel, hop-by-hop header view, one-click SOAR response
 */

'use strict';

const ETIModule = (() => {

  // ── State ──────────────────────────────────────────────────────────────────
  const state = {
    currentAnalysis: null,
    analysisHistory: [],
    currentTab: 'overview',
    graphInstance: null,
    analyzing: false,
    stats: { total: 0, critical: 0, high: 0, clean: 0 }
  };

  // ── API Client ─────────────────────────────────────────────────────────────
  const API = {
    base: '/api/email-threat',

    async post(path, body) {
      const token = window._authToken || localStorage.getItem('authToken') || '';
      const res = await fetch(this.base + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(body)
      });
      return res.json();
    },

    async get(path) {
      const token = window._authToken || localStorage.getItem('authToken') || '';
      const res = await fetch(this.base + path, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      return res.json();
    },

    analyzeDemo: (scenario) => API.post('/analyze-demo', { scenario }),
    analyzeEmail: (email, source) => API.post('/analyze', { email, source }),
    getStats: () => API.get('/stats'),
    getAttackGraph: () => API.get('/attack-graph'),
    getIncidents: () => API.get('/incidents'),
    getBlocklists: () => API.get('/blocklists'),
    getBehavioralAlerts: () => API.get('/behavioral-alerts'),
    getCampaigns: () => API.get('/campaigns')
  };

  // ── Initialization ─────────────────────────────────────────────────────────
  function init() {
    if (document.getElementById('etiModule')) return;  // Already initialized
    injectHTML();
    bindEvents();
    loadInitialStats();
  }

  function injectHTML() {
    const html = buildModuleHTML();
    const container = document.getElementById('mainContent') || document.body;
    const wrapper = document.createElement('div');
    wrapper.innerHTML = html;
    container.appendChild(wrapper.firstChild);
  }

  function buildModuleHTML() {
    return `
<div id="etiModule" class="eti-module" role="main">
  <!-- Toast Container -->
  <div class="eti-toast-container" id="etiToastContainer"></div>

  <!-- Analyzing Overlay -->
  <div class="eti-analyzing-overlay" id="etiAnalyzingOverlay">
    <div class="eti-spinner"></div>
    <div style="font-size: 14px; font-weight: 600; color: var(--eti-text-primary);">Analyzing Email Threat...</div>
    <div class="eti-analyzing-steps" id="etiAnalyzingSteps">
      <div class="eti-analyzing-step" data-step="parse"><div class="eti-step-dot"></div>Parsing email structure & headers</div>
      <div class="eti-analyzing-step" data-step="fingerprint"><div class="eti-step-dot"></div>Behavioral identity fingerprinting</div>
      <div class="eti-analyzing-step" data-step="detect"><div class="eti-step-dot"></div>Running threat detection rules (24 rules)</div>
      <div class="eti-analyzing-step" data-step="enrich"><div class="eti-step-dot"></div>Enriching with threat intelligence</div>
      <div class="eti-analyzing-step" data-step="score"><div class="eti-step-dot"></div>Computing risk score</div>
      <div class="eti-analyzing-step" data-step="explain"><div class="eti-step-dot"></div>Generating AI explanation</div>
      <div class="eti-analyzing-step" data-step="soar"><div class="eti-step-dot"></div>Executing SOAR response actions</div>
    </div>
  </div>

  <!-- Header -->
  <header class="eti-header">
    <div class="eti-header-left">
      <div class="eti-logo-badge">
        <i class="fas fa-envelope-open-text eti-logo-icon"></i>
        <div>
          <div class="eti-logo-text">ETI-AARE</div>
          <div class="eti-logo-sub">Email Threat Intelligence v1.0</div>
        </div>
      </div>
    </div>
    <div class="eti-header-stats">
      <div class="eti-header-stat total">
        <div class="eti-header-stat-value" id="etiStatTotal">0</div>
        <div class="eti-header-stat-label">Analyzed</div>
      </div>
      <div class="eti-header-stat critical">
        <div class="eti-header-stat-value" id="etiStatCritical">0</div>
        <div class="eti-header-stat-label">Critical</div>
      </div>
      <div class="eti-header-stat high">
        <div class="eti-header-stat-value" id="etiStatHigh">0</div>
        <div class="eti-header-stat-label">High</div>
      </div>
      <div class="eti-header-stat clean">
        <div class="eti-header-stat-value" id="etiStatClean">0</div>
        <div class="eti-header-stat-label">Clean</div>
      </div>
    </div>
    <div class="eti-header-actions">
      <button class="eti-btn eti-btn-ghost" onclick="ETIModule.openIncidents()">
        <i class="fas fa-ticket-alt"></i> Incidents
      </button>
      <button class="eti-btn eti-btn-ghost" onclick="ETIModule.openBlocklists()">
        <i class="fas fa-ban"></i> Blocklists
      </button>
    </div>
  </header>

  <!-- Main Layout -->
  <div class="eti-layout">
    <!-- LEFT: Ingest Panel -->
    <div class="eti-left-panel">
      <div class="eti-panel-header">
        <div class="eti-panel-title">
          <i class="fas fa-inbox"></i>
          Email Ingest
        </div>
      </div>

      <div class="eti-ingest-tabs">
        <button class="eti-ingest-tab active" data-source="manual">Manual</button>
        <button class="eti-ingest-tab" data-source="m365">M365</button>
        <button class="eti-ingest-tab" data-source="gmail">Gmail</button>
        <button class="eti-ingest-tab" data-source="smtp">SMTP</button>
      </div>

      <div class="eti-upload-zone" id="etiUploadZone">
        <div class="eti-upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>
        <div class="eti-upload-text">Drop .eml or .msg file here</div>
        <div class="eti-upload-sub">or click to browse</div>
        <input type="file" id="etiFileInput" accept=".eml,.msg,.txt" style="display:none">
      </div>

      <div class="eti-demo-scenarios">
        <div class="eti-demo-label">Quick Demo Scenarios</div>
        <div class="eti-demo-grid">
          <button class="eti-demo-btn phishing" onclick="ETIModule.runDemo('phishing')">
            <i class="fas fa-fish"></i> Phishing
          </button>
          <button class="eti-demo-btn bec" onclick="ETIModule.runDemo('bec')">
            <i class="fas fa-user-secret"></i> BEC
          </button>
          <button class="eti-demo-btn malware" onclick="ETIModule.runDemo('malware')">
            <i class="fas fa-bug"></i> Malware
          </button>
          <button class="eti-demo-btn clean" onclick="ETIModule.runDemo('clean')">
            <i class="fas fa-check-circle"></i> Clean
          </button>
        </div>
      </div>

      <!-- Email Queue -->
      <div class="eti-panel-header" style="border-top: 1px solid var(--eti-border);">
        <div class="eti-panel-title">
          <i class="fas fa-list"></i>
          Analysis Queue <span id="etiQueueCount" style="color:var(--eti-text-tertiary); font-weight:400;">(0)</span>
        </div>
      </div>
      <div class="eti-email-queue" id="etiEmailQueue">
        <div style="padding: 20px; text-align: center; color: var(--eti-text-tertiary); font-size: 12px;">
          No emails analyzed yet.<br>Use a demo scenario or upload an email file.
        </div>
      </div>
    </div>

    <!-- CENTER: Analysis Workspace -->
    <div class="eti-center-panel" style="position: relative;">
      <div class="eti-analysis-tabs" id="etiAnalysisTabs">
        <button class="eti-tab-btn active" data-tab="overview"><i class="fas fa-shield-alt"></i> Overview</button>
        <button class="eti-tab-btn" data-tab="evidence"><i class="fas fa-link"></i> Evidence Chain</button>
        <button class="eti-tab-btn" data-tab="headers"><i class="fas fa-route"></i> Header Analysis</button>
        <button class="eti-tab-btn" data-tab="intelligence"><i class="fas fa-database"></i> Threat Intel</button>
        <button class="eti-tab-btn" data-tab="behavioral"><i class="fas fa-fingerprint"></i> Behavioral</button>
        <button class="eti-tab-btn" data-tab="graph"><i class="fas fa-project-diagram"></i> Attack Graph</button>
        <button class="eti-tab-btn" data-tab="narrative"><i class="fas fa-book-open"></i> AI Narrative</button>
      </div>

      <div class="eti-analysis-content" id="etiAnalysisContent">
        <div class="eti-empty-state" id="etiEmptyState">
          <div class="eti-empty-icon"><i class="fas fa-envelope-open-text"></i></div>
          <div class="eti-empty-title">Email Threat Investigation Workspace</div>
          <div class="eti-empty-sub">Submit an email for analysis using the panel on the left. Use demo scenarios to explore the full capabilities of ETI-AARE.</div>
          <button class="eti-btn eti-btn-primary" onclick="ETIModule.runDemo('phishing')">
            <i class="fas fa-play"></i> Try Phishing Demo
          </button>
        </div>
        <div id="etiTabContent" style="display:none;"></div>
      </div>
    </div>

    <!-- RIGHT: Risk + Actions Panel -->
    <div class="eti-right-panel" id="etiRightPanel">
      <div class="eti-risk-panel">
        <div class="eti-risk-panel-title">Risk Score Breakdown</div>
        <div id="etiRiskBreakdown">
          <div style="color: var(--eti-text-tertiary); font-size: 11px; text-align: center; padding: 20px 0;">
            No analysis yet
          </div>
        </div>
      </div>

      <div class="eti-actions-panel" id="etiActionsPanel">
        <div class="eti-actions-title">Response Actions</div>
        <div id="etiResponseActions">
          <div style="color: var(--eti-text-tertiary); font-size: 11px;">Analyze an email to see response options</div>
        </div>
      </div>

      <div class="eti-indicators-panel" id="etiIndicatorsPanel">
        <div class="eti-risk-panel-title">Extracted Indicators</div>
        <div id="etiIndicatorsList">
          <div style="color: var(--eti-text-tertiary); font-size: 11px;">No indicators yet</div>
        </div>
      </div>
    </div>
  </div>
</div>
    `;
  }

  // ── Event Binding ──────────────────────────────────────────────────────────
  function bindEvents() {
    // Tab navigation
    document.addEventListener('click', (e) => {
      const tabBtn = e.target.closest('.eti-tab-btn');
      if (tabBtn && tabBtn.closest('#etiAnalysisTabs')) {
        switchTab(tabBtn.dataset.tab);
      }

      const ingestTab = e.target.closest('.eti-ingest-tab');
      if (ingestTab) {
        document.querySelectorAll('.eti-ingest-tab').forEach(t => t.classList.remove('active'));
        ingestTab.classList.add('active');
      }
    });

    // Section card collapse
    document.addEventListener('click', (e) => {
      const header = e.target.closest('.eti-section-card-header');
      if (header) {
        header.closest('.eti-section-card').classList.toggle('collapsed');
      }
    });

    // Upload zone
    setTimeout(() => {
      const zone = document.getElementById('etiUploadZone');
      const fileInput = document.getElementById('etiFileInput');
      if (!zone || !fileInput) return;

      zone.addEventListener('click', () => fileInput.click());
      zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
      zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
      zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) handleFileUpload(file);
      });
      fileInput.addEventListener('change', (e) => {
        if (e.target.files[0]) handleFileUpload(e.target.files[0]);
      });
    }, 200);
  }

  function switchTab(tab) {
    state.currentTab = tab;
    document.querySelectorAll('.eti-tab-btn').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    if (state.currentAnalysis) {
      renderTabContent(tab, state.currentAnalysis);
    }
  }

  // ── File Upload Handler ────────────────────────────────────────────────────
  async function handleFileUpload(file) {
    const text = await file.text();
    const rawEmail = parseEmlText(text);
    await analyzeEmail(rawEmail, 'upload');
  }

  function parseEmlText(text) {
    const lines = text.split('\n');
    const headers = [];
    let headersDone = false;
    let bodyLines = [];
    let subject = '';

    for (const line of lines) {
      if (!headersDone) {
        if (line.trim() === '') { headersDone = true; continue; }
        const [name, ...rest] = line.split(':');
        if (rest.length > 0) {
          const value = rest.join(':').trim();
          headers.push({ name, value });
          if (name.toLowerCase() === 'subject') subject = value;
        }
      } else {
        bodyLines.push(line);
      }
    }

    return {
      subject,
      internetMessageHeaders: headers,
      body: { contentType: 'text/plain', content: bodyLines.join('\n') }
    };
  }

  // ── Demo Runner ────────────────────────────────────────────────────────────
  async function runDemo(scenario) {
    if (state.analyzing) return;
    showAnalyzing(true);

    try {
      animateAnalyzingSteps();
      const result = await API.analyzeDemo(scenario);
      if (result.success) {
        processAnalysisResult(result.data);
        showToast(`${scenario.toUpperCase()} scenario analyzed`, `Risk: ${result.data.risk.final_score}/100 — ${result.data.risk.tier.toUpperCase()}`,
          result.data.risk.tier === 'critical' || result.data.risk.tier === 'high' ? 'critical' : 'info');
      } else {
        showToast('Analysis Error', result.error || 'Failed to analyze email', 'error');
      }
    } catch (err) {
      showToast('Connection Error', 'Could not reach ETI-AARE API. Is the backend running?', 'error');
      // Load mock data for UI demonstration
      processMockAnalysis(scenario);
    } finally {
      showAnalyzing(false);
    }
  }

  async function analyzeEmail(rawEmail, source) {
    if (state.analyzing) return;
    showAnalyzing(true);

    try {
      animateAnalyzingSteps();
      const result = await API.analyzeEmail(rawEmail, source);
      if (result.success) {
        processAnalysisResult(result.data);
      } else {
        showToast('Analysis Error', result.error || 'Analysis failed', 'error');
      }
    } catch (err) {
      showToast('Connection Error', 'API unavailable', 'error');
    } finally {
      showAnalyzing(false);
    }
  }

  function processAnalysisResult(data) {
    state.currentAnalysis = data;
    state.analysisHistory.unshift(data);

    updateStats(data);
    updateEmailQueue();
    renderAnalysisView(data);
    updateRightPanel(data);

    document.getElementById('etiEmptyState')?.setAttribute('style', 'display:none');
    document.getElementById('etiTabContent')?.removeAttribute('style');
  }

  // ── Mock data for offline demo ─────────────────────────────────────────────
  function processMockAnalysis(scenario) {
    const mockData = generateMockData(scenario);
    processAnalysisResult(mockData);
  }

  function generateMockData(scenario) {
    const scenarios = {
      phishing: {
        analysis_id: 'ETI-DEMO-PHISH',
        email: {
          message_id: '<demo@phish.example>',
          from: 'admin@m1cr0soft-security.tk',
          from_display: 'Microsoft Security Team',
          subject: 'URGENT: Your Microsoft 365 Account Will Be Suspended',
          received_at: new Date().toISOString(),
          auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail' },
          routing_hops: 3,
          attachment_count: 0,
          url_count: 2,
          indicators: { ips: ['185.234.219.123'], domains: ['m1cr0soft-security.tk', 'm1cr0s0ft.xyz'], urls: ['http://m1cr0s0ft.xyz/verify'], hashes: [], emails: [] }
        },
        detection: {
          rules_triggered: [
            { rule_id: 'ETI-AUTH-001', name: 'Complete Authentication Failure (SPF+DKIM+DMARC)', severity: 'critical', confidence: 85, mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
            { rule_id: 'ETI-SPOOF-001', name: 'Display Name Impersonation', severity: 'high', confidence: 80, mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
            { rule_id: 'ETI-PHISH-002', name: 'Homograph/Lookalike Domain Attack', severity: 'critical', confidence: 90, mitre: { technique: 'T1036', sub: 'T1036.005', name: 'Masquerading', tactic: 'Defense Evasion' } },
            { rule_id: 'ETI-PHISH-003', name: 'Mass Phishing Indicators', severity: 'high', confidence: 70, mitre: { technique: 'T1566', name: 'Phishing', tactic: 'Initial Access' } },
            { rule_id: 'ETI-URL-004', name: 'Lookalike Domain in URL', severity: 'critical', confidence: 90, mitre: { technique: 'T1056', name: 'Input Capture', tactic: 'Collection' } }
          ],
          ai_classification: { threat_type: 'phishing', confidence: 92, intent: 'Credential harvesting via Microsoft 365 impersonation', tone_analysis: { urgency: 85, fear_inducement: 70, manipulation_score: 82 }, explanation: 'High-confidence phishing attack using Microsoft impersonation with authentication failures and lookalike domain.' },
          bec_analysis: { is_bec: false, intents_detected: [], confidence: 0 },
          mitre_techniques: [
            { technique_id: 'T1566', sub_technique_id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'Initial Access', confidence: 90 },
            { technique_id: 'T1036', sub_technique_id: 'T1036.005', name: 'Masquerading', tactic: 'Defense Evasion', confidence: 90 },
            { technique_id: 'T1056', sub_technique_id: 'T1056.003', name: 'Input Capture: Web Portal Capture', tactic: 'Collection', confidence: 80 }
          ],
          final_verdict: { threat_level: 'critical', primary_type: 'phishing', confidence: 95, recommended_action: 'quarantine_and_block' }
        },
        risk: {
          final_score: 97, tier: 'critical', color: '#FF2D55', recommended_action: 'quarantine_and_block',
          sla_minutes: 15, confidence: 95, amplifier: 1.3,
          breakdown: {
            auth: { score: 28, details: { spf: 'fail', dkim: 'fail', dmarc: 'fail' }, label: 'Authentication Failures' },
            rules: { score: 45, by_severity: { critical: 3, high: 2, medium: 0, low: 0 }, total_rules: 5, label: 'Rule Detections' },
            ai: { score: 32, ai_confidence: 92, threat_type: 'phishing', label: 'AI Classification' },
            sender: { score: 20, anomaly_count: 2, label: 'Sender Anomalies' },
            social_eng: { score: 25, urgency_score: 85, flag_count: 3, label: 'Social Engineering' },
            urls: { score: 25, url_count: 2, suspicious_count: 2, label: 'URL Analysis' },
            routing: { score: 5, suspicious_hops: 1, label: 'Email Routing' },
            threat_intel: { score: 0, malicious_count: 0, label: 'Threat Intelligence' },
            attachments: { score: 0, attachment_count: 0, label: 'Attachments' },
            amplifier: { factor: 1.3, applied: ['multiple_indicators', 'auth_all_fail'] }
          }
        },
        explanation: {
          summary: {
            headline: 'CRITICAL RISK: Detected phishing attack designed to steal credentials or deliver malware',
            risk_level: 'critical',
            risk_score: 97,
            threat_type: 'phishing',
            in_one_sentence: 'This email from admin@m1cr0soft-security.tk exhibits definitive indicators of a phishing attack with a risk score of 97/100.',
            key_facts: [
              'Sender domain failed SPF authentication (email may be spoofed)',
              'Email signature invalid — DKIM verification failed',
              'DMARC policy failure — domain owner does not authorize this sender',
              'Display name impersonates a trusted brand but actual sending domain is different',
              'Critical rule triggered: Complete Authentication Failure (SPF+DKIM+DMARC)',
              'Lookalike domain detected impersonating a trusted brand'
            ]
          },
          evidence_chain: [
            { step: 1, category: 'Email Authentication', icon: 'shield-alt', verdict: 'fail', evidence: ['SPF Result: FAIL — Sending server is NOT authorized — strong spoofing indicator', 'DKIM Result: FAIL — Signature verification FAILED — email was modified or is spoofed', 'DMARC Result: FAIL — DMARC FAILED — neither SPF nor DKIM align with From domain'], risk_contribution: 'CRITICAL' },
            { step: 2, category: 'Sender Identity Analysis', icon: 'user-circle', verdict: 'suspicious', evidence: ['Display name "microsoft" doesn\'t match sending domain — impersonation technique', 'Reply-To hijack: Responses would go to account-recovery-help.ml instead of m1cr0soft-security.tk'], risk_contribution: 'HIGH' },
            { step: 3, category: 'Routing Analysis', icon: 'route', verdict: 'suspicious', evidence: ['Email traversed 3 relay servers', 'Suspicious hop: unknown (185.234.219.123)'], risk_contribution: 'LOW' },
            { step: 4, category: 'Content & Intent Analysis', icon: 'document-text', verdict: 'malicious', evidence: ['Urgency manipulation: urgent, immediately, suspended', 'Credential harvesting language: click here, sign in, verify your', 'Fear tactics: suspended, unusual activity, account locked'], risk_contribution: 'HIGH' },
            { step: 5, category: 'URL & Domain Analysis', icon: 'link', verdict: 'malicious', evidence: ['2 URLs found in email', 'Suspicious URL: http://m1cr0s0ft.xyz/verify — Techniques: ip_url, redirect_service'], risk_contribution: 'CRITICAL' }
          ],
          attack_narrative: `ATTACK NARRATIVE: This appears to be a link-based phishing campaign.

The attacker sent an email from admin@m1cr0soft-security.tk (domain: m1cr0soft-security.tk), which failed SPF authentication indicating a spoofed sender. The display name was crafted to impersonate "Microsoft Security Team" while using a malicious domain.

The email contains 2 URL(s) designed to redirect victims to malicious sites. At least one URL uses a lookalike domain (m1cr0s0ft.xyz) to trick users into believing they are visiting a legitimate Microsoft site.

The social engineering techniques employed (urgency, credential_harvesting, fear_tactics) are designed to pressure the victim into taking action without careful consideration.`,
          why_flagged: [
            { priority: 1, reason: 'Critical threat detection rules triggered', detail: ['ETI-AUTH-001: Complete Authentication Failure', 'ETI-PHISH-002: Homograph/Lookalike Domain', 'ETI-URL-004: Lookalike Domain in URL'] },
            { priority: 2, reason: 'Email authentication failures', detail: ['SPF: fail', 'DKIM: fail', 'DMARC: fail'] },
            { priority: 3, reason: 'AI classification: phishing (92% confidence)', detail: ['High-confidence phishing attack using Microsoft impersonation'] }
          ],
          analyst_notes: [
            { type: 'action', note: 'IMMEDIATE ACTION REQUIRED: Quarantine email and notify affected user(s)' },
            { type: 'investigation', note: 'Submit suspicious URLs to URLScan.io: http://m1cr0s0ft.xyz/verify' },
            { type: 'investigation', note: 'Investigate originating IP 185.234.219.123 in threat intelligence platforms' },
            { type: 'context', note: 'Email received at ' + new Date().toISOString() + ', message ID: <demo@phish.example>' }
          ],
          false_positive_assessment: { fp_probability: 5, assessment: 'Very likely a real threat', factors_suggesting_fp: ['No attachments'], factors_against_fp: ['SPF hard fail strongly indicates spoofing', 'Critical detection rules fired', 'Lookalike domain confirmed'] },
          mitre_explanation: [
            { technique_id: 'T1566', sub_technique_id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'Initial Access', confidence: 90, explanation: 'Phishing link: Email contains malicious URL redirecting to phishing site' },
            { technique_id: 'T1036', sub_technique_id: 'T1036.005', name: 'Masquerading', tactic: 'Defense Evasion', confidence: 90, explanation: 'Masquerading — using lookalike domain/filename to appear legitimate' }
          ]
        },
        behavioral: { is_new: true, profile_established: true, drift_score: 0, alerts: [] },
        attack_graph: { email_node_id: 'email_demo_001', connected_nodes: [], campaign_id: null },
        response: {
          triggered_playbooks: [{ id: 'PB-PHISH-CRIT', name: 'Critical Phishing Response' }],
          executed_actions: [
            { type: 'quarantine_email', status: 'executed', auto_executed: true },
            { type: 'block_sender', status: 'executed', auto_executed: true },
            { type: 'notify_soc', status: 'executed', auto_executed: true },
            { type: 'create_incident', status: 'executed', auto_executed: true }
          ],
          pending_actions: [{ type: 'scan_mailbox', status: 'awaiting_approval', requires_approval: true }],
          incident: {
            incident_id: 'INC-ETI-DEMO001',
            title: '[PHISHING] Suspicious email from admin@m1cr0soft-security.tk',
            severity: 'CRITICAL',
            status: 'open'
          }
        },
        processing_time_ms: 847
      }
    };

    // BEC scenario
    scenarios.bec = {
      ...scenarios.phishing,
      analysis_id: 'ETI-DEMO-BEC',
      email: {
        ...scenarios.phishing.email,
        from: 'ceo.johnson@company-corp.com',
        from_display: 'Robert Johnson (CEO)',
        subject: 'Urgent Wire Transfer Request',
        indicators: { ips: [], domains: ['gmail.com', 'company-corp.com'], urls: [], hashes: [], emails: ['rjohnson.ceo2024@gmail.com'] }
      },
      detection: {
        ...scenarios.phishing.detection,
        rules_triggered: [
          { rule_id: 'ETI-SPOOF-002', name: 'Reply-To Domain Mismatch (BEC Indicator)', severity: 'high', confidence: 85 },
          { rule_id: 'ETI-SPOOF-003', name: 'Executive Impersonation BEC', severity: 'critical', confidence: 80 },
          { rule_id: 'ETI-BEC-001', name: 'Wire Transfer Request BEC', severity: 'critical', confidence: 85 },
          { rule_id: 'ETI-BEC-002', name: 'Gift Card Purchase Request', severity: 'high', confidence: 90 }
        ],
        bec_analysis: { is_bec: true, intents_detected: ['financial_fraud'], confidence: 85 },
        ai_classification: { threat_type: 'bec', confidence: 88, intent: 'Executive impersonation for wire transfer fraud' },
        final_verdict: { threat_level: 'critical', primary_type: 'bec', confidence: 92, recommended_action: 'quarantine_and_block' }
      },
      risk: { ...scenarios.phishing.risk, final_score: 91, tier: 'critical' }
    };

    scenarios.clean = {
      ...scenarios.phishing,
      analysis_id: 'ETI-DEMO-CLEAN',
      email: {
        message_id: '<report@company.com>',
        from: 'reports@company.com',
        from_display: 'Reports System',
        subject: 'Q3 Sales Report - Internal Distribution',
        received_at: new Date().toISOString(),
        auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
        routing_hops: 2, attachment_count: 0, url_count: 0,
        indicators: { ips: [], domains: ['company.com'], urls: [], hashes: [], emails: [] }
      },
      detection: {
        rules_triggered: [],
        ai_classification: { threat_type: 'legitimate', confidence: 95 },
        bec_analysis: { is_bec: false, confidence: 0 },
        mitre_techniques: [],
        final_verdict: { threat_level: 'clean', primary_type: 'legitimate', confidence: 95, recommended_action: 'allow' }
      },
      risk: {
        final_score: 2, tier: 'clean', color: '#636366', recommended_action: 'allow', confidence: 95,
        breakdown: { auth: { score: 0 }, rules: { score: 0, total_rules: 0 }, ai: { score: 0 } }
      },
      explanation: {
        summary: {
          headline: 'CLEAN: Email authenticated and analyzed — no threats detected',
          risk_level: 'clean', risk_score: 2, threat_type: 'legitimate',
          in_one_sentence: 'This email from reports@company.com passed all authentication checks and contains no threat indicators.',
          key_facts: ['SPF passed — sender is authorized', 'DKIM passed — integrity verified', 'DMARC passed — domain policy compliant']
        },
        why_flagged: [],
        analyst_notes: [],
        evidence_chain: [],
        false_positive_assessment: { fp_probability: 98, assessment: 'Likely legitimate email' }
      }
    };

    return scenarios[scenario] || scenarios.phishing;
  }

  // ── Render Functions ───────────────────────────────────────────────────────
  function renderAnalysisView(data) {
    renderTabContent(state.currentTab, data);
  }

  function renderTabContent(tab, data) {
    const container = document.getElementById('etiTabContent');
    if (!container || !data) return;

    const renderers = {
      overview: () => renderOverview(data),
      evidence: () => renderEvidenceChain(data),
      headers: () => renderHeaderAnalysis(data),
      intelligence: () => renderThreatIntel(data),
      behavioral: () => renderBehavioral(data),
      graph: () => renderAttackGraph(data),
      narrative: () => renderNarrative(data)
    };

    container.innerHTML = (renderers[tab] || renderers.overview)();
    container.style.display = '';
  }

  function renderOverview(data) {
    const risk = data.risk;
    const detection = data.detection;
    const tier = risk.tier;
    const score = risk.final_score;

    const circumference = 2 * Math.PI * 30;
    const offset = circumference - (score / 100) * circumference;
    const tierColors = { critical: '#FF2D55', high: '#FF6B35', medium: '#FFD60A', low: '#30D158', clean: '#636366' };
    const color = tierColors[tier] || '#636366';

    const mitreChips = (detection.mitre_techniques || []).map(t => `
      <div class="eti-mitre-chip" title="${t.explanation || ''}">
        <span class="eti-mitre-id">${t.sub_technique_id || t.technique_id}</span>
        <span class="eti-mitre-name">${t.name}</span>
        <span class="eti-mitre-tactic">${t.tactic}</span>
        <span class="eti-mitre-conf">${t.confidence}%</span>
      </div>`).join('');

    const rules = (detection.rules_triggered || []).map(r => `
      <div class="eti-rule-item">
        <span class="eti-rule-id">${r.rule_id}</span>
        <span class="eti-rule-name">${r.name}</span>
        <span class="eti-rule-sev ${r.severity}">${r.severity}</span>
        <span class="eti-rule-conf">${r.confidence}%</span>
      </div>`).join('');

    const keyFacts = (data.explanation?.summary?.key_facts || []).map(f =>
      `<div class="eti-evidence-item"><i class="fas fa-exclamation-triangle" style="color:var(--eti-medium);margin-right:6px;font-size:10px;"></i>${f}</div>`
    ).join('');

    return `
      <div class="eti-animate-in">
        <!-- Verdict Card -->
        <div class="eti-verdict-card ${tier}">
          <div class="eti-verdict-score-ring">
            <svg width="80" height="80" viewBox="0 0 80 80">
              <circle class="track" cx="40" cy="40" r="30"/>
              <circle class="fill" cx="40" cy="40" r="30"
                stroke="${color}"
                stroke-dasharray="${circumference}"
                stroke-dashoffset="${offset}"/>
            </svg>
            <div class="eti-verdict-score-center">
              <div class="eti-verdict-score-num" style="color:${color}">${score}</div>
              <div class="eti-verdict-score-max">/100</div>
            </div>
          </div>
          <div class="eti-verdict-info">
            <div class="eti-verdict-type">${detection.final_verdict?.primary_type?.replace(/_/g,'  ')}</div>
            <div class="eti-verdict-headline">${data.explanation?.summary?.headline || tier.toUpperCase() + ' THREAT DETECTED'}</div>
            <div class="eti-verdict-sentence">${data.explanation?.summary?.in_one_sentence || ''}</div>
          </div>
          <div class="eti-verdict-action">
            <div class="eti-action-badge" style="color:${color};">${risk.recommended_action?.replace(/_/g,' ')}</div>
            <div class="eti-verdict-confidence">Confidence: ${risk.confidence}%</div>
            ${risk.sla_minutes ? `<div style="font-size:10px;color:var(--eti-text-tertiary);">SLA: ${risk.sla_minutes}min</div>` : ''}
          </div>
        </div>

        <!-- MITRE Techniques -->
        ${mitreChips ? `<div class="eti-mitre-bar"><div class="eti-mitre-label">MITRE ATT&CK Techniques</div>${mitreChips}</div>` : ''}

        <!-- Key Facts -->
        ${keyFacts ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-exclamation-circle"></i> Key Findings</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">${keyFacts}</div>
          </div>` : ''}

        <!-- Detection Rules -->
        ${rules ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-shield-virus"></i> Detection Rules (${detection.rules_triggered?.length || 0})</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              <div class="eti-rules-list">${rules}</div>
            </div>
          </div>` : '<div style="color:var(--eti-low);padding:16px;text-align:center;"><i class="fas fa-check-circle"></i> No threat rules triggered</div>'}

        <!-- AI Analysis -->
        ${data.detection.ai_classification ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-robot"></i> AI Analysis</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              <div class="eti-confidence-breakdown">
                <div class="eti-conf-item">
                  <div class="eti-conf-label">Threat Type</div>
                  <div class="eti-conf-value" style="font-size:14px;color:var(--eti-accent-blue)">${data.detection.ai_classification.threat_type}</div>
                </div>
                <div class="eti-conf-item">
                  <div class="eti-conf-label">AI Confidence</div>
                  <div class="eti-conf-value" style="color:var(--eti-medium)">${data.detection.ai_classification.confidence}%</div>
                  <div class="eti-conf-bar"><div class="eti-conf-bar-fill" style="width:${data.detection.ai_classification.confidence}%"></div></div>
                </div>
                ${data.detection.ai_classification.tone_analysis ? `
                <div class="eti-conf-item">
                  <div class="eti-conf-label">Urgency Score</div>
                  <div class="eti-conf-value" style="color:var(--eti-high)">${data.detection.ai_classification.tone_analysis.urgency || 0}</div>
                </div>
                <div class="eti-conf-item">
                  <div class="eti-conf-label">Manipulation</div>
                  <div class="eti-conf-value" style="color:var(--eti-critical)">${data.detection.ai_classification.tone_analysis.manipulation_score || 0}</div>
                </div>` : ''}
              </div>
              ${data.detection.ai_classification.explanation ? `<div class="eti-narrative" style="margin-top:10px;">${data.detection.ai_classification.explanation}</div>` : ''}
            </div>
          </div>` : ''}

        <!-- SOAR Response -->
        ${data.response ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-bolt"></i> SOAR Response</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              ${(data.response.triggered_playbooks || []).map(pb => `
                <div style="margin-bottom:8px;padding:8px 10px;background:rgba(0,122,255,0.07);border-radius:6px;border:1px solid rgba(0,122,255,0.2);">
                  <div style="font-size:11px;font-weight:600;color:var(--eti-accent-blue)">Playbook: ${pb.name}</div>
                </div>`).join('')}
              ${(data.response.executed_actions || []).map(a => `
                <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--eti-border);">
                  <i class="fas fa-check-circle" style="color:var(--eti-low);font-size:12px;"></i>
                  <span style="font-size:11px;color:var(--eti-text-secondary);flex:1;">${a.type.replace(/_/g,' ')}</span>
                  <span style="font-size:10px;color:var(--eti-low)">AUTO</span>
                </div>`).join('')}
              ${(data.response.pending_actions || []).map(a => `
                <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--eti-border);">
                  <i class="fas fa-clock" style="color:var(--eti-medium);font-size:12px;"></i>
                  <span style="font-size:11px;color:var(--eti-text-secondary);flex:1;">${a.type.replace(/_/g,' ')}</span>
                  <span style="font-size:10px;color:var(--eti-medium)">PENDING</span>
                </div>`).join('')}
              ${data.response.incident ? `<div style="margin-top:8px;padding:8px;background:rgba(255,45,85,0.07);border-radius:6px;border:1px solid rgba(255,45,85,0.2);font-size:11px;color:var(--eti-text-secondary);">
                <i class="fas fa-ticket-alt" style="color:var(--eti-critical);margin-right:5px;"></i>
                Incident created: ${data.response.incident.incident_id} (${data.response.incident.severity})
              </div>` : ''}
            </div>
          </div>` : ''}
      </div>
    `;
  }

  function renderEvidenceChain(data) {
    const chain = data.explanation?.evidence_chain || [];
    if (!chain.length) return '<div class="eti-empty-state"><div>No evidence chain available</div></div>';

    const verdictIcons = { pass: 'check', fail: 'times', suspicious: 'exclamation', malicious: 'skull', clean: 'check' };

    const steps = chain.map(step => `
      <div class="eti-evidence-step verdict-${step.verdict}">
        <div class="eti-evidence-step-icon"><i class="fas fa-${verdictIcons[step.verdict] || 'question'}"></i></div>
        <div class="eti-evidence-step-content">
          <div class="eti-evidence-step-header">
            <div class="eti-evidence-step-cat">Step ${step.step}: ${step.category}</div>
            <div class="eti-evidence-risk-pill ${step.risk_contribution}">${step.risk_contribution}</div>
          </div>
          <div class="eti-evidence-items">
            ${(step.evidence || []).map(e => `<div class="eti-evidence-item">${e}</div>`).join('')}
          </div>
        </div>
      </div>`).join('');

    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-link"></i> Evidence Chain Analysis</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-evidence-chain">${steps}</div>
          </div>
        </div>

        ${data.explanation?.why_flagged?.length ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-question-circle"></i> Why Was This Flagged?</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              ${data.explanation.why_flagged.map(r => `
                <div style="margin-bottom:10px;">
                  <div style="font-size:12px;font-weight:600;color:var(--eti-text-primary);margin-bottom:5px;">${r.priority}. ${r.reason}</div>
                  ${(r.detail || []).map(d => `<div class="eti-evidence-item">${d}</div>`).join('')}
                </div>`).join('')}
            </div>
          </div>` : ''}

        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-balance-scale"></i> False Positive Assessment</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div style="font-size:12px;color:var(--eti-text-secondary);margin-bottom:10px;">${data.explanation?.false_positive_assessment?.assessment || 'N/A'}</div>
            <div class="eti-fp-meter">
              <div class="eti-fp-label">False Positive Probability</div>
              <div class="eti-fp-track"><div class="eti-fp-fill" style="width:${data.explanation?.false_positive_assessment?.fp_probability || 0}%"></div></div>
              <div class="eti-fp-pct">${data.explanation?.false_positive_assessment?.fp_probability || 0}%</div>
            </div>
          </div>
        </div>
      </div>`;
  }

  function renderHeaderAnalysis(data) {
    const hops = (data.explanation?.evidence_chain?.find(s => s.category === 'Routing Analysis')?.evidence || []);
    const auth = data.email?.auth || {};
    const routing = { hops: 0, suspicious_hops: 0 };

    const authBadge = (result, label) => {
      const color = result === 'pass' ? 'var(--eti-low)' : result === 'fail' ? 'var(--eti-critical)' : 'var(--eti-medium)';
      return `<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--eti-border);margin-bottom:4px;">
        <span style="font-size:12px;color:var(--eti-text-secondary);font-weight:600;">${label}</span>
        <span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:4px;background:rgba(255,255,255,0.07);color:${color}">${(result || 'none').toUpperCase()}</span>
      </div>`;
    };

    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-shield-alt"></i> Email Authentication Results</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            ${authBadge(auth.spf, '🔐 SPF (Sender Policy Framework)')}
            ${authBadge(auth.dkim, '✏️ DKIM (DomainKeys Identified Mail)')}
            ${authBadge(auth.dmarc, '📋 DMARC (Domain-based Auth, Reporting & Conformance)')}
          </div>
        </div>

        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-route"></i> Routing Hop-by-Hop Analysis</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-hop-chain">
              ${hops.length > 0 ? hops.map((hop, i) => `
                <div class="eti-hop-item ${hop.toLowerCase().includes('suspicious') ? 'suspicious' : ''}">
                  <div class="eti-hop-num">${i+1}</div>
                  <div class="eti-hop-info">
                    <div class="eti-hop-hostname">${hop.replace(/^Suspicious hop: /, '')}</div>
                  </div>
                  ${hop.toLowerCase().includes('suspicious') ? '<div class="eti-hop-flag">SUSPICIOUS</div>' : ''}
                </div>`).join('') :
              `<div style="color:var(--eti-text-tertiary);font-size:12px;padding:10px;">Routing data from evidence chain analysis</div>`}
            </div>
          </div>
        </div>

        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-user"></i> Sender Analysis</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
              <div style="padding:8px;background:rgba(255,255,255,0.03);border-radius:6px;">
                <div style="font-size:10px;color:var(--eti-text-tertiary);margin-bottom:3px;">From Address</div>
                <div style="font-size:11px;font-family:monospace;color:var(--eti-accent-cyan)">${data.email?.from || 'N/A'}</div>
              </div>
              <div style="padding:8px;background:rgba(255,255,255,0.03);border-radius:6px;">
                <div style="font-size:10px;color:var(--eti-text-tertiary);margin-bottom:3px;">Display Name</div>
                <div style="font-size:11px;color:var(--eti-text-secondary)">${data.email?.from_display || 'N/A'}</div>
              </div>
            </div>
          </div>
        </div>
      </div>`;
  }

  function renderThreatIntel(data) {
    const enrichment = data.enrichment || {};
    const summary = enrichment.summary || {};
    const ctx = enrichment.threat_context || [];

    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-database"></i> Intelligence Summary</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:8px;margin-bottom:12px;">
              ${[
                { label: 'Malicious IPs', val: summary.malicious_ips || 0, color: 'critical' },
                { label: 'Bad Domains', val: summary.malicious_domains || 0, color: 'high' },
                { label: 'Bad URLs', val: summary.malicious_urls || 0, color: 'high' },
                { label: 'Known Malware', val: summary.malicious_hashes || 0, color: 'critical' }
              ].map(s => `
                <div style="padding:10px;background:rgba(255,255,255,0.03);border-radius:6px;text-align:center;border:1px solid var(--eti-border);">
                  <div style="font-size:22px;font-weight:800;color:var(--eti-${s.color})">${s.val}</div>
                  <div style="font-size:10px;color:var(--eti-text-tertiary)">${s.label}</div>
                </div>`).join('')}
            </div>
            ${ctx.length ? `
              <div style="font-size:11px;font-weight:600;color:var(--eti-text-secondary);margin-bottom:6px;">Threat Context Hits</div>
              ${ctx.map(c => `
                <div style="display:flex;gap:10px;align-items:center;padding:6px 10px;background:rgba(255,45,85,0.07);border:1px solid rgba(255,45,85,0.2);border-radius:6px;margin-bottom:4px;">
                  <i class="fas fa-radiation" style="color:var(--eti-critical);font-size:12px;"></i>
                  <span style="flex:1;font-size:11px;color:var(--eti-text-secondary);">${c.type.replace(/_/g,' ').toUpperCase()}: ${c.indicator}</span>
                  <span style="font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;background:rgba(255,45,85,0.2);color:var(--eti-critical)">${c.severity}</span>
                </div>`).join('')}
            ` : `<div style="color:var(--eti-text-tertiary);font-size:12px;text-align:center;padding:20px;">No threat intelligence matches found${!data.enrichment ? ' (Intel APIs not configured)' : ''}</div>`}
          </div>
        </div>
      </div>`;
  }

  function renderBehavioral(data) {
    const beh = data.behavioral || {};
    const driftDims = beh.drift_dimensions || {};
    const alerts = beh.alerts || [];

    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-fingerprint"></i> Behavioral Identity Fingerprinting</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            ${beh.is_new ? `
              <div style="padding:12px;background:rgba(0,122,255,0.07);border:1px solid rgba(0,122,255,0.2);border-radius:6px;font-size:12px;color:var(--eti-accent-blue);">
                <i class="fas fa-user-plus" style="margin-right:6px;"></i>
                New sender profile established. Future emails from this sender will be compared against this behavioral baseline.
              </div>` : `
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;padding:10px 12px;background:rgba(255,255,255,0.03);border-radius:6px;border:1px solid var(--eti-border);">
                <div style="flex:1;">
                  <div style="font-size:12px;color:var(--eti-text-secondary);">Overall Behavioral Drift</div>
                </div>
                <div style="font-size:20px;font-weight:800;color:${beh.drift_score > 0.6 ? 'var(--eti-critical)' : beh.drift_score > 0.3 ? 'var(--eti-medium)' : 'var(--eti-low)'}">
                  ${Math.round((beh.drift_score || 0) * 100)}%
                </div>
                <div style="font-size:11px;padding:3px 8px;border-radius:4px;background:rgba(255,255,255,0.07);color:var(--eti-text-tertiary);">
                  ${beh.anomaly_detected ? '⚠️ ANOMALY' : '✓ NORMAL'}
                </div>
              </div>
              <div class="eti-behavioral-drift">
                ${Object.entries(driftDims).filter(([,d]) => d.drift > 0).map(([dim, d]) => `
                  <div class="eti-drift-item ${d.drift > 0.5 ? 'alert' : ''}">
                    <div class="eti-drift-dim">${dim.replace(/_/g,' ')}</div>
                    <div class="eti-drift-bar"><div class="eti-drift-bar-fill" style="width:${Math.round(d.drift*100)}%;background:${d.drift > 0.7 ? 'var(--eti-critical)' : d.drift > 0.4 ? 'var(--eti-high)' : 'var(--eti-medium)'};"></div></div>
                    <div class="eti-drift-score" style="color:${d.drift > 0.7 ? 'var(--eti-critical)' : 'var(--eti-text-secondary)'};">${Math.round(d.drift*100)}%</div>
                  </div>`).join('') || '<div style="color:var(--eti-low);font-size:12px;"><i class="fas fa-check-circle"></i> No behavioral drift detected</div>'}
              </div>`}

            ${alerts.length ? `
              <div style="margin-top:12px;">
                <div style="font-size:11px;font-weight:600;color:var(--eti-critical);margin-bottom:6px;"><i class="fas fa-exclamation-triangle"></i> Behavioral Alerts</div>
                ${alerts.map(a => `
                  <div style="padding:8px 12px;background:rgba(255,45,85,0.08);border:1px solid rgba(255,45,85,0.3);border-radius:6px;font-size:11px;color:var(--eti-text-secondary);margin-bottom:4px;">
                    <strong style="color:var(--eti-critical)">${a.type.replace(/_/g,' ').toUpperCase()}</strong>: ${a.message}
                  </div>`).join('')}
              </div>` : ''}
          </div>
        </div>
      </div>`;
  }

  function renderAttackGraph(data) {
    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-project-diagram"></i> Email Attack Graph</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-graph-container">
              <canvas class="eti-graph-canvas" id="etiGraphCanvas"></canvas>
              <div class="eti-graph-legend">
                <div class="eti-graph-legend-item"><div class="eti-graph-legend-dot" style="background:#007AFF"></div> Email</div>
                <div class="eti-graph-legend-item"><div class="eti-graph-legend-dot" style="background:#FF3B30"></div> Malicious IP</div>
                <div class="eti-graph-legend-item"><div class="eti-graph-legend-dot" style="background:#FF9500"></div> Suspicious Domain</div>
                <div class="eti-graph-legend-item"><div class="eti-graph-legend-dot" style="background:#FF2D55"></div> Malware Hash</div>
                <div class="eti-graph-legend-item"><div class="eti-graph-legend-dot" style="background:#FFD60A"></div> Sender</div>
              </div>
            </div>
          </div>
        </div>
        <div id="etiCampaignsSection"></div>
      </div>`;
  }

  function renderNarrative(data) {
    const narrative = data.explanation?.attack_narrative || 'No narrative generated.';
    const notes = data.explanation?.analyst_notes || [];
    const mitre = data.explanation?.mitre_explanation || [];

    const noteIcons = { action: 'fa-exclamation-triangle', warning: 'fa-exclamation-circle', investigation: 'fa-search', context: 'fa-info-circle' };

    return `
      <div class="eti-animate-in">
        <div class="eti-section-card">
          <div class="eti-section-card-header">
            <div class="eti-section-card-title"><i class="fas fa-book-open"></i> AI-Generated Attack Narrative</div>
            <i class="fas fa-chevron-down eti-section-card-chevron"></i>
          </div>
          <div class="eti-section-card-body">
            <div class="eti-narrative">${narrative}</div>
          </div>
        </div>

        ${notes.length ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-clipboard-list"></i> Analyst Notes</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              <div class="eti-analyst-notes">
                ${notes.map(n => `
                  <div class="eti-analyst-note ${n.type}">
                    <i class="fas ${noteIcons[n.type] || 'fa-info'} eti-analyst-note-icon"></i>
                    ${n.note}
                  </div>`).join('')}
              </div>
            </div>
          </div>` : ''}

        ${mitre.length ? `
          <div class="eti-section-card">
            <div class="eti-section-card-header">
              <div class="eti-section-card-title"><i class="fas fa-shield-virus"></i> MITRE ATT&CK Explanation</div>
              <i class="fas fa-chevron-down eti-section-card-chevron"></i>
            </div>
            <div class="eti-section-card-body">
              ${mitre.map(t => `
                <div style="margin-bottom:12px;padding:10px 12px;background:rgba(191,90,242,0.07);border:1px solid rgba(191,90,242,0.2);border-radius:6px;">
                  <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px;">
                    <span style="font-size:12px;font-weight:700;font-family:monospace;color:#BF5AF2">${t.sub_technique_id || t.technique_id}</span>
                    <span style="font-size:11px;font-weight:600;color:var(--eti-text-primary)">${t.name}</span>
                    <span style="font-size:10px;color:var(--eti-text-tertiary);margin-left:auto">${t.tactic} · ${t.confidence}%</span>
                  </div>
                  <div style="font-size:11px;color:var(--eti-text-secondary)">${t.explanation}</div>
                </div>`).join('')}
            </div>
          </div>` : ''}
      </div>`;
  }

  // ── Right Panel Updates ────────────────────────────────────────────────────
  function updateRightPanel(data) {
    updateRiskBreakdown(data.risk);
    updateResponseActions(data);
    updateIndicators(data);
  }

  function updateRiskBreakdown(risk) {
    const container = document.getElementById('etiRiskBreakdown');
    if (!container) return;
    const bd = risk.breakdown || {};
    const dimensions = [
      { label: 'Authentication', score: bd.auth?.score || 0, max: 30 },
      { label: 'Detection Rules', score: bd.rules?.score || 0, max: 55 },
      { label: 'AI Analysis', score: bd.ai?.score || 0, max: 35 },
      { label: 'Threat Intel', score: bd.threat_intel?.score || 0, max: 60 },
      { label: 'Sender Anomalies', score: bd.sender?.score || 0, max: 30 },
      { label: 'Social Engineering', score: bd.social_eng?.score || 0, max: 35 },
      { label: 'Attachments', score: bd.attachments?.score || 0, max: 50 },
      { label: 'URLs', score: bd.urls?.score || 0, max: 40 }
    ].filter(d => d.score > 0 || d.label === 'Detection Rules');

    const getColor = (pct) => pct > 70 ? 'var(--eti-critical)' : pct > 40 ? 'var(--eti-high)' : pct > 15 ? 'var(--eti-medium)' : 'var(--eti-low)';

    container.innerHTML = dimensions.map(d => {
      const pct = Math.round((d.score / d.max) * 100);
      const color = getColor(pct);
      return `
        <div class="eti-risk-dimension">
          <div class="eti-risk-dim-label">${d.label}</div>
          <div class="eti-risk-bar-track">
            <div class="eti-risk-bar-fill" style="width:${Math.min(pct,100)}%;background:${color};"></div>
          </div>
          <div class="eti-risk-dim-score" style="color:${color}">${d.score}</div>
        </div>`;
    }).join('') +
    `<div style="margin-top:8px;padding:8px;background:rgba(255,255,255,0.03);border-radius:6px;text-align:center;">
       <div style="font-size:10px;color:var(--eti-text-tertiary)">Amplifier Applied</div>
       <div style="font-size:16px;font-weight:700;color:var(--eti-accent-blue)">×${risk.amplifier || 1.0}</div>
       <div style="font-size:10px;color:var(--eti-text-tertiary)">${(risk.breakdown?.amplifier?.applied || []).join(', ') || 'none'}</div>
     </div>`;
  }

  function updateResponseActions(data) {
    const container = document.getElementById('etiResponseActions');
    if (!container) return;
    const tier = data.risk?.tier;
    const executed = data.response?.executed_actions || [];
    const pending = data.response?.pending_actions || [];

    const actionDefs = [
      { type: 'quarantine_email', label: 'Quarantine Email', icon: 'lock', iconColor: 'red', danger: true },
      { type: 'block_sender', label: 'Block Sender', icon: 'ban', iconColor: 'orange', danger: true },
      { type: 'block_domain', label: 'Block Domain', icon: 'globe', iconColor: 'orange', danger: false },
      { type: 'notify_soc', label: 'Notify SOC Team', icon: 'bell', iconColor: 'blue', danger: false },
      { type: 'create_incident', label: 'Create Incident', icon: 'ticket-alt', iconColor: 'purple', danger: false },
      { type: 'scan_mailbox', label: 'Scan Mailbox', icon: 'search', iconColor: 'blue', danger: false }
    ];

    container.innerHTML = actionDefs.map(a => {
      const isExecuted = executed.some(e => e.type === a.type);
      const isPending = pending.some(p => p.type === a.type);
      const status = isExecuted ? 'EXECUTED' : isPending ? 'PENDING' : '';
      const statusColor = isExecuted ? 'var(--eti-low)' : isPending ? 'var(--eti-medium)' : '';

      return `
        <button class="eti-action-btn ${a.danger ? 'action-critical' : ''}" onclick="ETIModule.executeAction('${a.type}')">
          <div class="action-icon ${a.iconColor}"><i class="fas fa-${a.icon}"></i></div>
          <span style="flex:1">${a.label}</span>
          ${status ? `<span class="action-status" style="color:${statusColor}">${status}</span>` : ''}
        </button>`;
    }).join('');
  }

  function updateIndicators(data) {
    const container = document.getElementById('etiIndicatorsList');
    if (!container) return;
    const inds = data.email?.indicators || {};

    const groups = [
      { type: 'ips', label: 'IP Addresses', icon: 'server' },
      { type: 'domains', label: 'Domains', icon: 'globe' },
      { type: 'urls', label: 'URLs', icon: 'link' },
      { type: 'hashes', label: 'File Hashes', icon: 'fingerprint' }
    ];

    let html = '';
    for (const g of groups) {
      const items = (inds[g.type] || []).slice(0, 5);
      if (!items.length) continue;
      html += `<div class="eti-indicator-group">
        <div class="eti-indicator-group-title"><i class="fas fa-${g.icon}"></i> ${g.label}</div>
        ${items.map(item => `
          <div class="eti-indicator-item">
            <div class="eti-indicator-value">${item.length > 40 ? item.substring(0,37)+'...' : item}</div>
            <div class="eti-indicator-rep unknown">check</div>
          </div>`).join('')}
      </div>`;
    }

    container.innerHTML = html || '<div style="color:var(--eti-text-tertiary);font-size:11px;">No indicators extracted</div>';
  }

  // ── Email Queue ────────────────────────────────────────────────────────────
  function updateEmailQueue() {
    const container = document.getElementById('etiEmailQueue');
    const counter = document.getElementById('etiQueueCount');
    if (!container) return;

    counter.textContent = `(${state.analysisHistory.length})`;

    container.innerHTML = state.analysisHistory.slice(0, 20).map((data, i) => {
      const tier = data.risk?.tier || 'unknown';
      const score = data.risk?.final_score || 0;
      const tierColors = { critical: 'var(--eti-critical)', high: 'var(--eti-high)', medium: 'var(--eti-medium)', low: 'var(--eti-low)', clean: 'var(--eti-clean)' };

      return `
        <div class="eti-email-item risk-${tier} ${i === 0 ? 'selected' : ''}" onclick="ETIModule.selectAnalysis(${i})">
          <div class="eti-email-item-left"></div>
          <div class="eti-email-item-header">
            <div class="eti-email-from">${data.email?.from || 'unknown'}</div>
            <div class="eti-email-tier-badge ${tier}">${tier}</div>
          </div>
          <div class="eti-email-subject">${data.email?.subject || '(no subject)'}</div>
          <div class="eti-email-meta">
            <div class="eti-email-meta-chip">${data.detection?.rules_triggered?.length || 0} rules</div>
            ${data.email?.attachment_count > 0 ? `<div class="eti-email-meta-chip"><i class="fas fa-paperclip"></i> ${data.email.attachment_count}</div>` : ''}
            <div class="eti-email-score-mini" style="color:${tierColors[tier]}">${score}</div>
          </div>
        </div>`;
    }).join('');
  }

  // ── Statistics ─────────────────────────────────────────────────────────────
  function updateStats(data) {
    state.stats.total++;
    if (data.risk?.tier === 'critical') state.stats.critical++;
    if (data.risk?.tier === 'high') state.stats.high++;
    if (data.risk?.tier === 'clean') state.stats.clean++;

    document.getElementById('etiStatTotal').textContent = state.stats.total;
    document.getElementById('etiStatCritical').textContent = state.stats.critical;
    document.getElementById('etiStatHigh').textContent = state.stats.high;
    document.getElementById('etiStatClean').textContent = state.stats.clean;
  }

  async function loadInitialStats() {
    try {
      const result = await API.getStats();
      if (result.success && result.data) {
        const d = result.data;
        document.getElementById('etiStatTotal').textContent = d.total_analyzed || 0;
        document.getElementById('etiStatCritical').textContent = d.by_tier?.critical || 0;
        document.getElementById('etiStatHigh').textContent = d.by_tier?.high || 0;
        document.getElementById('etiStatClean').textContent = d.by_tier?.clean || 0;
      }
    } catch {}
  }

  // ── UI Helpers ─────────────────────────────────────────────────────────────
  function showAnalyzing(visible) {
    state.analyzing = visible;
    const overlay = document.getElementById('etiAnalyzingOverlay');
    if (overlay) overlay.classList.toggle('active', visible);
  }

  function animateAnalyzingSteps() {
    const steps = document.querySelectorAll('.eti-analyzing-step');
    let i = 0;
    const interval = setInterval(() => {
      if (i > 0) steps[i-1].classList.replace('active', 'done');
      if (i < steps.length) { steps[i].classList.add('active'); i++; }
      else { clearInterval(interval); }
    }, 200);
  }

  function showToast(title, message, type = 'info') {
    const container = document.getElementById('etiToastContainer');
    if (!container) return;

    const icons = { critical: '🚨', error: '❌', success: '✅', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `eti-toast ${type}`;
    toast.innerHTML = `
      <div class="eti-toast-icon">${icons[type] || 'ℹ️'}</div>
      <div class="eti-toast-text">
        <div class="eti-toast-title">${title}</div>
        <div class="eti-toast-msg">${message}</div>
      </div>
      <button onclick="this.parentElement.remove()" style="background:none;border:none;color:var(--eti-text-tertiary);cursor:pointer;padding:4px;">✕</button>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 5000);
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  return {
    init,
    runDemo,
    selectAnalysis: (index) => {
      const data = state.analysisHistory[index];
      if (data) {
        state.currentAnalysis = data;
        updateEmailQueue();
        renderAnalysisView(data);
        updateRightPanel(data);
      }
    },
    executeAction: (type) => {
      showToast('Action Initiated', `${type.replace(/_/g,' ')} action submitted`, 'success');
    },
    openIncidents: () => {
      showToast('Incidents', 'Opening incident management...', 'info');
    },
    openBlocklists: () => {
      showToast('Blocklists', 'Opening blocklist management...', 'info');
    }
  };
})();

// Auto-init when DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => ETIModule.init());
} else {
  ETIModule.init();
}

window.ETIModule = ETIModule;
