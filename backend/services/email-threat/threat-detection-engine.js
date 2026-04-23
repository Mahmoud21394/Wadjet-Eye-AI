/**
 * ETI-AARE Threat Detection Engine v1.0
 * Multi-layer threat detection: rule-based + AI-powered + behavioral
 * Detects: phishing, BEC, spear-phishing, malware delivery, credential harvesting, C2
 */

'use strict';

// ─── Detection Rule Types ───────────────────────────────────────────────────
const RULE_TYPES = {
  HEADER_ANOMALY: 'header_anomaly',
  AUTH_FAILURE: 'auth_failure',
  SENDER_SPOOF: 'sender_spoof',
  PAYLOAD: 'payload',
  URL_THREAT: 'url_threat',
  ATTACHMENT_THREAT: 'attachment_threat',
  SOCIAL_ENGINEERING: 'social_engineering',
  BEC: 'bec',
  PHISHING: 'phishing',
  MALWARE_DELIVERY: 'malware_delivery',
  C2_COMMUNICATION: 'c2',
  HOMOGRAPH: 'homograph'
};

// ─── MITRE ATT&CK Mappings ──────────────────────────────────────────────────
const MITRE_MAPPINGS = {
  'phishing': { technique: 'T1566', sub: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
  'phishing_link': { technique: 'T1566', sub: 'T1566.002', name: 'Phishing: Spearphishing Link', tactic: 'Initial Access' },
  'phishing_service': { technique: 'T1566', sub: 'T1566.003', name: 'Phishing: Spearphishing via Service', tactic: 'Initial Access' },
  'user_execution_attachment': { technique: 'T1204', sub: 'T1204.002', name: 'User Execution: Malicious File', tactic: 'Execution' },
  'user_execution_link': { technique: 'T1204', sub: 'T1204.001', name: 'User Execution: Malicious Link', tactic: 'Execution' },
  'credential_harvesting': { technique: 'T1056', sub: 'T1056.003', name: 'Input Capture: Web Portal Capture', tactic: 'Collection' },
  'bec_account_takeover': { technique: 'T1556', name: 'Modify Authentication Process', tactic: 'Credential Access' },
  'domain_spoofing': { technique: 'T1566', sub: 'T1566.001', name: 'Phishing', tactic: 'Initial Access' },
  'homograph_attack': { technique: 'T1036', sub: 'T1036.005', name: 'Masquerading: Match Legitimate Name', tactic: 'Defense Evasion' },
  'malware_dropper': { technique: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  'c2_callback': { technique: 'T1071', sub: 'T1071.003', name: 'Application Layer Protocol: Mail Protocols', tactic: 'Command and Control' },
  'data_exfil': { technique: 'T1048', sub: 'T1048.003', name: 'Exfiltration Over Unencrypted Protocol', tactic: 'Exfiltration' },
  'supply_chain': { technique: 'T1195', name: 'Supply Chain Compromise', tactic: 'Initial Access' }
};

// ─── Built-in Detection Rules (Sigma-style) ─────────────────────────────────
const DETECTION_RULES = [
  // ── Authentication Rules ──────────────────────────────────────────────────
  {
    id: 'ETI-AUTH-001',
    name: 'Complete Authentication Failure (SPF+DKIM+DMARC)',
    type: RULE_TYPES.AUTH_FAILURE,
    severity: 'critical',
    confidence: 85,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.auth.spf === 'fail' && email.auth.dkim === 'fail' && email.auth.dmarc === 'fail',
    description: 'All three email authentication protocols failed — strong indicator of spoofing'
  },
  {
    id: 'ETI-AUTH-002',
    name: 'DMARC Fail with SPF/DKIM Mismatch',
    type: RULE_TYPES.AUTH_FAILURE,
    severity: 'high',
    confidence: 75,
    mitre: MITRE_MAPPINGS.domain_spoofing,
    condition: (email) => email.auth.dmarc === 'fail' && (email.auth.spf !== 'pass' || email.auth.dkim !== 'pass'),
    description: 'DMARC failed indicating domain alignment mismatch'
  },
  {
    id: 'ETI-AUTH-003',
    name: 'No Email Authentication',
    type: RULE_TYPES.AUTH_FAILURE,
    severity: 'medium',
    confidence: 50,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.auth.spf === 'none' && email.auth.dkim === 'none',
    description: 'Email has no SPF or DKIM authentication — unverifiable sender'
  },

  // ── Sender Spoofing Rules ──────────────────────────────────────────────────
  {
    id: 'ETI-SPOOF-001',
    name: 'Display Name Impersonation',
    type: RULE_TYPES.SENDER_SPOOF,
    severity: 'high',
    confidence: 80,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.sender.anomalies?.some(a => a.type === 'display_name_domain_mismatch'),
    description: 'Display name impersonates a trusted brand while actual domain is different'
  },
  {
    id: 'ETI-SPOOF-002',
    name: 'Reply-To Domain Mismatch (BEC Indicator)',
    type: RULE_TYPES.BEC,
    severity: 'high',
    confidence: 85,
    mitre: MITRE_MAPPINGS.bec_account_takeover,
    condition: (email) => email.sender.anomalies?.some(a => a.type === 'from_reply_to_domain_mismatch'),
    description: 'Reply-To domain differs from From domain — classic BEC technique'
  },
  {
    id: 'ETI-SPOOF-003',
    name: 'Executive Impersonation BEC',
    type: RULE_TYPES.BEC,
    severity: 'critical',
    confidence: 80,
    mitre: MITRE_MAPPINGS.bec_account_takeover,
    condition: (email) => {
      const display = email.sender.display_name?.toLowerCase() || '';
      const execTitles = ['ceo', 'cfo', 'cto', 'coo', 'president', 'director', 'vp of'];
      const becPatterns = email.body.social_engineering_flags?.some(f => f.flag === 'bec_pattern');
      return execTitles.some(t => display.includes(t)) && becPatterns;
    },
    description: 'Executive name in display field combined with BEC patterns (wire transfer, gift card)'
  },

  // ── Phishing Rules ────────────────────────────────────────────────────────
  {
    id: 'ETI-PHISH-001',
    name: 'Credential Harvesting Link',
    type: RULE_TYPES.PHISHING,
    severity: 'critical',
    confidence: 85,
    mitre: MITRE_MAPPINGS.credential_harvesting,
    condition: (email) => {
      const urlFlags = (email.body.urls || []).some(u => u.techniques?.some(t =>
        ['redirect_service', 'homograph_domain', 'ip_url'].includes(t)));
      const seFlags = email.body.social_engineering_flags?.some(f => f.flag === 'credential_harvesting');
      return urlFlags && seFlags;
    },
    description: 'Suspicious URL combined with credential harvesting language'
  },
  {
    id: 'ETI-PHISH-002',
    name: 'Homograph/Lookalike Domain Attack',
    type: RULE_TYPES.HOMOGRAPH,
    severity: 'critical',
    confidence: 90,
    mitre: MITRE_MAPPINGS.homograph_attack,
    condition: (email) => email.domain_analysis?.high_risk?.some(d => d.flags?.some(f => f.toString().startsWith('lookalike'))),
    description: 'Domain using lookalike/homograph characters to impersonate trusted brands'
  },
  {
    id: 'ETI-PHISH-003',
    name: 'Mass Phishing Indicators',
    type: RULE_TYPES.PHISHING,
    severity: 'high',
    confidence: 70,
    mitre: MITRE_MAPPINGS.phishing_link,
    condition: (email) => {
      const urgency = email.body.urgency_score > 50;
      const hasUrl = email.body.urls?.length > 0;
      const authFail = email.auth.spf !== 'pass' || email.auth.dkim !== 'pass';
      const seScore = (email.body.social_engineering_flags?.length || 0) >= 2;
      return urgency && hasUrl && (authFail || seScore);
    },
    description: 'High urgency + suspicious URL + authentication/social engineering failures'
  },
  {
    id: 'ETI-PHISH-004',
    name: 'Brand Impersonation in Subject',
    type: RULE_TYPES.PHISHING,
    severity: 'high',
    confidence: 75,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.subject_analysis?.flags?.some(f => f.flag === 'brand_impersonation'),
    description: 'Email subject contains known brand name used for impersonation'
  },

  // ── Malware Delivery Rules ────────────────────────────────────────────────
  {
    id: 'ETI-MAL-001',
    name: 'Critical Attachment Malware Delivery',
    type: RULE_TYPES.MALWARE_DELIVERY,
    severity: 'critical',
    confidence: 90,
    mitre: MITRE_MAPPINGS.user_execution_attachment,
    condition: (email) => email.attachments?.some(a => a.threat_level === 'critical'),
    description: 'Executable/script attachment detected — primary malware delivery vector'
  },
  {
    id: 'ETI-MAL-002',
    name: 'Office Macro Delivery',
    type: RULE_TYPES.MALWARE_DELIVERY,
    severity: 'high',
    confidence: 80,
    mitre: MITRE_MAPPINGS.user_execution_attachment,
    condition: (email) => email.attachments?.some(a =>
      ['docm', 'xlsm', 'pptm'].includes(a.extension) || a.flags?.includes('macro_enabled')),
    description: 'Macro-enabled Office document detected'
  },
  {
    id: 'ETI-MAL-003',
    name: 'Double-Extension Attack',
    type: RULE_TYPES.MALWARE_DELIVERY,
    severity: 'critical',
    confidence: 95,
    mitre: MITRE_MAPPINGS.malware_dropper,
    condition: (email) => email.attachments?.some(a => a.flags?.includes('double_extension_attack')),
    description: 'File uses double extension (e.g., invoice.pdf.exe) to trick users'
  },
  {
    id: 'ETI-MAL-004',
    name: 'Archive with Executable Contents',
    type: RULE_TYPES.MALWARE_DELIVERY,
    severity: 'high',
    confidence: 85,
    mitre: MITRE_MAPPINGS.malware_dropper,
    condition: (email) => email.attachments?.some(a =>
      ['zip', 'rar', '7z'].includes(a.extension) && email.body.text.match(/password|passwort|mot de passe/i)),
    description: 'Password-protected archive with password in email body — malware delivery pattern'
  },

  // ── URL Threat Rules ──────────────────────────────────────────────────────
  {
    id: 'ETI-URL-001',
    name: 'IP-based URL (No Domain)',
    type: RULE_TYPES.URL_THREAT,
    severity: 'high',
    confidence: 85,
    mitre: MITRE_MAPPINGS.phishing_link,
    condition: (email) => (email.body.urls || []).some(u => u.techniques?.includes('ip_url')),
    description: 'URL uses raw IP address instead of domain — evasion of domain reputation checks'
  },
  {
    id: 'ETI-URL-002',
    name: 'URL Redirect Chain (Evasion)',
    type: RULE_TYPES.URL_THREAT,
    severity: 'high',
    confidence: 75,
    mitre: MITRE_MAPPINGS.homograph_attack,
    condition: (email) => (email.body.urls || []).some(u => u.techniques?.includes('redirect_service')),
    description: 'URLs using redirect/tracking services to mask final destination'
  },
  {
    id: 'ETI-URL-003',
    name: 'HTML Body Obfuscation',
    type: RULE_TYPES.PAYLOAD,
    severity: 'high',
    confidence: 80,
    mitre: MITRE_MAPPINGS.homograph_attack,
    condition: (email) => email.body.obfuscation_detected === true,
    description: 'HTML email uses visual obfuscation (hidden text, zero-size elements)'
  },
  {
    id: 'ETI-URL-004',
    name: 'Lookalike Domain in URL',
    type: RULE_TYPES.URL_THREAT,
    severity: 'critical',
    confidence: 90,
    mitre: MITRE_MAPPINGS.credential_harvesting,
    condition: (email) => (email.body.urls || []).some(u => {
      try {
        const d = new URL(u.deobfuscated).hostname;
        const assessment = require('./email-parser').URLAnalyzer.assessDomain(d);
        return assessment.risk === 'critical';
      } catch { return false; }
    }),
    description: 'URL contains domain impersonating a trusted brand'
  },

  // ── BEC Rules ─────────────────────────────────────────────────────────────
  {
    id: 'ETI-BEC-001',
    name: 'Wire Transfer Request BEC',
    type: RULE_TYPES.BEC,
    severity: 'critical',
    confidence: 85,
    mitre: MITRE_MAPPINGS.bec_account_takeover,
    condition: (email) => {
      const text = (email.body.text || '').toLowerCase();
      const wirePatterns = ['wire transfer', 'wire funds', 'bank transfer', 'ach transfer',
        'routing number', 'account number', 'swift code', 'iban'];
      return wirePatterns.some(p => text.includes(p)) &&
        email.body.social_engineering_flags?.some(f => f.flag === 'bec_pattern');
    },
    description: 'Wire transfer request combined with BEC behavioral patterns'
  },
  {
    id: 'ETI-BEC-002',
    name: 'Gift Card Purchase Request',
    type: RULE_TYPES.BEC,
    severity: 'high',
    confidence: 90,
    mitre: MITRE_MAPPINGS.bec_account_takeover,
    condition: (email) => {
      const text = (email.body.text || '').toLowerCase();
      return (text.includes('gift card') || text.includes('itunes') || text.includes('amazon card')) &&
        text.includes('purchase') && email.body.social_engineering_flags?.some(f => f.flag === 'bec_pattern');
    },
    description: 'Gift card purchase request — common BEC fraud vector'
  },
  {
    id: 'ETI-BEC-003',
    name: 'Vendor Email Compromise',
    type: RULE_TYPES.BEC,
    severity: 'critical',
    confidence: 80,
    mitre: MITRE_MAPPINGS.bec_account_takeover,
    condition: (email) => {
      const text = (email.body.text || '').toLowerCase();
      const vecPatterns = ['new bank account', 'updated banking', 'change payment', 'new payment details',
        'banking information has changed', 'new wire details'];
      return vecPatterns.some(p => text.includes(p));
    },
    description: 'Vendor email compromise — fraudulent payment detail change request'
  },

  // ── Advanced Rules ────────────────────────────────────────────────────────
  {
    id: 'ETI-ADV-001',
    name: 'Suspicious Routing (Multiple Unusual Hops)',
    type: RULE_TYPES.HEADER_ANOMALY,
    severity: 'medium',
    confidence: 60,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.routing.suspicious_hops >= 2,
    description: 'Email routed through multiple suspicious relay servers'
  },
  {
    id: 'ETI-ADV-002',
    name: 'Low-Reputation TLD Domain',
    type: RULE_TYPES.PHISHING,
    severity: 'medium',
    confidence: 65,
    mitre: MITRE_MAPPINGS.phishing,
    condition: (email) => email.domain_analysis?.high_risk?.some(d => d.flags?.includes('suspicious_tld')),
    description: 'Email involves domains using low-reputation TLDs known for abuse'
  },
  {
    id: 'ETI-ADV-003',
    name: 'DGA-Like Domain',
    type: RULE_TYPES.C2_COMMUNICATION,
    severity: 'high',
    confidence: 70,
    mitre: MITRE_MAPPINGS.c2_callback,
    condition: (email) => email.domain_analysis?.high_risk?.some(d => d.flags?.includes('possible_dga') || d.flags?.includes('likely_dga')),
    description: 'Domain matches DGA (Domain Generation Algorithm) patterns — possible C2'
  }
];

// ─── AI Threat Classifier ───────────────────────────────────────────────────
class AIThreatClassifier {
  constructor(llmProvider) {
    this.llm = llmProvider;
    this.modelVersion = 'gpt-4o-mini';
  }

  /**
   * LLM-based phishing/BEC/tone analysis
   * Returns structured AI classification with confidence and explanation
   */
  async classify(emailSummary) {
    const prompt = this._buildPrompt(emailSummary);

    try {
      if (!this.llm) {
        return this._fallbackClassification(emailSummary);
      }

      const response = await this.llm.complete({
        model: this.modelVersion,
        messages: [
          {
            role: 'system',
            content: `You are an expert email threat analyst for a SOC. Analyze the provided email metadata and return a structured JSON threat classification. 
Be precise and evidence-based. Return ONLY valid JSON.

Required format:
{
  "threat_type": "phishing|bec|malware_delivery|spam|legitimate|unknown",
  "sub_type": "spear_phishing|mass_phishing|executive_impersonation|vendor_fraud|credential_harvesting|etc",
  "confidence": 0-100,
  "intent": "brief description of attacker intent",
  "tone_analysis": {
    "urgency": 0-100,
    "authority_pressure": 0-100,
    "fear_inducement": 0-100,
    "manipulation_score": 0-100
  },
  "key_indicators": ["list of key indicators found"],
  "attack_stage": "reconnaissance|initial_access|execution|persistence|collection|exfiltration",
  "targeted": true/false,
  "sophistication": "low|medium|high|nation_state",
  "recommended_action": "quarantine|block_sender|block_domain|investigate|release",
  "explanation": "1-2 sentence explanation of the classification"
}`
          },
          { role: 'user', content: prompt }
        ],
        temperature: 0.1,
        max_tokens: 500
      });

      const content = response.choices?.[0]?.message?.content || '{}';
      const result = JSON.parse(content);
      result.source = 'ai_llm';
      result.model = this.modelVersion;
      return result;
    } catch (err) {
      return this._fallbackClassification(emailSummary);
    }
  }

  _buildPrompt(email) {
    const threatSignals = (email.threat_signals || []).map(s => `- ${s.type}: ${s.detail}`).join('\n');
    const urls = (email.body?.urls || []).slice(0, 5).map(u => u.deobfuscated).join(', ');
    const attachments = (email.attachments || []).map(a => `${a.filename}(${a.threat_level})`).join(', ');

    return `Email Analysis Request:
From: ${email.sender?.address || 'unknown'} (Display: ${email.sender?.display_name || 'none'})
Subject: ${email.subject || '(none)'}
Auth: SPF=${email.auth?.spf} DKIM=${email.auth?.dkim} DMARC=${email.auth?.dmarc}
Reply-To: ${email.sender?.reply_to || 'same as from'}
Routing: ${email.routing?.hop_count} hops, ${email.routing?.suspicious_hops} suspicious
Body length: ${(email.body?.text || '').length} chars
URLs: ${urls || 'none'}
Attachments: ${attachments || 'none'}
Urgency score: ${email.body?.urgency_score}/100
Social engineering flags: ${(email.body?.social_engineering_flags || []).map(f => f.flag).join(', ') || 'none'}
Sender anomalies: ${(email.sender?.anomalies || []).map(a => a.type).join(', ') || 'none'}
Threat signals detected:
${threatSignals || '- none'}
Subject flags: ${JSON.stringify(email.subject_analysis?.flags || [])}`;
  }

  _fallbackClassification(email) {
    // Deterministic rule-based fallback when no LLM available
    const score = (email.threat_signals || []).reduce((s, t) => s + (t.score || 0), 0);
    const hasBEC = (email.threat_signals || []).some(s => s.type.includes('bec'));
    const hasPhishing = (email.threat_signals || []).some(s => s.type.includes('phishing') || s.type.includes('spoof'));
    const hasMalware = (email.threat_signals || []).some(s => s.type.includes('attachment') || s.type.includes('malware'));

    let threat_type = 'unknown';
    let confidence = 0;
    if (hasBEC) { threat_type = 'bec'; confidence = 70; }
    else if (hasMalware) { threat_type = 'malware_delivery'; confidence = 75; }
    else if (hasPhishing || score > 60) { threat_type = 'phishing'; confidence = Math.min(score, 85); }
    else if (score > 20) { threat_type = 'suspicious'; confidence = score; }

    return {
      threat_type,
      confidence,
      source: 'rule_fallback',
      tone_analysis: {
        urgency: email.body?.urgency_score || 0,
        manipulation_score: Math.min(score, 100)
      },
      explanation: `Rule-based classification: ${(email.threat_signals || []).map(s => s.type).join(', ')}`
    };
  }

  /**
   * BEC Behavioral Intent Analysis
   */
  analyzeBECIntent(emailBody, senderContext) {
    const text = (emailBody || '').toLowerCase();
    const becIntents = {
      financial_fraud: ['wire transfer', 'bank account', 'routing number', 'swift', 'payment'],
      gift_card_fraud: ['gift card', 'itunes', 'google play', 'amazon card'],
      credential_theft: ['click here', 'sign in', 'verify account', 'reset password', 'confirm identity'],
      invoice_fraud: ['invoice', 'overdue', 'payment due', 'pay immediately'],
      data_theft: ['send me', 'forward', 'employee list', 'payroll', 'w-2', 'tax']
    };

    const detected = {};
    for (const [intent, keywords] of Object.entries(becIntents)) {
      const found = keywords.filter(k => text.includes(k));
      if (found.length > 0) detected[intent] = found;
    }

    return {
      intents_detected: Object.keys(detected),
      evidence: detected,
      is_bec: Object.keys(detected).length > 0,
      confidence: Math.min(Object.keys(detected).length * 25, 100)
    };
  }
}

// ─── Threat Detection Engine ─────────────────────────────────────────────────
class ThreatDetectionEngine {
  constructor(options = {}) {
    this.rules = [...DETECTION_RULES];
    this.aiClassifier = new AIThreatClassifier(options.llmProvider);
    this.customRules = options.customRules || [];
    this.enableAI = options.enableAI !== false;
    this.stats = { total: 0, threats: 0, fp_blocked: 0 };
  }

  /**
   * Run full detection pipeline on parsed email
   */
  async detect(parsedEmail) {
    this.stats.total++;
    const result = {
      email_id: parsedEmail.message_id,
      detections: [],
      ai_classification: null,
      bec_analysis: null,
      mitre_techniques: [],
      final_verdict: null,
      confidence: 0,
      processing_time: Date.now()
    };

    // ── Phase 1: Rule-based detection ──
    const ruleDetections = this._runRules(parsedEmail);
    result.detections = ruleDetections;

    // ── Phase 2: AI classification ──
    if (this.enableAI) {
      result.ai_classification = await this.aiClassifier.classify(parsedEmail);
    } else {
      result.ai_classification = this.aiClassifier._fallbackClassification(parsedEmail);
    }

    // ── Phase 3: BEC behavioral analysis ──
    result.bec_analysis = this.aiClassifier.analyzeBECIntent(
      parsedEmail.body?.text, parsedEmail.sender
    );

    // ── Phase 4: Consolidate MITRE techniques ──
    result.mitre_techniques = this._consolidateMitre(ruleDetections, result.ai_classification);

    // ── Phase 5: Final verdict ──
    result.final_verdict = this._computeVerdict(result);
    result.confidence = result.final_verdict.confidence;
    result.processing_time = Date.now() - result.processing_time;

    if (result.final_verdict.threat_level !== 'clean') this.stats.threats++;

    return result;
  }

  _runRules(email) {
    const detections = [];
    const allRules = [...this.rules, ...this.customRules];

    for (const rule of allRules) {
      try {
        if (rule.condition(email)) {
          detections.push({
            rule_id: rule.id,
            name: rule.name,
            type: rule.type,
            severity: rule.severity,
            confidence: rule.confidence,
            mitre: rule.mitre,
            description: rule.description,
            triggered_at: new Date().toISOString()
          });
        }
      } catch {}
    }

    return detections;
  }

  _consolidateMitre(detections, aiClass) {
    const techniques = new Map();

    // From rule detections
    for (const d of detections) {
      if (d.mitre) {
        const key = d.mitre.sub || d.mitre.technique;
        if (!techniques.has(key)) {
          techniques.set(key, {
            technique_id: d.mitre.technique,
            sub_technique_id: d.mitre.sub,
            name: d.mitre.name,
            tactic: d.mitre.tactic,
            confidence: d.confidence,
            sources: [d.rule_id]
          });
        } else {
          const existing = techniques.get(key);
          existing.confidence = Math.min(99, existing.confidence + 5);
          existing.sources.push(d.rule_id);
        }
      }
    }

    // From AI classification
    if (aiClass?.threat_type && aiClass.confidence > 50) {
      const aiMitre = {
        phishing: MITRE_MAPPINGS.phishing,
        bec: MITRE_MAPPINGS.bec_account_takeover,
        malware_delivery: MITRE_MAPPINGS.user_execution_attachment
      }[aiClass.threat_type];

      if (aiMitre) {
        const key = aiMitre.sub || aiMitre.technique;
        if (!techniques.has(key)) {
          techniques.set(key, {
            technique_id: aiMitre.technique,
            sub_technique_id: aiMitre.sub,
            name: aiMitre.name,
            tactic: aiMitre.tactic,
            confidence: aiClass.confidence,
            sources: ['ai_classifier']
          });
        }
      }
    }

    return [...techniques.values()].sort((a, b) => b.confidence - a.confidence);
  }

  _computeVerdict(result) {
    const detections = result.detections;
    const ai = result.ai_classification;

    const criticalCount = detections.filter(d => d.severity === 'critical').length;
    const highCount = detections.filter(d => d.severity === 'high').length;
    const mediumCount = detections.filter(d => d.severity === 'medium').length;

    const ruleScore = criticalCount * 40 + highCount * 25 + mediumCount * 10;
    const aiScore = ai ? (ai.confidence * 0.4) : 0;
    const combinedScore = Math.min(100, ruleScore + aiScore);

    // Determine primary threat type
    let primary_type = 'unknown';
    if (detections.some(d => d.type === RULE_TYPES.BEC) || result.bec_analysis?.is_bec) {
      primary_type = 'bec';
    } else if (detections.some(d => d.type === RULE_TYPES.MALWARE_DELIVERY)) {
      primary_type = 'malware_delivery';
    } else if (detections.some(d => d.type === RULE_TYPES.PHISHING) || detections.some(d => d.type === RULE_TYPES.HOMOGRAPH)) {
      primary_type = 'phishing';
    } else if (ai?.threat_type && ai.threat_type !== 'unknown') {
      primary_type = ai.threat_type;
    }

    // Determine threat level
    let threat_level, recommended_action;
    if (combinedScore >= 70 || criticalCount >= 1) {
      threat_level = 'critical';
      recommended_action = 'quarantine_and_block';
    } else if (combinedScore >= 45 || highCount >= 2) {
      threat_level = 'high';
      recommended_action = 'quarantine';
    } else if (combinedScore >= 25 || mediumCount >= 2) {
      threat_level = 'medium';
      recommended_action = 'flag_for_review';
    } else if (combinedScore > 0) {
      threat_level = 'low';
      recommended_action = 'monitor';
    } else {
      threat_level = 'clean';
      recommended_action = 'allow';
    }

    return {
      threat_level,
      primary_type,
      confidence: Math.round(combinedScore),
      rule_score: ruleScore,
      ai_score: Math.round(aiScore),
      recommended_action,
      detection_count: detections.length,
      critical_rules: detections.filter(d => d.severity === 'critical').map(d => d.rule_id)
    };
  }

  /**
   * Add custom Sigma-style rule at runtime
   */
  addRule(rule) {
    if (!rule.id || !rule.condition || typeof rule.condition !== 'function') {
      throw new Error('Rule must have id, name, and condition function');
    }
    this.customRules.push(rule);
    return this;
  }

  getStats() { return this.stats; }
  getRules() { return [...this.rules, ...this.customRules].map(r => ({ id: r.id, name: r.name, severity: r.severity })); }
}

module.exports = { ThreatDetectionEngine, AIThreatClassifier, DETECTION_RULES, RULE_TYPES, MITRE_MAPPINGS };
