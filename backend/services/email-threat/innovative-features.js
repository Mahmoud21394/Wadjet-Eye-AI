/**
 * ETI-AARE Innovative Feature #1: AI Explainability Engine v1.0
 * Provides human-readable, evidence-based explanations for every threat decision
 * Generates analyst-grade narratives, evidence chains, confidence breakdowns,
 * and "why was this flagged" explanations for SOC analysts
 *
 * Feature #2: Email Attack Graph Intelligence v1.0
 * Builds visual attack chain graphs linking email → phishing kit → C2 → victim
 * Maps relationships between indicators across emails to detect campaigns
 *
 * Feature #3: Behavioral Identity Fingerprinting (NOVEL) v1.0
 * Creates cryptographic behavioral fingerprints of sender identities
 * Detects account takeover, compromised senders, and impersonation through
 * multi-dimensional behavioral drift analysis
 */

'use strict';

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 1: AI Explainability Engine
// ═══════════════════════════════════════════════════════════════════════════

class AIExplainabilityEngine {
  constructor() {
    this.explanation_templates = EXPLANATION_TEMPLATES;
    this.evidence_chains = new Map();
  }

  /**
   * Generate comprehensive, analyst-grade explanation for a threat detection
   */
  explain(parsedEmail, detectionResult, riskScore, enrichmentResult) {
    const explanation = {
      summary: this._generateSummary(parsedEmail, detectionResult, riskScore),
      evidence_chain: this._buildEvidenceChain(parsedEmail, detectionResult, enrichmentResult),
      confidence_breakdown: this._explainConfidence(riskScore, detectionResult),
      attack_narrative: this._generateAttackNarrative(parsedEmail, detectionResult),
      indicator_explanations: this._explainIndicators(parsedEmail, enrichmentResult),
      why_flagged: this._generateWhyFlagged(detectionResult, riskScore),
      analyst_notes: this._generateAnalystNotes(parsedEmail, detectionResult, riskScore),
      false_positive_assessment: this._assessFalsePositive(parsedEmail, detectionResult, riskScore),
      mitre_explanation: this._explainMitre(detectionResult.mitre_techniques || []),
      generated_at: new Date().toISOString()
    };

    return explanation;
  }

  _generateSummary(email, detection, risk) {
    const type = detection.final_verdict?.primary_type || 'unknown';
    const tier = risk.tier || 'unknown';
    const score = risk.final_score || 0;
    const sender = email.sender?.address || 'unknown sender';
    const subject = email.subject || '(no subject)';

    const typeDescriptions = {
      phishing: 'phishing attack designed to steal credentials or deliver malware',
      bec: 'Business Email Compromise (BEC) attempting to commit financial fraud',
      malware_delivery: 'malware delivery campaign attempting to install malicious software',
      credential_harvesting: 'credential harvesting attack targeting login credentials',
      spam: 'bulk spam with potential malicious content',
      unknown: 'suspicious email with multiple threat indicators'
    };

    return {
      headline: `${tier.toUpperCase()} RISK: Detected ${typeDescriptions[type] || type}`,
      risk_level: tier,
      risk_score: score,
      threat_type: type,
      in_one_sentence: `This email from ${sender} exhibits ${score >= 80 ? 'definitive' : score >= 60 ? 'strong' : 'moderate'} indicators of a ${type.replace(/_/g, ' ')} attack with a risk score of ${score}/100.`,
      key_facts: this._extractKeyFacts(email, detection, risk)
    };
  }

  _extractKeyFacts(email, detection, risk) {
    const facts = [];

    if (email.auth?.spf === 'fail') facts.push('Sender domain failed SPF authentication (email may be spoofed)');
    if (email.auth?.dkim === 'fail') facts.push('Email signature invalid — DKIM verification failed');
    if (email.auth?.dmarc === 'fail') facts.push('DMARC policy failure — domain owner does not authorize this sender');
    if (email.sender?.anomalies?.some(a => a.type === 'display_name_domain_mismatch'))
      facts.push('Display name impersonates a trusted brand but actual sending domain is different');
    if (email.sender?.anomalies?.some(a => a.type === 'from_reply_to_domain_mismatch'))
      facts.push('Reply-To address routes responses to a different domain — classic BEC technique');

    const critRules = detection.detections?.filter(d => d.severity === 'critical') || [];
    critRules.forEach(r => facts.push(`Critical rule triggered: ${r.name}`));

    if (email.attachments?.some(a => a.threat_level === 'critical'))
      facts.push('Executable attachment detected — common malware delivery mechanism');
    if (email.body?.obfuscation_detected)
      facts.push('Email body uses HTML obfuscation techniques to hide malicious content');
    if ((email.domain_analysis?.lookalike_count || 0) > 0)
      facts.push('Lookalike domain detected impersonating a trusted brand');

    return facts;
  }

  _buildEvidenceChain(email, detection, enrichment) {
    const chain = [];
    let stepNum = 1;

    // Step 1: Source authentication
    chain.push({
      step: stepNum++,
      category: 'Email Authentication',
      icon: 'shield-check',
      verdict: email.auth?.spf === 'pass' && email.auth?.dkim === 'pass' ? 'pass' : 'fail',
      evidence: [
        `SPF Result: ${(email.auth?.spf || 'none').toUpperCase()} — ${this._explainSPF(email.auth?.spf)}`,
        `DKIM Result: ${(email.auth?.dkim || 'none').toUpperCase()} — ${this._explainDKIM(email.auth?.dkim)}`,
        `DMARC Result: ${(email.auth?.dmarc || 'none').toUpperCase()} — ${this._explainDMARC(email.auth?.dmarc)}`
      ],
      risk_contribution: email.auth?.spf === 'fail' ? 'HIGH' : email.auth?.dkim === 'fail' ? 'MEDIUM' : 'LOW'
    });

    // Step 2: Sender identity
    const senderAnomalies = email.sender?.anomalies || [];
    chain.push({
      step: stepNum++,
      category: 'Sender Identity Analysis',
      icon: 'user-circle',
      verdict: senderAnomalies.length > 0 ? 'suspicious' : 'pass',
      evidence: senderAnomalies.length > 0
        ? senderAnomalies.map(a => this._explainSenderAnomaly(a))
        : ['Sender identity appears consistent'],
      risk_contribution: senderAnomalies.length >= 2 ? 'HIGH' : senderAnomalies.length === 1 ? 'MEDIUM' : 'NONE'
    });

    // Step 3: Email routing
    chain.push({
      step: stepNum++,
      category: 'Routing Analysis',
      icon: 'route',
      verdict: (email.routing?.suspicious_hops || 0) > 0 ? 'suspicious' : 'pass',
      evidence: [
        `Email traversed ${email.routing?.hop_count || 0} relay servers`,
        ...(email.routing?.hops?.filter(h => h.suspicious).map(h =>
          `Suspicious hop: ${h.from_hostname || 'unknown'} (${h.from_ip || 'no IP'})`) || [])
      ],
      risk_contribution: (email.routing?.suspicious_hops || 0) > 1 ? 'MEDIUM' : 'LOW'
    });

    // Step 4: Content analysis
    const seFlags = email.body?.social_engineering_flags || [];
    chain.push({
      step: stepNum++,
      category: 'Content & Intent Analysis',
      icon: 'document-text',
      verdict: seFlags.length > 1 ? 'malicious' : seFlags.length > 0 ? 'suspicious' : 'clean',
      evidence: seFlags.map(f => {
        const desc = {
          urgency: `Urgency manipulation: ${f.matched_terms?.join(', ')}`,
          credential_harvesting: `Credential harvesting language: ${f.matched_terms?.join(', ')}`,
          bec_pattern: `BEC fraud pattern: ${f.matched_terms?.join(', ')}`,
          financial_lure: `Financial lure: ${f.matched_terms?.join(', ')}`,
          fear_tactics: `Fear tactics: ${f.matched_terms?.join(', ')}`
        };
        return desc[f.flag || f] || `Suspicious pattern: ${f.flag || f}`;
      }).concat(email.body?.urgency_score > 40 ? [`High urgency score: ${email.body.urgency_score}/100`] : []),
      risk_contribution: seFlags.length >= 3 ? 'CRITICAL' : seFlags.length >= 1 ? 'HIGH' : 'NONE'
    });

    // Step 5: Attachments
    if (email.attachments?.length > 0) {
      chain.push({
        step: stepNum++,
        category: 'Attachment Analysis',
        icon: 'paperclip',
        verdict: email.attachments.some(a => a.threat_level === 'critical') ? 'malicious' :
                 email.attachments.some(a => a.threat_level === 'high') ? 'suspicious' : 'clean',
        evidence: email.attachments.map(a =>
          `${a.filename} — Type: ${a.extension?.toUpperCase() || 'unknown'}, Risk: ${a.threat_level?.toUpperCase()}, Flags: ${(a.flags || []).join(', ') || 'none'}`
        ),
        risk_contribution: email.attachments.some(a => a.threat_level === 'critical') ? 'CRITICAL' : 'HIGH'
      });
    }

    // Step 6: URL/Domain reputation
    if ((email.body?.urls?.length || 0) > 0) {
      chain.push({
        step: stepNum++,
        category: 'URL & Domain Analysis',
        icon: 'link',
        verdict: (email.domain_analysis?.lookalike_count || 0) > 0 ? 'malicious' :
                 (email.body?.urls?.filter(u => u.is_suspicious).length || 0) > 0 ? 'suspicious' : 'clean',
        evidence: [
          `${email.body.urls.length} URLs found in email`,
          ...(email.body.urls.filter(u => u.is_suspicious).map(u =>
            `Suspicious URL: ${u.deobfuscated.substring(0, 100)} — Techniques: ${u.techniques?.join(', ')}`))
        ],
        risk_contribution: (email.domain_analysis?.lookalike_count || 0) > 0 ? 'CRITICAL' : 'MEDIUM'
      });
    }

    // Step 7: Threat intel
    if (enrichment?.threat_context?.length > 0) {
      chain.push({
        step: stepNum++,
        category: 'Threat Intelligence',
        icon: 'database',
        verdict: enrichment.summary?.threat_intel_score > 50 ? 'malicious' : 'suspicious',
        evidence: enrichment.threat_context.map(ctx =>
          `${ctx.type.replace(/_/g, ' ').toUpperCase()}: ${ctx.indicator} (${ctx.severity})`
        ),
        risk_contribution: enrichment.summary?.threat_intel_score > 70 ? 'CRITICAL' : 'HIGH'
      });
    }

    return chain;
  }

  _explainSPF(result) {
    const explanations = {
      pass: 'Sending server is authorized by domain owner',
      fail: 'Sending server is NOT authorized — strong spoofing indicator',
      softfail: 'Server may not be authorized — weak spoofing indicator',
      neutral: 'Domain owner makes no assertion about authorization',
      none: 'No SPF record published for this domain'
    };
    return explanations[result] || 'Unknown SPF status';
  }

  _explainDKIM(result) {
    const explanations = {
      pass: 'Cryptographic signature verified — email was not modified in transit',
      fail: 'Signature verification FAILED — email was modified or is spoofed',
      none: 'No DKIM signature found — authenticity cannot be verified'
    };
    return explanations[result] || 'Unknown DKIM status';
  }

  _explainDMARC(result) {
    const explanations = {
      pass: 'Domain alignment checks passed — email policy compliant',
      fail: 'DMARC FAILED — neither SPF nor DKIM align with From domain',
      none: 'No DMARC policy found — no domain alignment enforcement'
    };
    return explanations[result] || 'Unknown DMARC status';
  }

  _explainSenderAnomaly(anomaly) {
    const explanations = {
      display_name_domain_mismatch: `Display name "${anomaly.brand}" doesn't match sending domain — impersonation technique`,
      from_reply_to_domain_mismatch: `Reply-To hijack: Responses would go to ${anomaly.reply_to} instead of ${anomaly.from}`,
      spf_fail: 'SPF authentication failure indicates sender domain spoofing',
      dkim_fail: 'DKIM failure — email integrity compromised',
      dmarc_fail: 'DMARC enforcement failure',
      no_authentication: 'Zero email authentication — completely unverified sender',
      free_email_provider: `Business email using free provider (${anomaly.provider}) — suspicious for corporate communication`
    };
    return explanations[anomaly.type] || `Anomaly: ${anomaly.type}`;
  }

  _explainConfidence(risk, detection) {
    const dimensions = [
      { name: 'Authentication Signals', score: risk.breakdown?.auth?.score || 0, max: 30, weight: 'high' },
      { name: 'Rule Detection', score: risk.breakdown?.rules?.score || 0, max: 55, weight: 'critical' },
      { name: 'AI Classification', score: risk.breakdown?.ai?.score || 0, max: 35, weight: 'high' },
      { name: 'Threat Intelligence', score: risk.breakdown?.threat_intel?.score || 0, max: 60, weight: 'critical' },
      { name: 'Sender Analysis', score: risk.breakdown?.sender?.score || 0, max: 30, weight: 'medium' },
      { name: 'Content Analysis', score: risk.breakdown?.social_eng?.score || 0, max: 35, weight: 'high' },
      { name: 'Attachments', score: risk.breakdown?.attachments?.score || 0, max: 50, weight: 'critical' },
      { name: 'URL Analysis', score: risk.breakdown?.urls?.score || 0, max: 40, weight: 'high' }
    ].filter(d => d.score > 0);

    const topContributors = dimensions.sort((a, b) => b.score - a.score).slice(0, 4);

    return {
      overall_confidence: risk.confidence || 0,
      final_score: risk.final_score,
      amplifier_applied: risk.amplifier,
      amplifier_reasons: risk.breakdown?.amplifier?.applied || [],
      top_contributing_factors: topContributors,
      signal_count: dimensions.length,
      interpretation: this._interpretConfidence(risk.confidence || 0, risk.tier)
    };
  }

  _interpretConfidence(confidence, tier) {
    if (confidence >= 85) return 'Very high confidence — multiple independent indicators corroborate this threat classification';
    if (confidence >= 70) return 'High confidence — strong evidence from multiple signal sources';
    if (confidence >= 50) return 'Moderate confidence — significant indicators present but some uncertainty remains';
    if (confidence >= 30) return 'Low-medium confidence — suspicious but lacks definitive confirmation';
    return 'Low confidence — limited signals, investigate manually';
  }

  _generateAttackNarrative(email, detection) {
    const type = detection.final_verdict?.primary_type;
    const narratives = {
      phishing: this._phishingNarrative(email, detection),
      bec: this._becNarrative(email, detection),
      malware_delivery: this._malwareNarrative(email, detection),
      credential_harvesting: this._credentialNarrative(email)
    };
    return narratives[type] || this._genericNarrative(email, detection);
  }

  _phishingNarrative(email, detection) {
    const sender = email.sender?.address || 'unknown';
    const domain = email.sender?.domain || 'unknown';
    const hasUrl = (email.body?.urls?.length || 0) > 0;
    const hasAttachment = (email.attachments?.length || 0) > 0;

    return `ATTACK NARRATIVE: This appears to be a ${hasUrl && hasAttachment ? 'multi-vector' : hasUrl ? 'link-based' : 'attachment-based'} phishing campaign.

The attacker sent an email from ${sender} (domain: ${domain}), which ${email.auth?.spf === 'fail' ? 'failed SPF authentication indicating a spoofed sender' : 'uses a potentially compromised or fake domain'}. ${email.sender?.anomalies?.some(a => a.type === 'display_name_domain_mismatch') ? 'The display name was crafted to impersonate a trusted entity while using a malicious domain.' : ''}

${hasUrl ? `The email contains ${email.body.urls.length} URL(s) designed to redirect victims to malicious sites. ${email.domain_analysis?.lookalike_count > 0 ? 'At least one URL uses a lookalike domain to trick users into believing they are visiting a legitimate site.' : ''}` : ''}

${hasAttachment ? `A potentially malicious attachment (${email.attachments[0]?.filename}) was included, likely containing a dropper or exploit payload.` : ''}

The social engineering techniques employed (${(email.body?.social_engineering_flags || []).map(f => f.flag).join(', ') || 'urgency manipulation'}) are designed to pressure the victim into taking action without careful consideration.`;
  }

  _becNarrative(email, detection) {
    const becIntents = detection.bec_analysis?.intents_detected || [];
    return `ATTACK NARRATIVE: Business Email Compromise (BEC) Attack Detected.

The attacker is ${email.sender?.anomalies?.some(a => a.type === 'display_name_domain_mismatch') ? 'impersonating a trusted executive or business contact' : 'using a potentially compromised email account'} to conduct financial fraud.

${becIntents.includes('financial_fraud') ? 'The email contains wire transfer instructions or banking details — a clear indicator of BEC financial fraud attempting to redirect legitimate business payments.' : ''}
${becIntents.includes('gift_card_fraud') ? 'The email requests gift card purchases — a common BEC tactic used when wire transfers are unavailable.' : ''}
${becIntents.includes('invoice_fraud') ? 'Fraudulent invoice or payment change request detected — attacker attempting to intercept business payments.' : ''}
${becIntents.includes('credential_theft') ? 'Credential harvesting component detected — attacker may also be attempting to steal login credentials for further compromise.' : ''}

${email.sender?.anomalies?.some(a => a.type === 'from_reply_to_domain_mismatch') ? 'The Reply-To address has been manipulated so that victim responses go to the attacker-controlled mailbox rather than the impersonated sender.' : ''}`;
  }

  _malwareNarrative(email, detection) {
    const attachment = email.attachments?.[0];
    return `ATTACK NARRATIVE: Malware Delivery Campaign.

This email is part of a malware delivery operation. ${attachment ? `The malicious payload is embedded in the attachment "${attachment.filename}" (${attachment.extension?.toUpperCase()} file, ${attachment.threat_level} risk).` : ''}

${attachment?.flags?.includes('double_extension_attack') ? 'The file uses a double-extension attack technique (e.g., document.pdf.exe) to disguise an executable as a benign document.' : ''}
${attachment?.extension === 'docm' || attachment?.extension === 'xlsm' ? 'The macro-enabled Office document likely contains VBA macros that execute malicious code upon opening.' : ''}

${(email.body?.urls?.length || 0) > 0 ? 'The email also contains URLs that may serve as secondary payload delivery vectors or command-and-control beacons.' : ''}

Victim action required: Simply opening the attachment or clicking the link would trigger the malicious payload.`;
  }

  _credentialNarrative(email) {
    return `ATTACK NARRATIVE: Credential Harvesting Attack.

The attacker has created a convincing email designed to steal user credentials. The email uses ${email.body?.social_engineering_flags?.map(f => f.flag).join(', ') || 'social engineering'} to manipulate the victim into clicking a malicious link.

The destination URL ${(email.body?.urls || []).find(u => u.is_suspicious)?.deobfuscated ? `(${(email.body.urls.find(u => u.is_suspicious)).deobfuscated.substring(0, 80)}...)` : ''} likely hosts a phishing page designed to capture credentials and potentially perform session hijacking.`;
  }

  _genericNarrative(email, detection) {
    return `THREAT SUMMARY: Suspicious email with ${detection.detections?.length || 0} detection rule(s) triggered. Risk score: ${0}/100. Full analysis required.`;
  }

  _explainIndicators(email, enrichment) {
    const explained = [];

    // IPs
    for (const [ip, data] of Object.entries(enrichment?.ips || {})) {
      explained.push({
        type: 'ip_address',
        value: ip,
        context: `IP ${ip} — ${data.abuseipdb?.isp || 'Unknown ISP'}, ${data.abuseipdb?.country || 'Unknown Country'}`,
        threat: data.combined_reputation,
        detail: data.abuseipdb?.abuse_score > 50
          ? `AbuseIPDB Score: ${data.abuseipdb.abuse_score}/100 (${data.abuseipdb.total_reports} reports)`
          : 'No significant abuse history found'
      });
    }

    // Domains
    for (const [domain, data] of Object.entries(enrichment?.domains || {})) {
      explained.push({
        type: 'domain',
        value: domain,
        threat: data.combined_reputation,
        context: `Domain ${domain}`,
        detail: data.virustotal?.categories ? `Categorized as: ${Object.values(data.virustotal.categories).join(', ')}` : 'No category data'
      });
    }

    // Hashes
    for (const [hash, data] of Object.entries(enrichment?.hashes || {})) {
      if (data?.virustotal?.found) {
        explained.push({
          type: 'file_hash',
          value: hash.substring(0, 16) + '...',
          threat: data.combined_reputation,
          context: `File: ${data.virustotal.name || 'unknown'}`,
          detail: `VirusTotal: ${data.virustotal.detection_ratio}, Threat names: ${(data.virustotal.threat_names || []).join(', ') || 'none'}`
        });
      }
    }

    return explained;
  }

  _generateWhyFlagged(detection, risk) {
    const reasons = [];

    if (detection.detections?.some(d => d.severity === 'critical')) {
      reasons.push({
        priority: 1,
        reason: 'Critical threat detection rules triggered',
        detail: detection.detections.filter(d => d.severity === 'critical').map(d => d.name)
      });
    }

    if (risk.breakdown?.auth?.score > 15) {
      reasons.push({
        priority: 2,
        reason: 'Email authentication failures',
        detail: [`SPF: ${risk.breakdown.auth.details.spf || 'pass'}`, `DKIM: ${risk.breakdown.auth.details.dkim || 'pass'}`, `DMARC: ${risk.breakdown.auth.details.dmarc || 'pass'}`].filter(s => !s.includes('pass'))
      });
    }

    if (risk.breakdown?.ai?.score > 20) {
      reasons.push({
        priority: 3,
        reason: `AI classification: ${detection.ai_classification?.threat_type} (${detection.ai_classification?.confidence}% confidence)`,
        detail: [detection.ai_classification?.explanation || 'AI model identified suspicious patterns']
      });
    }

    if (risk.breakdown?.threat_intel?.malicious_count > 0) {
      reasons.push({
        priority: 4,
        reason: 'Malicious indicators matched threat intelligence',
        detail: [`${risk.breakdown.threat_intel.malicious_count} indicators matched known malicious sources`]
      });
    }

    return reasons.sort((a, b) => a.priority - b.priority);
  }

  _generateAnalystNotes(email, detection, risk) {
    const notes = [];

    if (risk.tier === 'critical') {
      notes.push({ type: 'action', note: 'IMMEDIATE ACTION REQUIRED: Quarantine email and notify affected user(s)' });
    }

    if (detection.final_verdict?.primary_type === 'bec') {
      notes.push({ type: 'warning', note: 'BEC ATTACK: Contact the supposed sender via known-good channel to verify any financial requests before processing' });
    }

    if (email.attachments?.some(a => a.sha256)) {
      notes.push({ type: 'investigation', note: `Detonate attachment hashes in sandbox: ${email.attachments.map(a => a.sha256?.substring(0, 16)).filter(Boolean).join(', ')}` });
    }

    if ((email.body?.urls?.length || 0) > 0) {
      notes.push({ type: 'investigation', note: 'Submit suspicious URLs to URLScan.io for screenshot and behavior analysis' });
    }

    if (email.routing?.originating_ip) {
      notes.push({ type: 'investigation', note: `Investigate originating IP ${email.routing.originating_ip} in threat intelligence platforms` });
    }

    notes.push({ type: 'context', note: `Email received at ${email.received_at}, message ID: ${email.message_id}` });

    return notes;
  }

  _assessFalsePositive(email, detection, risk) {
    const indicators_for_fp = [];
    const indicators_against_fp = [];

    // For FP
    if (email.auth?.spf === 'pass') indicators_for_fp.push('SPF passed — sender might be legitimate');
    if (email.auth?.dkim === 'pass') indicators_for_fp.push('DKIM passed — email integrity verified');
    if (!email.attachments?.length) indicators_for_fp.push('No attachments');
    if (risk.breakdown?.rules?.by_severity?.critical === 0) indicators_for_fp.push('No critical rules triggered');

    // Against FP
    if (email.auth?.spf === 'fail') indicators_against_fp.push('SPF hard fail strongly indicates spoofing');
    if (detection.detections?.some(d => d.severity === 'critical')) indicators_against_fp.push('Critical detection rules fired');
    if (email.domain_analysis?.lookalike_count > 0) indicators_against_fp.push('Lookalike domain confirmed');
    if (detection.bec_analysis?.is_bec) indicators_against_fp.push('BEC behavioral analysis confirms fraud pattern');

    const fp_probability = indicators_for_fp.length / (indicators_for_fp.length + indicators_against_fp.length + 1) * 100;

    return {
      fp_probability: Math.round(fp_probability),
      assessment: fp_probability < 15 ? 'Very likely a real threat' :
                  fp_probability < 35 ? 'Probably a real threat' :
                  fp_probability < 60 ? 'Uncertain — manual review recommended' : 'Possible false positive',
      factors_suggesting_fp: indicators_for_fp,
      factors_against_fp: indicators_against_fp
    };
  }

  _explainMitre(techniques) {
    return techniques.map(t => ({
      technique_id: t.technique_id,
      sub_technique_id: t.sub_technique_id,
      name: t.name,
      tactic: t.tactic,
      confidence: t.confidence,
      explanation: this._getMitreExplanation(t.technique_id, t.sub_technique_id)
    }));
  }

  _getMitreExplanation(technique, sub) {
    const explanations = {
      'T1566': 'Adversaries may send phishing messages to gain access to victim systems',
      'T1566.001': 'Phishing attachment: Email contains malicious file attachment',
      'T1566.002': 'Phishing link: Email contains malicious URL redirecting to phishing site',
      'T1204': 'Attacker relies on user to execute malicious content',
      'T1204.002': 'User must open the malicious file attachment to trigger execution',
      'T1056': 'Adversary attempts to capture user credentials',
      'T1556': 'Account manipulation or credential access in email context',
      'T1036.005': 'Masquerading — using lookalike domain/filename to appear legitimate',
      'T1071.003': 'Using email protocols for command-and-control communication',
      'T1105': 'Ingress tool transfer — delivering malicious tools via email'
    };
    return explanations[sub] || explanations[technique] || 'See MITRE ATT&CK framework for details';
  }
}

const EXPLANATION_TEMPLATES = {}; // Extensible template store


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 2: Email Attack Graph Intelligence
// ═══════════════════════════════════════════════════════════════════════════

class AttackGraphEngine {
  constructor() {
    this.nodes = new Map();  // node_id -> node
    this.edges = [];         // {from, to, relationship, weight}
    this.campaigns = new Map();
    this.node_counter = 0;
  }

  /**
   * Add a processed email to the attack graph
   * Automatically detects relationships and campaign clustering
   */
  addEmail(parsedEmail, detectionResult, enrichmentResult) {
    const emailNode = this._createEmailNode(parsedEmail, detectionResult);
    this.nodes.set(emailNode.id, emailNode);

    // Add sender node
    const senderNode = this._getOrCreateNode('sender', parsedEmail.sender?.domain || parsedEmail.sender?.address, {
      address: parsedEmail.sender?.address,
      domain: parsedEmail.sender?.domain,
      display_name: parsedEmail.sender?.display_name
    });
    this.edges.push({ from: senderNode.id, to: emailNode.id, relationship: 'sent', weight: 1 });

    // Add IP nodes
    for (const ip of parsedEmail.indicators?.ips || []) {
      const ipNode = this._getOrCreateNode('ip', ip, {
        ip,
        reputation: enrichmentResult?.ips?.[ip]?.combined_reputation,
        abuse_score: enrichmentResult?.ips?.[ip]?.abuseipdb?.abuse_score
      });
      this.edges.push({ from: ipNode.id, to: emailNode.id, relationship: 'originated_from', weight: 2 });
    }

    // Add domain nodes
    for (const domain of parsedEmail.indicators?.domains || []) {
      const domNode = this._getOrCreateNode('domain', domain, {
        domain,
        reputation: enrichmentResult?.domains?.[domain]?.combined_reputation
      });
      this.edges.push({ from: emailNode.id, to: domNode.id, relationship: 'contains_domain', weight: 1 });
    }

    // Add attachment hash nodes
    for (const att of parsedEmail.attachments || []) {
      if (att.sha256) {
        const hashNode = this._getOrCreateNode('file_hash', att.sha256, {
          hash: att.sha256,
          filename: att.filename,
          threat_level: att.threat_level,
          vt_score: enrichmentResult?.hashes?.[att.sha256]?.virustotal?.detection_ratio
        });
        this.edges.push({ from: emailNode.id, to: hashNode.id, relationship: 'carries_payload', weight: 3 });
      }
    }

    // Add URL nodes
    for (const url of (parsedEmail.body?.urls || []).filter(u => u.is_suspicious)) {
      const urlNode = this._getOrCreateNode('url', url.deobfuscated, {
        url: url.deobfuscated,
        techniques: url.techniques
      });
      this.edges.push({ from: emailNode.id, to: urlNode.id, relationship: 'links_to', weight: 2 });
    }

    // ── Campaign detection ──
    this._detectCampaigns(emailNode);

    return {
      email_node_id: emailNode.id,
      connected_nodes: this._getConnectedNodes(emailNode.id),
      campaign_id: emailNode.campaign_id || null
    };
  }

  _createEmailNode(email, detection) {
    const id = `email_${email.message_id?.replace(/[<>@]/g, '_') || Date.now()}`;
    return {
      id,
      type: 'email',
      label: email.subject?.substring(0, 50) || '(no subject)',
      threat_type: detection.final_verdict?.primary_type,
      risk_tier: detection.final_verdict?.threat_level,
      confidence: detection.final_verdict?.confidence,
      timestamp: email.received_at,
      campaign_id: null
    };
  }

  _getOrCreateNode(type, identifier, attributes) {
    const id = `${type}_${crypto.createHash('md5').update(String(identifier)).digest('hex').substring(0, 8)}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, { id, type, identifier, ...attributes, first_seen: new Date().toISOString(), occurrence_count: 0 });
    }
    const node = this.nodes.get(id);
    node.occurrence_count++;
    node.last_seen = new Date().toISOString();
    return node;
  }

  _detectCampaigns(emailNode) {
    // Find emails sharing indicators
    const relatedNodes = this._getConnectedNodes(emailNode.id);
    const campaignIndicators = relatedNodes.filter(n => ['ip', 'domain', 'file_hash'].includes(n.type) && n.occurrence_count > 1);

    if (campaignIndicators.length > 0) {
      // Find or create campaign
      let campaignId = null;
      for (const [cId, campaign] of this.campaigns) {
        if (campaignIndicators.some(n => campaign.indicator_ids.has(n.id))) {
          campaignId = cId;
          campaign.email_count++;
          campaign.indicator_ids = new Set([...campaign.indicator_ids, ...campaignIndicators.map(n => n.id)]);
          break;
        }
      }

      if (!campaignId) {
        campaignId = `CAMPAIGN-${Date.now().toString(36).toUpperCase()}`;
        this.campaigns.set(campaignId, {
          id: campaignId,
          email_count: 1,
          indicator_ids: new Set(campaignIndicators.map(n => n.id)),
          first_seen: new Date().toISOString(),
          last_seen: new Date().toISOString(),
          threat_type: emailNode.threat_type
        });
      }

      emailNode.campaign_id = campaignId;
      this.campaigns.get(campaignId).last_seen = new Date().toISOString();
    }
  }

  _getConnectedNodes(nodeId) {
    const connected = [];
    for (const edge of this.edges) {
      if (edge.from === nodeId && this.nodes.has(edge.to)) connected.push(this.nodes.get(edge.to));
      if (edge.to === nodeId && this.nodes.has(edge.from)) connected.push(this.nodes.get(edge.from));
    }
    return connected;
  }

  /**
   * Export graph for visualization (D3.js / vis.js compatible)
   */
  exportForVisualization(limit = 200) {
    const nodeList = [...this.nodes.values()].slice(0, limit);
    const nodeIds = new Set(nodeList.map(n => n.id));
    const edgeList = this.edges.filter(e => nodeIds.has(e.from) && nodeIds.has(e.to)).slice(0, limit * 2);

    return {
      nodes: nodeList.map(n => ({
        id: n.id,
        label: this._getNodeLabel(n),
        type: n.type,
        color: this._getNodeColor(n),
        size: Math.min(20 + (n.occurrence_count || 0) * 3, 50),
        data: n
      })),
      edges: edgeList.map((e, i) => ({
        id: `edge_${i}`,
        from: e.from,
        to: e.to,
        label: e.relationship,
        weight: e.weight
      })),
      stats: {
        total_nodes: this.nodes.size,
        total_edges: this.edges.length,
        campaigns: this.campaigns.size,
        node_types: this._countNodeTypes()
      }
    };
  }

  _getNodeLabel(node) {
    if (node.type === 'email') return node.label;
    if (node.type === 'ip') return node.ip;
    if (node.type === 'domain') return node.domain;
    if (node.type === 'file_hash') return `${node.filename || 'hash'}\n${node.hash?.substring(0, 8)}...`;
    if (node.type === 'url') return node.url?.substring(0, 40) + '...';
    if (node.type === 'sender') return node.address || node.domain;
    return node.identifier;
  }

  _getNodeColor(node) {
    const colors = {
      email: '#007AFF',
      ip: node.reputation === 'malicious' ? '#FF3B30' : node.reputation === 'suspicious' ? '#FF9500' : '#34C759',
      domain: node.reputation === 'malicious' ? '#FF3B30' : '#AF52DE',
      file_hash: node.threat_level === 'critical' ? '#FF2D55' : '#FF6B35',
      url: '#5AC8FA',
      sender: '#FFD60A'
    };
    return colors[node.type] || '#8E8E93';
  }

  _countNodeTypes() {
    const counts = {};
    for (const node of this.nodes.values()) {
      counts[node.type] = (counts[node.type] || 0) + 1;
    }
    return counts;
  }

  getCampaigns() {
    return [...this.campaigns.values()].map(c => ({
      ...c,
      indicator_ids: [...c.indicator_ids]
    }));
  }
}


// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 3: Behavioral Identity Fingerprinting (NOVEL)
// Creates a cryptographic multi-dimensional behavioral profile for each
// sender identity. Detects account takeover, sender compromise, and
// impersonation through behavioral drift analysis.
// ═══════════════════════════════════════════════════════════════════════════

class BehavioralIdentityFingerprinter {
  constructor() {
    this.profiles = new Map();  // sender_key -> BehavioralProfile
    this.alerts = [];
    this.drift_threshold = 0.6;  // 60% behavioral change triggers alert
  }

  /**
   * Process email and update/create sender behavioral profile
   * Returns behavioral analysis with drift detection
   */
  processEmail(parsedEmail) {
    const senderKey = parsedEmail.sender?.address?.toLowerCase() || 'unknown';
    const fingerprint = this._extractFingerprint(parsedEmail);

    let profile = this.profiles.get(senderKey);
    const isNewProfile = !profile;

    if (!profile) {
      profile = this._createProfile(senderKey, fingerprint, parsedEmail);
      this.profiles.set(senderKey, profile);
      return { is_new: true, profile_established: true, fingerprint, drift_score: 0, alerts: [] };
    }

    // ── Compare fingerprint to established profile ──
    const driftAnalysis = this._analyzeDrift(profile, fingerprint);
    const alerts = this._generateDriftAlerts(senderKey, driftAnalysis, profile, parsedEmail);

    // ── Update profile (rolling average) ──
    this._updateProfile(profile, fingerprint);

    // ── Store alerts ──
    if (alerts.length > 0) {
      this.alerts.push(...alerts.map(a => ({ ...a, timestamp: new Date().toISOString() })));
    }

    return {
      is_new: false,
      sender: senderKey,
      fingerprint,
      drift_score: driftAnalysis.overall_drift,
      drift_dimensions: driftAnalysis.dimensions,
      alerts,
      profile_summary: this._summarizeProfile(profile),
      anomaly_detected: driftAnalysis.overall_drift > this.drift_threshold
    };
  }

  /**
   * Extract multi-dimensional behavioral fingerprint from email
   */
  _extractFingerprint(email) {
    return {
      // Temporal patterns
      send_hour: new Date(email.received_at || Date.now()).getHours(),
      send_day: new Date(email.received_at || Date.now()).getDay(),

      // Authentication pattern
      auth_pattern: this._hashAuthPattern(email.auth),

      // Routing pattern
      hop_count: email.routing?.hop_count || 0,
      originating_ip_prefix: email.routing?.originating_ip?.split('.').slice(0, 2).join('.') || 'unknown',

      // Communication style metrics
      subject_length: (email.subject || '').length,
      body_length: (email.body?.text || '').length,
      url_count: (email.body?.urls || []).length,
      attachment_count: (email.attachments || []).length,

      // Language patterns (simplified)
      uppercase_ratio: this._calcUppercaseRatio(email.subject || ''),
      punctuation_density: this._calcPunctuationDensity(email.body?.text || ''),

      // Recipient patterns
      recipient_count: (email.recipients?.to?.length || 0) + (email.recipients?.cc?.length || 0),

      // Mailer fingerprint
      x_mailer: email.sender?.x_mailer || 'unknown',
      content_type_signature: email.body?.html ? 'html' : 'text',

      // Reply-to behavior
      uses_different_reply_to: !!(email.sender?.reply_to && email.sender?.reply_to !== email.sender?.address),

      // Domain age category (estimated from routing)
      domain_class: this._classifyDomain(email.sender?.domain)
    };
  }

  _hashAuthPattern(auth) {
    const pattern = `${auth?.spf?.[0] || 'n'}${auth?.dkim?.[0] || 'n'}${auth?.dmarc?.[0] || 'n'}`;
    return pattern;
  }

  _calcUppercaseRatio(text) {
    if (!text || text.length === 0) return 0;
    const upper = (text.match(/[A-Z]/g) || []).length;
    const letters = (text.match(/[a-zA-Z]/g) || []).length;
    return letters > 0 ? Math.round((upper / letters) * 100) : 0;
  }

  _calcPunctuationDensity(text) {
    if (!text || text.length === 0) return 0;
    const punct = (text.match(/[!?.,;:]/g) || []).length;
    return Math.round((punct / text.length) * 1000);  // per 1000 chars
  }

  _classifyDomain(domain) {
    if (!domain) return 'unknown';
    const freeDomains = new Set(['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']);
    if (freeDomains.has(domain)) return 'free';
    return 'business';
  }

  _createProfile(senderKey, fingerprint, email) {
    return {
      sender: senderKey,
      established_at: new Date().toISOString(),
      email_count: 1,
      fingerprint_history: [fingerprint],
      baseline: { ...fingerprint },
      averages: { ...fingerprint },
      auth_pattern_history: new Set([fingerprint.auth_pattern]),
      ip_prefix_history: new Set([fingerprint.originating_ip_prefix]),
      mailer_history: new Set([fingerprint.x_mailer]),
      known_reply_to: fingerprint.uses_different_reply_to,
      last_updated: new Date().toISOString()
    };
  }

  _analyzeDrift(profile, fingerprint) {
    const dimensions = {};

    // Authentication pattern drift (HIGH RISK)
    if (!profile.auth_pattern_history.has(fingerprint.auth_pattern)) {
      dimensions.auth_pattern = {
        drift: 1.0,
        severity: 'critical',
        description: `Authentication pattern changed from established ${[...profile.auth_pattern_history].join('/')} to ${fingerprint.auth_pattern}`,
        expected: [...profile.auth_pattern_history].join('/'),
        observed: fingerprint.auth_pattern
      };
    } else {
      dimensions.auth_pattern = { drift: 0, severity: 'none' };
    }

    // IP origin drift (HIGH RISK)
    if (!profile.ip_prefix_history.has(fingerprint.originating_ip_prefix) &&
        fingerprint.originating_ip_prefix !== 'unknown') {
      dimensions.ip_origin = {
        drift: 0.8,
        severity: 'high',
        description: `New originating IP subnet: ${fingerprint.originating_ip_prefix}.x.x (previous: ${[...profile.ip_prefix_history].slice(-3).join(', ')})`,
        expected: [...profile.ip_prefix_history].slice(-3),
        observed: fingerprint.originating_ip_prefix
      };
    } else {
      dimensions.ip_origin = { drift: 0, severity: 'none' };
    }

    // Reply-To behavior change (MEDIUM-HIGH RISK)
    if (fingerprint.uses_different_reply_to !== profile.known_reply_to) {
      dimensions.reply_to_behavior = {
        drift: 0.9,
        severity: 'high',
        description: `Reply-To behavior changed: ${!profile.known_reply_to ? 'sender now using different reply-to (NEW - BEC indicator)' : 'reply-to manipulation removed'}`,
        expected: profile.known_reply_to,
        observed: fingerprint.uses_different_reply_to
      };
    } else {
      dimensions.reply_to_behavior = { drift: 0, severity: 'none' };
    }

    // Mailer fingerprint change (MEDIUM RISK)
    if (!profile.mailer_history.has(fingerprint.x_mailer) && fingerprint.x_mailer !== 'unknown') {
      dimensions.mailer = {
        drift: 0.6,
        severity: 'medium',
        description: `Email client changed from ${[...profile.mailer_history].join('/')} to ${fingerprint.x_mailer}`,
        expected: [...profile.mailer_history],
        observed: fingerprint.x_mailer
      };
    } else {
      dimensions.mailer = { drift: 0, severity: 'none' };
    }

    // Send time anomaly (LOW-MEDIUM RISK)
    const avg_hour = profile.averages.send_hour;
    const hour_diff = Math.abs(fingerprint.send_hour - avg_hour);
    const normalized_hour_diff = Math.min(hour_diff, 24 - hour_diff) / 12;
    if (normalized_hour_diff > 0.5) {
      dimensions.send_time = {
        drift: normalized_hour_diff,
        severity: 'low',
        description: `Unusual send time: ${fingerprint.send_hour}:00 (typical: ~${Math.round(avg_hour)}:00)`,
        expected: avg_hour,
        observed: fingerprint.send_hour
      };
    } else {
      dimensions.send_time = { drift: 0, severity: 'none' };
    }

    // Content style drift (LOW RISK)
    const body_len_ratio = profile.averages.body_length > 0
      ? Math.abs(fingerprint.body_length - profile.averages.body_length) / profile.averages.body_length
      : 0;
    if (body_len_ratio > 2.0 && profile.email_count > 5) {  // Extreme body length change
      dimensions.content_style = {
        drift: Math.min(body_len_ratio / 3, 1),
        severity: 'low',
        description: `Unusual email body length: ${fingerprint.body_length} chars (typical: ~${Math.round(profile.averages.body_length)} chars)`,
        expected: profile.averages.body_length,
        observed: fingerprint.body_length
      };
    } else {
      dimensions.content_style = { drift: 0, severity: 'none' };
    }

    // Compute overall drift (weighted)
    const weights = { auth_pattern: 0.35, ip_origin: 0.25, reply_to_behavior: 0.20, mailer: 0.10, send_time: 0.05, content_style: 0.05 };
    const overall_drift = Object.entries(dimensions).reduce((sum, [key, d]) => sum + (d.drift || 0) * (weights[key] || 0.1), 0);

    return { dimensions, overall_drift: Math.round(overall_drift * 100) / 100 };
  }

  _generateDriftAlerts(senderKey, driftAnalysis, profile, email) {
    const alerts = [];

    for (const [dim, data] of Object.entries(driftAnalysis.dimensions)) {
      if (data.drift >= 0.6) {
        alerts.push({
          type: 'behavioral_drift',
          dimension: dim,
          severity: data.severity,
          sender: senderKey,
          message: data.description,
          drift_score: data.drift,
          mitre_technique: dim === 'auth_pattern' || dim === 'ip_origin' ? 'T1078' : 'T1566',
          recommendation: this._getDriftRecommendation(dim, data.severity)
        });
      }
    }

    if (driftAnalysis.overall_drift > this.drift_threshold) {
      alerts.push({
        type: 'account_takeover_suspected',
        severity: 'critical',
        sender: senderKey,
        message: `HIGH BEHAVIORAL DRIFT (${Math.round(driftAnalysis.overall_drift * 100)}%): Sender behavior significantly deviates from established profile — possible account takeover`,
        drift_score: driftAnalysis.overall_drift,
        mitre_technique: 'T1078',
        recommendation: 'Immediately verify sender identity through out-of-band communication'
      });
    }

    return alerts;
  }

  _getDriftRecommendation(dimension, severity) {
    const recommendations = {
      auth_pattern: 'Investigate authentication infrastructure changes — could indicate email gateway compromise',
      ip_origin: 'Verify if sender is traveling or using a VPN — if unexpected, treat as potential account takeover',
      reply_to_behavior: 'Do NOT reply to this email — verify sender identity via phone before responding',
      mailer: 'Check if sender changed email client — could indicate account access from different device',
      send_time: 'Unusual send time may indicate automated sending or different time zone access',
      content_style: 'Significant writing style change — verify if authentic or ghostwritten/automated'
    };
    return recommendations[dimension] || 'Manual review recommended';
  }

  _updateProfile(profile, fingerprint) {
    profile.email_count++;
    profile.last_updated = new Date().toISOString();
    profile.fingerprint_history.push(fingerprint);
    if (profile.fingerprint_history.length > 50) profile.fingerprint_history.shift();

    // Update rolling averages
    const alpha = 0.2;  // Exponential moving average factor
    for (const key of ['send_hour', 'hop_count', 'subject_length', 'body_length', 'url_count', 'attachment_count', 'recipient_count', 'uppercase_ratio', 'punctuation_density']) {
      if (typeof fingerprint[key] === 'number') {
        profile.averages[key] = profile.averages[key] * (1 - alpha) + fingerprint[key] * alpha;
      }
    }

    // Update sets (keep last 10 unique values)
    profile.auth_pattern_history.add(fingerprint.auth_pattern);
    if (profile.auth_pattern_history.size > 5) {
      profile.auth_pattern_history.delete([...profile.auth_pattern_history][0]);
    }
    profile.ip_prefix_history.add(fingerprint.originating_ip_prefix);
    if (profile.ip_prefix_history.size > 10) {
      profile.ip_prefix_history.delete([...profile.ip_prefix_history][0]);
    }
    profile.mailer_history.add(fingerprint.x_mailer);
  }

  _summarizeProfile(profile) {
    return {
      sender: profile.sender,
      emails_analyzed: profile.email_count,
      established_at: profile.established_at,
      typical_send_hour: Math.round(profile.averages.send_hour),
      typical_body_length: Math.round(profile.averages.body_length),
      known_auth_patterns: [...profile.auth_pattern_history],
      known_ip_subnets: [...profile.ip_prefix_history].slice(-5),
      known_mailers: [...profile.mailer_history]
    };
  }

  getProfile(senderAddress) {
    const key = senderAddress?.toLowerCase();
    const profile = this.profiles.get(key);
    if (!profile) return null;
    return this._summarizeProfile(profile);
  }

  getAlerts(limit = 50) {
    return this.alerts.slice(-limit).reverse();
  }

  getStats() {
    return {
      total_profiles: this.profiles.size,
      total_alerts: this.alerts.length,
      high_risk_senders: this.alerts.filter(a => a.type === 'account_takeover_suspected').length
    };
  }
}

module.exports = {
  AIExplainabilityEngine,
  AttackGraphEngine,
  BehavioralIdentityFingerprinter
};
