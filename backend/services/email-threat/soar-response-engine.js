/**
 * ETI-AARE SOAR Response Engine v1.0
 * Automated Security Orchestration, Automation and Response
 * Actions: quarantine, block sender/IP/domain, notify, create incident, isolate user
 */

'use strict';

const crypto = require('crypto');

// ─── Response Action Types ────────────────────────────────────────────────────
const ACTION_TYPES = {
  QUARANTINE: 'quarantine_email',
  BLOCK_SENDER: 'block_sender',
  BLOCK_DOMAIN: 'block_domain',
  BLOCK_IP: 'block_ip',
  BLOCK_URL: 'block_url',
  NOTIFY_USER: 'notify_user',
  NOTIFY_SOC: 'notify_soc',
  CREATE_INCIDENT: 'create_incident',
  ISOLATE_USER: 'isolate_user',
  FORCE_MFA: 'force_mfa_reset',
  SCAN_MAILBOX: 'scan_mailbox',
  PURGE_SIMILAR: 'purge_similar_emails',
  THREAT_HUNT: 'trigger_threat_hunt'
};

// ─── Response Playbooks (decision trees) ─────────────────────────────────────
const RESPONSE_PLAYBOOKS = {
  'critical_phishing': {
    id: 'PB-PHISH-CRIT',
    name: 'Critical Phishing Response',
    description: 'Automated response for high-confidence phishing with malicious indicators',
    trigger: (risk, detection) =>
      risk.tier === 'critical' && detection.final_verdict.primary_type === 'phishing',
    actions: [
      { type: ACTION_TYPES.QUARANTINE, priority: 1, auto: true },
      { type: ACTION_TYPES.BLOCK_SENDER, priority: 2, auto: true },
      { type: ACTION_TYPES.PURGE_SIMILAR, priority: 3, auto: true, desc: 'Remove similar emails from all mailboxes' },
      { type: ACTION_TYPES.NOTIFY_SOC, priority: 4, auto: true },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 5, auto: true, severity: 'critical' },
      { type: ACTION_TYPES.SCAN_MAILBOX, priority: 6, auto: false, requires_approval: true }
    ],
    mitre_techniques: ['T1566.001', 'T1566.002']
  },

  'bec_response': {
    id: 'PB-BEC-001',
    name: 'Business Email Compromise Response',
    description: 'Response playbook for detected BEC attacks',
    trigger: (risk, detection) =>
      detection.final_verdict.primary_type === 'bec' ||
      detection.detections?.some(d => d.type === 'bec'),
    actions: [
      { type: ACTION_TYPES.QUARANTINE, priority: 1, auto: true },
      { type: ACTION_TYPES.NOTIFY_SOC, priority: 2, auto: true, urgency: 'immediate' },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 3, auto: true, severity: 'critical', category: 'BEC' },
      { type: ACTION_TYPES.BLOCK_SENDER, priority: 4, auto: true },
      { type: ACTION_TYPES.NOTIFY_USER, priority: 5, auto: false, message: 'Potential BEC attack detected targeting your account' },
      { type: ACTION_TYPES.FORCE_MFA, priority: 6, auto: false, requires_approval: true }
    ],
    mitre_techniques: ['T1556', 'T1566.001']
  },

  'malware_delivery': {
    id: 'PB-MAL-001',
    name: 'Malware Delivery Response',
    description: 'Response for emails delivering malicious attachments',
    trigger: (risk, detection) =>
      detection.final_verdict.primary_type === 'malware_delivery' ||
      detection.detections?.some(d => d.type === 'malware_delivery'),
    actions: [
      { type: ACTION_TYPES.QUARANTINE, priority: 1, auto: true },
      { type: ACTION_TYPES.BLOCK_SENDER, priority: 2, auto: true },
      { type: ACTION_TYPES.BLOCK_DOMAIN, priority: 3, auto: true },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 4, auto: true, severity: 'critical', category: 'Malware' },
      { type: ACTION_TYPES.SCAN_MAILBOX, priority: 5, auto: true, desc: 'Scan for similar malware attachments' },
      { type: ACTION_TYPES.THREAT_HUNT, priority: 6, auto: false, requires_approval: true }
    ],
    mitre_techniques: ['T1566.001', 'T1204.002', 'T1105']
  },

  'high_risk_phishing': {
    id: 'PB-PHISH-HIGH',
    name: 'High Risk Phishing Response',
    description: 'Response for high confidence phishing without confirmed malicious intel',
    trigger: (risk, detection) =>
      risk.tier === 'high' && detection.final_verdict.primary_type === 'phishing',
    actions: [
      { type: ACTION_TYPES.QUARANTINE, priority: 1, auto: true },
      { type: ACTION_TYPES.NOTIFY_SOC, priority: 2, auto: true },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 3, auto: true, severity: 'high' },
      { type: ACTION_TYPES.BLOCK_SENDER, priority: 4, auto: false, requires_approval: true }
    ],
    mitre_techniques: ['T1566']
  },

  'malicious_intel': {
    id: 'PB-INTEL-001',
    name: 'Malicious Threat Intel Match',
    description: 'Response when email indicators match known malicious threat intel',
    trigger: (risk, detection, enrichment) =>
      enrichment?.summary?.threat_intel_score > 70,
    actions: [
      { type: ACTION_TYPES.QUARANTINE, priority: 1, auto: true },
      { type: ACTION_TYPES.BLOCK_IP, priority: 2, auto: true },
      { type: ACTION_TYPES.BLOCK_DOMAIN, priority: 3, auto: true },
      { type: ACTION_TYPES.BLOCK_URL, priority: 4, auto: true },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 5, auto: true, severity: 'critical', category: 'TI-Match' }
    ],
    mitre_techniques: ['T1566', 'T1071']
  },

  'suspicious_monitoring': {
    id: 'PB-MON-001',
    name: 'Suspicious Email Monitoring',
    description: 'Soft response for medium-risk suspicious emails',
    trigger: (risk) => risk.tier === 'medium',
    actions: [
      { type: ACTION_TYPES.NOTIFY_SOC, priority: 1, auto: true, urgency: 'normal' },
      { type: ACTION_TYPES.CREATE_INCIDENT, priority: 2, auto: true, severity: 'medium' }
    ],
    mitre_techniques: ['T1566']
  }
};

// ─── Incident Generator ───────────────────────────────────────────────────────
class IncidentGenerator {
  static create(email, detection, risk, enrichment, triggeredPlaybook) {
    const id = `INC-ETI-${Date.now().toString(36).toUpperCase()}`;
    const severity = risk.tier.toUpperCase();

    return {
      incident_id: id,
      title: this._generateTitle(email, detection),
      description: this._generateDescription(email, detection, risk),
      severity,
      status: 'open',
      category: this._determineCategory(detection),
      source: 'ETI-AARE',
      email_metadata: {
        message_id: email.message_id,
        from: email.sender?.address,
        subject: email.subject,
        received_at: email.received_at
      },
      risk_score: risk.final_score,
      mitre_techniques: detection.mitre_techniques?.map(t => t.technique_id) || [],
      indicators: email.indicators,
      threat_intel_hits: enrichment?.threat_context?.length || 0,
      playbook_id: triggeredPlaybook?.id,
      assigned_to: null,
      sla_deadline: risk.sla_minutes ? new Date(Date.now() + risk.sla_minutes * 60000).toISOString() : null,
      created_at: new Date().toISOString(),
      timeline: [
        {
          ts: new Date().toISOString(),
          event: 'incident_created',
          detail: `Auto-created by ETI-AARE with risk score ${risk.final_score}`
        }
      ],
      tags: this._generateTags(email, detection, risk)
    };
  }

  static _generateTitle(email, detection) {
    const type = detection.final_verdict?.primary_type?.replace(/_/g, ' ').toUpperCase();
    const sender = email.sender?.address || 'unknown';
    return `[${type}] Suspicious email from ${sender} - "${(email.subject || '').substring(0, 60)}"`;
  }

  static _generateDescription(email, detection, risk) {
    const rules = (detection.detections || []).map(d => `• ${d.name} (${d.severity})`).join('\n');
    return `Email Threat Intelligence Analysis:

Risk Score: ${risk.final_score}/100 (${risk.tier.toUpperCase()})
Threat Type: ${detection.final_verdict?.primary_type}
AI Classification: ${detection.ai_classification?.threat_type} (${detection.ai_classification?.confidence}% confidence)

From: ${email.sender?.address} (Display: ${email.sender?.display_name})
Subject: ${email.subject}
Authentication: SPF=${email.auth?.spf} DKIM=${email.auth?.dkim} DMARC=${email.auth?.dmarc}

Triggered Detection Rules:
${rules || '• No specific rules'}

Recommended Action: ${risk.recommended_action}`;
  }

  static _determineCategory(detection) {
    const type = detection.final_verdict?.primary_type;
    const categories = {
      phishing: 'Phishing',
      bec: 'Business Email Compromise',
      malware_delivery: 'Malware',
      credential_harvesting: 'Credential Theft',
      c2: 'Command & Control',
      spam: 'Spam'
    };
    return categories[type] || 'Suspicious Email';
  }

  static _generateTags(email, detection, risk) {
    const tags = [risk.tier, detection.final_verdict?.primary_type];
    if (email.attachments?.length > 0) tags.push('has_attachment');
    if (email.body?.urls?.length > 0) tags.push('has_url');
    if (email.auth?.spf === 'fail') tags.push('spf_fail');
    if (email.auth?.dmarc === 'fail') tags.push('dmarc_fail');
    detection.mitre_techniques?.forEach(t => tags.push(t.technique_id));
    return tags.filter(Boolean);
  }
}

// ─── SOAR Response Engine ─────────────────────────────────────────────────────
class SOARResponseEngine {
  constructor(config = {}) {
    this.playbooks = { ...RESPONSE_PLAYBOOKS };
    this.integrations = config.integrations || {};
    this.auto_response_enabled = config.auto_response_enabled !== false;
    this.dry_run = config.dry_run || false;
    this.blocklists = {
      senders: new Set(),
      domains: new Set(),
      ips: new Set(),
      urls: new Set()
    };
    this.quarantine = new Map(); // message_id -> quarantine record
    this.incidents = new Map();
    this.action_log = [];
  }

  /**
   * Execute automated response based on risk and detection results
   */
  async respond(parsedEmail, detectionResult, riskScore, enrichmentResult) {
    const response = {
      email_id: parsedEmail.message_id,
      triggered_playbooks: [],
      executed_actions: [],
      pending_actions: [],
      incident: null,
      blocklist_updates: [],
      response_time: Date.now()
    };

    // ── Select playbooks ──
    const triggered = this._selectPlaybooks(riskScore, detectionResult, enrichmentResult);
    response.triggered_playbooks = triggered.map(p => ({ id: p.id, name: p.name }));

    // ── Execute actions ──
    for (const playbook of triggered) {
      for (const action of playbook.actions.sort((a, b) => a.priority - b.priority)) {
        const result = await this._executeAction(action, parsedEmail, detectionResult, riskScore, enrichmentResult, playbook);
        if (result.auto_executed) {
          response.executed_actions.push(result);
        } else {
          response.pending_actions.push(result);
        }
      }
    }

    // ── Deduplicate ──
    response.executed_actions = this._deduplicateActions(response.executed_actions);
    response.pending_actions = this._deduplicateActions(response.pending_actions);

    // ── Create incident (if any playbook triggered) ──
    if (triggered.length > 0 && riskScore.tier !== 'clean') {
      response.incident = IncidentGenerator.create(
        parsedEmail, detectionResult, riskScore, enrichmentResult, triggered[0]
      );
      this.incidents.set(response.incident.incident_id, response.incident);
    }

    response.response_time = Date.now() - response.response_time;
    this.action_log.push({ ts: new Date().toISOString(), email_id: parsedEmail.message_id, response });

    return response;
  }

  _selectPlaybooks(risk, detection, enrichment) {
    const triggered = [];
    for (const [key, pb] of Object.entries(this.playbooks)) {
      try {
        if (pb.trigger(risk, detection, enrichment)) {
          triggered.push(pb);
        }
      } catch {}
    }
    // Sort by specificity (more specific playbooks first)
    return triggered.sort((a, b) => b.actions.length - a.actions.length).slice(0, 2);
  }

  async _executeAction(action, email, detection, risk, enrichment, playbook) {
    const actionRecord = {
      type: action.type,
      playbook_id: playbook.id,
      auto_executed: action.auto && this.auto_response_enabled,
      requires_approval: action.requires_approval || false,
      status: 'pending',
      result: null,
      executed_at: null
    };

    if (!action.auto || !this.auto_response_enabled) {
      actionRecord.status = 'awaiting_approval';
      return actionRecord;
    }

    // ── Execute auto actions ──
    try {
      actionRecord.executed_at = new Date().toISOString();

      switch (action.type) {
        case ACTION_TYPES.QUARANTINE:
          actionRecord.result = await this._quarantineEmail(email);
          break;
        case ACTION_TYPES.BLOCK_SENDER:
          actionRecord.result = this._blockSender(email.sender?.address, email.sender?.domain);
          break;
        case ACTION_TYPES.BLOCK_DOMAIN:
          actionRecord.result = this._blockDomains(email.indicators?.domains || []);
          break;
        case ACTION_TYPES.BLOCK_IP:
          actionRecord.result = this._blockIps(email.indicators?.ips || []);
          break;
        case ACTION_TYPES.BLOCK_URL:
          actionRecord.result = this._blockUrls(email.indicators?.urls || []);
          break;
        case ACTION_TYPES.NOTIFY_SOC:
          actionRecord.result = await this._notifySOC(email, detection, risk, playbook, action);
          break;
        case ACTION_TYPES.CREATE_INCIDENT:
          actionRecord.result = { incident_created: true, via: 'respond_method' };
          break;
        case ACTION_TYPES.PURGE_SIMILAR:
          actionRecord.result = this._schedulePurgeSimilar(email);
          break;
        case ACTION_TYPES.SCAN_MAILBOX:
          actionRecord.result = this._scheduleMailboxScan(email);
          break;
        default:
          actionRecord.result = { note: 'action_scheduled_for_manual_review' };
      }
      actionRecord.status = this.dry_run ? 'dry_run' : 'executed';
    } catch (err) {
      actionRecord.status = 'failed';
      actionRecord.error = err.message;
    }

    return actionRecord;
  }

  async _quarantineEmail(email) {
    const record = {
      message_id: email.message_id,
      from: email.sender?.address,
      subject: email.subject,
      quarantined_at: new Date().toISOString(),
      status: 'quarantined',
      reason: 'ETI-AARE automated response'
    };
    this.quarantine.set(email.message_id, record);
    return { quarantined: true, record };
  }

  _blockSender(address, domain) {
    const blocked = [];
    if (address) { this.blocklists.senders.add(address); blocked.push({ type: 'sender', value: address }); }
    if (domain) { this.blocklists.domains.add(domain); blocked.push({ type: 'domain', value: domain }); }
    return { blocked };
  }

  _blockDomains(domains) {
    const blocked = [];
    for (const d of domains) { this.blocklists.domains.add(d); blocked.push(d); }
    return { blocked_domains: blocked };
  }

  _blockIps(ips) {
    const blocked = [];
    for (const ip of ips) { this.blocklists.ips.add(ip); blocked.push(ip); }
    return { blocked_ips: blocked };
  }

  _blockUrls(urls) {
    const blocked = [];
    for (const url of urls) { this.blocklists.urls.add(url); blocked.push(url); }
    return { blocked_urls: blocked };
  }

  async _notifySOC(email, detection, risk, playbook, action) {
    const notification = {
      channel: 'soc_dashboard',
      urgency: action.urgency || 'normal',
      title: `[${risk.tier.toUpperCase()}] Email Threat Detected`,
      message: `Risk Score: ${risk.final_score} | Type: ${detection.final_verdict?.primary_type} | From: ${email.sender?.address}`,
      playbook: playbook.name,
      timestamp: new Date().toISOString()
    };

    // Emit to real-time if integration available
    if (this.integrations.realtime?.emit) {
      this.integrations.realtime.emit('email_threat', notification);
    }

    return { notified: true, notification };
  }

  _schedulePurgeSimilar(email) {
    return {
      scheduled: true,
      task: 'purge_similar_emails',
      criteria: { sender_domain: email.sender?.domain, subject_pattern: email.subject?.substring(0, 30) }
    };
  }

  _scheduleMailboxScan(email) {
    return {
      scheduled: true,
      task: 'mailbox_scan',
      criteria: { hashes: email.indicators?.hashes, domains: email.indicators?.domains }
    };
  }

  _deduplicateActions(actions) {
    const seen = new Set();
    return actions.filter(a => {
      if (seen.has(a.type)) return false;
      seen.add(a.type);
      return true;
    });
  }

  // ── Query Methods ──────────────────────────────────────────────────────────

  getBlocklists() {
    return {
      senders: [...this.blocklists.senders],
      domains: [...this.blocklists.domains],
      ips: [...this.blocklists.ips],
      urls: [...this.blocklists.urls],
      totals: {
        senders: this.blocklists.senders.size,
        domains: this.blocklists.domains.size,
        ips: this.blocklists.ips.size,
        urls: this.blocklists.urls.size
      }
    };
  }

  getQuarantine() {
    return [...this.quarantine.values()];
  }

  getIncidents() {
    return [...this.incidents.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
  }

  getActionLog(limit = 50) {
    return this.action_log.slice(-limit).reverse();
  }

  isBlocked(indicator) {
    return this.blocklists.senders.has(indicator) ||
           this.blocklists.domains.has(indicator) ||
           this.blocklists.ips.has(indicator) ||
           this.blocklists.urls.has(indicator);
  }

  releaseFromQuarantine(messageId, analystNote) {
    const record = this.quarantine.get(messageId);
    if (!record) return { success: false, error: 'not_found' };
    record.status = 'released';
    record.released_at = new Date().toISOString();
    record.analyst_note = analystNote;
    return { success: true, record };
  }
}

module.exports = { SOARResponseEngine, IncidentGenerator, RESPONSE_PLAYBOOKS, ACTION_TYPES };
