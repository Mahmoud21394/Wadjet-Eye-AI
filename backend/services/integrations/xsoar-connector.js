/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Palo Alto XSOAR Connector (Phase 6)
 *  backend/services/integrations/xsoar-connector.js
 *
 *  Integrates with Palo Alto XSOAR (Cortex XSOAR) REST API:
 *  • Create incidents from Wadjet-Eye alerts
 *  • Trigger playbooks on incidents
 *  • Sync incident status back to Wadjet-Eye
 *  • CEF event forwarding
 *
 *  Audit finding: No SIEM/SOAR integration
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');

// ── Configuration ─────────────────────────────────────────────────
const XSOAR_BASE_URL  = () => process.env.XSOAR_BASE_URL || 'https://xsoar.company.com';
const XSOAR_API_KEY   = () => process.env.XSOAR_API_KEY;
const XSOAR_API_KEY_ID = () => process.env.XSOAR_API_KEY_ID;  // For standard auth
const XSOAR_VERIFY_SSL = process.env.XSOAR_VERIFY_SSL !== 'false';

// ── HTTP client ───────────────────────────────────────────────────
async function xsoarRequest(method, path, body = null) {
  const apiKey = XSOAR_API_KEY();
  if (!apiKey) throw new Error('XSOAR_API_KEY not configured');

  const baseUrl  = XSOAR_BASE_URL();
  const parsed   = new URL(`${baseUrl}${path}`);
  const transport = parsed.protocol === 'https:' ? https : http;

  // XSOAR supports two auth schemes:
  // 1. Standard: Authorization: <api-key>
  // 2. Advanced: x-xdr-auth-id + x-xdr-nonce + x-xdr-timestamp (hash-based)
  const apiKeyId = XSOAR_API_KEY_ID();
  let authHeaders;

  if (apiKeyId) {
    // Advanced auth (Cortex XDR / XSOAR 8+)
    const nonce   = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now().toString();
    const authString = apiKey + nonce + timestamp;
    const authHash  = crypto.createHash('sha256').update(authString).digest('hex');
    authHeaders = {
      'x-xdr-auth-id':   apiKeyId,
      'x-xdr-nonce':     nonce,
      'x-xdr-timestamp': timestamp,
      'x-xdr-hmac-sha256': authHash,
    };
  } else {
    // Standard auth
    authHeaders = { 'Authorization': apiKey };
  }

  const payload = body ? JSON.stringify(body) : null;

  return new Promise((resolve, reject) => {
    const options = {
      hostname:           parsed.hostname,
      port:               parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:               parsed.pathname + parsed.search,
      method,
      rejectUnauthorized: XSOAR_VERIFY_SSL,
      headers: {
        'Content-Type': 'application/json',
        'Accept':       'application/json',
        ...authHeaders,
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    };

    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        try {
          const data = text ? JSON.parse(text) : {};
          if (res.statusCode >= 400) {
            reject(new Error(`XSOAR HTTP ${res.statusCode}: ${JSON.stringify(data)}`));
          } else {
            resolve(data);
          }
        } catch (_) {
          if (res.statusCode >= 400) {
            reject(new Error(`XSOAR HTTP ${res.statusCode}: ${text}`));
          } else {
            resolve({ raw: text });
          }
        }
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Severity mapping ──────────────────────────────────────────────
const SEVERITY_MAP = {
  critical:      4,  // XSOAR: 0=Unknown 0.5=Informational 1=Low 2=Medium 3=High 4=Critical
  high:          3,
  medium:        2,
  low:           1,
  informational: 0.5,
  unknown:       0,
};

// ── Incident management ───────────────────────────────────────────

/**
 * createIncident — create an XSOAR incident from a Wadjet-Eye alert/incident
 * @param {object} alert   - Wadjet-Eye alert object
 * @param {object} options - { playbook_id, auto_close }
 */
async function createIncident(alert, options = {}) {
  const incidentPayload = {
    name:          `[WadjetEye] ${alert.title}`,
    type:          mapTypeToXSOAR(alert.category),
    severity:      SEVERITY_MAP[alert.severity] || 0,
    details:       buildIncidentDetails(alert),
    occurred:      alert.event_time || alert.created_at || new Date().toISOString(),
    owner:         '',    // Leave unassigned — let XSOAR routing decide
    labels: [
      { type: 'Source',          value: 'WadjetEye-AI' },
      { type: 'TenantId',        value: alert.tenant_id || 'unknown' },
      { type: 'AlertId',         value: alert.id || 'unknown' },
      { type: 'MitreTactic',     value: alert.mitre_tactic || '' },
      { type: 'MitreTechnique',  value: alert.mitre_technique || '' },
      { type: 'RiskScore',       value: String(alert.risk_score || 0) },
      { type: 'DetectionSource', value: alert.detection_source || 'raykan' },
    ],
    ...(options.playbook_id ? { playbookId: options.playbook_id } : {}),
    rawJSON: JSON.stringify({
      alert_id:        alert.id,
      tenant_id:       alert.tenant_id,
      severity:        alert.severity,
      risk_score:      alert.risk_score,
      confidence:      alert.confidence,
      mitre_tactic:    alert.mitre_tactic,
      mitre_technique: alert.mitre_technique,
      host:            alert.host,
      username:        alert.username,
      source_ip:       alert.source_ip,
      ioc_count:       alert.ioc_count,
      tags:            alert.tags,
      ai_summary:      alert.ai_summary,
      evidence:        alert.evidence,
    }),
  };

  const result = await xsoarRequest('POST', '/incident', incidentPayload);
  console.log(`[XSOAR] Incident created: ${result.id} for alert ${alert.id}`);
  return { success: true, xsoar_incident_id: result.id, incident: result };
}

function buildIncidentDetails(alert) {
  const lines = [
    `**Source:** Wadjet-Eye AI v4.1.0`,
    `**Alert ID:** ${alert.id}`,
    `**Severity:** ${alert.severity?.toUpperCase()} (Risk Score: ${alert.risk_score}/100)`,
    `**Confidence:** ${alert.confidence}%`,
    '',
    `**MITRE ATT&CK:**`,
    `  - Tactic: ${alert.mitre_tactic || 'N/A'}`,
    `  - Technique: ${alert.mitre_technique || 'N/A'}`,
    '',
    `**Affected Entities:**`,
    `  - Host: ${alert.host || 'N/A'}`,
    `  - User: ${alert.username || 'N/A'}`,
    `  - Source IP: ${alert.source_ip || 'N/A'}`,
    '',
    alert.ai_summary ? `**AI Analysis:**\n${alert.ai_summary}` : '',
    '',
    `**Detection Rule:** ${alert.rule_name || alert.rule_id || 'N/A'}`,
    `**Tags:** ${(alert.tags || []).join(', ')}`,
  ];
  return lines.filter(Boolean).join('\n');
}

function mapTypeToXSOAR(category) {
  const typeMap = {
    'malware':           'Malware',
    'ransomware':        'Malware',
    'lateral-movement':  'Network',
    'credential-access': 'Authentication',
    'exfiltration':      'Data Exfiltration',
    'phishing':          'Phishing',
    'vulnerability':     'Vulnerability',
    'insider-threat':    'Insider Threat',
    'brute-force':       'Authentication',
    'command-control':   'Network',
    'reconnaissance':    'Network',
  };
  const cat = (category || '').toLowerCase().replace(/\s+/g, '-');
  return typeMap[cat] || 'Unclassified';
}

// ── Playbook execution ────────────────────────────────────────────

/**
 * runPlaybook — trigger an XSOAR playbook on an existing incident
 * @param {string} xsoarIncidentId - XSOAR incident ID
 * @param {string} playbookId      - XSOAR playbook ID or name
 */
async function runPlaybook(xsoarIncidentId, playbookId) {
  const result = await xsoarRequest('POST', `/incident/investigate`, {
    id:         xsoarIncidentId,
    version:    1,
    playbookId,
  });
  return { success: true, task_id: result.id };
}

// ── Incident status sync ──────────────────────────────────────────

/**
 * getIncidentStatus — fetch current status of an XSOAR incident
 */
async function getIncidentStatus(xsoarIncidentId) {
  const result = await xsoarRequest('GET', `/incident/${xsoarIncidentId}`);
  return {
    id:     result.id,
    status: result.status,
    owner:  result.owner,
    closed: result.closed || null,
    reason: result.closeReason,
    notes:  result.closeNotes,
  };
}

/**
 * closeIncident — close an XSOAR incident
 */
async function closeIncident(xsoarIncidentId, reason, notes) {
  return xsoarRequest('POST', `/incident/close`, {
    id:          xsoarIncidentId,
    closeReason: reason || 'Resolved',
    closeNotes:  notes || 'Closed by Wadjet-Eye AI',
  });
}

// ── Batch forwarding ──────────────────────────────────────────────

/**
 * forwardAlerts — create XSOAR incidents for multiple alerts
 * Only forwards alerts meeting the severity threshold.
 */
async function forwardAlerts(alerts, options = {}) {
  const minSeverity = options.minSeverity || 'medium';
  const SEVERITY_ORDER = ['unknown', 'informational', 'low', 'medium', 'high', 'critical'];
  const minIdx = SEVERITY_ORDER.indexOf(minSeverity);

  const toForward = alerts.filter(a =>
    SEVERITY_ORDER.indexOf(a.severity) >= minIdx
  );

  const results = [];
  for (const alert of toForward) {
    try {
      const result = await createIncident(alert, options);
      results.push({ alert_id: alert.id, ...result });
    } catch (err) {
      console.error(`[XSOAR] Failed to forward alert ${alert.id}:`, err.message);
      results.push({ alert_id: alert.id, success: false, error: err.message });
    }
  }

  return {
    total:     alerts.length,
    forwarded: results.filter(r => r.success).length,
    skipped:   alerts.length - toForward.length,
    failed:    results.filter(r => !r.success).length,
    results,
  };
}

// ── Search incidents ──────────────────────────────────────────────

/**
 * searchIncidents — search XSOAR incidents by filter
 */
async function searchIncidents(filter = {}, page = 0, size = 100) {
  return xsoarRequest('POST', '/incidents/search', {
    filter: {
      query:        filter.query || '-status:Closed',
      ...filter,
    },
    fromDate:     filter.fromDate || '',
    toDate:       filter.toDate || '',
    page,
    size,
    sort: [{ field: 'created', asc: false }],
  });
}

// ── Health check ──────────────────────────────────────────────────
async function healthCheck() {
  try {
    if (!XSOAR_API_KEY()) {
      return { healthy: false, error: 'XSOAR_API_KEY not configured' };
    }
    // Lightweight call: fetch XSOAR server info
    const info = await xsoarRequest('GET', '/about');
    return {
      healthy:       true,
      version:       info.version || 'unknown',
      xsoar_base:    XSOAR_BASE_URL(),
    };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

module.exports = {
  createIncident,
  runPlaybook,
  getIncidentStatus,
  closeIncident,
  forwardAlerts,
  searchIncidents,
  healthCheck,
};
