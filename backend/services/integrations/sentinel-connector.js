/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Microsoft Sentinel Connector (Phase 6)
 *  backend/services/integrations/sentinel-connector.js
 *
 *  Sends alerts/incidents to Microsoft Sentinel via:
 *  • Log Analytics Workspace REST API (CEF/JSON ingestion)
 *  • Sentinel Incidents API (Microsoft Security Graph)
 *  • Azure Monitor Data Collection Endpoint (DCE/DCR)
 *
 *  Audit finding: No SIEM integration for Sentinel/Splunk/XSOAR
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const crypto = require('crypto');

// ── Configuration ─────────────────────────────────────────────────
const SENTINEL_WORKSPACE_ID  = () => process.env.SENTINEL_WORKSPACE_ID;
const SENTINEL_SHARED_KEY    = () => process.env.SENTINEL_SHARED_KEY;
const SENTINEL_LOG_TYPE      = process.env.SENTINEL_LOG_TYPE || 'WadjetEyeAlerts';
const SENTINEL_CLIENT_ID     = () => process.env.SENTINEL_CLIENT_ID;
const SENTINEL_CLIENT_SECRET = () => process.env.SENTINEL_CLIENT_SECRET;
const SENTINEL_TENANT_ID     = () => process.env.SENTINEL_TENANT_ID;
const SENTINEL_SUB_ID        = () => process.env.SENTINEL_SUBSCRIPTION_ID;
const SENTINEL_RG            = () => process.env.SENTINEL_RESOURCE_GROUP;
const SENTINEL_WORKSPACE_NAME= () => process.env.SENTINEL_WORKSPACE_NAME;

// DCE endpoint for new-generation ingestion (preferred)
const SENTINEL_DCE_ENDPOINT  = () => process.env.SENTINEL_DCE_ENDPOINT;
const SENTINEL_DCR_RULE_ID   = () => process.env.SENTINEL_DCR_RULE_ID;
const SENTINEL_STREAM_NAME   = () => process.env.SENTINEL_STREAM_NAME || 'Custom-WadjetEyeAlerts_CL';

// ── HTTP helper ───────────────────────────────────────────────────
function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: text });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── OAuth2 token cache ────────────────────────────────────────────
let _tokenCache = null;
let _tokenExpiry = 0;

async function getOAuthToken() {
  if (_tokenCache && Date.now() < _tokenExpiry - 60000) return _tokenCache;

  const body = new URLSearchParams({
    grant_type:    'client_credentials',
    client_id:     SENTINEL_CLIENT_ID(),
    client_secret: SENTINEL_CLIENT_SECRET(),
    scope:         'https://management.azure.com/.default',
  }).toString();

  const options = {
    hostname: 'login.microsoftonline.com',
    path:     `/${SENTINEL_TENANT_ID()}/oauth2/v2.0/token`,
    method:   'POST',
    headers:  {
      'Content-Type':   'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const req = https.request(options, (res) => {
    const chunks = [];
    res.on('data', c => chunks.push(c));
    res.on('end', () => {
      const data = JSON.parse(Buffer.concat(chunks).toString());
      _tokenCache = data.access_token;
      _tokenExpiry = Date.now() + (data.expires_in * 1000);
    });
  });
  req.write(body);
  req.end();

  return new Promise((resolve, reject) => {
    req.on('close', () => resolve(_tokenCache));
    req.on('error', reject);
  });
}

// ── Log Analytics Workspace Data Collector API ────────────────────
// Uses HMAC-SHA256 signature authentication (legacy but widely supported)

function buildSignature(workspaceId, sharedKey, date, contentLength, method, contentType, resource) {
  const stringToHash = `${method}\n${contentLength}\n${contentType}\nx-ms-date:${date}\n${resource}`;
  const bytesToHash  = Buffer.from(stringToHash, 'utf8');
  const keyBytes     = Buffer.from(sharedKey, 'base64');
  const sha256       = crypto.createHmac('sha256', keyBytes).update(bytesToHash).digest('base64');
  return `SharedKey ${workspaceId}:${sha256}`;
}

/**
 * sendToLogAnalytics — send JSON events to Log Analytics Workspace
 * @param {object[]} events - Array of event objects
 * @param {string} logType  - Custom log table name (appended with _CL)
 */
async function sendToLogAnalytics(events, logType = SENTINEL_LOG_TYPE) {
  const workspaceId = SENTINEL_WORKSPACE_ID();
  const sharedKey   = SENTINEL_SHARED_KEY();

  if (!workspaceId || !sharedKey) {
    throw new Error('SENTINEL_WORKSPACE_ID and SENTINEL_SHARED_KEY required');
  }

  const body        = JSON.stringify(Array.isArray(events) ? events : [events]);
  const contentLength = Buffer.byteLength(body, 'utf8');
  const rfcDate     = new Date().toUTCString();
  const contentType = 'application/json';
  const resource    = '/api/logs';

  const signature = buildSignature(
    workspaceId, sharedKey, rfcDate, contentLength, 'POST', contentType, resource
  );

  const options = {
    hostname: `${workspaceId}.ods.opinsights.azure.com`,
    path:     `${resource}?api-version=2016-04-01`,
    method:   'POST',
    headers: {
      'Content-Type':     contentType,
      'Log-Type':         logType,
      'Authorization':    signature,
      'x-ms-date':        rfcDate,
      'Content-Length':   contentLength,
      'time-generated-field': 'TimeGenerated',
    },
  };

  const result = await httpsRequest(options, null);

  if (result.status === 200 || result.status === 202) {
    return { success: true, status: result.status, events_sent: Array.isArray(events) ? events.length : 1 };
  }
  throw new Error(`Sentinel Log Analytics rejected request: HTTP ${result.status} — ${result.body}`);
}

// ── DCE/DCR Ingestion API (new-generation) ────────────────────────
/**
 * sendViaDCE — ingests events via Data Collection Endpoint (newer, preferred)
 * Requires: SENTINEL_DCE_ENDPOINT, SENTINEL_DCR_RULE_ID, SENTINEL_STREAM_NAME
 */
async function sendViaDCE(events) {
  const dceEndpoint = SENTINEL_DCE_ENDPOINT();
  const dcrRuleId   = SENTINEL_DCR_RULE_ID();
  const streamName  = SENTINEL_STREAM_NAME();

  if (!dceEndpoint || !dcrRuleId || !streamName) {
    throw new Error('SENTINEL_DCE_ENDPOINT, SENTINEL_DCR_RULE_ID, SENTINEL_STREAM_NAME required');
  }

  const token   = await getOAuthToken();
  const body    = JSON.stringify(Array.isArray(events) ? events : [events]);
  const url     = new URL(`${dceEndpoint}/dataCollectionRules/${dcrRuleId}/streams/${streamName}?api-version=2023-01-01`);

  const options = {
    hostname: url.hostname,
    path:     url.pathname + url.search,
    method:   'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const result = await httpsRequest(options, null);
  const req = https.request(options);
  req.write(body);
  req.end();

  if (result.status === 200 || result.status === 204) {
    return { success: true, method: 'dce', events_sent: Array.isArray(events) ? events.length : 1 };
  }
  throw new Error(`DCE ingestion failed: HTTP ${result.status} — ${result.body}`);
}

// ── Alert → Sentinel format transformer ──────────────────────────

/**
 * alertToSentinelFormat — convert Wadjet-Eye alert to Sentinel CEF-compatible JSON
 */
function alertToSentinelFormat(alert) {
  return {
    TimeGenerated:       alert.created_at || new Date().toISOString(),
    AlertId:             alert.id,
    TenantId:            alert.tenant_id,
    AlertName:           alert.title,
    Description:         alert.description || '',
    Severity:            mapSeverityToSentinel(alert.severity),
    Status:              alert.status,
    RiskScore:           alert.risk_score || 0,
    Confidence:          alert.confidence || 0,
    Category:            alert.category || '',
    MitreTactic:         alert.mitre_tactic || '',
    MitreTechnique:      alert.mitre_technique || '',
    AffectedHost:        alert.host || '',
    AffectedUser:        alert.username || '',
    SourceIP:            alert.source_ip || '',
    DetectionSource:     alert.detection_source || 'wadjet-eye-raykan',
    RuleId:              alert.rule_id || '',
    RuleName:            alert.rule_name || '',
    Tags:                (alert.tags || []).join(','),
    IncidentId:          alert.incident_id || '',
    AISummary:           alert.ai_summary || '',
    EventTime:           alert.event_time || alert.created_at,
    EnrichedData:        JSON.stringify(alert.enrichment_data || {}),
    WadjetEyeVersion:    '4.1.0',
    DataSource:          'WadjetEyeAI',
  };
}

function mapSeverityToSentinel(severity) {
  const map = {
    critical:       'High',
    high:           'High',
    medium:         'Medium',
    low:            'Low',
    informational:  'Informational',
    unknown:        'Unknown',
  };
  return map[severity] || 'Unknown';
}

// ── Sentinel Incident creation (Security Graph) ───────────────────

/**
 * createSentinelIncident — create an incident in Sentinel via Security Graph API
 */
async function createSentinelIncident(incident) {
  const subId     = SENTINEL_SUB_ID();
  const rg        = SENTINEL_RG();
  const workspace = SENTINEL_WORKSPACE_NAME();

  if (!subId || !rg || !workspace) {
    throw new Error('SENTINEL_SUBSCRIPTION_ID, SENTINEL_RESOURCE_GROUP, SENTINEL_WORKSPACE_NAME required');
  }

  const token = await getOAuthToken();
  const incidentId = `wadjet-${incident.id || Date.now()}`;
  const apiPath  = `/subscriptions/${subId}/resourceGroups/${rg}/providers/Microsoft.OperationalInsights/workspaces/${workspace}/providers/Microsoft.SecurityInsights/incidents/${incidentId}?api-version=2023-02-01`;

  const body = {
    properties: {
      title:       incident.title,
      description: incident.description || incident.ai_narrative || '',
      severity:    mapSeverityToSentinel(incident.severity),
      status:      'New',
      labels:      (incident.mitre_tactics || []).map(t => ({ labelName: t })),
      additionalData: {
        alertsCount: incident.alert_count || 0,
        affectedHosts: incident.affected_hosts || [],
        affectedUsers: incident.affected_users || [],
        wadjetIncidentId: incident.id,
      },
    },
  };

  const bodyStr = JSON.stringify(body);
  const options = {
    hostname: 'management.azure.com',
    path:     apiPath,
    method:   'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
      'Content-Length': Buffer.byteLength(bodyStr),
    },
  };

  const result = await httpsRequest(options, body);
  if (result.status === 200 || result.status === 201) {
    return { success: true, sentinel_incident_id: incidentId };
  }
  throw new Error(`Sentinel incident creation failed: HTTP ${result.status} — ${result.body}`);
}

// ── Batch forwarding ──────────────────────────────────────────────

/**
 * forwardAlerts — forward batch of alerts to Sentinel
 * @param {object[]} alerts   - Wadjet-Eye alert objects
 * @param {object}   options  - { useDCE: boolean }
 */
async function forwardAlerts(alerts, options = {}) {
  if (!alerts || alerts.length === 0) return { success: true, forwarded: 0 };

  const sentinelAlerts = alerts.map(alertToSentinelFormat);

  // Split into batches of 500 (Sentinel limit)
  const BATCH_SIZE = 500;
  const results = [];

  for (let i = 0; i < sentinelAlerts.length; i += BATCH_SIZE) {
    const batch = sentinelAlerts.slice(i, i + BATCH_SIZE);
    try {
      if (options.useDCE && SENTINEL_DCE_ENDPOINT()) {
        results.push(await sendViaDCE(batch));
      } else {
        results.push(await sendToLogAnalytics(batch));
      }
    } catch (err) {
      console.error('[Sentinel] Batch failed:', err.message);
      results.push({ success: false, error: err.message, batch_size: batch.length });
    }
  }

  const succeeded = results.filter(r => r.success).reduce((sum, r) => sum + (r.events_sent || 0), 0);
  const failed    = results.filter(r => !r.success).length;

  return {
    success:   failed === 0,
    forwarded: succeeded,
    batches:   results.length,
    errors:    failed,
  };
}

// ── Health check ──────────────────────────────────────────────────
async function healthCheck() {
  try {
    const hasWorkspace = !!(SENTINEL_WORKSPACE_ID() && SENTINEL_SHARED_KEY());
    const hasDCE       = !!(SENTINEL_DCE_ENDPOINT() && SENTINEL_DCR_RULE_ID());
    const hasGraph     = !!(SENTINEL_CLIENT_ID() && SENTINEL_CLIENT_SECRET() && SENTINEL_TENANT_ID());

    return {
      healthy: hasWorkspace || hasDCE,
      methods: {
        log_analytics: hasWorkspace,
        dce_ingestion: hasDCE,
        security_graph: hasGraph,
      },
    };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

module.exports = {
  sendToLogAnalytics,
  sendViaDCE,
  createSentinelIncident,
  forwardAlerts,
  alertToSentinelFormat,
  healthCheck,
};
