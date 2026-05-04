/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Splunk HEC + Sentinel + XSOAR Connectors (Phase 6)
 *  backend/services/integrations/splunk-connector.js
 *
 *  Implements:
 *  • Splunk HTTP Event Collector (HEC) — alert/event forwarding
 *  • Microsoft Sentinel Log Analytics API — CEF event ingestion
 *  • XSOAR REST API — incident/playbook creation
 *  • CEF/Syslog collector server (UDP/TCP)
 *  • Generic webhook connector
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const https  = require('https');
const http   = require('http');
const crypto = require('crypto');
const dgram  = require('dgram');
const net    = require('net');
const config = require('../../config');

// ══════════════════════════════════════════════════════════════════
//  SPLUNK HEC CONNECTOR
// ══════════════════════════════════════════════════════════════════

class SplunkConnector {
  constructor(opts = {}) {
    this.url      = opts.url   || config.splunk.hecUrl;
    this.token    = opts.token || config.splunk.hecToken;
    this.index    = opts.index || config.splunk.index || 'main';
    this.source   = opts.source || 'wadjet-eye';
    this.sourcetype = opts.sourcetype || '_json';
    this.batchSize  = opts.batchSize  || 100;
    this._queue   = [];
    this._flushTimer = null;
    this.enabled  = !!(this.url && this.token);
  }

  // ── Send single event ─────────────────────────────────────────
  async sendEvent(event, opts = {}) {
    if (!this.enabled) return { sent: false, reason: 'HEC not configured' };

    const payload = this._buildPayload(event, opts);
    return this._post('/services/collector/event', payload);
  }

  // ── Send alert as Splunk event ────────────────────────────────
  async sendAlert(alert) {
    return this.sendEvent({
      time:       new Date(alert.created_at || Date.now()).getTime() / 1000,
      host:       alert.source_host || 'wadjet-eye',
      source:     this.source,
      sourcetype: 'wadjet:alert',
      index:      this.index,
      event: {
        alert_id:       alert.id,
        severity:       alert.severity,
        category:       alert.category,
        title:          alert.title,
        description:    alert.description,
        tenant_id:      alert.tenant_id,
        src_ip:         alert.src_ip,
        dst_ip:         alert.dst_ip,
        mitre_tactic:   alert.mitre_tactic,
        mitre_technique: alert.mitre_technique,
        iocs:           alert.iocs || [],
        confidence:     alert.confidence,
        rule_id:        alert.rule_id,
        ts:             alert.created_at,
      },
    });
  }

  // ── Batch send ────────────────────────────────────────────────
  async sendBatch(events) {
    if (!this.enabled) return { sent: 0, failed: 0 };

    const batches  = [];
    for (let i = 0; i < events.length; i += this.batchSize) {
      batches.push(events.slice(i, i + this.batchSize));
    }

    let sent = 0, failed = 0;
    for (const batch of batches) {
      const payload = batch
        .map(e => JSON.stringify(this._buildPayload(e)))
        .join('\n');

      const res = await this._rawPost('/services/collector/event', payload);
      if (res.ok) sent += batch.length;
      else failed += batch.length;
    }

    return { sent, failed };
  }

  // ── Queue with auto-flush ────────────────────────────────────
  queue(event) {
    this._queue.push(event);
    if (this._queue.length >= this.batchSize) {
      this._flush();
    } else if (!this._flushTimer) {
      this._flushTimer = setTimeout(() => this._flush(), 5000);
    }
  }

  async _flush() {
    clearTimeout(this._flushTimer);
    this._flushTimer = null;
    if (this._queue.length === 0) return;
    const batch = this._queue.splice(0, this._queue.length);
    await this.sendBatch(batch);
  }

  _buildPayload(event, opts = {}) {
    if (event.event !== undefined) return event; // already formatted
    return {
      time:       Math.floor(Date.now() / 1000),
      host:       'wadjet-eye',
      source:     this.source,
      sourcetype: opts.sourcetype || this.sourcetype,
      index:      opts.index      || this.index,
      event,
    };
  }

  async _post(path, payload) {
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return this._rawPost(path, body);
  }

  _rawPost(path, body) {
    return new Promise((resolve) => {
      const parsed  = new URL(this.url);
      const isHttps = parsed.protocol === 'https:';
      const reqLib  = isHttps ? https : http;

      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     path,
        method:   'POST',
        timeout:  15000,
        headers: {
          'Authorization':  `Splunk ${this.token}`,
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-Splunk-Request-Channel': crypto.randomUUID(),
        },
        rejectUnauthorized: process.env.SPLUNK_VERIFY_SSL !== 'false',
      };

      const req = reqLib.request(options, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString());
            resolve({ ok: res.statusCode === 200, status: res.statusCode, data });
          } catch {
            resolve({ ok: res.statusCode === 200, status: res.statusCode });
          }
        });
      });

      req.on('error',   err => resolve({ ok: false, error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'HEC timeout' }); });
      req.write(body);
      req.end();
    });
  }
}

// ══════════════════════════════════════════════════════════════════
//  MICROSOFT SENTINEL CONNECTOR (Log Analytics API)
// ══════════════════════════════════════════════════════════════════

class SentinelConnector {
  constructor(opts = {}) {
    this.workspaceId = opts.workspaceId || config.sentinel.workspaceId;
    this.primaryKey  = opts.primaryKey  || config.sentinel.primaryKey;
    this.logType     = opts.logType     || config.sentinel.logType;
    this.enabled     = !!(this.workspaceId && this.primaryKey);
  }

  // ── Build HMAC-SHA256 signature for Log Analytics ─────────────
  _buildSignature(date, contentLength) {
    const stringToSign = `POST\n${contentLength}\napplication/json\nx-ms-date:${date}\n/api/logs`;
    const key = Buffer.from(this.primaryKey, 'base64');
    const hmac = crypto.createHmac('sha256', key).update(stringToSign, 'utf8').digest('base64');
    return `SharedKey ${this.workspaceId}:${hmac}`;
  }

  // ── Send log batch ────────────────────────────────────────────
  async sendLogs(records, opts = {}) {
    if (!this.enabled) return { sent: false, reason: 'Sentinel not configured' };

    const logType = opts.logType || this.logType;
    const body    = JSON.stringify(Array.isArray(records) ? records : [records]);
    const date    = new Date().toUTCString();
    const sig     = this._buildSignature(date, Buffer.byteLength(body));
    const uri     = `${this.workspaceId}.ods.opinsights.azure.com`;

    return new Promise((resolve) => {
      const options = {
        hostname: uri,
        port:     443,
        path:     '/api/logs?api-version=2016-04-01',
        method:   'POST',
        timeout:  20000,
        headers: {
          'Content-Type':    'application/json',
          'Log-Type':        logType,
          'Authorization':   sig,
          'x-ms-date':       date,
          'time-generated-field': 'TimeGenerated',
          'Content-Length':  Buffer.byteLength(body),
        },
      };

      const req = https.request(options, (res) => {
        resolve({ ok: res.statusCode === 200, status: res.statusCode });
      });

      req.on('error',   err => resolve({ ok: false, error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'Sentinel timeout' }); });
      req.write(body);
      req.end();
    });
  }

  // ── Send alert to Sentinel ────────────────────────────────────
  async sendAlert(alert) {
    return this.sendLogs({
      TimeGenerated:    alert.created_at || new Date().toISOString(),
      AlertId:          alert.id,
      Severity:         alert.severity,
      Category:         alert.category,
      Title:            alert.title,
      Description:      alert.description,
      TenantId:         alert.tenant_id,
      SourceIp:         alert.src_ip || '',
      DestinationIp:    alert.dst_ip || '',
      MitreTactic:      alert.mitre_tactic || '',
      MitreTechnique:   alert.mitre_technique || '',
      Confidence:       alert.confidence || 0,
      RuleId:           alert.rule_id || '',
      IOCs:             JSON.stringify(alert.iocs || []),
      Platform:         'WadjetEyeAI',
    });
  }
}

// ══════════════════════════════════════════════════════════════════
//  CORTEX XSOAR CONNECTOR
// ══════════════════════════════════════════════════════════════════

class XsoarConnector {
  constructor(opts = {}) {
    this.url     = opts.url     || process.env.XSOAR_URL     || '';
    this.apiKey  = opts.apiKey  || process.env.XSOAR_API_KEY || '';
    this.keyId   = opts.keyId   || process.env.XSOAR_KEY_ID  || '';
    this.enabled = !!(this.url && this.apiKey);
  }

  async _request(method, path, body = null) {
    return new Promise((resolve) => {
      const parsed   = new URL(this.url + path);
      const isHttps  = parsed.protocol === 'https:';
      const reqLib   = isHttps ? https : http;
      const payload  = body ? JSON.stringify(body) : null;

      // XSOAR Advanced auth: Authorization: <keyId>:<apiKey>
      const authHeader = this.keyId
        ? `${this.keyId}:${this.apiKey}`
        : this.apiKey;

      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method,
        timeout:  30000,
        headers: {
          'Content-Type':  'application/json',
          'Authorization': authHeader,
          'x-xdr-auth-id': this.keyId || '',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
        rejectUnauthorized: process.env.XSOAR_VERIFY_SSL !== 'false',
      };

      const req = reqLib.request(options, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString());
            resolve({ ok: res.statusCode < 400, status: res.statusCode, data });
          } catch {
            resolve({ ok: res.statusCode < 400, status: res.statusCode, data: null });
          }
        });
      });

      req.on('error',   err => resolve({ ok: false, error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'XSOAR timeout' }); });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ── Create incident in XSOAR ──────────────────────────────────
  async createIncident(alert) {
    if (!this.enabled) return { created: false, reason: 'XSOAR not configured' };

    const incident = {
      name:      `WadjetEye: ${alert.title}`,
      type:      _xsoarIncidentType(alert.severity),
      severity:  _xsoarSeverity(alert.severity),
      owner:     '',
      playbookId: process.env.XSOAR_DEFAULT_PLAYBOOK || '',
      details:   alert.description || '',
      labels: [
        { type: 'alert_id',          value: alert.id || '' },
        { type: 'mitre_technique',   value: alert.mitre_technique || '' },
        { type: 'src_ip',            value: alert.src_ip || '' },
        { type: 'tenant_id',         value: alert.tenant_id || '' },
      ],
      customFields: {
        wadjet_alert_id:    alert.id,
        wadjet_severity:    alert.severity,
        wadjet_confidence:  String(alert.confidence || 0),
        mitre_tactic:       alert.mitre_tactic || '',
        mitre_technique:    alert.mitre_technique || '',
        iocs:               JSON.stringify(alert.iocs || []),
      },
    };

    return this._request('POST', '/incident', incident);
  }

  // ── Run playbook ──────────────────────────────────────────────
  async runPlaybook(incidentId, playbookId) {
    if (!this.enabled) return { ok: false, reason: 'XSOAR not configured' };
    return this._request('POST', '/playbook/run', { incidentId, playbookId });
  }

  // ── Get incident status ───────────────────────────────────────
  async getIncident(incidentId) {
    if (!this.enabled) return null;
    const res = await this._request('GET', `/incident/${incidentId}`);
    return res.ok ? res.data : null;
  }
}

function _xsoarSeverity(severity) {
  const map = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  return map[severity] ?? 2;
}

function _xsoarIncidentType(severity) {
  if (severity === 'CRITICAL') return 'Critical Threat';
  if (severity === 'HIGH')     return 'High Severity Alert';
  return 'Security Alert';
}

// ══════════════════════════════════════════════════════════════════
//  CEF/SYSLOG COLLECTOR SERVER
// ══════════════════════════════════════════════════════════════════

class CefSyslogCollector {
  constructor(opts = {}) {
    this.udpPort    = opts.udpPort    || parseInt(process.env.SYSLOG_UDP_PORT, 10) || 514;
    this.tcpPort    = opts.tcpPort    || parseInt(process.env.SYSLOG_TCP_PORT, 10) || 1514;
    this.onMessage  = opts.onMessage  || null;
    this._udpServer = null;
    this._tcpServer = null;
  }

  // ── Parse CEF message ────────────────────────────────────────
  static parseCef(raw) {
    const CEF_HEADER = /^(?:<\d+>)?(?:\w{3}\s+\d+\s+\S+\s+)?CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/;
    const match = raw.match(CEF_HEADER);

    if (!match) return { raw, type: 'syslog', parsed: false };

    const [, version, vendor, product, devVersion, sigId, name, severity, ext] = match;

    // Parse extension fields
    const extensions = {};
    const extParts = ext.match(/(\w+)=((?:[^\\=\s]|\\.)+(?:\s(?!\w+=)(?:[^\\=\s]|\\.)+)*)/g) || [];
    for (const part of extParts) {
      const eqIdx = part.indexOf('=');
      if (eqIdx > 0) {
        extensions[part.substring(0, eqIdx)] = part.substring(eqIdx + 1);
      }
    }

    return {
      type:       'cef',
      parsed:     true,
      cef_version: parseInt(version, 10),
      device_vendor:  vendor,
      device_product: product,
      device_version: devVersion,
      signature_id:   sigId,
      name,
      severity:   parseInt(severity, 10),
      extensions,
      raw,
      received_at: new Date().toISOString(),
    };
  }

  // ── Parse Syslog (RFC 5424 / RFC 3164) ───────────────────────
  static parseSyslog(raw) {
    // RFC 5424
    const rfc5424 = /^<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+)(?: (\S+))? (.*)$/;
    const match5424 = raw.match(rfc5424);
    if (match5424) {
      const [, pri, , ts, host, app, procid, msgid, , msg] = match5424;
      const facility = Math.floor(parseInt(pri, 10) / 8);
      const level    = parseInt(pri, 10) % 8;
      return { type: 'syslog', protocol: 'rfc5424', facility, level, host, app, procid, msgid, msg, ts, raw };
    }

    // RFC 3164
    const rfc3164 = /^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s(.*)$/;
    const match3164 = raw.match(rfc3164);
    if (match3164) {
      const [, pri, ts, host, app, msg] = match3164;
      const facility = Math.floor(parseInt(pri, 10) / 8);
      const level    = parseInt(pri, 10) % 8;
      return { type: 'syslog', protocol: 'rfc3164', facility, level, host, app, msg, ts, raw };
    }

    return { type: 'unknown', raw, received_at: new Date().toISOString() };
  }

  // ── Start UDP collector ───────────────────────────────────────
  startUdp() {
    this._udpServer = dgram.createSocket('udp4');

    this._udpServer.on('message', (msg) => {
      const raw    = msg.toString('utf8').trim();
      const parsed = raw.includes('CEF:') ? CefSyslogCollector.parseCef(raw) : CefSyslogCollector.parseSyslog(raw);
      if (this.onMessage) this.onMessage(parsed);
    });

    this._udpServer.on('error', (err) => {
      console.error('[Syslog UDP] Error:', err.message);
    });

    this._udpServer.bind(this.udpPort, () => {
      console.log(`[Syslog UDP] Collector listening on UDP :${this.udpPort}`);
    });

    return this._udpServer;
  }

  // ── Start TCP collector ───────────────────────────────────────
  startTcp() {
    this._tcpServer = net.createServer((socket) => {
      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split('\n');
        buffer = lines.pop(); // incomplete last line

        for (const line of lines) {
          const raw    = line.trim();
          if (!raw) continue;
          const parsed = raw.includes('CEF:') ? CefSyslogCollector.parseCef(raw) : CefSyslogCollector.parseSyslog(raw);
          if (this.onMessage) this.onMessage(parsed);
        }
      });
      socket.on('error', () => {});
    });

    this._tcpServer.listen(this.tcpPort, () => {
      console.log(`[Syslog TCP] Collector listening on TCP :${this.tcpPort}`);
    });

    return this._tcpServer;
  }

  start() {
    this.startUdp();
    this.startTcp();
    return this;
  }

  stop() {
    this._udpServer?.close();
    this._tcpServer?.close();
  }
}

// ══════════════════════════════════════════════════════════════════
//  GENERIC WEBHOOK CONNECTOR
// ══════════════════════════════════════════════════════════════════

class WebhookConnector {
  constructor(opts = {}) {
    this.url     = opts.url;
    this.secret  = opts.secret || '';
    this.method  = opts.method  || 'POST';
    this.headers = opts.headers || {};
    this.enabled = !!this.url;
  }

  async send(payload) {
    if (!this.enabled) return { sent: false, reason: 'No webhook URL' };

    const body   = JSON.stringify(payload);
    const sig    = this.secret
      ? `sha256=${crypto.createHmac('sha256', this.secret).update(body).digest('hex')}`
      : undefined;

    return new Promise((resolve) => {
      const parsed  = new URL(this.url);
      const isHttps = parsed.protocol === 'https:';
      const reqLib  = isHttps ? https : http;

      const options = {
        hostname: parsed.hostname,
        port:     parsed.port || (isHttps ? 443 : 80),
        path:     parsed.pathname + parsed.search,
        method:   this.method,
        timeout:  15000,
        headers: {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-WadjetEye-Signature': sig || '',
          'X-Delivery-ID': crypto.randomUUID(),
          ...this.headers,
        },
      };

      const req = reqLib.request(options, (res) => {
        resolve({ sent: true, status: res.statusCode, ok: res.statusCode < 400 });
      });

      req.on('error',   err => resolve({ sent: false, error: err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ sent: false, error: 'Webhook timeout' }); });
      req.write(body);
      req.end();
    });
  }
}

// ── Singleton instances (lazy-init) ──────────────────────────────
let _splunk   = null;
let _sentinel = null;
let _xsoar    = null;

function getSplunk()   { return _splunk   = _splunk   || new SplunkConnector(); }
function getSentinel() { return _sentinel = _sentinel || new SentinelConnector(); }
function getXsoar()    { return _xsoar    = _xsoar    || new XsoarConnector(); }

// ── Fan-out: send alert to all configured integrations ───────────
async function fanoutAlert(alert) {
  const results = await Promise.allSettled([
    getSplunk().sendAlert(alert),
    getSentinel().sendAlert(alert),
    getXsoar().createIncident(alert),
  ]);

  return {
    splunk:   results[0].status === 'fulfilled' ? results[0].value : { ok: false, error: results[0].reason?.message },
    sentinel: results[1].status === 'fulfilled' ? results[1].value : { ok: false, error: results[1].reason?.message },
    xsoar:    results[2].status === 'fulfilled' ? results[2].value : { ok: false, error: results[2].reason?.message },
  };
}

module.exports = {
  SplunkConnector,
  SentinelConnector,
  XsoarConnector,
  CefSyslogCollector,
  WebhookConnector,
  getSplunk,
  getSentinel,
  getXsoar,
  fanoutAlert,
};
