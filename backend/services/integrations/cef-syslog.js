/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — CEF/Syslog Collector & Forwarder (Phase 6)
 *  backend/services/integrations/cef-syslog.js
 *
 *  Implements:
 *  • CEF (Common Event Format) parser — ingest from SIEM agents
 *  • Syslog UDP/TCP receiver (RFC 5424 + RFC 3164)
 *  • CEF event generator — forward to external SIEMs
 *  • Syslog forwarder — send to remote syslog servers
 *
 *  Audit finding: No CEF/Syslog event collection pipeline
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

const dgram  = require('dgram');
const net    = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');

// ── CEF Version & Vendor ──────────────────────────────────────────
const CEF_VERSION  = '0';
const CEF_VENDOR   = 'Wadjet-Eye AI';
const CEF_PRODUCT  = 'WadjetEye';
const CEF_VERSION_STR = '4.1.0';

// ── Severity Mapping (CEF uses 0-10) ─────────────────────────────
const SEVERITY_TO_CEF = {
  critical:      10,
  high:          7,
  medium:        5,
  low:           2,
  informational: 0,
  unknown:       0,
};

// ══════════════════════════════════════════════════════════════════
//  CEF PARSER
// ══════════════════════════════════════════════════════════════════

/**
 * parseCEF — parse a raw CEF string into a structured object
 *
 * CEF format:
 *   CEF:Version|Device Vendor|Device Product|Device Version|
 *   Device Event Class ID|Name|Severity|[Extension]
 *
 * @param {string} rawLine - Raw CEF log line (may start with syslog header)
 * @returns {object|null}  - Parsed CEF object or null on parse failure
 */
function parseCEF(rawLine) {
  if (!rawLine || typeof rawLine !== 'string') return null;

  // Strip optional syslog priority + timestamp prefix
  let cefPart = rawLine;
  const syslogMatch = rawLine.match(/<\d+>(?:\w+ \d+ \d{2}:\d{2}:\d{2} \S+ )?(CEF:.+)/);
  if (syslogMatch) cefPart = syslogMatch[1];

  // RFC 5424 structured syslog
  const rfc5424Match = rawLine.match(/^<\d+>\d+ \S+ \S+ \S+ \S+ \S+ \S* (CEF:.+)/);
  if (rfc5424Match) cefPart = rfc5424Match[1];

  if (!cefPart.startsWith('CEF:')) return null;

  // Split header fields (first 8 fields separated by unescaped |)
  // CEF allows escaped pipe as \|
  const parts = cefPart.replace(/\\([|\\])/g, (_, c) => `\x00${c === '|' ? 'PIPE' : 'BACKSLASH'}\x00`).split('|');
  if (parts.length < 7) return null;

  const restorePipe = (s) => s.replace(/\x00PIPE\x00/g, '|').replace(/\x00BACKSLASH\x00/g, '\\');

  const [cefHeader, vendor, product, version, eventClassId, name, severity, ...extensionParts] = parts;
  const extensionStr = restorePipe(extensionParts.join('|'));

  // Parse extension key=value pairs
  const extension = parseExtension(extensionStr);

  return {
    cef_version:    cefHeader.replace('CEF:', ''),
    device_vendor:  restorePipe(vendor),
    device_product: restorePipe(product),
    device_version: restorePipe(version),
    event_class_id: restorePipe(eventClassId),
    name:           restorePipe(name),
    severity:       parseInt(severity, 10) || 0,
    extension,
    // Normalized fields
    source_ip:      extension.src || extension.spt || null,
    dest_ip:        extension.dst || extension.dpt || null,
    source_port:    extension.spt ? parseInt(extension.spt, 10) : null,
    dest_port:      extension.dpt ? parseInt(extension.dpt, 10) : null,
    username:       extension.suser || extension.duser || null,
    host:           extension.dhost || extension.shost || null,
    message:        extension.msg || extension.cs1 || null,
    outcome:        extension.outcome || null,
    event_time:     extension.rt ? new Date(parseInt(extension.rt, 10)) : new Date(),
    raw:            rawLine,
  };
}

/**
 * parseExtension — parse CEF extension key=value string
 * Handles quoted values and escaped characters
 */
function parseExtension(extStr) {
  const result = {};
  if (!extStr) return result;

  // Regex: matches key=value where value runs until next key= or end
  // Values can contain spaces but not unescaped = before next key
  const keyValRegex = /(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)/g;
  let match;
  while ((match = keyValRegex.exec(extStr)) !== null) {
    const key = match[1];
    const val = match[2].replace(/\\([=\\|])/g, '$1').trim();
    result[key] = val;
  }
  return result;
}

// ══════════════════════════════════════════════════════════════════
//  CEF GENERATOR
// ══════════════════════════════════════════════════════════════════

/**
 * alertToCEF — convert Wadjet-Eye alert to CEF string
 */
function alertToCEF(alert) {
  const severity = SEVERITY_TO_CEF[alert.severity] ?? 5;
  const eventClassId = alert.rule_id || `WADJET-${alert.category || 'ALERT'}`;
  const name = escapeCEFHeader(alert.title || 'Security Alert');

  const ext = buildCEFExtension({
    rt:           new Date(alert.created_at || Date.now()).getTime(),
    src:          alert.source_ip || '',
    dst:          alert.dest_ip || '',
    shost:        alert.host || '',
    suser:        alert.username || '',
    msg:          (alert.description || alert.ai_summary || '').substring(0, 500),
    cs1Label:     'RuleId',
    cs1:          alert.rule_id || '',
    cs2Label:     'MitreTactic',
    cs2:          alert.mitre_tactic || '',
    cs3Label:     'MitreTechnique',
    cs3:          alert.mitre_technique || '',
    cs4Label:     'RiskScore',
    cs4:          String(alert.risk_score || 0),
    cs5Label:     'Confidence',
    cs5:          String(alert.confidence || 0),
    cs6Label:     'AlertId',
    cs6:          alert.id || '',
    cn1Label:     'RiskScore',
    cn1:          alert.risk_score || 0,
    outcome:      mapOutcome(alert.status),
    externalId:   alert.id || '',
    cat:          alert.category || 'Security',
    deviceCustomString7Label: 'TenantId',
    deviceCustomString7: alert.tenant_id || '',
  });

  return `CEF:${CEF_VERSION}|${CEF_VENDOR}|${CEF_PRODUCT}|${CEF_VERSION_STR}|${eventClassId}|${name}|${severity}|${ext}`;
}

function escapeCEFHeader(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

function escapeCEFExtValue(str) {
  return String(str).replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r/g, '\\r').replace(/\n/g, '\\n');
}

function buildCEFExtension(fields) {
  return Object.entries(fields)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${escapeCEFExtValue(v)}`)
    .join(' ');
}

function mapOutcome(status) {
  const map = {
    open:           'Unknown',
    in_progress:    'Unknown',
    escalated:      'Unknown',
    closed:         'Success',
    false_positive: 'Failure',
    true_positive:  'Success',
    duplicate:      'Unknown',
  };
  return map[status] || 'Unknown';
}

// ══════════════════════════════════════════════════════════════════
//  SYSLOG RECEIVER (UDP + TCP)
// ══════════════════════════════════════════════════════════════════

class SyslogReceiver extends EventEmitter {
  constructor(options = {}) {
    super();
    this.udpPort    = options.udpPort || 514;
    this.tcpPort    = options.tcpPort || 514;
    this.host       = options.host    || '0.0.0.0';
    this.maxLineLen = options.maxLineLen || 65536;

    this._udpServer = null;
    this._tcpServer = null;
    this._stats = { udp_received: 0, tcp_received: 0, cef_parsed: 0, errors: 0 };
  }

  /**
   * start — bind UDP and TCP listeners
   */
  async start() {
    await Promise.all([
      this._startUDP(),
      this._startTCP(),
    ]);
    console.log(`[Syslog] Receiver listening — UDP:${this.udpPort} TCP:${this.tcpPort}`);
  }

  _startUDP() {
    return new Promise((resolve, reject) => {
      this._udpServer = dgram.createSocket('udp4');

      this._udpServer.on('message', (msg, rinfo) => {
        this._stats.udp_received++;
        const line = msg.toString('utf8').trim();
        this._processLine(line, { protocol: 'udp', remote_ip: rinfo.address, remote_port: rinfo.port });
      });

      this._udpServer.on('error', (err) => {
        this._stats.errors++;
        this.emit('error', { source: 'udp', error: err.message });
      });

      this._udpServer.bind(this.udpPort, this.host, () => resolve());
    });
  }

  _startTCP() {
    return new Promise((resolve, reject) => {
      this._tcpServer = net.createServer((socket) => {
        let buffer = '';

        socket.on('data', (data) => {
          buffer += data.toString('utf8');
          const lines = buffer.split('\n');
          buffer = lines.pop();  // Keep incomplete line in buffer

          for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed) {
              this._stats.tcp_received++;
              this._processLine(trimmed, {
                protocol:    'tcp',
                remote_ip:   socket.remoteAddress,
                remote_port: socket.remotePort,
              });
            }
          }
        });

        socket.on('error', (err) => {
          this._stats.errors++;
          this.emit('error', { source: 'tcp', error: err.message });
        });

        socket.setTimeout(60000);
        socket.on('timeout', () => socket.destroy());
      });

      this._tcpServer.listen(this.tcpPort, this.host, () => resolve());
    });
  }

  _processLine(line, meta) {
    if (!line || line.length > this.maxLineLen) return;

    // Try CEF parsing first
    if (line.includes('CEF:')) {
      const parsed = parseCEF(line);
      if (parsed) {
        this._stats.cef_parsed++;
        this.emit('cef', { ...parsed, _meta: meta, id: crypto.randomUUID() });
        return;
      }
    }

    // Emit as raw syslog
    const syslog = parseSyslog(line, meta);
    this.emit('syslog', syslog);
  }

  stats() {
    return { ...this._stats };
  }

  async stop() {
    if (this._udpServer) {
      await new Promise(r => this._udpServer.close(r));
    }
    if (this._tcpServer) {
      await new Promise(r => this._tcpServer.close(r));
    }
  }
}

/**
 * parseSyslog — basic RFC 3164/5424 syslog parser
 */
function parseSyslog(line, meta = {}) {
  const result = {
    raw:         line,
    timestamp:   new Date(),
    facility:    null,
    severity:    null,
    host:        meta.remote_ip || null,
    program:     null,
    pid:         null,
    message:     line,
    _meta:       meta,
    id:          crypto.randomUUID(),
  };

  // Parse priority <PRI>
  const priMatch = line.match(/^<(\d+)>/);
  if (priMatch) {
    const pri      = parseInt(priMatch[1], 10);
    result.facility = Math.floor(pri / 8);
    result.severity = pri % 8;
  }

  // RFC 3164: <PRI>MMM DD HH:MM:SS host program[pid]: msg
  const r3164 = line.match(/^(?:<\d+>)?(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)/);
  if (r3164) {
    result.host    = r3164[2];
    result.program = r3164[3];
    result.pid     = r3164[4] ? parseInt(r3164[4], 10) : null;
    result.message = r3164[5];
  }

  // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
  const r5424 = line.match(/^<\d+>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(.*)/);
  if (r5424) {
    result.timestamp = new Date(r5424[2]);
    result.host      = r5424[3];
    result.program   = r5424[4];
    result.pid       = r5424[5] !== '-' ? r5424[5] : null;
    result.message   = r5424[8] || '';
  }

  return result;
}

// ══════════════════════════════════════════════════════════════════
//  SYSLOG FORWARDER
// ══════════════════════════════════════════════════════════════════

/**
 * SyslogForwarder — sends CEF events to a remote syslog server
 */
class SyslogForwarder {
  constructor(options = {}) {
    this.host     = options.host || 'localhost';
    this.port     = options.port || 514;
    this.protocol = options.protocol || 'udp';
    this.facility = options.facility || 1;   // 1 = user-level
    this.tag      = options.tag || 'wadjet-eye';
    this._socket  = null;
    this._tcpConn = null;
    this._stats   = { sent: 0, errors: 0 };
  }

  /**
   * send — forward a CEF string via UDP or TCP syslog
   */
  async send(cefLine) {
    const timestamp = new Date().toUTCString().replace(',', '').substring(5, 24);
    const priority  = (this.facility * 8) + 6;  // facility + informational
    const syslogLine = `<${priority}>${timestamp} wadjet-eye ${this.tag}: ${cefLine}\n`;
    const payload    = Buffer.from(syslogLine, 'utf8');

    if (this.protocol === 'udp') {
      return this._sendUDP(payload);
    } else {
      return this._sendTCP(payload);
    }
  }

  async _sendUDP(payload) {
    return new Promise((resolve, reject) => {
      const client = dgram.createSocket('udp4');
      client.send(payload, 0, payload.length, this.port, this.host, (err) => {
        client.close();
        if (err) {
          this._stats.errors++;
          reject(err);
        } else {
          this._stats.sent++;
          resolve({ sent: true });
        }
      });
    });
  }

  async _sendTCP(payload) {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port }, () => {
        socket.write(payload, (err) => {
          socket.end();
          if (err) {
            this._stats.errors++;
            reject(err);
          } else {
            this._stats.sent++;
            resolve({ sent: true });
          }
        });
      });
      socket.on('error', (err) => {
        this._stats.errors++;
        reject(err);
      });
      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('TCP syslog connection timeout'));
      });
    });
  }

  /**
   * forwardAlert — convert alert to CEF and forward
   */
  async forwardAlert(alert) {
    const cefLine = alertToCEF(alert);
    return this.send(cefLine);
  }

  /**
   * forwardAlerts — batch forward multiple alerts
   */
  async forwardAlerts(alerts) {
    const results = [];
    for (const alert of alerts) {
      try {
        await this.forwardAlert(alert);
        results.push({ id: alert.id, success: true });
      } catch (err) {
        results.push({ id: alert.id, success: false, error: err.message });
      }
    }
    return {
      total:   alerts.length,
      success: results.filter(r => r.success).length,
      failed:  results.filter(r => !r.success).length,
      results,
    };
  }

  stats() {
    return { ...this._stats };
  }
}

module.exports = {
  // CEF parsing/generation
  parseCEF,
  parseSyslog,
  alertToCEF,
  parseExtension,

  // Receiver
  SyslogReceiver,

  // Forwarder
  SyslogForwarder,
};
