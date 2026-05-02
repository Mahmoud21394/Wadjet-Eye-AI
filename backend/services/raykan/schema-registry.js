/**
 * ═══════════════════════════════════════════════════════════════════
 *  RAYKAN — Schema Registry v1.0
 *  Wadjet-Eye AI Platform
 *
 *  Central registry of known log-source schemas and field-alias
 *  profiles.  Every telemetry source that RAYKAN ingests has a
 *  corresponding SCHEMA_PROFILE here that maps its native field
 *  names to the canonical RAYKAN field set.
 *
 *  Design principles:
 *   1. Single source of truth for field aliases — no per-module
 *      alias tables; all modules import from here.
 *   2. Zero breaking changes — profiles are additive; adding a new
 *      source never removes existing mappings.
 *   3. Validated at load time — malformed profiles emit a warning
 *      and are skipped rather than crashing the engine.
 *
 *  Public API:
 *   SchemaRegistry.getProfile(sourceId)     → SchemaProfile | null
 *   SchemaRegistry.resolveField(evt, canon) → value | null
 *   SchemaRegistry.listProfiles()           → string[]
 *   SchemaRegistry.detectSource(evt)        → sourceId | 'unknown'
 *
 *  Canonical field names (used throughout the RAYKAN pipeline):
 *   eventId, timestamp, user, computer, process, commandLine,
 *   parentProc, srcIp, dstIp, srcPort, dstPort, filePath, hash,
 *   regKey, url, domain, eventCategory, bytesSent, targetProcess,
 *   accessType, fileName, sourceHost, targetHost
 *
 *  backend/services/raykan/schema-registry.js
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
//  SCHEMA PROFILES
//  Each profile maps canonical RAYKAN field names to one or more native
//  source field names (first non-null win wins).
// ─────────────────────────────────────────────────────────────────────────────
const SCHEMA_PROFILES = {

  // ── Windows Event Log (EVTX) ────────────────────────────────────────────────
  evtx: {
    label      : 'Windows Event Log (EVTX)',
    formatHints: ['evtx', 'windows', 'winevt'],
    channelHints: ['security', 'system', 'application', 'microsoft-windows'],
    fields: {
      eventId      : ['EventID',         'event_id'],
      timestamp    : ['TimeCreated',      'SystemTime',   'timestamp'],
      user         : ['SubjectUserName',  'TargetUserName', 'User', 'username'],
      computer     : ['Computer',         'WorkstationName', 'hostname'],
      process      : ['ProcessName',      'Image',          'process_name'],
      commandLine  : ['CommandLine',      'cmd'],
      parentProc   : ['ParentProcessName','ParentImage'],
      srcIp        : ['IpAddress',        'SourceAddress',  'src_ip'],
      dstIp        : ['DestinationIp',    'dest_ip'],
      srcPort      : ['IpPort',           'SourcePort',     'src_port'],
      dstPort      : ['DestinationPort',  'dest_port'],
      filePath     : ['TargetFilename',   'ObjectName',     'file_path'],
      hash         : ['Hashes',           'hash',           'md5'],
      regKey       : ['TargetObject',     'registry_key'],
      channel      : ['Channel',          'log'],
      logonType    : ['LogonType',        'logon_type'],
      authPackage  : ['AuthenticationPackageName', 'AuthPackage'],
    },
  },

  // ── Sysmon (EID 1–29) ───────────────────────────────────────────────────────
  sysmon: {
    label      : 'Sysmon (System Monitor)',
    formatHints: ['sysmon'],
    channelHints: ['microsoft-windows-sysmon/operational', 'sysmon'],
    fields: {
      eventId      : ['EventID',          'event_id'],
      timestamp    : ['UtcTime',          'TimeCreated', 'timestamp'],
      user         : ['User',             'username'],
      computer     : ['Computer',         'hostname'],
      process      : ['Image',            'ProcessName'],
      commandLine  : ['CommandLine',      'cmd'],
      parentProc   : ['ParentImage',      'ParentProcessName'],
      srcIp        : ['SourceIp',         'src_ip'],
      dstIp        : ['DestinationIp',    'dst_ip',     'dest_ip'],
      srcPort      : ['SourcePort',       'src_port'],
      dstPort      : ['DestinationPort',  'dst_port'],
      filePath     : ['TargetFilename',   'ImageLoaded', 'file_path'],
      hash         : ['Hashes',           'hash'],
      regKey       : ['TargetObject'],
      url          : ['QueryName',        'dns_query'],
      domain       : ['QueryName',        'domain'],
      targetProcess: ['TargetImage',      'target_process'],
      accessType   : ['GrantedAccess',    'access_type'],
    },
  },

  // ── Linux Syslog / Auditd ────────────────────────────────────────────────────
  syslog: {
    label      : 'Linux Syslog / Auditd',
    formatHints: ['syslog', 'linux', 'auditd'],
    channelHints: ['auth.log', 'secure', 'syslog', 'messages'],
    fields: {
      timestamp    : ['syslog_timestamp', 'timestamp', '@timestamp'],
      user         : ['username',         'user',       'uid'],
      computer     : ['hostname',         'host'],
      process      : ['program',          'appname',    'process_name'],
      commandLine  : ['message',          'cmd'],
      srcIp        : ['src_ip',           'address',    'client'],
      srcPort      : ['src_port'],
      pid          : ['pid',              'process_id'],
    },
  },

  // ── CEF (Common Event Format — ArcSight, Palo Alto, etc.) ───────────────────
  cef: {
    label      : 'CEF (Common Event Format)',
    formatHints: ['cef'],
    channelHints: [],
    fields: {
      eventId      : ['deviceEventClassId', 'signatureId'],
      timestamp    : ['rt',                 'end',          '@timestamp'],
      user         : ['suser',              'duser'],
      computer     : ['dhost',              'src'],
      process      : ['sproc',              'dproc'],
      srcIp        : ['src',                'sourceAddress'],
      dstIp        : ['dst',                'destinationAddress'],
      srcPort      : ['spt',                'sourcePort'],
      dstPort      : ['dpt',                'destinationPort'],
      filePath     : ['fname',              'filePath'],
      url          : ['request',            'requestURL'],
      bytesSent    : ['out',                'bytesOut',     'bytes_sent'],
    },
  },

  // ── LEEF (Log Event Extended Format — IBM QRadar) ──────────────────────────
  leef: {
    label      : 'LEEF (Log Event Extended Format)',
    formatHints: ['leef'],
    channelHints: [],
    fields: {
      eventId      : ['devEventId'],
      timestamp    : ['devTimeFormat',    'devTime',    '@timestamp'],
      user         : ['usrName',          'accountName'],
      computer     : ['srcHost',          'dstHost'],
      srcIp        : ['src',              'srcIP'],
      dstIp        : ['dst',              'dstIP'],
      srcPort      : ['srcPort'],
      dstPort      : ['dstPort'],
      url          : ['url',              'requestURL'],
      bytesSent    : ['totalBytes',       'txBytes'],
    },
  },

  // ── Web / HTTP (IIS, Apache, NGINX W3C) ──────────────────────────────────────
  webserver: {
    label      : 'Web Server Log (IIS / Apache / NGINX)',
    formatHints: ['webserver', 'iis', 'apache', 'nginx', 'http'],
    channelHints: ['w3svc', 'httpd', 'access_log'],
    fields: {
      timestamp    : ['time',             'datetime',   '@timestamp'],
      srcIp        : ['c-ip',             'client_ip',  'remote_addr'],
      dstIp        : ['s-ip',             'server_ip'],
      url          : ['cs-uri-stem',      'request_uri','path'],
      httpMethod   : ['cs-method',        'method',     'request_method'],
      statusCode   : ['sc-status',        'status',     'response_code'],
      bytesSent    : ['sc-bytes',         'bytes_sent', 'body_bytes_sent'],
      userAgent    : ['cs(User-Agent)',    'user_agent', 'http_user_agent'],
    },
  },

  // ── Firewall / Network (Cisco ASA, Palo Alto, Check Point) ───────────────────
  firewall: {
    label      : 'Firewall / Network',
    formatHints: ['firewall', 'netflow', 'paloalto', 'cisco_asa'],
    channelHints: [],
    fields: {
      timestamp    : ['start',            'timestamp',  '@timestamp'],
      srcIp        : ['src_ip',           'sourceAddress', 'IpAddress'],
      dstIp        : ['dst_ip',           'destinationAddress'],
      srcPort      : ['src_port',         'sourcePort'],
      dstPort      : ['dst_port',         'destinationPort'],
      protocol     : ['proto',            'protocol',   'transport'],
      action       : ['action',           'disposition'],
      bytesSent    : ['bytes_sent',       'BytesSent',  'sc-bytes'],
    },
  },

  // ── Database (MSSQL, MySQL, PostgreSQL audit) ────────────────────────────────
  database: {
    label      : 'Database Audit Log',
    formatHints: ['database', 'mssql', 'mysql', 'postgresql', 'oracle'],
    channelHints: [],
    fields: {
      timestamp    : ['event_time',       'timestamp',  '@timestamp'],
      user         : ['server_principal_name', 'user_host', 'username'],
      computer     : ['server_name',      'host'],
      srcIp        : ['client_net_address','host', 'connection_id'],
      commandLine  : ['statement',        'sql_text',   'query'],
      database     : ['database_name',    'schema_name'],
    },
  },

  // ── Generic EDR / XDR telemetry (custom event_type-based) ─────────────────────
  edr: {
    label      : 'EDR / XDR Custom Telemetry',
    formatHints: ['edr', 'xdr', 'telemetry'],
    channelHints: [],
    // Detected when event has 'event_type' field (no EventID / Channel)
    detectionField: 'event_type',
    fields: {
      eventCategory: ['event_type',       'eventCategory'],
      timestamp    : ['timestamp',        '@timestamp',  'ts'],
      user         : ['user',             'username',    'subject_user'],
      computer     : ['hostname',         'host',        'computer'],
      process      : ['process',          'image',       'process_name'],
      commandLine  : ['commandLine',      'cmd',         'command'],
      srcIp        : ['src_ip',           'sourceIp',    'source_address'],
      dstIp        : ['dst_ip',           'destIp',      'destination_address'],
      dstPort      : ['dest_port',        'dstPort',     'destination_port'],
      bytesSent    : ['bytes_sent',       'bytesSent'],
      targetProcess: ['target_process',   'targetProcess'],
      accessType   : ['access_type',      'accessType',  'grantedAccess'],
      fileName     : ['file_name',        'fileName',    'target_filename'],
      hash         : ['hash',             'sha256',      'md5'],
      sourceHost   : ['source_host',      'sourceHost'],
      targetHost   : ['target_host',      'targetHost',  'dest_host'],
    },
  },
};

// ─────────────────────────────────────────────────────────────────────────────
//  SCHEMA REGISTRY CLASS
// ─────────────────────────────────────────────────────────────────────────────
class SchemaRegistry {
  constructor() {
    this._profiles = new Map();
    this._loadProfiles();
  }

  _loadProfiles() {
    for (const [id, profile] of Object.entries(SCHEMA_PROFILES)) {
      if (!profile.fields || typeof profile.fields !== 'object') {
        console.warn(`[SchemaRegistry] Skipping malformed profile: ${id}`);
        continue;
      }
      this._profiles.set(id, profile);
    }
    console.log(`[SchemaRegistry] Loaded ${this._profiles.size} schema profiles`);
  }

  /**
   * getProfile — Returns the schema profile for the given sourceId.
   * @param {string} sourceId
   * @returns {Object|null}
   */
  getProfile(sourceId) {
    return this._profiles.get(sourceId) || null;
  }

  /**
   * listProfiles — Returns all registered profile IDs.
   * @returns {string[]}
   */
  listProfiles() {
    return [...this._profiles.keys()];
  }

  /**
   * detectSource — Heuristically identifies the schema profile that best
   * matches the given raw event object.  Returns a profile ID string or
   * 'unknown' when no profile matches.
   *
   * @param {Object} evt — raw (un-normalized) event object
   * @returns {string}
   */
  detectSource(evt) {
    if (!evt || typeof evt !== 'object') return 'unknown';

    // 1. Explicit format hint
    const fmt = (evt.format || evt._format || '').toLowerCase();
    if (fmt) {
      for (const [id, profile] of this._profiles) {
        if ((profile.formatHints || []).some(h => fmt.includes(h))) return id;
      }
    }

    // 2. Channel hint
    const ch = (evt.Channel || evt.channel || evt.log || '').toLowerCase();
    if (ch) {
      for (const [id, profile] of this._profiles) {
        if ((profile.channelHints || []).some(h => ch.includes(h))) return id;
      }
    }

    // 3. Detection field (e.g. event_type for EDR)
    for (const [id, profile] of this._profiles) {
      if (profile.detectionField && evt[profile.detectionField] != null) return id;
    }

    // 4. Key-presence heuristics
    if (evt.EventID != null || evt.event_id != null) {
      if (evt.Image != null || evt.CommandLine != null) return 'sysmon';
      return 'evtx';
    }
    if (evt['cs-uri-stem'] != null || evt['cs-method'] != null)  return 'webserver';
    if (evt.syslog_timestamp != null || evt.program != null)     return 'syslog';
    if (evt.CEF != null || evt.leef_version != null)             return evt.CEF ? 'cef' : 'leef';
    if (evt.sql_text != null || evt.statement != null)           return 'database';
    if (evt.action != null && (evt.src_ip != null || evt.dst_ip != null)) return 'firewall';

    return 'unknown';
  }

  /**
   * resolveField — Resolves a canonical field name to its value in the raw
   * event, using the field alias mapping from the detected (or provided)
   * schema profile.
   *
   * @param {Object} evt       — raw event object
   * @param {string} canonical — canonical RAYKAN field name
   * @param {string} [profileId] — optional override; auto-detected if omitted
   * @returns {*} value or null
   */
  resolveField(evt, canonical, profileId = null) {
    const pid     = profileId || this.detectSource(evt);
    const profile = this._profiles.get(pid);
    if (!profile) return evt[canonical] || null;

    const aliases = profile.fields[canonical] || [];
    for (const alias of aliases) {
      // Support dot-notation into raw sub-objects
      const val = alias.includes('.')
        ? alias.split('.').reduce((o, k) => (o != null ? o[k] : null), evt)
        : (evt[alias] ?? evt.raw?.[alias]);
      if (val != null) return val;
    }

    // Final fallback: try the canonical name directly
    return evt[canonical] ?? evt.raw?.[canonical] ?? null;
  }

  /**
   * applyProfile — Returns a copy of evt with all canonical fields
   * populated from the schema profile.  Used in _normalizeEvents() as
   * a pre-processing step before the manual alias block.
   *
   * @param {Object} evt
   * @param {string} [profileId]
   * @returns {Object} enriched event (original object is NOT mutated)
   */
  applyProfile(evt, profileId = null) {
    const pid     = profileId || this.detectSource(evt);
    const profile = this._profiles.get(pid);
    if (!profile) return evt;

    const overlay = {};
    for (const canonical of Object.keys(profile.fields)) {
      const val = this.resolveField(evt, canonical, pid);
      if (val != null) overlay[canonical] = val;
    }

    // Preserve the detected schema source for downstream diagnostics
    return Object.assign({}, evt, overlay, { _schemaSource: pid });
  }
}

// ── Singleton instance ────────────────────────────────────────────
const _registry = new SchemaRegistry();

module.exports = _registry;
module.exports.SchemaRegistry  = SchemaRegistry;
module.exports.SCHEMA_PROFILES = SCHEMA_PROFILES;
